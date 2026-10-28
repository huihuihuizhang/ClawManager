package systembackupconfig

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	ev "clawreef/internal/systembackupevidence"
	sec "clawreef/internal/systembackupsecurity"
)

// Publication authority/ledger/ready provenance are explicit protocol models;
// ciphertext uses actual framing/KEK crypto and an fsynced local test file.
// This is not a real diagnostic producer, SQL publication grant or crash test.
type responseStageFixture struct {
	file              *os.File
	path, mode        string
	sealed, discarded bool
	afterSeal         func()
}

func (s *responseStageFixture) Write(raw []byte) (int, error) {
	if s.sealed || s.discarded {
		return 0, errors.New("sealed stage")
	}
	return s.file.Write(raw)
}
func (s *responseStageFixture) Seal(ctx context.Context, m ev.Manifest) error {
	if ctx.Err() != nil || s.mode == "seal-failed" {
		return errors.New("PRIVATE stage seal failed")
	}
	if s.mode == "corrupt-stage" {
		if _, err := s.file.WriteAt([]byte("!"), 0); err != nil {
			return err
		}
	}
	if s.mode == "short-stage" {
		if err := s.file.Truncate(m.ObjectSize - 1); err != nil {
			return err
		}
	}
	if err := s.file.Sync(); err != nil {
		return err
	}
	s.sealed = true
	if s.afterSeal != nil {
		s.afterSeal()
	}
	return nil
}

type responseStageBadClose struct{ io.ReadCloser }

func (r responseStageBadClose) Close() error {
	r.ReadCloser.Close()
	return errors.New("PRIVATE staging close failed")
}
func (s *responseStageFixture) Open(ctx context.Context) (io.ReadCloser, error) {
	if ctx.Err() != nil || !s.sealed || s.discarded {
		return nil, errors.New("closed/unsealed stage")
	}
	stat, err := s.file.Stat()
	if err != nil {
		return nil, err
	}
	r := io.NopCloser(io.NewSectionReader(s.file, 0, stat.Size()))
	if s.mode == "close-failed" {
		return responseStageBadClose{r}, nil
	}
	return r, nil
}
func (s *responseStageFixture) Discard(ctx context.Context) error {
	if ctx.Err() != nil {
		return errors.New("canceled cleanup")
	}
	if s.discarded {
		return nil
	}
	s.file.Close()
	err := os.Remove(s.path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	s.discarded = true
	return nil
}

type responseFactoryFixture struct {
	t                              *testing.T
	mode                           string
	content                        ConfigMutationResponseContent
	stage                          *responseStageFixture
	preparedCalls, publishCalls    int
	ownerCustody, pending, revoked bool
	object                         []byte
	publication                    ConfigMutationResponsePublication
	guard                          *responseScopedGuardFixture
	cancel                         context.CancelFunc
	keys                           *responseTestKeys
}

func (f *responseFactoryFixture) AuthorizeContent(ctx context.Context, i ev.Identity) (ev.ContentAuthorization, error) {
	if f.revoked {
		return ev.ContentAuthorization{}, errors.New("PRIVATE content authority revoked")
	}
	return (responseContentAuthorityFixture{f.content}).AuthorizeContent(ctx, i)
}
func (f *responseFactoryFixture) PreparePublication(_ context.Context, c ConfigMutationResponseContent) (ConfigMutationResponsePublicationInputs, error) {
	f.preparedCalls++
	f.content = c
	if _, ok := c.Preparation().RequestBinding(); !ok {
		return ConfigMutationResponsePublicationInputs{}, errors.New("unbound attempt")
	}
	root := f.t.TempDir()
	f.t.Logf("LOCAL_RESPONSE_STAGE_TEMP path=%s", root)
	file, err := os.CreateTemp(root, "ciphertext-*.bin")
	if err != nil {
		return ConfigMutationResponsePublicationInputs{}, err
	}
	f.stage = &responseStageFixture{file: file, path: file.Name(), mode: f.mode}
	f.t.Cleanup(func() { f.stage.Discard(context.Background()) })
	if f.mode == "revoked-after-seal" {
		f.stage.afterSeal = func() { f.revoked = true }
	}
	if f.mode == "cancel-after-seal" {
		f.stage.afterSeal = f.cancel
	}
	f.keys = newResponseTestKeys(f.t, c.KEKReference())
	in := ConfigMutationResponsePublicationInputs{Authority: f, Keys: f.keys, Stage: f.stage, Publisher: f, Root: "responses", ValidUntil: c.until}
	switch f.mode {
	case "factory-error":
		return in, errors.New("PRIVATE factory refused")
	case "missing-key":
		in.Keys = nil
	case "missing-authority":
		in.Authority = nil
	case "missing-publisher":
		in.Publisher = nil
	case "bad-root":
		in.Root = "../outside"
	case "expired-input":
		in.ValidUntil = c.created
	case "wrong-key":
		in.Keys = newResponseTestKeys(f.t, ev.KeyRef{Identity: strings.Repeat("f", 64), Version: "other"})
	}
	return in, nil
}
func (f *responseFactoryFixture) Publish(ctx context.Context, p ConfigMutationResponsePublication, stage ConfigMutationResponseCiphertextStage) (ConfigMutationResponsePublished, error) {
	f.publishCalls++
	f.ownerCustody = true
	f.publication = p
	if f.stage != stage || !f.stage.sealed {
		return ConfigMutationResponsePublished{}, errors.New("not original sealed stage")
	}
	if f.mode == "unknown-after-pending" {
		f.pending = true
		return ConfigMutationResponsePublished{}, errors.New("PRIVATE publish outcome unknown")
	}
	r, err := p.OpenCiphertext(ctx)
	if err != nil {
		return ConfigMutationResponsePublished{}, err
	}
	f.object, err = io.ReadAll(r)
	closed := r.Close()
	if err != nil || closed != nil {
		return ConfigMutationResponsePublished{}, errors.New("original ciphertext read failed")
	}
	m := p.Binding().Manifest()
	c := p.Binding().Content()
	if registrationHash(string(f.object)) != m.ObjectHash || int64(len(f.object)) != m.ObjectSize || bytes.Contains(f.object, c.Bytes()) {
		return ConfigMutationResponsePublished{}, errors.New("wrong original ciphertext")
	}
	ref := ev.Ref{Identity: c.StoreReference().IdentityHash, Version: c.StoreReference().Version, RelativeKey: "responses/" + c.identity.Installation + "/system/" + c.identity.OwnerID + "/" + c.identity.ID + "/" + c.identity.ContentHash + ".bin", ImmutableVersion: "immutable-v1"}
	f.guard = &responseScopedGuardFixture{attempt: p.Binding().Request().AttemptSHA256(), ref: ref, until: c.until}
	switch f.mode {
	case "wrong-store":
		ref.Version = "other"
	case "wrong-key-path":
		ref.RelativeKey = "responses/other"
	case "null-version":
		ref.ImmutableVersion = "null"
	case "unicode-version":
		ref.ImmutableVersion = "版本"
	case "wrong-guard-scope":
		f.guard.attempt = strings.Repeat("f", 64)
	case "expired-guard":
		f.guard.until = c.created
	}
	if err := stage.Discard(context.Background()); err != nil {
		return ConfigMutationResponsePublished{}, err
	}
	if f.mode == "missing-guard" {
		return ConfigMutationResponsePublished{Reference: ref}, nil
	}
	if f.mode == "revoked-after-publish" {
		f.revoked = true
	}
	return ConfigMutationResponsePublished{Reference: ref, Guard: f.guard}, nil
}

type responseScopedGuardFixture struct {
	attempt string
	ref     ev.Ref
	until   time.Time
	tx      *sql.Tx
	checks  int
	revoked bool
}

func (g *responseScopedGuardFixture) ValidUntil() time.Time { return g.until }
func (g *responseScopedGuardFixture) RecheckPublication(_ context.Context, tx *sql.Tx, b ConfigMutationResponsePublicationBinding, ref ev.Ref, _ time.Time) error {
	g.checks++
	if g.revoked || tx != g.tx || b.Request().AttemptSHA256() != g.attempt || ref != g.ref {
		return errors.New("PRIVATE exact publication admission failed")
	}
	return nil
}
func responseBoundPreparation(t *testing.T, large bool) sec.ConfigMutationResponsePreparation {
	t.Helper()
	input, _ := responseContentFixture(t, large)
	raw, err := json.Marshal(map[string]any{"expected_version": 1, "change_reason": "raw request reason", "config": json.RawMessage(input.ContentPolicy().Config.CanonicalJSON())})
	if err != nil {
		t.Fatal(err)
	}
	r, err := sec.DecodeConfigMutationRequest(sec.ConfigUpdateEndpoint, raw)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := input.BindRequest(r, "mutation_key_0123456789", "full-responses-1", "sop_12345678-1234-1234-1234-123456789abc", 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	return bound
}
func responsesFixture(t *testing.T, large bool, mode string) (*ConfigResourceDiagnosticResponses, sec.ConfigMutationResponsePreparation, *responseFactoryFixture) {
	t.Helper()
	reader, _, _, _, _ := replayReaderFixture(t, false)
	factory := &responseFactoryFixture{t: t, mode: mode}
	s, err := NewConfigResourceDiagnosticResponses(reader, factory)
	if err != nil {
		t.Fatal(err)
	}
	return s, responseBoundPreparation(t, large), factory
}
func TestConfigResourceDiagnosticResponsesCompleteInlineAndPublishedPreparation(t *testing.T) {
	for _, large := range []bool{false, true} {
		name := "inline"
		if large {
			name = "published"
		}
		t.Run(name, func(t *testing.T) {
			s, input, f := responsesFixture(t, large, "")
			result, err := s.Prepare(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			p := result.(*preparedConfigMutationEvidenceResponse)
			if !bytes.Equal(p.content.Bytes(), input.Bytes()) || !evidenceIDPattern.MatchString(p.content.Identity().ID) {
				t.Fatal("lost full immutable body or id")
			}
			if large {
				m := p.prepared.Manifest()
				store := &responseTestObject{data: f.object, ref: p.ref, info: ev.ObjectInfo{Version: p.ref.ImmutableVersion, SHA256: m.ObjectHash, Size: m.ObjectSize}}
				scope := ConfigMutationResponseReadScope{Installation: m.Identity.Installation, Actor: input.Actor(), Now: time.Now().UTC(), ValidUntil: p.ValidUntil(), Root: "responses", Store: ev.KeyRef{Identity: p.ref.Identity, Version: p.ref.Version}, KEK: m.Key}
				raw, err := ReadPublishedConfigMutationResponse(context.Background(), scope, m, p.ref, store, f.keys)
				if err != nil || !bytes.Equal(raw, input.Bytes()) {
					t.Fatal("published original response roundtrip", err)
				}
			}
			state, tx := responseSQLFixture(t, p.content, p.prepared.Manifest(), p.ref)
			if large {
				f.guard.tx = tx
				if !f.ownerCustody || !f.stage.discarded || f.publishCalls != 1 || f.publication.Binding().Request().RequestHash() == "" {
					t.Fatal("publisher custody/scope not bound")
				}
			}
			id, err := p.Stage(context.Background(), tx, p.content.created)
			if err != nil || id != 67 {
				t.Fatal("atomic evidence staging", err)
			}
			if err = p.Recheck(context.Background(), tx, p.content.created); err != nil {
				t.Fatal("final original publication check", err)
			}
			if state.commits != 0 || !large && (f.preparedCalls != 0 || state.writes != 1) || large && (state.writes != 0 || f.guard.checks != 2) {
				t.Fatal("wrong publication branch/transaction ownership")
			}
		})
	}
}
func TestConfigResourceDiagnosticResponsesDiscardOnlyBeforePublicationCustody(t *testing.T) {
	for _, name := range []string{"factory-error", "missing-key", "missing-authority", "missing-publisher", "bad-root", "expired-input", "wrong-key", "seal-failed", "corrupt-stage", "short-stage", "close-failed", "revoked-after-seal", "cancel-after-seal", "unknown-after-pending", "wrong-store", "wrong-key-path", "null-version", "unicode-version", "missing-guard", "expired-guard", "revoked-after-publish"} {
		t.Run(name, func(t *testing.T) {
			s, input, f := responsesFixture(t, true, name)
			ctx := context.Background()
			if name == "cancel-after-seal" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				f.cancel = cancel
			}
			out, err := s.Prepare(ctx, input)
			if err != sec.ErrRegistrationUnavailable || out != nil {
				t.Fatal("invalid publication returned success/diagnostics", err)
			}
			if name == "unknown-after-pending" {
				if !f.ownerCustody || !f.pending || f.stage.discarded || f.publishCalls != 1 {
					t.Fatal("D discarded/retried unknown original ciphertext")
				}
				if _, err = os.Stat(f.stage.path); err != nil {
					t.Fatal("original ciphertext unavailable for owner recovery", err)
				}
			} else if f.stage == nil || !f.stage.discarded {
				t.Fatal("owned staging not cleaned")
			}
			if !f.ownerCustody && f.publishCalls != 0 {
				t.Fatal("publication before verified handoff")
			}
		})
	}
}
func TestConfigResourceDiagnosticResponsesScopedGuardCannotBeReusedOrExtended(t *testing.T) {
	for _, name := range []string{"wrong-guard-scope", "extended", "revoked"} {
		t.Run(name, func(t *testing.T) {
			mode := ""
			if name == "wrong-guard-scope" {
				mode = name
			}
			s, input, f := responsesFixture(t, true, mode)
			result, err := s.Prepare(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			p := result.(*preparedConfigMutationEvidenceResponse)
			state, tx := responseSQLFixture(t, p.content, p.prepared.Manifest(), p.ref)
			f.guard.tx = tx
			if name == "extended" {
				f.guard.until = f.guard.until.Add(time.Second)
			}
			if name == "revoked" {
				f.guard.revoked = true
			}
			if id, err := p.Stage(context.Background(), tx, p.content.created); id != 0 || err != sec.ErrRegistrationUnavailable || state.writes != 0 || state.commits != 0 {
				t.Fatal("unbound/renewed/revoked publication committed", err)
			}
		})
	}
}
func TestConfigResourceDiagnosticResponsesRejectUnboundFactsAndIncompleteAssembly(t *testing.T) {
	s, _, f := responsesFixture(t, true, "")
	unbound, _ := responseContentFixture(t, true)
	if out, err := s.Prepare(context.Background(), unbound); out != nil || err != sec.ErrRegistrationUnavailable || f.preparedCalls != 0 {
		t.Fatal("unbound preparation reached publisher", err)
	}
	for _, name := range []string{"reader", "publisher", "typed-nil-publisher"} {
		t.Run(name, func(t *testing.T) {
			reader := s.reader
			var factory ConfigMutationResponsePublicationFactory = f
			if name == "reader" {
				reader = nil
			}
			if name == "publisher" {
				factory = nil
			}
			if name == "typed-nil-publisher" {
				var empty *responseFactoryFixture
				factory = empty
			}
			if out, err := NewConfigResourceDiagnosticResponses(reader, factory); out != nil || err != sec.ErrRegistrationUnavailable {
				t.Fatal("missing runtime source accepted", err)
			}
		})
	}
}
func TestConfigResourceDiagnosticResponsesDelegateOnlyAuthenticatedSQLReplay(t *testing.T) {
	reader, in, state, _, _, _, want := mappedReplayReaderFixture(t, true)
	f := &responseFactoryFixture{t: t}
	s, err := NewConfigResourceDiagnosticResponses(reader, f)
	if err != nil {
		t.Fatal(err)
	}
	read, err := s.Read(context.Background(), in)
	if err != nil || !bytes.Equal(read.Bytes(), want) {
		t.Fatal("original SQL replay", err)
	}
	tx, err := reader.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = read.Recheck(context.Background(), tx, state.now); err != nil || f.preparedCalls != 0 || f.publishCalls != 0 {
		t.Fatal("read repeated publication", err)
	}
}
