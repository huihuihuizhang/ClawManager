package systembackupconfig

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	ev "clawreef/internal/systembackupevidence"
	sec "clawreef/internal/systembackupsecurity"
)

// Current SQL and provider-owner authority are protocol doubles here. The
// concrete D SQLLoginSessions/canonical/file-RBAC adapter has separate composed
// security tests; no fixture here creates a deployment grant or credential.
type replayCurrentAuthorityFixture struct {
	s      *replaySQLState
	denied bool
	checks int
}

func (a *replayCurrentAuthorityFixture) AuthorizeReplay(ctx context.Context, tx *sql.Tx, in sec.ConfigMutationResponseReplayPreparation, now time.Time) error {
	a.checks++
	if a.denied || ctx.Err() != nil || tx == nil || !a.s.active || in.Facts() != a.s.facts || now.Before(in.Facts().AuthorizedAt) {
		return errors.New("PRIVATE current configure denied")
	}
	return nil
}

type replayOwnerAuthorityFunc func(context.Context, sec.ConfigMutationResponseReplayPreparation, ConfigMutationResponseLocation) (ConfigMutationResponseReadAccess, error)

func (f replayOwnerAuthorityFunc) Prepare(ctx context.Context, in sec.ConfigMutationResponseReplayPreparation, l ConfigMutationResponseLocation) (ConfigMutationResponseReadAccess, error) {
	return f(ctx, in, l)
}

type replayOwnerCallbackAccess struct {
	ConfigMutationResponseReadAccess
	after func()
}

type replayUnwrapCallbackKeys struct {
	ev.Keys
	after    func()
	returned []byte
}

func (k *replayUnwrapCallbackKeys) Unwrap(ctx context.Context, ref ev.KeyRef, wrapped []byte) ([]byte, error) {
	var err error
	k.returned, err = k.Keys.Unwrap(ctx, ref, wrapped)
	k.after()
	return k.returned, err
}

type replayReadCallbackStream struct {
	io.ReadCloser
	after func()
}

func (r replayReadCallbackStream) Read(dst []byte) (int, error) {
	n, err := r.ReadCloser.Read(dst)
	r.after()
	return n, err
}

func (a replayOwnerCallbackAccess) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if err := a.ConfigMutationResponseReadAccess.Recheck(ctx, tx, now); err != nil {
		return err
	}
	a.after()
	return nil
}
func mappedReplayReaderFixture(t *testing.T, large bool) (*SQLConfigMutationResponseReader, sec.ConfigMutationResponseReplayPreparation, *replaySQLState, *replayAccessFixture, *replayCurrentAuthorityFixture, []ConfigMutationResponseHistoricalReadBinding, []byte) {
	t.Helper()
	r, in, s, owner, body := replayReaderFixture(t, large)
	current := &replayCurrentAuthorityFixture{s: s}
	var bindings []ConfigMutationResponseHistoricalReadBinding
	if large {
		bindings = []ConfigMutationResponseHistoricalReadBinding{{Store: sec.BootstrapSecretRef{Purpose: "evidence_store", IdentityHash: owner.resources.Store.Identity, Version: owner.resources.Store.Version}, KEK: sec.BootstrapSecretRef{Purpose: "evidence_kek", IdentityHash: owner.resources.KEK.Identity, Version: owner.resources.KEK.Version}, Root: owner.resources.Root, Owner: r.authority}}
	}
	a, err := NewPinnedConfigMutationResponseReplayAuthority(in.Facts().Installation, in.Facts().Database, current, bindings)
	if err != nil {
		t.Fatal(err)
	}
	r.authority = a
	return r, in, s, owner, current, bindings, body
}
func TestConfigMutationReplayMappedAuthorityReadsInlineAndRetainedExactObject(t *testing.T) {
	for _, large := range []bool{false, true} {
		name := "inline"
		if large {
			name = "external-retained"
		}
		t.Run(name, func(t *testing.T) {
			r, in, s, _, current, bindings, want := mappedReplayReaderFixture(t, large)
			// Deployment input slices are copied; changing a later caller's map cannot
			// substitute latest/current resources for an already selected old pair.
			if large {
				bindings[0].Root = "wrong-root"
				bindings[0].Store.Version = "current-latest"
			}
			read, err := r.Read(context.Background(), in)
			if err != nil || !bytes.Equal(read.Bytes(), want) {
				t.Fatal("exact original read", err)
			}
			tx, err := r.db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if err = read.Recheck(context.Background(), tx, s.now); err != nil || current.checks < 8 {
				t.Fatal("current SQL authority not composed", err, current.checks)
			}
			if s.writes != 0 || s.commits != 0 {
				t.Fatal("replay read wrote/committed")
			}
		})
	}
}
func TestConfigMutationReplayMappingHasNoFallbackOrPurposeEscalation(t *testing.T) {
	for _, name := range []string{"no-mapping", "different-store-version", "different-key-version", "different-store-identity", "wrong-root", "owner-resources-drift", "owner-revoked", "current-revoked", "owner-callback-revokes-current", "grant-extended-after-prepare"} {
		t.Run(name, func(t *testing.T) {
			r, in, s, owner, current, bindings, _ := mappedReplayReaderFixture(t, true)
			switch name {
			case "no-mapping":
				bindings = nil
			case "different-store-version":
				bindings[0].Store.Version = "other-version"
			case "different-key-version":
				bindings[0].KEK.Version = "other-version"
			case "different-store-identity":
				bindings[0].Store.IdentityHash = strings.Repeat("f", 64)
			case "wrong-root":
				bindings[0].Root = "another-root"
			case "owner-resources-drift":
				owner.resources.KEK.Version = "another-version"
			case "owner-revoked":
				owner.revoked = true
			case "current-revoked":
				current.denied = true
			case "owner-callback-revokes-current":
				bindings[0].Owner = replayOwnerAuthorityFunc(func(context.Context, sec.ConfigMutationResponseReplayPreparation, ConfigMutationResponseLocation) (ConfigMutationResponseReadAccess, error) {
					return replayOwnerCallbackAccess{owner, func() { current.denied = true }}, nil
				})
			case "grant-extended-after-prepare":
				owner.resources.Reader.(*replayUnlockedObject).after = func() { owner.until = owner.until.Add(time.Second) }
			}
			a, err := NewPinnedConfigMutationResponseReplayAuthority(in.Facts().Installation, in.Facts().Database, current, bindings)
			if err != nil {
				t.Fatal(err)
			}
			r.authority = a
			read, err := r.Read(context.Background(), in)
			if err != sec.ErrRegistrationUnavailable || read != nil {
				t.Fatal("unmapped/unscoped resource returned", err)
			}
			if s.active || s.writes != 0 || s.commits != 0 {
				t.Fatal("failed admission leaked transaction or wrote")
			}
		})
	}
}
func TestConfigMutationReplayMappingRejectsInvalidDeploymentBindings(t *testing.T) {
	for _, name := range []string{"nil-current", "typed-nil-current", "store-purpose", "kek-purpose", "nil-owner", "typed-nil-owner", "duplicate", "unsafe-root", "malformed-version"} {
		t.Run(name, func(t *testing.T) {
			_, in, _, _, current, bindings, _ := mappedReplayReaderFixture(t, true)
			var auth ConfigMutationResponseCurrentAuthorizer = current
			switch name {
			case "nil-current":
				auth = nil
			case "typed-nil-current":
				var empty *replayCurrentAuthorityFixture
				auth = empty
			case "store-purpose":
				bindings[0].Store.Purpose = "artifact_create"
			case "kek-purpose":
				bindings[0].KEK.Purpose = "artifact_kek"
			case "nil-owner":
				bindings[0].Owner = nil
			case "typed-nil-owner":
				var empty *PinnedConfigMutationResponseReplayAuthority
				bindings[0].Owner = empty
			case "duplicate":
				bindings = append(bindings, bindings[0])
			case "unsafe-root":
				bindings[0].Root = "responses/../outside"
			case "malformed-version":
				bindings[0].Store.Version = "../latest"
			}
			if a, err := NewPinnedConfigMutationResponseReplayAuthority(in.Facts().Installation, in.Facts().Database, auth, bindings); a != nil || err != sec.ErrRegistrationUnavailable {
				t.Fatal("invalid binding admitted", err)
			}
		})
	}
}
func TestConfigMutationReplayResourcesRequireAdmissionAndRemainReadOnly(t *testing.T) {
	r, in, s, owner, current, _, _ := mappedReplayReaderFixture(t, true)
	access, err := r.authority.Prepare(context.Background(), in, ConfigMutationResponseLocation{s.snapshot})
	if err != nil {
		t.Fatal(err)
	}
	if !isNil(access.Resources().Reader) || !isNil(access.Resources().Keys) {
		t.Fatal("resources exposed before current SQL admission")
	}
	p := access.(*pinnedConfigMutationResponseReadAccess)
	if _, err = p.resources.Reader.Stat(context.Background(), s.snapshot.Ref); err != ev.ErrUnavailable {
		t.Fatal("unadmitted object access", err)
	}
	tx, err := r.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = access.Recheck(context.Background(), tx, s.now); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	resources := access.Resources()
	if _, err = resources.Keys.Wrap(context.Background(), resources.KEK, make([]byte, 32)); err != ev.ErrKey {
		t.Fatal("read became Wrap authority", err)
	}
	other := s.snapshot.Ref
	other.ImmutableVersion = "another-object-version"
	if _, err = resources.Reader.Stat(context.Background(), other); err != ev.ErrUnavailable {
		t.Fatal("another immutable object admitted", err)
	}
	if stream, err := resources.Reader.Range(context.Background(), s.snapshot.Ref, 0, s.snapshot.Manifest.ObjectSize+1); stream != nil || err != ev.ErrUnavailable {
		t.Fatal("out-of-object range admitted", err)
	}
	if dek, err := resources.Keys.Unwrap(context.Background(), resources.KEK, []byte("another object's wrapped DEK")); dek != nil || err != ev.ErrKey {
		t.Fatal("same-key decryption oracle", err)
	}
	store := owner.resources.Reader.(*replayUnlockedObject).responseTestObject
	var header struct {
		Wrapped string `json:"wrapped_dek_base64"`
	}
	if json.Unmarshal(store.data[12:s.snapshot.Manifest.HeaderSize], &header) != nil {
		t.Fatal("fixture envelope")
	}
	wrapped, err := base64.StdEncoding.DecodeString(header.Wrapped)
	if err != nil {
		t.Fatal(err)
	}
	dek, err := resources.Keys.Unwrap(context.Background(), resources.KEK, wrapped)
	if err != nil || len(dek) != 32 {
		t.Fatal("exact original envelope rejected", err)
	}
	wipe(dek)
	ctx, cancel := context.WithCancel(context.Background())
	stream, err := resources.Reader.Range(ctx, s.snapshot.Ref, 0, 12)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	cancel()
	if n, err := stream.Read(make([]byte, 12)); n != 0 || err != ev.ErrUnavailable {
		t.Fatal("canceled open stream survived", err)
	}
	current.denied = true
	tx, err = r.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if access.Recheck(context.Background(), tx, s.now) != sec.ErrRegistrationUnavailable {
		t.Fatal("revocation not observed")
	}
	if !isNil(access.Resources().Reader) {
		t.Fatal("failed recheck retained admission")
	}
	if _, err = resources.Reader.Stat(context.Background(), s.snapshot.Ref); err != ev.ErrUnavailable {
		t.Fatal("previously obtained object handle survived revoked admission", err)
	}
}

func TestConfigMutationReplayDiscardsBytesCanceledInsideProviderCallback(t *testing.T) {
	for _, name := range []string{"stream", "DEK"} {
		t.Run(name, func(t *testing.T) {
			r, in, s, owner, _, _, _ := mappedReplayReaderFixture(t, true)
			var callbackKeys *replayUnwrapCallbackKeys
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if name == "DEK" {
				callbackKeys = &replayUnwrapCallbackKeys{Keys: owner.resources.Keys, after: cancel}
				owner.resources.Keys = callbackKeys
			}
			access, err := r.authority.Prepare(ctx, in, ConfigMutationResponseLocation{s.snapshot})
			if err != nil {
				t.Fatal(err)
			}
			tx, err := r.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err = access.Recheck(ctx, tx, s.now); err != nil {
				t.Fatal(err)
			}
			if err = tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			if name == "stream" {
				p := access.(*pinnedConfigMutationResponseReadAccess)
				stream := &configResponseBoundReadCloser{access: p, ctx: ctx, reader: replayReadCallbackStream{io.NopCloser(strings.NewReader("provider bytes")), cancel}}
				defer stream.Close()
				buf := make([]byte, len("provider bytes"))
				n, err := stream.Read(buf)
				if n != 0 || err != ev.ErrUnavailable || !bytes.Equal(buf, make([]byte, len(buf))) {
					t.Fatal("canceled provider bytes survived", err)
				}
			} else {
				store := owner.resources.Reader.(*replayUnlockedObject).responseTestObject
				var header struct {
					Wrapped string `json:"wrapped_dek_base64"`
				}
				if json.Unmarshal(store.data[12:s.snapshot.Manifest.HeaderSize], &header) != nil {
					t.Fatal("fixture header")
				}
				wrapped, err := base64.StdEncoding.DecodeString(header.Wrapped)
				if err != nil {
					t.Fatal(err)
				}
				resources := access.Resources()
				dek, err := resources.Keys.Unwrap(ctx, resources.KEK, wrapped)
				if dek != nil || err != ev.ErrKey || len(callbackKeys.returned) != 32 || !bytes.Equal(callbackKeys.returned, make([]byte, 32)) {
					t.Fatal("canceled unwrap retained DEK", err)
				}
			}
		})
	}
}
