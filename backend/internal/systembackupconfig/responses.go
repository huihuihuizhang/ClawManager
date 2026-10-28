package systembackupconfig

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"io"
	"time"

	ev "clawreef/internal/systembackupevidence"
	sec "clawreef/internal/systembackupsecurity"
)

// Stage is newly owned, encrypted staging supplied by the real publication
// owner. Seal must fsync/pin the ORIGINAL bytes and reject subsequent writes;
// Open must reopen those same bytes. No HTTP/plaintext path is accepted.
type ConfigMutationResponseCiphertextStage interface {
	io.Writer
	Seal(context.Context, ev.Manifest) error
	Open(context.Context) (io.ReadCloser, error)
	Discard(context.Context) error
}
type ConfigMutationResponsePublicationFactory interface {
	// Every nonnil returned Stage transfers cleanup responsibility to D, even
	// on error. It must not already belong to a committed pending history.
	PreparePublication(context.Context, ConfigMutationResponseContent) (ConfigMutationResponsePublicationInputs, error)
}
type ConfigMutationResponsePublicationInputs struct {
	Authority  ev.ContentAuthority
	Keys       ev.Keys
	Stage      ConfigMutationResponseCiphertextStage
	Publisher  ConfigMutationResponseCiphertextPublisher
	Root       string
	ValidUntil time.Time
}
type ConfigMutationResponseCiphertextPublisher interface {
	// Exclusive staging custody transfers ON ENTRY, including every error.
	// The owner must durably persist this exact diagnostic attempt/pending
	// intent before any PUT, retain ORIGINAL ciphertext on unknown outcomes,
	// and return only independently authenticated ready/healthy provenance.
	// Current capability_snapshot-only SystemPublication cannot implement this
	// profile by relabeling it. No D retry/regeneration/DELETE is performed.
	Publish(context.Context, ConfigMutationResponsePublication, ConfigMutationResponseCiphertextStage) (ConfigMutationResponsePublished, error)
}
type ConfigMutationResponsePublished struct {
	Reference ev.Ref
	Guard     ConfigMutationResponseScopedPublicationGuard
}
type ConfigMutationResponseScopedPublicationGuard interface {
	ValidUntil() time.Time
	// SQL only, in the writer's transaction. Verify actual current authority,
	// durable pending/result provenance, exact PUBLIC request/attempt binding,
	// retention and immutable original object; comparison data is not a grant.
	RecheckPublication(context.Context, *sql.Tx, ConfigMutationResponsePublicationBinding, ev.Ref, time.Time) error
}
type ConfigMutationResponsePublicationBinding struct {
	content  ConfigMutationResponseContent
	prepared ev.Prepared
}

func (b ConfigMutationResponsePublicationBinding) Content() ConfigMutationResponseContent {
	return b.content
}
func (b ConfigMutationResponsePublicationBinding) Prepared() ev.Prepared { return b.prepared }
func (b ConfigMutationResponsePublicationBinding) Manifest() ev.Manifest {
	return b.prepared.Manifest()
}
func (b ConfigMutationResponsePublicationBinding) Request() sec.ConfigMutationResponseRequestBinding {
	v, _ := b.content.input.RequestBinding()
	return v
}
func (ConfigMutationResponsePublicationBinding) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrConfigMutation
}

type ConfigMutationResponsePublication struct {
	binding ConfigMutationResponsePublicationBinding
	stage   ConfigMutationResponseCiphertextStage
	until   time.Time
}

func (p ConfigMutationResponsePublication) Binding() ConfigMutationResponsePublicationBinding {
	return p.binding
}
func (ConfigMutationResponsePublication) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrConfigMutation
}

type ConfigResourceDiagnosticResponses struct {
	reader    *SQLConfigMutationResponseReader
	publisher ConfigMutationResponsePublicationFactory
}

// Kept only for explicit ConfigResource diagnostic experiments. This type does
// not satisfy the public Operation response interface and cannot wire a writer.
var _ sec.ConfigResourceDiagnosticResponses = (*ConfigResourceDiagnosticResponses)(nil)

func NewConfigResourceDiagnosticResponses(reader *SQLConfigMutationResponseReader, publisher ConfigMutationResponsePublicationFactory) (*ConfigResourceDiagnosticResponses, error) {
	if reader == nil || reader.db == nil || !validDatabase(reader.database) || !installationIDPattern.MatchString(reader.installation) || isNil(reader.authority) || isNil(publisher) {
		return nil, sec.ErrRegistrationUnavailable
	}
	return &ConfigResourceDiagnosticResponses{reader, publisher}, nil
}
func (s *ConfigResourceDiagnosticResponses) Read(ctx context.Context, input sec.ConfigMutationResponseReplayPreparation) (sec.PreparedConfigMutationResponseRead, error) {
	if s == nil || s.reader == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	return s.reader.Read(ctx, input)
}
func newConfigResponseEvidenceID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", sec.ErrRegistrationUnavailable
	}
	id[6] = id[6]&15 | 64
	id[8] = id[8]&63 | 128
	raw := hex.EncodeToString(id[:])
	return "sev_" + raw[:8] + "-" + raw[8:12] + "-" + raw[12:16] + "-" + raw[16:20] + "-" + raw[20:], nil
}
func (s *ConfigResourceDiagnosticResponses) Prepare(ctx context.Context, input sec.ConfigMutationResponsePreparation) (out sec.PreparedConfigMutationResponse, err error) {
	fail := func() (sec.PreparedConfigMutationResponse, error) { return nil, sec.ErrRegistrationUnavailable }
	if s == nil || s.reader == nil || isNil(s.publisher) || ctx == nil || ctx.Err() != nil || input.Database() != s.reader.database || input.ContentPolicy().InstallationID != s.reader.installation || !time.Now().Before(input.ValidUntil()) {
		return fail()
	}
	binding, ok := input.RequestBinding()
	if !ok || !hashPattern.MatchString(binding.ScopeSHA256()) || !hashPattern.MatchString(binding.AttemptSHA256()) || binding.HighestVersion()+1 != input.ContentPolicy().Version {
		return fail()
	}
	id, err := newConfigResponseEvidenceID()
	if err != nil {
		return fail()
	}
	c, err := PrepareConfigMutationResponseContent(ctx, input, id)
	if err != nil {
		return fail()
	}
	if len(c.payload) <= 8192 {
		return PrepareInlineConfigMutationResponse(c)
	}
	inputs, err := s.publisher.PreparePublication(ctx, c)
	owned := !isNil(inputs.Stage)
	defer func() {
		if owned {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if inputs.Stage.Discard(cleanupCtx) != nil {
				out = nil
				err = sec.ErrProviderEvidenceStorage
			}
		}
	}()
	if err != nil || !owned || isNil(inputs.Authority) || isNil(inputs.Keys) || isNil(inputs.Publisher) || !configMutationResponseRelativeKey(inputs.Root) || inputs.ValidUntil.IsZero() {
		return fail()
	}
	expectedKey := inputs.Root + "/" + c.identity.Installation + "/system/" + c.identity.OwnerID + "/" + c.identity.ID + "/" + c.identity.ContentHash + ".bin"
	if !configMutationResponseRelativeKey(expectedKey) {
		return fail()
	}
	baseline, err := inputs.Authority.AuthorizeContent(ctx, c.identity)
	if err != nil || baseline.ConfigResponse == nil || !hashPattern.MatchString(baseline.ProducerIdentityHash) {
		return fail()
	}
	call := &responseContentAuthority{inputs.Authority, c, baseline.ProducerIdentityHash, baseline.ValidUntil, baseline.ConfigResponse.ValidUntil}
	until := c.until
	for _, bound := range []time.Time{inputs.ValidUntil, baseline.ValidUntil, baseline.ConfigResponse.ValidUntil} {
		if bound.Before(until) {
			until = bound
		}
	}
	if !time.Now().Before(until) {
		return fail()
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	if _, err = call.AuthorizeContent(ctx, c.identity); err != nil {
		return fail()
	}
	prepared, err := c.Encrypt(ctx, call, inputs.Keys, inputs.Stage)
	if err != nil || inputs.Stage.Seal(ctx, prepared.Manifest()) != nil {
		return fail()
	}
	publication := ConfigMutationResponsePublication{ConfigMutationResponsePublicationBinding{c, prepared}, inputs.Stage, until}
	// Independently read/hash the sealed local bytes before handing custody to
	// a publisher. A partial read/close or substituted object cannot pass.
	if verifyConfigResponseCiphertext(ctx, publication) != nil {
		return fail()
	}
	if _, err = call.AuthorizeContent(ctx, c.identity); err != nil || ctx.Err() != nil || !time.Now().Before(until) {
		return fail()
	}
	owned = false // The owner now owns recovery/cleanup even if Publish fails.
	published, err := inputs.Publisher.Publish(ctx, publication, inputs.Stage)
	ref := published.Reference
	if err != nil || isNil(published.Guard) || ref.Identity != c.store.IdentityHash || ref.Version != c.store.Version || ref.RelativeKey != expectedKey || !configResponseImmutableVersion(ref.ImmutableVersion) || ctx.Err() != nil || !time.Now().Before(until) {
		return fail()
	}
	if _, err = call.AuthorizeContent(ctx, c.identity); err != nil {
		return fail()
	}
	guardUntil := published.Guard.ValidUntil()
	if guardUntil.IsZero() {
		return fail()
	}
	if guardUntil.Before(until) {
		until = guardUntil
	}
	if !time.Now().Before(until) {
		return fail()
	}
	guard := &configResponseScopedPublicationGuard{publication.binding, ref, published.Guard, guardUntil, until}
	return PreparePublishedConfigMutationResponse(c, prepared, ref, guard)
}
func configResponseImmutableVersion(v string) bool {
	if v == "" || v == "null" || len(v) > 256 {
		return false
	}
	for _, ch := range []byte(v) {
		if ch < 0x20 || ch > 0x7e {
			return false
		}
	}
	return true
}

type configResponseScopedPublicationGuard struct {
	binding           ConfigMutationResponsePublicationBinding
	ref               ev.Ref
	owner             ConfigMutationResponseScopedPublicationGuard
	ownerUntil, until time.Time
}

func (g *configResponseScopedPublicationGuard) ValidUntil() time.Time { return g.until }
func (g *configResponseScopedPublicationGuard) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if ctx == nil || ctx.Err() != nil || tx == nil || !now.Before(g.until) || !g.owner.ValidUntil().Equal(g.ownerUntil) || g.owner.RecheckPublication(ctx, tx, g.binding, g.ref, now) != nil || !g.owner.ValidUntil().Equal(g.ownerUntil) || ctx.Err() != nil {
		return sec.ErrRegistrationUnavailable
	}
	return nil
}
