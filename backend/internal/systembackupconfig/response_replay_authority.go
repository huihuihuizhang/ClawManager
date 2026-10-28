package systembackupconfig

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"regexp"
	"sync/atomic"
	"time"

	ev "clawreef/internal/systembackupevidence"
	sec "clawreef/internal/systembackupsecurity"
)

// The concrete D implementation is sec.SQLConfigMutationReplayAuthorizer.
// This boundary must recheck current SQL session, config, canonical RBAC and
// original receipt risk in the supplied transaction, without commit/network.
type ConfigMutationResponseCurrentAuthorizer interface {
	AuthorizeReplay(context.Context, *sql.Tx, sec.ConfigMutationResponseReplayPreparation, time.Time) error
}

var _ ConfigMutationResponseCurrentAuthorizer = (*sec.SQLConfigMutationReplayAuthorizer)(nil)

// This mapping is trusted deployment input, not a grant. Owner must be an
// actual exact-version historical read/unwrap authority. A current/read or
// bootstrap mapping is not promoted into retained response read authority.
type ConfigMutationResponseHistoricalReadBinding struct {
	Store, KEK sec.BootstrapSecretRef
	Root       string
	Owner      ConfigMutationResponseReplayAuthority
}
type configResponseHistoricalKey struct{ store, kek sec.BootstrapSecretRef }
type PinnedConfigMutationResponseReplayAuthority struct {
	installation string
	database     sec.DatabaseIdentity
	current      ConfigMutationResponseCurrentAuthorizer
	bindings     map[configResponseHistoricalKey]ConfigMutationResponseHistoricalReadBinding
}

var responseReferenceVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func validResponsePurposeRef(r sec.BootstrapSecretRef, purpose string) bool {
	return r.Purpose == purpose && hashPattern.MatchString(r.IdentityHash) && responseReferenceVersion.MatchString(r.Version)
}
func NewPinnedConfigMutationResponseReplayAuthority(installation string, database sec.DatabaseIdentity, current ConfigMutationResponseCurrentAuthorizer, bindings []ConfigMutationResponseHistoricalReadBinding) (*PinnedConfigMutationResponseReplayAuthority, error) {
	if !installationIDPattern.MatchString(installation) || !validDatabase(database) || isNil(current) || len(bindings) > 4096 {
		return nil, sec.ErrRegistrationUnavailable
	}
	a := &PinnedConfigMutationResponseReplayAuthority{installation, database, current, make(map[configResponseHistoricalKey]ConfigMutationResponseHistoricalReadBinding, len(bindings))}
	for _, b := range bindings {
		k := configResponseHistoricalKey{b.Store, b.KEK}
		if !validResponsePurposeRef(b.Store, "evidence_store") || !validResponsePurposeRef(b.KEK, "evidence_kek") || !configMutationResponseRelativeKey(b.Root) || isNil(b.Owner) {
			return nil, sec.ErrRegistrationUnavailable
		}
		if _, exists := a.bindings[k]; exists {
			return nil, sec.ErrRegistrationUnavailable
		}
		a.bindings[k] = b
	}
	return a, nil
}

type pinnedConfigMutationResponseReadAccess struct {
	input             sec.ConfigMutationResponseReplayPreparation
	current           ConfigMutationResponseCurrentAuthorizer
	owner             ConfigMutationResponseReadAccess
	ownerUntil, until time.Time
	resources         ConfigMutationResponseReadResources
	admitted          atomic.Bool
}

func (p *pinnedConfigMutationResponseReadAccess) Resources() ConfigMutationResponseReadResources {
	if !p.admitted.Load() {
		return ConfigMutationResponseReadResources{}
	}
	return p.resources
}
func (p *pinnedConfigMutationResponseReadAccess) ValidUntil() time.Time { return p.until }
func (p *pinnedConfigMutationResponseReadAccess) live(ctx context.Context) bool {
	return ctx != nil && ctx.Err() == nil && time.Now().Before(p.until) && (isNil(p.owner) || p.owner.ValidUntil().Equal(p.ownerUntil))
}
func (p *pinnedConfigMutationResponseReadAccess) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if p == nil {
		return sec.ErrRegistrationUnavailable
	}
	p.admitted.Store(false)
	if tx == nil || !p.live(ctx) || now.Before(p.input.Facts().AuthorizedAt) || !now.Before(p.until) || isNil(p.current) {
		return sec.ErrRegistrationUnavailable
	}
	if p.current.AuthorizeReplay(ctx, tx, p.input, now) != nil {
		return sec.ErrRegistrationUnavailable
	}
	if !isNil(p.owner) && p.owner.Recheck(ctx, tx, now) != nil {
		return sec.ErrRegistrationUnavailable
	}
	// Recheck current configure/original-risk permission AFTER owner callbacks.
	if p.current.AuthorizeReplay(ctx, tx, p.input, now) != nil || !p.live(ctx) {
		return sec.ErrRegistrationUnavailable
	}
	p.admitted.Store(true)
	return nil
}
func (p *pinnedConfigMutationResponseReadAccess) canRead(ctx context.Context) bool {
	return p.admitted.Load() && p.live(ctx)
}
func (a *PinnedConfigMutationResponseReplayAuthority) Prepare(ctx context.Context, input sec.ConfigMutationResponseReplayPreparation, location ConfigMutationResponseLocation) (ConfigMutationResponseReadAccess, error) {
	f := input.Facts()
	s := location.snapshot
	fail := func() (ConfigMutationResponseReadAccess, error) { return nil, sec.ErrRegistrationUnavailable }
	if a == nil || ctx == nil || ctx.Err() != nil || f.Installation != a.installation || f.Database != a.database || isNil(a.current) || s.ID != f.EvidenceID || s.Checksum != f.ResponseHash || s.Owner != f.Installation || s.OwnerType != "system" || s.Kind != "diagnostic" || !time.Now().Before(f.ValidUntil) {
		return fail()
	}
	if _, err := sec.NewConfigMutationResponseReplayPreparation(f); err != nil {
		return fail()
	}
	p := &pinnedConfigMutationResponseReadAccess{input: input, current: a.current, until: f.ValidUntil}
	if s.Expires.Before(p.until) {
		p.until = s.Expires
	}
	if s.State == "inline" {
		if !time.Now().Before(p.until) {
			return fail()
		}
		return p, nil
	}
	if !location.External() {
		return fail()
	}
	m, ref := location.Manifest(), location.Reference()
	k := configResponseHistoricalKey{sec.BootstrapSecretRef{Purpose: "evidence_store", IdentityHash: ref.Identity, Version: ref.Version}, sec.BootstrapSecretRef{Purpose: "evidence_kek", IdentityHash: m.Key.Identity, Version: m.Key.Version}}
	b, ok := a.bindings[k]
	if !ok || isNil(b.Owner) {
		return fail()
	}
	expected := b.Root + "/" + f.Installation + "/system/" + f.Installation + "/" + m.Identity.ID + "/" + m.Identity.ContentHash + ".bin"
	if ref.RelativeKey != expected || !configMutationResponseRelativeKey(expected) || ref.ImmutableVersion == "" || ref.ImmutableVersion == "null" || len(ref.ImmutableVersion) > 256 {
		return fail()
	}
	owner, err := b.Owner.Prepare(ctx, input, location)
	if err != nil || isNil(owner) {
		return fail()
	}
	p.owner, p.ownerUntil = owner, owner.ValidUntil()
	if p.ownerUntil.IsZero() {
		return fail()
	}
	if p.ownerUntil.Before(p.until) {
		p.until = p.ownerUntil
	}
	resources := owner.Resources()
	store := ev.KeyRef{Identity: b.Store.IdentityHash, Version: b.Store.Version}
	key := ev.KeyRef{Identity: b.KEK.IdentityHash, Version: b.KEK.Version}
	if resources.Root != b.Root || resources.Store != store || resources.KEK != key || isNil(resources.Reader) || isNil(resources.Keys) || !p.live(ctx) {
		return fail()
	}
	p.resources = ConfigMutationResponseReadResources{Root: b.Root, Store: store, KEK: key, Reader: &configResponseExactObjectReader{p, ref, m.ObjectSize, resources.Reader}, Keys: &configResponseUnwrapOnlyKeys{p, key, m.Identity, m.EnvelopeHash, resources.Keys}}
	return p, nil
}

// Expose exactly Stat/Range for this one immutable object and Unwrap for this
// one historical evidence KEK. These wrappers cannot mint underlying provider
// credentials; the real owner adapters remain responsible for current ACLs.
type configResponseExactObjectReader struct {
	access *pinnedConfigMutationResponseReadAccess
	ref    ev.Ref
	size   int64
	reader ev.VerifiedObjectReader
}

func (r *configResponseExactObjectReader) Stat(ctx context.Context, ref ev.Ref) (ev.ObjectInfo, error) {
	if ref != r.ref || !r.access.canRead(ctx) {
		return ev.ObjectInfo{}, ev.ErrUnavailable
	}
	i, err := r.reader.Stat(ctx, ref)
	if err != nil || !r.access.canRead(ctx) {
		return ev.ObjectInfo{}, ev.ErrUnavailable
	}
	return i, nil
}
func (r *configResponseExactObjectReader) Range(ctx context.Context, ref ev.Ref, offset, length int64) (io.ReadCloser, error) {
	if ref != r.ref || !r.access.canRead(ctx) || r.size < 1 || offset < 0 || length < 1 || length > ev.ChunkSize+28 || length > r.size || offset > r.size-length {
		return nil, ev.ErrUnavailable
	}
	reader, err := r.reader.Range(ctx, ref, offset, length)
	if err != nil || isNil(reader) || !r.access.canRead(ctx) {
		if !isNil(reader) {
			reader.Close()
		}
		return nil, ev.ErrUnavailable
	}
	return &configResponseBoundReadCloser{access: r.access, reader: reader, ctx: ctx}, nil
}

type configResponseBoundReadCloser struct {
	access *pinnedConfigMutationResponseReadAccess
	reader io.ReadCloser
	ctx    context.Context
}

func (r *configResponseBoundReadCloser) Read(dst []byte) (int, error) {
	if !r.access.canRead(r.ctx) {
		return 0, ev.ErrUnavailable
	}
	n, err := r.reader.Read(dst)
	if n < 0 || n > len(dst) {
		wipe(dst)
		return 0, ev.ErrUnavailable
	}
	if !r.access.canRead(r.ctx) || err != nil && err != io.EOF {
		wipe(dst[:n])
		return 0, ev.ErrUnavailable
	}
	return n, err
}
func (r *configResponseBoundReadCloser) Close() error {
	if r.reader.Close() != nil {
		return ev.ErrUnavailable
	}
	return nil
}

type configResponseUnwrapOnlyKeys struct {
	access       *pinnedConfigMutationResponseReadAccess
	key          ev.KeyRef
	identity     ev.Identity
	envelopeHash string
	keys         ev.Keys
}

func (*configResponseUnwrapOnlyKeys) Wrap(context.Context, ev.KeyRef, []byte) ([]byte, error) {
	return nil, ev.ErrKey
}
func (k *configResponseUnwrapOnlyKeys) Unwrap(ctx context.Context, ref ev.KeyRef, wrapped []byte) ([]byte, error) {
	if ref != k.key || len(wrapped) < 1 || len(wrapped) > 4096 || !k.access.canRead(ctx) {
		return nil, ev.ErrKey
	}
	header, err := json.Marshal(struct {
		Schema   string      `json:"schema_version"`
		Identity ev.Identity `json:"identity"`
		Key      ev.KeyRef   `json:"key"`
		Wrapped  string      `json:"wrapped_dek_base64"`
	}{ev.Framing, k.identity, k.key, base64.StdEncoding.EncodeToString(wrapped)})
	if err != nil {
		return nil, ev.ErrKey
	}
	decoder := json.NewDecoder(bytes.NewReader(header))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return nil, ev.ErrKey
	}
	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(value) != nil || registrationHash(string(bytes.TrimSuffix(canonical.Bytes(), []byte("\n")))) != k.envelopeHash {
		return nil, ev.ErrKey
	}
	dek, err := k.keys.Unwrap(ctx, ref, wrapped)
	if err != nil || len(dek) != 32 || !k.access.canRead(ctx) {
		wipe(dek)
		return nil, ev.ErrKey
	}
	return dek, nil
}
