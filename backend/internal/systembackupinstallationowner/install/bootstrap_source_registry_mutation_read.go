package install

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"sync"
	"sync/atomic"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	sec "clawreef/internal/systembackupsecurity"
)

// An original native READ source and independent current-ledger observation for
// the first enable. Neither this type nor OfflineBootstrapGrant authorizes the
// mutation write. The actual session/RBAC/strong-auth/nonce/KEK factory does so.
type BootstrapSourceRegistryMutationRead struct {
	mu                                  sync.Mutex
	origin                              *BootstrapSourceRegistryMutationRead
	failed                              atomic.Bool
	ctx                                 context.Context
	source                              *consumerCaptureState
	read                                *PreparedBootstrapSourceRegistriesV2
	identity                            *owner.PreparedReferenceCurrentIdentity
	files                               []consumerPinnedFile
	notBefore, until, floor, inputFloor time.Time
	tx                                  *sql.Tx
}

func (*BootstrapSourceRegistryMutationRead) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*BootstrapSourceRegistryMutationRead) String() string {
	return "OriginalEnableOnlySourceRegistryRead"
}
func (*BootstrapSourceRegistryMutationRead) GoString() string {
	return "OriginalEnableOnlySourceRegistryRead"
}
func (p *BootstrapSourceRegistryMutationRead) fail() error {
	if p != nil {
		p.failed.Store(true)
		if p.origin != nil {
			p.origin.failed.Store(true)
		}
	}
	return ErrInstall
}

func (c *CaptureSigningConsumer) PrepareSourceRegistryEnableOnlyRead(ctx context.Context, in sec.ConfigMutationResourceInput, files BootstrapSourceRegistryFiles, mappingFiles BootstrapTerminalFiles, binding string) (*BootstrapSourceRegistryMutationRead, error) {
	if c == nil || !consumerSameContext(ctx, ctx) || sec.ValidateEnableOnlyConfigMutation(in) != nil || !digestPattern.MatchString(binding) {
		return nil, ErrInstall
	}
	current, _ := in.Configs()
	source, err := c.load(ctx)
	if err != nil {
		return nil, ErrInstall
	}
	defer source.request.observer.Close()
	if source.request.config.SHA256() != current.SHA256() {
		return nil, ErrInstall
	}
	locator, _, public, err := readBootstrapOriginalPublicSource(ctx, c, source)
	if err != nil {
		return nil, ErrInstall
	}
	raw, err := readBootstrapSourcePin(BootstrapSourceFilePin{files.RecordFile, files.RecordSHA256}, 262144)
	if err != nil {
		return nil, ErrInstall
	}
	signature, err := ReadPrivateFile(files.SignatureFile, ed25519.SignatureSize)
	if err != nil {
		return nil, ErrInstall
	}
	r, err := verifyBootstrapSourceV2(raw, signature, public)
	if err != nil {
		return nil, ErrInstall
	}
	// The actual original OfflineBootstrapGrant is consumed ONLY by the original
	// native-read source constructor. Never call its bootstrap SQL admission or
	// cast a bootstrap resource check into a mutation observation.
	read, err := c.PrepareBootstrapSourceRegistriesV2(ctx, source.request.grant, source.request.config, r.Selection, files)
	if err != nil {
		return nil, ErrInstall
	}
	captureRaw, err := readBootstrapSourceAuthenticated(source, locator.RecordFile, 262144)
	var capture owner.Record
	if err != nil || decodeExact(captureRaw, &capture) != nil || r.CaptureRecordSHA256 != hash(captureRaw) || r.PlanSHA256 != locator.PlanSHA256 || r.Target != capture.Target || r.Actor != capture.Actor || !functionalSelectionMatches(capture, r.Selection) {
		return nil, ErrInstall
	}
	pinRaw, err := readBootstrapSourceAuthenticated(source, locator.TrustPinFile, 262144)
	var pin owner.TrustPin
	if err != nil || decodeExact(pinRaw, &pin) != nil || pin.RecordSHA256 != hash(captureRaw) {
		return nil, ErrInstall
	}
	currentIdentity, err := owner.NewReferenceCurrentIdentity(pin, owner.RecordFiles{RecordFile: locator.RecordFile, SignatureFile: locator.SignatureFile})
	if err != nil {
		return nil, ErrInstall
	}
	identity, err := currentIdentity.PrepareEnableOnly(ctx, in)
	if err != nil {
		return nil, ErrInstall
	}
	mapRaw, err := readBootstrapSourcePin(BootstrapSourceFilePin{mappingFiles.MappingFile, mappingFiles.MappingSHA256}, 262144)
	if err != nil {
		return nil, ErrInstall
	}
	mapSignature, err := ReadPrivateFile(mappingFiles.SignatureFile, ed25519.SignatureSize)
	if err != nil {
		return nil, ErrInstall
	}
	mapping, err := verifyBootstrapOriginalMapping(mapRaw, mapSignature, public)
	if err != nil || mapping.PlanSHA256 != r.PlanSHA256 || mapping.CaptureRecordSHA256 != r.CaptureRecordSHA256 || mapping.SelectionSHA256 != bootstrapSourceSelectionHash(r.Selection) || mapping.Target != r.Target || mapping.Actor != r.Actor || mapping.Enrollment != r.Enrollment || mapping.NotBefore.Before(r.NotBefore) || mapping.Until.After(r.Until) {
		return nil, ErrInstall
	}
	known := map[string]bool{}
	for _, key := range sec.MissingBootstrapOwnerAdapters(sec.BootstrapOwnerAdapters{}) {
		known[key] = true
	}
	seen := map[string]bool{}
	bound := 0
	for _, item := range mapping.Owners {
		if !known[item.Key] || seen[item.Key] || !digestPattern.MatchString(item.SHA256) {
			return nil, ErrInstall
		}
		seen[item.Key] = true
		switch item.Key {
		case "registry:parts", "registry:redis_sources", "registry:secret_allowlist", "registry:source_writers":
			if item.SHA256 != binding {
				return nil, ErrInstall
			}
			bound++
		}
	}
	if bound != 4 {
		return nil, ErrInstall
	}
	end := r.Until
	for _, until := range []time.Time{mapping.Until, identity.ValidUntil()} {
		if until.Before(end) {
			end = until
		}
	}
	if deadline, ok := ctx.Deadline(); !ok {
		return nil, ErrInstall
	} else if deadline.Before(end) {
		end = deadline
	}
	nb := r.NotBefore
	if mapping.NotBefore.After(nb) {
		nb = mapping.NotBefore
	}
	p := &BootstrapSourceRegistryMutationRead{ctx: ctx, source: source, read: read, identity: identity, notBefore: nb, until: end, files: []consumerPinnedFile{{mappingFiles.MappingFile, mappingFiles.MappingSHA256, 262144}, {mappingFiles.SignatureFile, hash(mapSignature), ed25519.SignatureSize}}}
	p.origin = p
	if p.local(ctx) != nil {
		return nil, ErrInstall
	}
	return p, nil
}

func (p *BootstrapSourceRegistryMutationRead) local(ctx context.Context) error {
	if p == nil || p.origin != p || p.failed.Load() || !consumerSameContext(ctx, p.ctx) || ctx.Err() != nil || p.source == nil || p.read == nil || p.read.origin != p.read || p.read.base == nil {
		return p.fail()
	}
	now := time.Now().UTC()
	if now.Before(p.notBefore) || !now.Before(p.until) {
		return p.fail()
	}
	if p.source.current(ctx) != nil {
		return p.fail()
	}
	b := p.read.base
	b.mu.Lock()
	err := b.local(ctx)
	b.mu.Unlock()
	if err != nil {
		return p.fail()
	}
	for _, file := range p.files {
		raw, err := ReadPrivateFile(file.path, file.limit)
		if err != nil || hash(raw) != file.sha {
			return p.fail()
		}
	}
	for _, pin := range bootstrapSourceV2Files(p.read.record.Source) {
		raw, err := readBootstrapSourcePin(pin, bootstrapSourceV2FileLimit(p.read.record.Source, pin))
		clear(raw)
		if err != nil {
			return p.fail()
		}
	}
	now = time.Now().UTC()
	if now.Before(p.notBefore) || !now.Before(p.until) || ctx.Err() != nil {
		return p.fail()
	}
	return nil
}

// Only the real opaque original read source is exposed to B's private reader.
// It grants no mutation write permission and is unavailable after SQL begins.
func (p *BootstrapSourceRegistryMutationRead) NativeReadSource(ctx context.Context) (*PreparedBootstrapSourceRegistriesV2, error) {
	if p == nil {
		return nil, ErrInstall
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.tx != nil || p.local(ctx) != nil {
		return nil, p.fail()
	}
	return p.read, nil
}
func (p *BootstrapSourceRegistryMutationRead) ValidUntil() time.Time {
	if p == nil {
		return time.Time{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.origin != p || p.failed.Load() {
		_ = p.fail()
		return time.Time{}
	}
	return p.until
}

// Explicit mutation-contract raw SQL: this uses A's original current identity,
// not BootstrapSQL/AuthorizeCandidate or a transaction adapter. All I/O here
// is local immutable pins or original current-ledger SQL, with LAST SQL time.
func (p *BootstrapSourceRegistryMutationRead) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if p == nil {
		return ErrInstall
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if tx == nil || p.tx != nil && p.tx != tx || now.IsZero() || !p.inputFloor.IsZero() && now.Before(p.inputFloor) || now.Before(p.notBefore) || !now.Before(p.until) || p.local(ctx) != nil || p.identity.Recheck(ctx, tx, now) != nil {
		return p.fail()
	}
	if until := p.identity.ValidUntil(); until.Before(p.until) {
		p.until = until
	}
	if p.local(ctx) != nil {
		return p.fail()
	}
	var tail time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&tail) != nil || tail.Before(now) || !p.floor.IsZero() && tail.Before(p.floor) || tail.Before(p.notBefore) || !tail.Before(p.until) || ctx.Err() != nil || !time.Now().Before(p.until) {
		return p.fail()
	}
	p.tx = tx
	p.floor = tail
	p.inputFloor = now
	return nil
}
