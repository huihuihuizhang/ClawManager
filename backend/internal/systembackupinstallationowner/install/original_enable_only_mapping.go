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

// EnableOnlyOriginalMapping authenticates the original resource association
// for unchanged resources. It grants no mutation permission, native capability,
// bootstrap consumption or execution authority, and accepts no caller grant.
type EnableOnlyOriginalMapping struct {
	capture *CaptureSigningConsumer
	files   BootstrapTerminalFiles
}

func NewEnableOnlyOriginalMapping(capture *CaptureSigningConsumer, files BootstrapTerminalFiles) (*EnableOnlyOriginalMapping, error) {
	if capture == nil || !bootstrapSourcePinValid(BootstrapSourceFilePin{files.MappingFile, files.MappingSHA256}) || files.MappingFile == files.SignatureFile {
		return nil, ErrInstall
	}
	return &EnableOnlyOriginalMapping{capture: capture, files: files}, nil
}

type PreparedEnableOnlyOriginalMapping struct {
	mu                              sync.Mutex
	origin                          *PreparedEnableOnlyOriginalMapping
	failed                          atomic.Bool
	ctx                             context.Context
	source                          *consumerCaptureState
	current                         *owner.PreparedReferenceCurrentIdentity
	files                           []consumerPinnedFile
	start, until, floor, inputFloor time.Time
	tx                              *sql.Tx
}

func (*PreparedEnableOnlyOriginalMapping) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (p *PreparedEnableOnlyOriginalMapping) ValidUntil() time.Time {
	if p == nil || p.origin != p || p.failed.Load() {
		return time.Time{}
	}
	return p.until
}

func (a *EnableOnlyOriginalMapping) PrepareEnableOnly(ctx context.Context, in sec.ConfigMutationResourceInput, bindings []BootstrapOriginalOwnerBinding) (*PreparedEnableOnlyOriginalMapping, error) {
	if a == nil || a.capture == nil || !consumerSameContext(ctx, ctx) || ctx.Err() != nil || sec.ValidateEnableOnlyConfigMutation(in) != nil || len(bindings) == 0 {
		return nil, ErrInstall
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, ErrInstall
	}
	bindings = append([]BootstrapOriginalOwnerBinding(nil), bindings...)
	source, e := a.capture.load(ctx)
	if e != nil {
		return nil, ErrInstall
	}
	defer source.request.observer.Close()
	current, _ := in.Configs()
	if source.request.config.SHA256() != current.SHA256() {
		return nil, ErrInstall
	}
	locator, _, public, e := readBootstrapOriginalPublicSource(ctx, a.capture, source)
	if e != nil {
		return nil, ErrInstall
	}
	recordRaw, e := ReadPrivateFile(locator.RecordFile, 262144)
	var record owner.Record
	if e != nil || decodeExact(recordRaw, &record) != nil || record.ConfigSHA256 != current.SHA256() || record.Target.InstallationID != in.InstallationID() {
		return nil, ErrInstall
	}
	raw, e := ReadPrivateFile(a.files.MappingFile, 262144)
	if e != nil || hash(raw) != a.files.MappingSHA256 {
		return nil, ErrInstall
	}
	signature, e := ReadPrivateFile(a.files.SignatureFile, ed25519.SignatureSize)
	if e != nil {
		return nil, ErrInstall
	}
	mapping, e := verifyBootstrapOriginalMapping(raw, signature, public)
	if e != nil || mapping.PlanSHA256 != locator.PlanSHA256 || mapping.CaptureRecordSHA256 != hash(recordRaw) || mapping.Target != record.Target || mapping.Actor != record.Actor || mapping.SelectionSHA256 != record.SelectionSHA256 || !mapping.NotBefore.Equal(record.NotBefore) || !mapping.Until.Equal(record.Until) {
		return nil, ErrInstall
	}
	enrollmentRaw, e := ReadPrivateFile(locator.EnrollmentPinFile, 262144)
	if e != nil {
		return nil, ErrInstall
	}
	enrollment, e := DecodeEnrollmentPin(enrollmentRaw, locator.EnrollmentPinSHA256)
	if e != nil || mapping.Enrollment != enrollment {
		return nil, ErrInstall
	}
	// The signed original composition must be complete. Only the requested
	// concrete bindings are consumed; missing/duplicate/unknown entries reject.
	known := map[string]bool{}
	for _, key := range sec.MissingBootstrapOwnerAdapters(sec.BootstrapOwnerAdapters{}) {
		known[key] = true
	}
	byKey := map[string]string{}
	for n, b := range mapping.Owners {
		if !known[b.Key] || !digestPattern.MatchString(b.SHA256) || n > 0 && mapping.Owners[n-1].Key >= b.Key {
			return nil, ErrInstall
		}
		byKey[b.Key] = b.SHA256
	}
	if len(byKey) != len(known) || byKey["reference:capture_signing"] != hash(recordRaw) {
		return nil, ErrInstall
	}
	requested := map[string]bool{}
	for _, b := range bindings {
		if requested[b.Key] || !digestPattern.MatchString(b.SHA256) || byKey[b.Key] != b.SHA256 {
			return nil, ErrInstall
		}
		requested[b.Key] = true
	}
	pinRaw, e := ReadPrivateFile(locator.TrustPinFile, 262144)
	var pin owner.TrustPin
	if e != nil || hash(pinRaw) != locator.TrustPinSHA256 || decodeExact(pinRaw, &pin) != nil || pin.RecordSHA256 != hash(recordRaw) {
		return nil, ErrInstall
	}
	identity, e := owner.NewReferenceCurrentIdentity(pin, owner.RecordFiles{RecordFile: locator.RecordFile, SignatureFile: locator.SignatureFile})
	if e != nil {
		return nil, ErrInstall
	}
	prepared, e := identity.PrepareEnableOnly(ctx, in)
	if e != nil {
		return nil, ErrInstall
	}
	until := mapping.Until
	if deadline.Before(until) {
		until = deadline
	}
	if prepared.ValidUntil().Before(until) {
		until = prepared.ValidUntil()
	}
	p := &PreparedEnableOnlyOriginalMapping{ctx: ctx, source: source, current: prepared, start: mapping.NotBefore, until: until, files: []consumerPinnedFile{{a.files.MappingFile, a.files.MappingSHA256, 262144}, {a.files.SignatureFile, hash(signature), ed25519.SignatureSize}}}
	p.origin = p
	if p.local(ctx) != nil {
		return nil, ErrInstall
	}
	return p, nil
}
func (p *PreparedEnableOnlyOriginalMapping) fail() error {
	if p != nil {
		p.failed.Store(true)
		if p.origin != nil {
			p.origin.failed.Store(true)
		}
	}
	return ErrInstall
}
func (p *PreparedEnableOnlyOriginalMapping) local(ctx context.Context) error {
	if p == nil || p.origin != p || p.failed.Load() || !consumerSameContext(ctx, p.ctx) || ctx.Err() != nil || p.source == nil || p.source.current(ctx) != nil {
		return p.fail()
	}
	for _, pin := range p.files {
		raw, e := ReadPrivateFile(pin.path, pin.limit)
		if e != nil || hash(raw) != pin.sha {
			return p.fail()
		}
	}
	return nil
}
func (p *PreparedEnableOnlyOriginalMapping) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if p == nil {
		return ErrInstall
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.local(ctx) != nil || tx == nil || p.tx != nil && p.tx != tx || now.Before(p.start) || !now.Before(p.until) || !p.inputFloor.IsZero() && now.Before(p.inputFloor) || p.current.Recheck(ctx, tx, now) != nil {
		return p.fail()
	}
	var tail time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&tail) != nil || tail.Before(now) || !p.floor.IsZero() && tail.Before(p.floor) || tail.Before(p.start) || !tail.Before(p.until) || ctx.Err() != nil || p.local(ctx) != nil {
		return p.fail()
	}
	p.tx = tx
	p.floor = tail
	p.inputFloor = now
	return nil
}
