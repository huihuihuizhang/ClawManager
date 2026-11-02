package systembackupinstallationowner

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

type RecordFiles struct{ RecordFile, SignatureFile string }

func localFile(path string, max int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrOwner
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, ErrOwner
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > max {
		return nil, ErrOwner
	}
	raw, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(raw)) > max {
		return nil, ErrOwner
	}
	return raw, nil
}
func (f RecordFiles) read(p TrustPin) (*AuthenticatedRecord, error) {
	if f.RecordFile == f.SignatureFile {
		return nil, ErrOwner
	}
	raw, e := localFile(f.RecordFile, 262144)
	if e != nil {
		return nil, e
	}
	sig, e := localFile(f.SignatureFile, 64)
	if e != nil {
		return nil, e
	}
	return VerifyRecord(raw, sig, p)
}

type CaptureSigningValidator struct {
	pin      TrustPin
	files    RecordFiles
	observer *CaptureSigningObserver
}

func NewCaptureSigningValidator(pin TrustPin, files RecordFiles, observer *CaptureSigningObserver) (*CaptureSigningValidator, error) {
	if !pin.valid() || observer == nil || observer.client == nil || nilInterface(observer.cfg.Kubernetes) || files.RecordFile == files.SignatureFile {
		return nil, ErrOwner
	}
	for _, p := range []string{files.RecordFile, files.SignatureFile} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return nil, ErrOwner
		}
	}
	pin.Issuer = bytes.Clone(pin.Issuer)
	return &CaptureSigningValidator{pin, files, observer}, nil
}
func (*CaptureSigningValidator) MarshalJSON() ([]byte, error) { return nil, ErrOwner }

type PreparedCaptureSigning struct {
	mu            sync.Mutex
	origin        *PreparedCaptureSigning
	validator     *CaptureSigningValidator
	ctx           context.Context
	auth          *AuthenticatedRecord
	grant         sec.OfflineBootstrapGrant
	config        sec.BootstrapConfig
	observation   *signingObservation
	guard         *OwnerGuard
	failed        bool
	candidateHash string
}

func (*PreparedCaptureSigning) MarshalJSON() ([]byte, error) { return nil, ErrOwner }

type OwnerGuard struct {
	prepared  *PreparedCaptureSigning
	legacy    *sql.Tx
	candidate candidateWrite
	first     ownerLedgerState
	until     time.Time
	failed    bool
}

func (*OwnerGuard) MarshalJSON() ([]byte, error) { return nil, ErrOwner }

var _ sec.BootstrapResourceValidator = (*CaptureSigningValidator)(nil)
var _ sec.BootstrapResourceCheck = (*PreparedCaptureSigning)(nil)

// A physical failure becomes an unusable dependency, not successful admission.
// Current signed identity can still be checked at L2 before L3 exact history.
func (v *CaptureSigningValidator) Prepare(ctx context.Context, g sec.OfflineBootstrapGrant, c sec.BootstrapConfig) (sec.BootstrapResourceCheck, error) {
	return v.prepare(ctx, g, c, "")
}
func (v *CaptureSigningValidator) prepare(ctx context.Context, g sec.OfflineBootstrapGrant, c sec.BootstrapConfig, selection string) (*PreparedCaptureSigning, error) {
	if v == nil || !sameContext(ctx, ctx) || ctx.Err() != nil {
		return nil, ErrOwner
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrOwner
	}
	a, e := v.files.read(v.pin)
	if e != nil || !matchConfig(a, g, c) || (selection != "" && selection != a.record.SelectionSHA256) {
		return nil, ErrOwner
	}
	owned, e := sec.DecodeBootstrapConfig(c.CanonicalJSON())
	if e != nil {
		return nil, ErrOwner
	}
	p := &PreparedCaptureSigning{validator: v, ctx: ctx, auth: a, grant: g, config: owned, candidateHash: selection}
	p.origin = p
	p.observation, _ = v.observer.observe(ctx, a)
	if ctx.Err() != nil {
		return nil, ErrOwner
	}
	return p, nil
}
func (p *PreparedCaptureSigning) local() error {
	a, e := p.validator.files.read(p.validator.pin)
	if e != nil || !bytes.Equal(a.raw, p.auth.raw) || !bytes.Equal(a.signature, p.auth.signature) {
		return ErrOwner
	}
	return nil
}
func minimum(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}
func (p *PreparedCaptureSigning) identityRead(ctx context.Context, q ledgerRead, sample func() (time.Time, error), first *ownerLedgerState) (ownerLedgerState, time.Time, error) {
	var zero ownerLedgerState
	if p.origin != p || !sameContext(ctx, p.ctx) || ctx.Err() != nil || p.local() != nil {
		return zero, time.Time{}, ErrOwner
	}
	before, e := sample()
	if e != nil {
		return zero, time.Time{}, ErrOwner
	}
	facts, e := readOwnerLedger(ctx, q, p.auth, before)
	if e != nil {
		return zero, time.Time{}, e
	}
	after, e := sample()
	r := p.auth.record
	if e != nil || !validTime(after) || after.Before(before) || after.Before(r.NotBefore) || !after.Before(r.Until) || ctx.Err() != nil || p.local() != nil {
		return zero, time.Time{}, ErrOwner
	}
	// Head expiry is also enforced after delivery, not its statement start.
	var raw, sig []byte
	if q.QueryRowContext(ctx, `SELECT signed_head,signature FROM system_backup_installation_owner_heads WHERE installation_id=? AND enrollment_id=? FOR SHARE`, p.auth.pin.InstallationID, p.auth.pin.EnrollmentID).Scan(&raw, &sig) != nil {
		return zero, time.Time{}, ErrOwner
	}
	h, e := verifyHead(raw, sig, p.auth.pin)
	if e != nil || digest(raw) != facts.headHash || after.Before(h.NotBefore) || !after.Before(h.Until) {
		return zero, time.Time{}, ErrOwner
	}
	final, e := sample()
	until := minimum(r.Until, h.Until)
	if e != nil || final.Before(after) || !final.Before(until) || ctx.Err() != nil {
		return zero, time.Time{}, ErrOwner
	}
	if first != nil && facts != *first {
		return zero, time.Time{}, ErrOwner
	}
	return facts, until, nil
}

// Must be called by the original L2 caller before the operation/history lookup.
// It is not called implicitly from a late resource Recheck. This branch remains
// UNLINKED until the concrete original caller integrates it.
func (p *PreparedCaptureSigning) AuthorizeOriginal(ctx context.Context, tx *sql.Tx, g sec.OfflineBootstrapGrant, c sec.BootstrapConfig) (*OwnerGuard, error) {
	if p == nil || tx == nil {
		return nil, ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.origin != p || p.failed || p.guard != nil || p.candidateHash != "" || g != p.grant || !bytes.Equal(c.CanonicalJSON(), p.config.CanonicalJSON()) {
		p.failed = true
		return nil, ErrOwner
	}
	sample := func() (time.Time, error) {
		var t time.Time
		e := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&t)
		return t, e
	}
	facts, until, e := p.identityRead(ctx, tx, sample, nil)
	if e != nil {
		p.failed = true
		return nil, e
	}
	p.guard = &OwnerGuard{prepared: p, legacy: tx, first: facts, until: until}
	return p.guard, nil
}

// Identity-only historical recheck retains current owner/admin/head authority.
// It does not require/repeat an old physical probe or make new consumption legal.
func (g *OwnerGuard) RecheckOriginalIdentity(ctx context.Context, tx *sql.Tx) error {
	if g == nil || g.prepared == nil || tx == nil {
		return ErrOwner
	}
	p := g.prepared
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failed || g.failed || p.guard != g || g.legacy != tx {
		p.failed = true
		g.failed = true
		return ErrOwner
	}
	g.failed = true
	sample := func() (time.Time, error) {
		var t time.Time
		e := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&t)
		return t, e
	}
	_, until, e := p.identityRead(ctx, tx, sample, &g.first)
	if e != nil || !until.Equal(g.until) {
		p.failed = true
		return ErrOwner
	}
	g.failed = false
	return nil
}
func (p *PreparedCaptureSigning) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if p == nil {
		return ErrOwner
	}
	p.mu.Lock()
	if p.origin != p {
		p.mu.Unlock()
		return ErrOwner
	}
	g := p.guard
	p.mu.Unlock()
	if g == nil {
		p.mu.Lock()
		p.failed = true
		p.mu.Unlock()
		return ErrOwner
	}
	if g.RecheckOriginalIdentity(ctx, tx) != nil {
		return ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.resourceCurrent(ctx, now) {
		p.failed = true
		return ErrOwner
	}
	var after time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&after) != nil || after.Before(now) || !p.resourceCurrent(ctx, after) || !after.Before(g.until) {
		p.failed = true
		return ErrOwner
	}
	return nil
}
func (p *PreparedCaptureSigning) resourceCurrent(ctx context.Context, now time.Time) bool {
	o := p.observation
	// identityRead already completed current local-file checks BEFORE its
	// independent final SQL clock. Do not perform new file I/O after that clock.
	return !p.failed && sameContext(ctx, p.ctx) && ctx.Err() == nil && validTime(now) && o != nil && o.owner == p.validator.observer && o.recordHash == p.auth.pin.RecordSHA256 && !now.Before(o.observed) && now.Before(o.until) && now.Before(p.auth.record.Until)
}
