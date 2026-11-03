package systembackupinstallationowner

import (
	"bytes"
	"context"
	"database/sql"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

// ReferenceCurrentIdentity checks only the currently active ORIGINAL source
// of an unchanged installed reference set. It grants no mutation permission.
// This API accepts no OfflineBootstrapGrant and creates no bootstrap check.
type ReferenceCurrentIdentity struct {
	pin   TrustPin
	files RecordFiles
}

func NewReferenceCurrentIdentity(pin TrustPin, files RecordFiles) (*ReferenceCurrentIdentity, error) {
	if _, e := NewCaptureSigningIdentityOnlyValidator(pin, files); e != nil {
		return nil, e
	}
	pin.Issuer = bytes.Clone(pin.Issuer)
	return &ReferenceCurrentIdentity{pin: pin, files: files}, nil
}

type PreparedReferenceCurrentIdentity struct {
	mu                       sync.Mutex
	origin                   *PreparedReferenceCurrentIdentity
	source                   *ReferenceCurrentIdentity
	ctx                      context.Context
	auth                     *AuthenticatedRecord
	tx                       *sql.Tx
	first                    ownerLedgerState
	locked                   bool
	failed                   atomic.Bool
	floor, inputFloor, until time.Time
}

func (*PreparedReferenceCurrentIdentity) MarshalJSON() ([]byte, error) { return nil, ErrOwner }
func (s *ReferenceCurrentIdentity) PrepareEnableOnly(ctx context.Context, in sec.ConfigMutationResourceInput) (*PreparedReferenceCurrentIdentity, error) {
	if s == nil || !sameContext(ctx, ctx) || ctx.Err() != nil || sec.ValidateEnableOnlyConfigMutation(in) != nil {
		return nil, ErrOwner
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrOwner
	}
	a, e := s.files.read(s.pin)
	if e != nil {
		return nil, ErrOwner
	}
	current, _ := in.Configs()
	actor := in.Actor()
	r := a.record
	if r.ConfigSHA256 != current.SHA256() || r.Target.InstallationID != in.InstallationID() || actor.UserID != r.Actor.UserID || actor.Subject != "user:"+strconv.FormatInt(actor.UserID, 10) {
		return nil, ErrOwner
	}
	p := &PreparedReferenceCurrentIdentity{source: s, ctx: ctx, auth: a, until: r.Until}
	p.origin = p
	return p, nil
}
func (p *PreparedReferenceCurrentIdentity) ValidUntil() time.Time {
	if p == nil {
		return time.Time{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.origin != p || p.failed.Load() {
		return time.Time{}
	}
	return p.until
}

// Called inside D's real mutation transaction. Reads only the original local
// immutable bytes and controlled SQL head/grant/account identity. The separate
// mutation authority must already own its actual session/admin prefix.
func (p *PreparedReferenceCurrentIdentity) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if p == nil {
		return ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	bad := func() error {
		p.failed.Store(true)
		if p.origin != nil && p.origin != p {
			p.origin.failed.Store(true)
		}
		return ErrOwner
	}
	if p.origin != p || p.failed.Load() || tx == nil || !sameContext(ctx, p.ctx) || ctx.Err() != nil || !validTime(now) || !p.inputFloor.IsZero() && now.Before(p.inputFloor) || p.tx != nil && p.tx != tx {
		return bad()
	}
	a, e := p.source.files.read(p.source.pin)
	if e != nil || !bytes.Equal(a.raw, p.auth.raw) || !bytes.Equal(a.signature, p.auth.signature) {
		return bad()
	}
	var before time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&before) != nil || !validTime(before) || before.Before(now) || !p.floor.IsZero() && before.Before(p.floor) || before.Before(p.auth.record.NotBefore) || !before.Before(p.until) {
		return bad()
	}
	facts, e := readOwnerLedger(ctx, tx, p.auth, before)
	if e != nil || p.locked && facts != p.first {
		return bad()
	}
	var raw, sig []byte
	if tx.QueryRowContext(ctx, `SELECT signed_head,signature FROM system_backup_installation_owner_heads WHERE installation_id=? AND enrollment_id=? FOR SHARE`, p.auth.pin.InstallationID, p.auth.pin.EnrollmentID).Scan(&raw, &sig) != nil {
		return bad()
	}
	head, e := verifyHead(raw, sig, p.auth.pin)
	if e != nil || digest(raw) != facts.headHash {
		return bad()
	}
	end := minimum(p.auth.record.Until, head.Until)
	var after time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&after) != nil || !validTime(after) || after.Before(before) || after.Before(head.NotBefore) || !after.Before(end) || ctx.Err() != nil {
		return bad()
	}
	if p.locked && !end.Equal(p.until) {
		return bad()
	}
	a, e = p.source.files.read(p.source.pin)
	if e != nil || !bytes.Equal(a.raw, p.auth.raw) || !bytes.Equal(a.signature, p.auth.signature) {
		return bad()
	}
	p.tx = tx
	p.first = facts
	p.locked = true
	p.floor = after
	p.inputFloor = now
	p.until = end
	return nil
}
