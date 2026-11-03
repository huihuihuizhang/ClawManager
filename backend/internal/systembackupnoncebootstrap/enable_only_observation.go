package systembackupnoncebootstrap

import (
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"database/sql"
	"sync"
	"sync/atomic"
	"time"
)

type EnableOnlyObservation struct {
	mu                                sync.Mutex
	origin                            *EnableOnlyObservation
	failed                            atomic.Bool
	validator                         *Validator
	ctx                               context.Context
	started, until, floor, inputFloor time.Time
	tx                                *sql.Tx
}

func (*EnableOnlyObservation) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrRegistrationUnavailable
}
func (o *EnableOnlyObservation) ValidUntil() time.Time {
	if o == nil || o.origin != o || o.failed.Load() {
		return time.Time{}
	}
	return o.until
}

// ObserveEnableOnly checks actual exact-version secret bytes; it does not
// mint a nonce, consume one or obtain config mutation authority.
func (v *Validator) ObserveEnableOnly(ctx context.Context, in sec.ConfigMutationResourceInput) (*EnableOnlyObservation, error) {
	if v == nil || v.now == nil || !sameCandidateNonceContext(ctx, ctx) || ctx.Err() != nil || sec.ValidateEnableOnlyConfigMutation(in) != nil || in.InstallationID() != v.binding.InstallationID {
		return nil, sec.ErrRegistrationUnavailable
	}
	current, _ := in.Configs()
	return v.observeEnableOnlyCurrent(ctx, current)
}
func (v *Validator) observeEnableOnlyCurrent(ctx context.Context, current sec.ConfigValues) (*EnableOnlyObservation, error) {
	fail := func() (*EnableOnlyObservation, error) { return nil, sec.ErrRegistrationUnavailable }
	if v == nil || v.now == nil || ctx == nil || ctx.Err() != nil {
		return fail()
	}

	if current.SHA256() != v.binding.ConfigSHA256 {
		return nil, sec.ErrRegistrationUnavailable
	}
	start := v.now().UTC().Truncate(time.Microsecond)
	if !v.live(start) {
		return nil, sec.ErrRegistrationUnavailable
	}
	active := 0
	for _, k := range v.binding.Keys {
		if ctx.Err() != nil || v.validateKey(k) != nil {
			return nil, sec.ErrRegistrationUnavailable
		}
		for _, p := range current.References() {
			if p.Purpose == "nonce_hmac" && p.IdentityHash == k.IdentityHash && p.Version == k.Version {
				active++
			}
		}
	}
	end := v.now().UTC()
	until := start.Add(30 * time.Second)
	if v.binding.ExpiresAt.Before(until) {
		until = v.binding.ExpiresAt
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(until) {
		until = deadline
	}
	if active != 1 || ctx.Err() != nil || end.Before(start) || !end.Before(until) {
		return nil, sec.ErrRegistrationUnavailable
	}
	copy := *v
	copy.binding.Keys = append([]Key(nil), v.binding.Keys...)
	o := &EnableOnlyObservation{validator: &copy, ctx: ctx, started: start, until: until}
	o.origin = o
	return o, nil
}
func (o *EnableOnlyObservation) fail() error {
	if o != nil {
		o.failed.Store(true)
		if o.origin != nil {
			o.origin.failed.Store(true)
		}
	}
	return sec.ErrRegistrationUnavailable
}
func (o *EnableOnlyObservation) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if o == nil {
		return sec.ErrRegistrationUnavailable
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.origin != o || o.failed.Load() || !sameCandidateNonceContext(ctx, o.ctx) || ctx.Err() != nil || tx == nil || o.tx != nil && o.tx != tx || !o.inputFloor.IsZero() && now.Before(o.inputFloor) {
		return o.fail()
	}
	v := o.validator
	validTime := func(t time.Time) bool { return v.live(t) && !t.Before(o.started) && t.Before(o.until) }
	if !validTime(now) || !validTime(v.now().UTC()) {
		return o.fail()
	}
	var sid, db string
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&sid, &db) != nil || sid != v.binding.ServerUUID || db != v.binding.Database {
		return o.fail()
	}
	// Read the complete persisted global identity set and retained ledger in the
	// caller's transaction. Missing material must not shrink the required set.
	rows, e := tx.QueryContext(ctx, `SELECT nonce_hmac_ref_version,nonce_hmac_identity_hash,NULL FROM system_backup_v2_configs
UNION SELECT nonce_hmac_key_version,NULL,MAX(retain_until) FROM system_backup_v2_strong_auth_nonces WHERE retain_until>? GROUP BY nonce_hmac_key_version`, now)
	if e != nil {
		return o.fail()
	}
	keys := map[string]Key{}
	for _, k := range v.binding.Keys {
		keys[k.Version] = k
	}
	count := 0
	for rows.Next() {
		var ver string
		var identity sql.NullString
		var retained sql.NullTime
		if rows.Scan(&ver, &identity, &retained) != nil {
			rows.Close()
			return o.fail()
		}
		k, ok := keys[ver]
		if !ok || (!identity.Valid && !retained.Valid) || (identity.Valid && identity.String != k.IdentityHash) || (retained.Valid && (!retained.Time.After(now) || retained.Time.After(k.ProtectedUntil))) {
			rows.Close()
			return o.fail()
		}
		count++
		if count > 20000 {
			rows.Close()
			return o.fail()
		}
	}
	err := rows.Err()
	closed := rows.Close()
	if err != nil || closed != nil {
		return o.fail()
	}
	for _, k := range v.binding.Keys {
		if ctx.Err() != nil || v.validateKey(k) != nil {
			return o.fail()
		}
	}
	var tail time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&tail) != nil || tail.Before(now) || !o.floor.IsZero() && tail.Before(o.floor) || !validTime(tail) || !validTime(v.now().UTC()) || ctx.Err() != nil {
		return o.fail()
	}
	o.tx = tx
	o.floor = tail
	o.inputFloor = now
	return nil
}
