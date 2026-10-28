package systembackupnoncebootstrap

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	stdhash "hash"
	"reflect"
	"strconv"
	"sync/atomic"
	"time"

	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

// The concrete A bridge acquires this COMPLETE GLOBAL config index/range at
// L1, before the producer domain. These later reads revisit only that prefix.
// Never narrow either global source to the current installation or active key.
const candidateNonceConfigSQL = "SELECT id,origin_installation_id,version,config_sha256,enabled,nonce_hmac_ref_version,nonce_hmac_identity_hash FROM system_backup_v2_configs FORCE INDEX(uk_sb_config_version) ORDER BY origin_installation_id,version FOR UPDATE"
const candidateNonceRetainedSQL = "SELECT id,nonce_hmac_key_version,retain_until FROM system_backup_v2_strong_auth_nonces FORCE INDEX(idx_sb_auth_nonce_retention) WHERE retain_until>? ORDER BY retain_until,id FOR UPDATE"

// This is material validation, NOT independent deployment/bootstrap authority.
// Original mapping authentication and L3 historical/new-use branching remain
// mandatory responsibilities of the fixed original resource authority.
type PreparedCandidateNonce struct{ state *candidateNonceState }
type candidateNonceState struct {
	ctx               context.Context
	validator         *Validator // Owned original binding; no wall-clock callback.
	active            sec.BootstrapSecretRef
	observed, expires time.Time
	ready             bool
	used              atomic.Bool
}
type CandidateNonceCheck struct {
	state                        *candidateNonceState
	tx                           pd.BootstrapSQL
	cutoff                       time.Time
	configDigest, retainedDigest [32]byte
	configRows, retainedRows     uint64
}

func (PreparedCandidateNonce) String() string   { return "PreparedCandidateNonce" }
func (PreparedCandidateNonce) GoString() string { return "PreparedCandidateNonce" }
func (PreparedCandidateNonce) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrRegistrationUnavailable
}
func (*PreparedCandidateNonce) UnmarshalJSON([]byte) error { return sec.ErrRegistrationUnavailable }
func (CandidateNonceCheck) String() string                 { return "CandidateNonceCheck" }
func (CandidateNonceCheck) GoString() string               { return "CandidateNonceCheck" }
func (CandidateNonceCheck) MarshalJSON() ([]byte, error)   { return nil, sec.ErrRegistrationUnavailable }
func (*CandidateNonceCheck) UnmarshalJSON([]byte) error    { return sec.ErrRegistrationUnavailable }
func sameCandidateNonceContext(a, b context.Context) bool {
	if a == nil || b == nil {
		return false
	}
	x, y := reflect.ValueOf(a), reflect.ValueOf(b)
	return x.Comparable() && y.Comparable() && !(x.Kind() == reflect.Pointer && x.IsNil()) && !(y.Kind() == reflect.Pointer && y.IsNil()) && a == b
}

func (v *Validator) PrepareCandidateAttempt(ctx context.Context, g sec.OfflineBootstrapGrant, c sec.BootstrapConfig) (*PreparedCandidateNonce, error) {
	if v == nil || v.now == nil || !sameCandidateNonceContext(ctx, ctx) || ctx.Err() != nil || g.InstallationID != v.binding.InstallationID || g.ServerUUID != v.binding.ServerUUID || g.Database != v.binding.Database || g.ConfigSHA256 != v.binding.ConfigSHA256 || c.SHA256() != v.binding.ConfigSHA256 {
		return nil, sec.ErrRegistrationUnavailable
	}
	owned, err := sec.DecodeBootstrapConfig(c.CanonicalJSON())
	if err != nil || owned.SHA256() != g.ConfigSHA256 {
		return nil, sec.ErrRegistrationUnavailable
	}
	s := &candidateNonceState{ctx: ctx}
	legacy, err := v.Prepare(ctx, g, owned)
	if ctx.Err() != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	if err != nil {
		return &PreparedCandidateNonce{s}, nil
	} // No permission/deadline on physical failure.
	checked, ok := legacy.(*check)
	if !ok || checked == nil || checked.validator == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	copy := Validator{binding: checked.validator.binding}
	copy.binding.Keys = append([]Key(nil), copy.binding.Keys...)
	s.validator = &copy
	s.observed, s.expires = checked.observed, checked.expires
	for _, ref := range owned.References() {
		if ref.Purpose == "nonce_hmac" {
			s.active = ref
		}
	}
	s.ready = true
	return &PreparedCandidateNonce{s}, nil
}

// Intersect this ORIGINAL deadline into admission.DependencyExpiresAt so D's
// final clock after every callback/write still enforces it. Nil never means
// unlimited life. Ceil is equivalent to strict raw expiry for UTC(6) samples.
func (p *PreparedCandidateNonce) DependencyDeadline() *pd.Timestamp {
	if p == nil || p.state == nil || !p.state.ready {
		return nil
	}
	t := p.state.expires.UTC()
	if rem := t.Nanosecond() % 1000; rem != 0 {
		t = t.Add(time.Duration(1000-rem) * time.Nanosecond)
	}
	stamp := pd.Timestamp(t.Format("2006-01-02T15:04:05.000000Z"))
	if _, err := stamp.Time(); err != nil {
		return nil
	}
	return &stamp
}
func candidateNonceTime(s *candidateNonceState, now time.Time) bool {
	_, offset := now.Zone()
	return s != nil && s.ready && s.validator != nil && now.Year() >= 1000 && now.Year() <= 9999 && offset == 0 && now.Nanosecond()%1000 == 0 && s.validator.live(now) && !now.Before(s.observed) && now.Before(s.expires)
}
func nonceDigestField(h stdhash.Hash, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	h.Write(size[:])
	h.Write([]byte(value))
}
func nonceDigestResult(h stdhash.Hash) [32]byte {
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func (c *CandidateNonceCheck) keys() map[string]Key {
	keys := make(map[string]Key, len(c.state.validator.binding.Keys))
	for _, key := range c.state.validator.binding.Keys {
		keys[key.Version] = key
	}
	return keys
}
func (c *CandidateNonceCheck) scope(ctx context.Context, tx pd.BootstrapReadSQL) error {
	var server, database string
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE()").Scan(&server, &database) != nil || server != c.state.validator.binding.ServerUUID || database != c.state.validator.binding.Database {
		return sec.ErrRegistrationUnavailable
	}
	return nil
}

// Stream raw rows without inventing a 20,000 RAW-row cap. Legacy UNION deduped
// config tuples and MAX grouped retained versions; arbitrarily many duplicates
// can have the same legitimate required key set. Memory remains bounded by the
// original <=10,000-key map plus a rolling digest, under the one attempt ctx.
func (c *CandidateNonceCheck) configs(ctx context.Context, tx pd.BootstrapReadSQL, final bool) ([32]byte, uint64, error) {
	var zero [32]byte
	rows, err := tx.QueryContext(ctx, candidateNonceConfigSQL)
	if err != nil {
		return zero, 0, sec.ErrRegistrationUnavailable
	}
	defer rows.Close()
	h := sha256.New()
	keys := c.keys()
	var count uint64
	added := 0
	for rows.Next() {
		if ctx.Err() != nil {
			return zero, 0, sec.ErrRegistrationUnavailable
		}
		var id, installation, version, configHash, keyVersion, identity string
		var enabled bool
		if rows.Scan(&id, &installation, &version, &configHash, &enabled, &keyVersion, &identity) != nil {
			return zero, 0, sec.ErrRegistrationUnavailable
		}
		key, ok := keys[keyVersion]
		if !ok || key.IdentityHash != identity {
			return zero, 0, sec.ErrRegistrationUnavailable
		}
		if installation == c.state.validator.binding.InstallationID {
			if !final || version != "1" || configHash != c.state.validator.binding.ConfigSHA256 || enabled || keyVersion != c.state.active.Version || identity != c.state.active.IdentityHash || added != 0 {
				return zero, 0, sec.ErrRegistrationUnavailable
			}
			// The auto-generated ID is observed, never fabricated. Its exact row
			// and full flattened config are independently checked by A/D.
			added++
			continue
		}
		for _, value := range []string{id, installation, version, configHash, strconv.FormatBool(enabled), keyVersion, identity} {
			nonceDigestField(h, value)
		}
		count++
	}
	if rows.Err() != nil || rows.Close() != nil || (final && added != 1) {
		return zero, 0, sec.ErrRegistrationUnavailable
	}
	return nonceDigestResult(h), count, nil
}
func (c *CandidateNonceCheck) retained(ctx context.Context, tx pd.BootstrapReadSQL) ([32]byte, uint64, error) {
	var zero [32]byte
	rows, err := tx.QueryContext(ctx, candidateNonceRetainedSQL, c.cutoff)
	if err != nil {
		return zero, 0, sec.ErrRegistrationUnavailable
	}
	defer rows.Close()
	h := sha256.New()
	keys := c.keys()
	var count uint64
	for rows.Next() {
		if ctx.Err() != nil {
			return zero, 0, sec.ErrRegistrationUnavailable
		}
		var id, version string
		var until sql.NullTime
		if rows.Scan(&id, &version, &until) != nil {
			return zero, 0, sec.ErrRegistrationUnavailable
		}
		key, ok := keys[version]
		if !ok || !until.Valid || !until.Time.After(c.cutoff) || until.Time.After(key.ProtectedUntil) {
			return zero, 0, sec.ErrRegistrationUnavailable
		}
		for _, value := range []string{id, version, until.Time.UTC().Format(time.RFC3339Nano)} {
			nonceDigestField(h, value)
		}
		count++
	}
	if rows.Err() != nil || rows.Close() != nil {
		return zero, 0, sec.ErrRegistrationUnavailable
	}
	return nonceDigestResult(h), count, nil
}
func (c *CandidateNonceCheck) materials(ctx context.Context) error {
	for _, key := range c.state.validator.binding.Keys {
		// The original concrete helper verifies exact descriptor identity,
		// purpose/provider/scope, reads exactly 32 actual bytes and wipes them.
		if ctx.Err() != nil || c.state.validator.validateKey(key) != nil {
			return sec.ErrRegistrationUnavailable
		}
	}
	return nil
}

// L5 only, after A's complete GLOBAL config L1 and D's L3 fresh-use branch.
// Acquires the complete GLOBAL retained nonce range and insertion gaps in the
// original caller tx. The original cutoff/range never shrinks in final checks.
func (p *PreparedCandidateNonce) LockReferences(ctx context.Context, tx pd.BootstrapSQL) (*CandidateNonceCheck, error) {
	if p == nil || p.state == nil || !p.state.used.CompareAndSwap(false, true) {
		return nil, sec.ErrRegistrationUnavailable
	}
	s := p.state
	if !s.ready || p.DependencyDeadline() == nil || !sameCandidateNonceContext(ctx, s.ctx) || ctx.Err() != nil || !pd.SameBootstrapTransaction(tx, tx) {
		return nil, sec.ErrRegistrationUnavailable
	}
	now, err := tx.SampleTime(ctx)
	if err != nil || !candidateNonceTime(s, now) {
		return nil, sec.ErrRegistrationUnavailable
	}
	c := &CandidateNonceCheck{state: s, tx: tx, cutoff: now}
	if c.scope(ctx, tx) != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	c.configDigest, c.configRows, err = c.configs(ctx, tx, false)
	if err != nil {
		return nil, err
	}
	c.retainedDigest, c.retainedRows, err = c.retained(ctx, tx)
	if err != nil {
		return nil, err
	}
	if c.materials(ctx) != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	end, err := tx.SampleTime(ctx)
	if err != nil || end.Before(now) || !candidateNonceTime(s, end) || ctx.Err() != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	return c, nil
}

// Final resource callback runs under D's private read/time view after public
// writes close, BEFORE fixed SQL-only FinalGuard. Keep original late local-file
// change/removal refusal and wipe; no provider/network, new locks or refreshed
// observations. All SQL here revisits the same already-held global prefix.
func (c *CandidateNonceCheck) Recheck(ctx context.Context, tx pd.BootstrapReadSQL) error {
	if c == nil || c.state == nil || !sameCandidateNonceContext(ctx, c.state.ctx) || ctx.Err() != nil || !pd.SameBootstrapTransaction(c.tx, tx) {
		return sec.ErrRegistrationUnavailable
	}
	start, err := tx.SampleTime(ctx)
	if err != nil || start.Before(c.cutoff) || !candidateNonceTime(c.state, start) {
		return sec.ErrRegistrationUnavailable
	}
	if c.scope(ctx, tx) != nil {
		return sec.ErrRegistrationUnavailable
	}
	configDigest, configRows, err := c.configs(ctx, tx, true)
	if err != nil || configDigest != c.configDigest || configRows != c.configRows {
		return sec.ErrRegistrationUnavailable
	}
	retainedDigest, retainedRows, err := c.retained(ctx, tx)
	if err != nil || retainedDigest != c.retainedDigest || retainedRows != c.retainedRows || c.materials(ctx) != nil {
		return sec.ErrRegistrationUnavailable
	}
	end, err := tx.SampleTime(ctx)
	if err != nil || ctx.Err() != nil || end.Before(start) || !candidateNonceTime(c.state, end) {
		return sec.ErrRegistrationUnavailable
	}
	return nil
}
