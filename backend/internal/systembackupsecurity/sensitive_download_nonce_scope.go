package systembackupsecurity

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// SensitiveDownloadNonceScope holds only the L0/L1 part of admission. It is NOT
// the complete prelocked download authority: current authentication, operation
// keys, owner/references, capacity and evidence must still be locked by D in
// order. The caller owns a fresh RepeatableRead transaction and its sole commit.
// In particular this must never be called from the legacy evidence-row callback.
type SensitiveDownloadNonceScope struct {
	state                *sensitiveDownloadNonceState
	tx                   *sql.Tx
	installation, active string
	configVersion        int64
	versions             []string
	observedAt           time.Time
}

type sensitiveDownloadNonceState struct {
	mu                         sync.Mutex
	failed, candidatesLocked   bool
	useAttempted, useSucceeded bool
	proof                      SensitiveDownloadProofVerification
	lastObserved               time.Time
}

func (*SensitiveDownloadNonceScope) MarshalJSON() ([]byte, error) {
	return nil, ErrRegistrationUnavailable
}
func (*SensitiveDownloadNonceScope) String() string   { return "SensitiveDownloadNonceScope" }
func (*SensitiveDownloadNonceScope) GoString() string { return "SensitiveDownloadNonceScope" }

const sensitiveDownloadInstallationsSQL = "SELECT origin_installation_id FROM system_backup_v2_installation_state ORDER BY origin_installation_id FOR UPDATE"
const sensitiveDownloadNonceVersionsSQL = `SELECT nonce_hmac_ref_version FROM system_backup_v2_configs
UNION SELECT nonce_hmac_key_version FROM system_backup_v2_strong_auth_nonces WHERE retain_until>? ORDER BY 1`
const sensitiveDownloadNonceLookupSQL = "SELECT id FROM system_backup_v2_strong_auth_nonces WHERE nonce_hmac=? AND nonce_hmac_key_version=? FOR UPDATE"

// LockSensitiveDownloadNonceScope establishes the same global installation
// serialization as the existing nonce consumers, including the empty ranges.
// History is derived from persisted config UNION retained ledger, never from
// available secret files or a caller-supplied list. Database identity is checked
// on this transaction's connection. No transaction, row or token is written.
func LockSensitiveDownloadNonceScope(ctx context.Context, tx *sql.Tx, database DatabaseIdentity, installation string) (*SensitiveDownloadNonceScope, error) {
	if ctx == nil || ctx.Err() != nil || tx == nil || !database.valid() || !sensitiveDownloadInstallation.MatchString(installation) {
		return nil, ErrRegistrationUnavailable
	}
	if database.check(ctx, tx) != nil {
		return nil, ErrRegistrationUnavailable
	}
	rows, err := tx.QueryContext(ctx, sensitiveDownloadInstallationsSQL)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	found, count, previous := false, 0, ""
	valid := true
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil || !readInstallationPattern.MatchString(id) || count >= 10000 || count > 0 && id <= previous {
			valid = false
			break
		}
		found = found || id == installation
		previous, count = id, count+1
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if !valid || readErr != nil || closeErr != nil || !found {
		return nil, ErrRegistrationUnavailable
	}
	var version int64
	if tx.QueryRowContext(ctx, "SELECT active_config_version FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE", installation).Scan(&version) != nil || version < 1 || version > 9007199254740991 {
		return nil, ErrRegistrationUnavailable
	}
	var active string
	if tx.QueryRowContext(ctx, "SELECT nonce_hmac_ref_version FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR UPDATE", installation, version).Scan(&active) != nil || !sensitiveDownloadNonceVersion(active) {
		return nil, ErrRegistrationUnavailable
	}
	now, err := sensitiveDownloadNonceClock(ctx, tx, time.Time{})
	if err != nil {
		return nil, err
	}
	rows, err = tx.QueryContext(ctx, sensitiveDownloadNonceVersionsSQL, now)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	versions := []string{}
	found, valid, previous = false, true, ""
	for rows.Next() {
		var v string
		if rows.Scan(&v) != nil || !sensitiveDownloadNonceVersion(v) || len(versions) >= 10000 || len(versions) > 0 && v <= previous {
			valid = false
			break
		}
		versions = append(versions, v)
		found, previous = found || v == active, v
	}
	readErr, closeErr = rows.Err(), rows.Close()
	if !valid || readErr != nil || closeErr != nil || !found {
		return nil, ErrRegistrationUnavailable
	}
	// A lock/history read can block. Do not hand A a stale verification time.
	now, err = sensitiveDownloadNonceClock(ctx, tx, now)
	if err != nil {
		return nil, err
	}
	return &SensitiveDownloadNonceScope{state: &sensitiveDownloadNonceState{}, tx: tx, installation: installation, active: active, configVersion: version, versions: versions, observedAt: now}, nil
}

func sensitiveDownloadNonceVersion(v string) bool {
	return len(v) <= 128 && registryVersionPath.MatchString(v) && !strings.Contains(v, "..")
}

func sensitiveDownloadNonceClock(ctx context.Context, tx *sql.Tx, floor time.Time) (time.Time, error) {
	if ctx == nil || ctx.Err() != nil || tx == nil {
		return time.Time{}, ErrRegistrationUnavailable
	}
	now, err := configMutationClock(ctx, tx)
	_, offset := now.Zone()
	if err != nil || now.Before(floor) || offset != 0 || now.Year() < 1970 || now.Year() > 9999 || now.Nanosecond()%1000 != 0 || ctx.Err() != nil {
		return time.Time{}, ErrRegistrationUnavailable
	}
	return now.UTC(), nil
}

func (s *SensitiveDownloadNonceScope) RequiredVersions() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.versions...)
}

func (s *SensitiveDownloadNonceScope) ActiveVersion() string {
	if s == nil {
		return ""
	}
	return s.active
}

// LockCandidates is the L5 lookup, AFTER D's operation-key and owner/reference
// locks and successful current authorization/proof validation. Every historical
// HMAC candidate is checked globally, with the original unique-index key order.
// Even an expired existing row rejects reuse. No nonce is consumed here.
// A scope may attempt this once; errors permanently invalidate it. This is not
// proof that D's intervening locks, claim CAS or commit have happened.
func (s *SensitiveDownloadNonceScope) LockCandidates(ctx context.Context, tx *sql.Tx, proof SensitiveDownloadProofVerification) error {
	if s == nil || s.state == nil {
		return ErrRegistrationUnavailable
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	if s.state.failed {
		return ErrRegistrationUnavailable
	}
	if s.state.candidatesLocked {
		s.state.failed = true
		return ErrRegistrationUnavailable
	}
	s.state.failed = true
	if ctx == nil || ctx.Err() != nil || tx == nil || tx != s.tx || proof.request.installation != s.installation ||
		proof.request.canonical == "" || proof.active.KeyVersion != s.active || len(proof.candidates) != len(s.versions) {
		return ErrRegistrationUnavailable
	}
	candidates := append([]NonceHMACCandidate(nil), proof.candidates...)
	byVersion := make(map[string]string, len(candidates))
	for _, c := range candidates {
		if !providerHashPattern.MatchString(c.HMAC) || !sensitiveDownloadNonceVersion(c.KeyVersion) || byVersion[c.KeyVersion] != "" {
			return ErrRegistrationUnavailable
		}
		byVersion[c.KeyVersion] = c.HMAC
	}
	for _, v := range s.versions {
		if byVersion[v] == "" {
			return ErrRegistrationUnavailable
		}
	}
	if byVersion[s.active] != proof.active.HMAC {
		return ErrRegistrationUnavailable
	}
	// The actual unique key is (nonce_hmac,key_version), not installation or
	// version alone; use the same deterministic order across consumers.
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].HMAC < candidates[j].HMAC || candidates[i].HMAC == candidates[j].HMAC && candidates[i].KeyVersion < candidates[j].KeyVersion
	})
	floor := s.observedAt
	if s.state.lastObserved.After(floor) {
		floor = s.state.lastObserved
	}
	now, err := sensitiveDownloadNonceClock(ctx, tx, floor)
	if err != nil {
		return ErrRegistrationUnavailable
	}
	if err = proof.RecheckProofAt(now); err != nil {
		return err
	}
	for _, c := range candidates {
		var id int64
		err = tx.QueryRowContext(ctx, sensitiveDownloadNonceLookupSQL, c.HMAC, c.KeyVersion).Scan(&id)
		if err == nil {
			if id < 1 {
				return ErrRegistrationUnavailable
			}
			return verificationError(FailureReplayed, "strong-auth nonce was already consumed")
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return ErrRegistrationUnavailable
		}
	}
	now, err = sensitiveDownloadNonceClock(ctx, tx, now)
	if err != nil {
		return ErrRegistrationUnavailable
	}
	if err = proof.RecheckProofAt(now); err != nil {
		return err
	}
	s.state.candidatesLocked, s.state.failed = true, false
	s.state.proof, s.state.lastObserved = proof, now
	return nil
}

// UseLockedCandidates lends the already locked active candidate exactly once
// to D's same-transaction SQL writer. This callback is trusted internal code:
// it must not commit, roll back, acquire a new earlier lock or perform network
// I/O. Success here alone proves no ledger row or download authority; D must
// independently read back its actual nonce/operation/receipt and final guards.
// Copies of the scope share the attempt/failure latch.
func (s *SensitiveDownloadNonceScope) UseLockedCandidates(ctx context.Context, tx *sql.Tx, proof SensitiveDownloadProofVerification, write func(NonceHMACCandidate) error) error {
	if s == nil || s.state == nil {
		return ErrRegistrationUnavailable
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	st := s.state
	if st.failed {
		return ErrRegistrationUnavailable
	}
	if st.useAttempted {
		st.failed = true
		return ErrRegistrationUnavailable
	}
	st.failed, st.useAttempted = true, true
	if !st.candidatesLocked || ctx == nil || ctx.Err() != nil || tx == nil || tx != s.tx || write == nil || !st.proof.SameAdmissionVerification(proof) {
		return ErrRegistrationUnavailable
	}
	now, err := sensitiveDownloadNonceClock(ctx, tx, st.lastObserved)
	if err != nil {
		return err
	}
	if err = proof.RecheckProofAt(now); err != nil {
		return err
	}
	if err = write(proof.ActiveNonce()); err != nil {
		return err
	}
	now, err = sensitiveDownloadNonceClock(ctx, tx, now)
	if err != nil {
		return err
	}
	if err = proof.RecheckProofAt(now); err != nil {
		return err
	}
	st.lastObserved, st.useSucceeded, st.failed = now, true, false
	return nil
}

// RecheckUsedCandidates checks only this scope's original transaction/proof and
// fresh monotonic SQL UTC after its one successful callback. It does not assert
// that the callback inserted a nonce or that current authorization is valid.
func (s *SensitiveDownloadNonceScope) RecheckUsedCandidates(ctx context.Context, tx *sql.Tx, proof SensitiveDownloadProofVerification) error {
	if s == nil || s.state == nil {
		return ErrRegistrationUnavailable
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	st := s.state
	if st.failed {
		return ErrRegistrationUnavailable
	}
	st.failed = true
	if !st.useSucceeded || !st.candidatesLocked || ctx == nil || ctx.Err() != nil || tx == nil || tx != s.tx || !st.proof.SameAdmissionVerification(proof) {
		return ErrRegistrationUnavailable
	}
	now, err := sensitiveDownloadNonceClock(ctx, tx, st.lastObserved)
	if err != nil {
		return err
	}
	if err = proof.RecheckProofAt(now); err != nil {
		return err
	}
	st.lastObserved, st.failed = now, false
	return nil
}
