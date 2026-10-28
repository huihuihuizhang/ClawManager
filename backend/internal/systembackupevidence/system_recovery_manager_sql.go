package systembackupevidence

import (
	"bytes"
	"context"
	"encoding/hex"
	"reflect"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

const recoveryManagerSelect = `SELECT origin_installation_id,issuer_identity_hash,credential_binding_hash,can_read_fence,can_write_fence,can_manage_deployment,enabled,authorized_until,revoked_at,row_version FROM system_backup_v2_recovery_managers WHERE scope_key=? AND management_identity_hash=?`

type RecoveryManagerPermission string

const (
	RecoveryManagerReadFence        RecoveryManagerPermission = "read_fence"
	RecoveryManagerWriteFence       RecoveryManagerPermission = "write_fence"
	RecoveryManagerManageDeployment RecoveryManagerPermission = "manage_deployment"
)

// RecoveryManagerRowGuard is L1b. Its caller must already hold the L0 parent
// and any L1a deployment row used by this transaction. It never grants a
// permission from the mTLS proof alone.
type RecoveryManagerRowGuard struct {
	scope    pd.Scope
	scopeKey []byte
	identity []byte
	row      recoveryManagerRow
	locked   bool
}

type recoveryManagerRow struct {
	origin     string
	issuer     []byte
	credential []byte
	read       bool
	write      bool
	manage     bool
	enabled    bool
	until      time.Time
	revoked    *time.Time
	version    int64
}

func NewRecoveryManagerRowGuard(scope pd.Scope, facts RecoveryManagerPeerFacts) (*RecoveryManagerRowGuard, error) {
	if facts.Scope != scope || !digestPattern.MatchString(facts.IdentityHash) ||
		!digestPattern.MatchString(facts.IssuerIdentityHash) ||
		!digestPattern.MatchString(facts.CredentialBindingHash) || !systemPeerTime(facts.ExpiresAt) {
		return nil, ErrInvalid
	}
	scopeKey, err := pd.RecoveryScopeKey(scope)
	if err != nil || len(scopeKey) != 32 {
		return nil, ErrInvalid
	}
	identity, err := hex.DecodeString(facts.IdentityHash)
	if err != nil || len(identity) != 32 {
		return nil, ErrInvalid
	}
	return &RecoveryManagerRowGuard{scope: scope, scopeKey: scopeKey, identity: identity}, nil
}

func readRecoveryManagerRow(ctx context.Context, tx pd.ReadSQL, scopeKey, identity []byte, lock bool) (recoveryManagerRow, error) {
	q := recoveryManagerSelect
	if lock {
		q += " FOR UPDATE"
	}
	var row recoveryManagerRow
	if err := tx.QueryRowContext(ctx, q, scopeKey, identity).Scan(&row.origin, &row.issuer, &row.credential,
		&row.read, &row.write, &row.manage, &row.enabled, &row.until, &row.revoked, &row.version); err != nil {
		return recoveryManagerRow{}, err
	}
	return row, nil
}

func (g *RecoveryManagerRowGuard) Lock(ctx context.Context, tx pd.SQL) error {
	if g == nil || g.locked || tx == nil || ctx == nil || ctx.Err() != nil {
		return ErrDenied
	}
	row, err := readRecoveryManagerRow(ctx, tx, g.scopeKey, g.identity, true)
	if err != nil || row.origin != string(g.scope.Installation) || row.version < 1 ||
		len(row.issuer) != 32 || len(row.credential) != 32 || !systemPeerTime(row.until) {
		return ErrDenied
	}
	g.row, g.locked = row, true
	return nil
}

func (g *RecoveryManagerRowGuard) Admit(facts RecoveryManagerPeerFacts, permission RecoveryManagerPermission, dbNow time.Time) error {
	if g == nil || !g.locked || facts.Scope != g.scope || !systemPeerTime(dbNow) ||
		!g.row.enabled || g.row.revoked != nil || !dbNow.Before(g.row.until) ||
		!systemPeerTime(facts.ExpiresAt) || !dbNow.Before(facts.ExpiresAt) ||
		!bytes.Equal(g.identity, mustRecoveryManagerDigest(facts.IdentityHash)) ||
		!bytes.Equal(g.row.issuer, mustRecoveryManagerDigest(facts.IssuerIdentityHash)) ||
		!bytes.Equal(g.row.credential, mustRecoveryManagerDigest(facts.CredentialBindingHash)) {
		return ErrDenied
	}
	switch permission {
	case RecoveryManagerReadFence:
		if g.row.read {
			return nil
		}
	case RecoveryManagerWriteFence:
		if g.row.write {
			return nil
		}
	case RecoveryManagerManageDeployment:
		if g.row.manage {
			return nil
		}
	}
	return ErrDenied
}

func mustRecoveryManagerDigest(s string) []byte {
	if !digestPattern.MatchString(s) {
		return nil
	}
	b, _ := hex.DecodeString(s)
	return b
}

// Recheck reads only the L1b row locked above and rejects row or permission
// drift. The caller repeats RecoveryManagerPeerAuthenticator.Check first.
func (g *RecoveryManagerRowGuard) Recheck(ctx context.Context, tx pd.ReadSQL, facts RecoveryManagerPeerFacts, permission RecoveryManagerPermission, dbNow time.Time) error {
	if g == nil || !g.locked || tx == nil || ctx == nil || ctx.Err() != nil {
		return ErrDenied
	}
	row, err := readRecoveryManagerRow(ctx, tx, g.scopeKey, g.identity, false)
	if err != nil || !reflect.DeepEqual(row, g.row) {
		return ErrDenied
	}
	return g.Admit(facts, permission, dbNow)
}
