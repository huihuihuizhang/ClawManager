//go:build systembackup_mysql

package systembackupevidence

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// This authority is a test substitute. Production management authentication,
// deployment admission and reserved audit capacity remain A/D review inputs.
type dRecoveryFenceMySQLAuthority struct {
	db          *sql.DB
	allow       bool
	badHash     bool
	failAudit   bool
	failRecheck bool
	intentHook  func()
}

func (a *dRecoveryFenceMySQLAuthority) PrepareRecoveryFence(context.Context, pd.RecoveryFenceRequest) (pd.RecoveryFenceSession, error) {
	return a, nil
}
func (*dRecoveryFenceMySQLAuthority) LockInstallation(context.Context, pd.SQL, pd.RecoveryFenceRequest) error {
	return nil
}
func (a *dRecoveryFenceMySQLAuthority) Authorize(ctx context.Context, tx pd.SQL, r pd.RecoveryFenceRequest, _ pd.RecoveryFenceRow) (pd.RecoveryFenceAdmission, error) {
	var now time.Time
	if err := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
		return pd.RecoveryFenceAdmission{}, err
	}
	h, err := pd.RecoveryFenceHash(r)
	if err != nil {
		return pd.RecoveryFenceAdmission{}, err
	}
	if a.badHash {
		h = pd.Hash(strings.Repeat("f", 64))
	}
	return pd.RecoveryFenceAdmission{VerifiedRequestHash: h, IdentityExpiresAt: systemExecutionStamp(now.Add(time.Minute)), ManagementAllowed: a.allow}, nil
}
func (a *dRecoveryFenceMySQLAuthority) Audit(ctx context.Context, tx pd.SQL, _ pd.RecoveryFenceRequest, stage string) error {
	if stage == "intent" && a.intentHook != nil {
		a.intentHook()
	}
	if stage == "result" {
		if _, err := tx.ExecContext(ctx, "INSERT INTO synthetic_guard_marker (n) VALUES (?)", 2); err != nil {
			return err
		}
		if a.failAudit {
			return pd.ErrUnavailable
		}
	}
	return nil
}
func (a *dRecoveryFenceMySQLAuthority) Recheck(context.Context, pd.ReadSQL, pd.RecoveryFenceRequest, pd.RecoveryFenceRow, time.Time) error {
	if a.failRecheck || !a.allow {
		return pd.ErrGuardRequired
	}
	return nil
}

func dRecoveryFenceRequest(scope pd.Scope, identity pd.Hash) pd.RecoveryFenceRequest {
	return pd.RecoveryFenceRequest{Scope: scope, Operation: "register", IdentityHash: identity, ExpectedEpoch: "0", ExpectedRowVersion: "0", ReasonHash: pd.Hash(strings.Repeat("b", 64))}
}

func dRecoveryFenceStored(t *testing.T, db *sql.DB, history pd.HistoricalBindingRecord, identity pd.Hash) (int64, int64, bool, bool) {
	t.Helper()
	encoded, err := pd.EncodeStoredRecord(&history)
	mustSQL(t, err)
	identityBytes, err := hex.DecodeString(string(identity))
	mustSQL(t, err)
	var epoch, version int64
	var revoked sql.NullTime
	err = db.QueryRow("SELECT revocation_epoch,row_version,revoked_at FROM system_backup_v2_producer_recovery_revocations WHERE scope_key=? AND workload_identity_hash=?", encoded.Columns["scope_key"], identityBytes).Scan(&epoch, &version, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, false, false
	}
	mustSQL(t, err)
	return epoch, version, revoked.Valid, true
}

func TestDRecoveryFenceMySQL(t *testing.T) {
	ctx := context.Background()
	t.Run("register_rotate_rekey_and_revoke", func(t *testing.T) {
		db, _ := dProducerMySQLDB(t)
		f := newDIntegrationFixtureWithDB(t, db)
		a := &dRecoveryFenceMySQLAuthority{db: db, allow: true}
		m, err := pd.NewRecoveryFenceManager(db, f.history.Scope, a)
		mustSQL(t, err)
		identity := pd.Hash(strings.Repeat("a", 64))
		r := dRecoveryFenceRequest(f.history.Scope, identity)
		missing := r
		missing.Operation, missing.ExpectedEpoch, missing.ExpectedRowVersion = "rotate", "1", "1"
		if _, err = m.ChangeFence(ctx, missing); !errors.Is(err, pd.ErrConflict) {
			t.Fatal("missing rotate", err)
		}
		missing.Operation = "revoke"
		if _, err = m.ChangeFence(ctx, missing); !errors.Is(err, pd.ErrConflict) {
			t.Fatal("missing revoke", err)
		}
		registered, err := m.ChangeFence(ctx, r)
		mustSQL(t, err)
		if registered.Epoch != "1" || registered.RowVersion != "1" || registered.Revoked {
			t.Fatal("register", registered)
		}
		if _, err = m.ChangeFence(ctx, r); !errors.Is(err, pd.ErrConflict) {
			t.Fatal("duplicate register", err)
		}
		r.Operation, r.ExpectedEpoch, r.ExpectedRowVersion = "rotate", "1", "1"
		rotated, err := m.ChangeFence(ctx, r)
		mustSQL(t, err)
		if rotated.Epoch != "2" || rotated.RowVersion != "2" || rotated.Revoked {
			t.Fatal("same identity rotate", rotated)
		}
		if _, err = m.ChangeFence(ctx, r); !errors.Is(err, pd.ErrConflict) {
			t.Fatal("stale CAS", err)
		}
		r.ExpectedEpoch, r.ExpectedRowVersion = "2", "2"
		next := pd.Hash(strings.Repeat("c", 64))
		r.NextIdentityHash = &next
		changed, err := m.ChangeFence(ctx, r)
		mustSQL(t, err)
		if changed.IdentityHash != next || changed.Epoch != "3" || changed.RowVersion != "1" || changed.Revoked {
			t.Fatal("new identity", changed)
		}
		oldEpoch, oldVersion, oldRevoked, oldFound := dRecoveryFenceStored(t, db, f.history, identity)
		newEpoch, newVersion, newRevoked, newFound := dRecoveryFenceStored(t, db, f.history, next)
		if !oldFound || oldEpoch != 3 || oldVersion != 3 || !oldRevoked || !newFound || newEpoch != 3 || newVersion != 1 || newRevoked {
			t.Fatal("rotation rows", oldEpoch, oldVersion, oldRevoked, newEpoch, newVersion, newRevoked)
		}
		r.IdentityHash, r.NextIdentityHash, r.Operation, r.ExpectedEpoch, r.ExpectedRowVersion = next, nil, "revoke", "3", "1"
		revoked, err := m.ChangeFence(ctx, r)
		mustSQL(t, err)
		if !revoked.Revoked || revoked.Epoch != "4" || revoked.RowVersion != "2" {
			t.Fatal("revoke", revoked)
		}
		if _, err = m.ChangeFence(ctx, r); !errors.Is(err, pd.ErrConflict) {
			t.Fatal("duplicate revoke", err)
		}
		r.Operation, r.ExpectedEpoch, r.ExpectedRowVersion = "register", "0", "0"
		if _, err = m.ChangeFence(ctx, r); !errors.Is(err, pd.ErrConflict) {
			t.Fatal("revoked identity reused", err)
		}
	})
	t.Run("concurrent_rotate_single_winner", func(t *testing.T) {
		db, _ := dProducerMySQLDB(t)
		f := newDIntegrationFixtureWithDB(t, db)
		a := &dRecoveryFenceMySQLAuthority{db: db, allow: true}
		m, err := pd.NewRecoveryFenceManager(db, f.history.Scope, a)
		mustSQL(t, err)
		identity := pd.Hash(strings.Repeat("d", 64))
		r := dRecoveryFenceRequest(f.history.Scope, identity)
		_, err = m.ChangeFence(ctx, r)
		mustSQL(t, err)
		r.Operation, r.ExpectedEpoch, r.ExpectedRowVersion = "rotate", "1", "1"
		results := make(chan error, 2)
		for range 2 {
			go func() { _, err := m.ChangeFence(ctx, r); results <- err }()
		}
		success, conflicts := 0, 0
		for range 2 {
			switch err := <-results; {
			case err == nil:
				success++
			case errors.Is(err, pd.ErrConflict):
				conflicts++
			default:
				t.Fatal("concurrent rotate", err)
			}
		}
		epoch, version, revoked, found := dRecoveryFenceStored(t, db, f.history, identity)
		if success != 1 || conflicts != 1 || !found || epoch != 2 || version != 2 || revoked {
			t.Fatal("concurrent row", success, conflicts, epoch, version, revoked)
		}
	})
	t.Run("rollback_audit_guard_and_second_insert", func(t *testing.T) {
		db, _ := dProducerMySQLDB(t)
		f := newDIntegrationFixtureWithDB(t, db)
		a := &dRecoveryFenceMySQLAuthority{db: db, allow: true}
		m, err := pd.NewRecoveryFenceManager(db, f.history.Scope, a)
		mustSQL(t, err)
		identity := pd.Hash(strings.Repeat("e", 64))
		r := dRecoveryFenceRequest(f.history.Scope, identity)
		_, err = m.ChangeFence(ctx, r)
		mustSQL(t, err)
		r.Operation, r.ExpectedEpoch, r.ExpectedRowVersion = "rotate", "1", "1"
		before := dMySQLSnapshot(t, db)
		a.failAudit = true
		if _, err = m.ChangeFence(ctx, r); err == nil {
			t.Fatal("result audit accepted")
		}
		dMySQLUnchanged(t, db, before)
		a.failAudit, a.failRecheck = false, true
		if _, err = m.ChangeFence(ctx, r); !errors.Is(err, pd.ErrGuardRequired) {
			t.Fatal("final guard accepted", err)
		}
		dMySQLUnchanged(t, db, before)
		a.failRecheck = false
		next := pd.Hash(strings.Repeat("f", 64))
		r.NextIdentityHash = &next
		_, err = db.ExecContext(ctx, "CREATE TRIGGER reject_recovery_new_identity BEFORE INSERT ON system_backup_v2_producer_recovery_revocations FOR EACH ROW SET NEW.row_version = 0")
		mustSQL(t, err)
		if _, err = m.ChangeFence(ctx, r); err == nil {
			t.Fatal("second insert accepted")
		}
		dMySQLUnchanged(t, db, before)
		_, err = db.ExecContext(ctx, "DROP TRIGGER reject_recovery_new_identity")
		mustSQL(t, err)
		if _, err = m.ChangeFence(ctx, r); err != nil {
			t.Fatal("retry after rollback", err)
		}
	})
	t.Run("commit_ack_loss_never_returns_row", func(t *testing.T) {
		db, lost := dProducerMySQLDB(t)
		f := newDIntegrationFixtureWithDB(t, db)
		a := &dRecoveryFenceMySQLAuthority{db: db, allow: true}
		m, err := pd.NewRecoveryFenceManager(db, f.history.Scope, a)
		mustSQL(t, err)
		identity := pd.Hash(strings.Repeat("9", 64))
		r := dRecoveryFenceRequest(f.history.Scope, identity)
		lost.Store(true)
		row, err := m.ChangeFence(ctx, r)
		if !reflect.DeepEqual(row, pd.RecoveryFenceRow{}) || !errors.Is(err, pd.ErrCommitUnknown) {
			t.Fatal("unknown commit returned authority", row, err)
		}
		epoch, version, revoked, found := dRecoveryFenceStored(t, db, f.history, identity)
		if !found || epoch != 1 || version != 1 || revoked {
			t.Fatal("committed row not observable", epoch, version, revoked)
		}
		if retry, err := m.ChangeFence(ctx, r); !reflect.DeepEqual(retry, pd.RecoveryFenceRow{}) || !errors.Is(err, pd.ErrConflict) {
			t.Fatal("uncertain commit replay", retry, err)
		}
	})
}
