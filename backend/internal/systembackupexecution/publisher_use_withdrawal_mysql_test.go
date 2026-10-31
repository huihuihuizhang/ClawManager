package systembackupexecution

import (
	c "clawreef/internal/systembackupcontroller"
	"context"
	"database/sql"
	"testing"
	"time"
)

// Actual original SQL claim/receipt, original publisher factory and TLS Unwrap.
// The callback must not hold an SQL lock that prevents legitimate Release.
func TestAPublisherDEKUseAllowsRealClaimWithdrawal(t *testing.T) {
	x := newAPublisherVerifierFixture(t)
	h, ctx := x.history, context.Background()
	verifier, err := x.factory.ForPart(ctx, h.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Close()
	applied := false
	err = verifier.WithDEK(ctx, x.envelope, func(key []byte) error {
		if len(key) != 32 {
			t.Fatal("original DEK missing")
		}
		bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		next, releaseErr := (c.ClaimCoordinator{Executor: h.db, InstallationID: h.original.InstallationID}).Release(bounded, h.token, time.Second)
		if releaseErr != nil {
			t.Error("actual Release blocked during original DEK callback", releaseErr)
			return releaseErr
		}
		var owner sql.NullString
		var revision uint64
		if h.db.QueryRowContext(bounded, "SELECT controller_owner,row_version FROM system_backup_v2_backups WHERE public_id=?", h.original.TaskPublicID).Scan(&owner, &revision) != nil || owner.Valid || revision != next || revision <= h.token.RowVersion {
			t.Error("intended original SQL claim withdrawal did not occur")
			return c.ErrExecutionAuthority
		}
		applied = true
		return nil
	})
	if !applied {
		t.Fatal("test returned without actually withdrawing original SQL authority", err)
	}
	if err == nil {
		t.Fatal("DEK callback accepted after actual original claim withdrawal")
	}
}

// The inexpensive per-read permission check must not replace the final full
// authentication of immutable original encrypted history.
func TestAPublisherDEKUseReauthenticatesOriginalPlanAtFinalCheck(t *testing.T) {
	x := newAPublisherVerifierFixture(t)
	h, ctx := x.history, context.Background()
	verifier, err := x.factory.ForPart(ctx, h.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Close()
	applied := false
	err = verifier.WithDEK(ctx, x.envelope, func(key []byte) error {
		if len(key) != 32 {
			t.Fatal("original DEK missing")
		}
		changed, changeErr := h.admin.ExecContext(ctx, `UPDATE system_backup_v2_execution_records SET sealed_payload=CONCAT(sealed_payload,'x') WHERE origin_installation_id=? AND task_public_id=? AND attempt_no=? AND phase='capture' AND record_kind='plan'`, h.original.InstallationID, h.original.TaskPublicID, h.original.AttemptNo)
		if changeErr != nil {
			t.Error("original plan change blocked", changeErr)
			return changeErr
		}
		if count, changeErr := changed.RowsAffected(); changeErr != nil || count != 1 {
			t.Error("original plan fault did not change exactly one row")
			return c.ErrExecutionRecord
		}
		applied = true
		return nil
	})
	if !applied {
		t.Fatal("negative returned without changing original plan", err)
	}
	if err == nil {
		t.Fatal("final full original history check was skipped")
	}
}
