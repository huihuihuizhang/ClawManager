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
