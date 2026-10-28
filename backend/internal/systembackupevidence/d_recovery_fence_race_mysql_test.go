//go:build systembackup_mysql

package systembackupevidence

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

func dRaceFenceAgainstRecovery(t *testing.T, manager *pd.RecoveryFenceManager, authority *dRecoveryFenceMySQLAuthority, change pd.RecoveryFenceRequest, recovery *dRecoveryMySQLAuthority, work func() error) error {
	t.Helper()
	locked := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unlock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unlock)
	authority.intentHook = func() {
		close(locked)
		<-release
	}
	managerResult := make(chan error, 1)
	go func() { _, err := manager.ChangeFence(context.Background(), change); managerResult <- err }()
	select {
	case <-locked:
	case <-time.After(8 * time.Second):
		t.Fatal("management transaction did not acquire fence lock")
	}
	authReached := make(chan struct{}, 1)
	recovery.authorized = authReached
	recoveryResult := make(chan error, 1)
	go func() { recoveryResult <- work() }()
	select {
	case <-authReached:
	case <-time.After(8 * time.Second):
		t.Fatal("recovery did not reach L2")
	}
	select {
	case err := <-recoveryResult:
		t.Fatal("recovery passed locked fence before management committed", err)
	case <-time.After(150 * time.Millisecond):
	}
	unlock()
	select {
	case err := <-managerResult:
		if err != nil {
			t.Fatal("management change", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("management change did not finish")
	}
	select {
	case err := <-recoveryResult:
		return err
	case <-time.After(8 * time.Second):
		t.Fatal("recovery did not resolve after management commit")
		return nil
	}
}

func dRecoveryEvidenceState(t *testing.T, db *sql.DB, evidence pd.EvidenceID) (string, int64, sql.NullString) {
	t.Helper()
	var state string
	var version int64
	var owner sql.NullString
	mustSQL(t, db.QueryRow("SELECT storage_state,row_version,claim_owner FROM system_backup_v2_evidence WHERE public_id=?", string(evidence)).Scan(&state, &version, &owner))
	return state, version, owner
}

func TestDRecoveryFenceRecoveryRaceMySQL(t *testing.T) {
	ctx := context.Background()
	t.Run("rotate_blocks_old_epoch_claim", func(t *testing.T) {
		db, _ := dProducerMySQLDB(t)
		f := newDIntegrationFixtureWithDB(t, db, false, true)
		f.advance("pending")
		identity := pd.Hash(strings.Repeat("7", 64))
		management := &dRecoveryFenceMySQLAuthority{db: db, allow: true}
		manager, err := pd.NewRecoveryFenceManager(db, f.history.Scope, management)
		mustSQL(t, err)
		change := dRecoveryFenceRequest(f.history.Scope, identity)
		_, err = manager.ChangeFence(ctx, change)
		mustSQL(t, err)
		recovery := &dRecoveryMySQLAuthority{f: f, identity: identity, epoch: "1"}
		service, err := pd.NewHistoricalRecovery(db, f.history.Scope, recovery)
		mustSQL(t, err)
		dRecoveryMySQLWaitCutoff(t, db, f.history.OwnerWriteExpiresAt)
		var now time.Time
		mustSQL(t, db.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&now))
		request := pd.RecoveryRequest{Scope: f.history.Scope, EvidenceID: f.history.Evidence.EvidenceID, ExpectedEvidenceVersion: "1", Nonce: "fence-race-claim", ClaimExpiresAt: systemExecutionStamp(now.Add(90 * time.Second)), BudgetUntil: systemExecutionStamp(now.Add(120 * time.Second))}
		beforeState, beforeVersion, beforeOwner := dRecoveryEvidenceState(t, db, request.EvidenceID)
		change.Operation, change.ExpectedEpoch, change.ExpectedRowVersion = "rotate", "1", "1"
		err = dRaceFenceAgainstRecovery(t, manager, management, change, recovery, func() error {
			_, err := service.ClaimRecovery(ctx, request)
			return err
		})
		if !errors.Is(err, pd.ErrGuardRequired) {
			t.Fatal("old-epoch claim not fenced", err)
		}
		state, version, owner := dRecoveryEvidenceState(t, db, request.EvidenceID)
		if state != beforeState || version != beforeVersion || owner != beforeOwner {
			t.Fatal("fenced claim changed evidence", state, version, owner)
		}
		epoch, rowVersion, revoked, found := dRecoveryFenceStored(t, db, f.history, identity)
		if !found || epoch != 2 || rowVersion != 2 || revoked {
			t.Fatal("rotation not committed", epoch, rowVersion, revoked)
		}
	})
	t.Run("revoke_blocks_old_epoch_finish", func(t *testing.T) {
		db, _ := dProducerMySQLDB(t)
		f := newDIntegrationFixtureWithDB(t, db, false, true)
		f.advance("pending")
		identity := pd.Hash(strings.Repeat("8", 64))
		management := &dRecoveryFenceMySQLAuthority{db: db, allow: true}
		manager, err := pd.NewRecoveryFenceManager(db, f.history.Scope, management)
		mustSQL(t, err)
		change := dRecoveryFenceRequest(f.history.Scope, identity)
		_, err = manager.ChangeFence(ctx, change)
		mustSQL(t, err)
		recovery := &dRecoveryMySQLAuthority{f: f, identity: identity, epoch: "1"}
		service, err := pd.NewHistoricalRecovery(db, f.history.Scope, recovery)
		mustSQL(t, err)
		dRecoveryMySQLWaitCutoff(t, db, f.history.OwnerWriteExpiresAt)
		var now time.Time
		mustSQL(t, db.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&now))
		request := pd.RecoveryRequest{Scope: f.history.Scope, EvidenceID: f.history.Evidence.EvidenceID, ExpectedEvidenceVersion: "1", Nonce: "fence-race-finish", ClaimExpiresAt: systemExecutionStamp(now.Add(90 * time.Second)), BudgetUntil: systemExecutionStamp(now.Add(120 * time.Second))}
		claim, err := service.ClaimRecovery(ctx, request)
		mustSQL(t, err)
		beforeState, beforeVersion, beforeOwner := dRecoveryEvidenceState(t, db, request.EvidenceID)
		if !beforeOwner.Valid {
			t.Fatal("precondition claim missing")
		}
		var observed time.Time
		mustSQL(t, db.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&observed))
		result := pd.RecoveryFinishRequest{State: "write_unknown", ProofHash: pd.Hash(strings.Repeat("b", 64)), ObjectHash: f.history.Evidence.ObjectHash, ObjectBytes: f.history.Evidence.ObjectBytes, ObservedAt: systemExecutionStamp(observed), BudgetUntil: systemExecutionStamp(observed.Add(30 * time.Second))}
		change.Operation, change.ExpectedEpoch, change.ExpectedRowVersion = "revoke", "1", "1"
		err = dRaceFenceAgainstRecovery(t, manager, management, change, recovery, func() error {
			_, err := service.FinishRecovery(ctx, claim, result)
			return err
		})
		if !errors.Is(err, pd.ErrGuardRequired) {
			t.Fatal("old-epoch finish not fenced", err)
		}
		state, version, owner := dRecoveryEvidenceState(t, db, request.EvidenceID)
		if state != beforeState || version != beforeVersion || owner != beforeOwner {
			t.Fatal("fenced finish changed evidence", state, version, owner)
		}
		epoch, rowVersion, revoked, found := dRecoveryFenceStored(t, db, f.history, identity)
		if !found || epoch != 2 || rowVersion != 2 || !revoked {
			t.Fatal("revoke not committed", epoch, rowVersion, revoked)
		}
	})
}
