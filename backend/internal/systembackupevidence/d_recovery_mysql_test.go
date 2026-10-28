//go:build systembackup_mysql

package systembackupevidence

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// This is a D-only SQL fixture. A's original-row loader is real, while
// workload admission, capacity/audit policy and C Stat proof are synthetic.
type dRecoveryMySQLAuthority struct {
	f          *dIntegrationFixture
	identity   pd.Hash
	epoch      pd.Counter
	failAudit  bool
	match      bool
	authorized chan<- struct{}
}

func (a *dRecoveryMySQLAuthority) PrepareRecovery(ctx context.Context, _ pd.RecoveryRequest, op string, _ *pd.RecoveryFinishRequest) (pd.PreparedRecovery, error) {
	var now time.Time
	if err := a.f.db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
		return pd.PreparedRecovery{}, err
	}
	copy := *a
	p := pd.PreparedRecovery{Session: &copy}
	if op != "load" {
		p.CapacityObservedAt = &now
	}
	return p, nil
}
func (*dRecoveryMySQLAuthority) LockInstallation(context.Context, pd.SQL, pd.RecoveryRequest) error {
	return nil
}
func (a *dRecoveryMySQLAuthority) Authorize(ctx context.Context, tx pd.SQL, _ pd.RecoveryRequest, hash pd.Hash, _ string) (pd.RecoveryAdmission, error) {
	var now time.Time
	if err := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
		return pd.RecoveryAdmission{}, err
	}
	if a.authorized != nil {
		select {
		case a.authorized <- struct{}{}:
		default:
		}
	}
	return pd.RecoveryAdmission{VerifiedRequestHash: hash, IdentityHash: a.identity, RevocationEpoch: a.epoch, IdentityExpiresAt: systemExecutionStamp(now.Add(time.Minute)), DeploymentExpiresAt: systemExecutionStamp(now.Add(time.Minute)), StatAllowed: true, AdditionalCost: "0"}, nil
}
func (a *dRecoveryMySQLAuthority) LockReferences(ctx context.Context, tx pd.SQL, r pd.RecoveryRequest, _ pd.HistoricalBindingRecord) error {
	rows, err := tx.QueryContext(ctx, "SELECT reference_kind FROM system_backup_producer_evidence_refs WHERE evidence_id=? ORDER BY reference_kind FOR UPDATE", string(r.EvidenceID))
	if err != nil {
		return err
	}
	defer rows.Close()
	hold := false
	for rows.Next() {
		var kind string
		if err = rows.Scan(&kind); err != nil {
			return err
		}
		hold = hold || kind == "hold"
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if !hold {
		return pd.ErrGuardRequired
	}
	return nil
}
func (*dRecoveryMySQLAuthority) Reserve(_ context.Context, _ pd.SQL, _ pd.RecoveryRequest, cost uint64) error {
	if cost != 65536 {
		return pd.ErrInvalid
	}
	return nil
}
func (a *dRecoveryMySQLAuthority) Audit(ctx context.Context, tx pd.SQL, _ pd.RecoveryRequest, stage string) error {
	if stage != "result" {
		return nil
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO synthetic_guard_marker (n) VALUES (?)", 1); err != nil {
		return err
	}
	if a.failAudit {
		return pd.ErrUnavailable
	}
	return nil
}
func (a *dRecoveryMySQLAuthority) LockEvidence(ctx context.Context, tx pd.SQL, _ pd.RecoveryRequest, h pd.HistoricalBindingRecord) (pd.FinishEvidence, error) {
	owned, ok := tx.(*pd.Transaction)
	if !ok {
		return pd.FinishEvidence{}, pd.ErrGuardRequired
	}
	record, err := loadSystemHistoricalRecord(ctx, owned, h, a.f.channel)
	if err != nil {
		return pd.FinishEvidence{}, err
	}
	historyHash, err := pd.PendingHistoryHash(h)
	if err != nil {
		return pd.FinishEvidence{}, err
	}
	manifest := h.Evidence.ManifestHash
	row := pd.CallEvidence{EvidenceID: h.Evidence.EvidenceID, OwnerType: "system", OwnerID: h.Scope.Installation, EvidenceType: "capability_snapshot", State: record.State, RowVersion: pd.ZeroCounter(strconv.FormatInt(record.RowVersion, 10)), ManifestHash: &manifest}
	if record.Claim != "" {
		v := pd.ID(record.Claim)
		until := systemExecutionStamp(record.ClaimUntil)
		row.ClaimOwner = &v
		row.ClaimExpiresAt = &until
	}
	var version *pd.Text
	if record.Ref.ImmutableVersion != "" {
		v := pd.Text(record.Ref.ImmutableVersion)
		version = &v
	}
	return pd.FinishEvidence{ClaimEvidence: pd.ClaimEvidence{Evidence: row, HistoryHash: historyHash, RetentionExpiresAt: h.RetentionExpiresAt, ProtectedUntil: systemExecutionStamp(record.ProtectedUntil)}, ImmutableVersion: version, Failure: record.Failure}, nil
}
func (a *dRecoveryMySQLAuthority) VerifyStat(ctx context.Context, tx pd.SQL, _ pd.RecoveryRequest, _ pd.HistoricalBindingRecord, r pd.RecoveryFinishRequest) (pd.RecoveryStatAdmission, error) {
	var now time.Time
	if err := tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
		return pd.RecoveryStatAdmission{}, err
	}
	return pd.RecoveryStatAdmission{VerifiedProofHash: r.ProofHash, ProofExpiresAt: systemExecutionStamp(now.Add(time.Minute)), Matched: a.match}, nil
}
func (a *dRecoveryMySQLAuthority) Recheck(ctx context.Context, tx pd.ReadSQL, _ pd.RecoveryRequest, h pd.HistoricalBindingRecord, _ time.Time) error {
	return a.f.check(ctx, tx, &h)
}

func dRecoveryMySQLInstallIdentity(t *testing.T, db *sql.DB, h pd.HistoricalBindingRecord, identity pd.Hash) {
	t.Helper()
	row, err := pd.EncodeStoredRecord(&h)
	mustSQL(t, err)
	bytes, err := hex.DecodeString(string(identity))
	mustSQL(t, err)
	_, err = db.Exec("INSERT INTO system_backup_v2_producer_recovery_revocations (scope_key,workload_identity_hash,revocation_epoch,revoked_at,row_version,updated_at) VALUES (?,?,1,NULL,1,UTC_TIMESTAMP(6))", row.Columns["scope_key"], bytes)
	mustSQL(t, err)
}
func dRecoveryMySQLWaitCutoff(t *testing.T, db *sql.DB, cutoff pd.Timestamp) {
	t.Helper()
	deadline := time.Now().Add(25 * time.Second)
	want, err := cutoff.Time()
	mustSQL(t, err)
	for {
		var now time.Time
		mustSQL(t, db.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&now))
		if !now.Before(want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("owner cutoff wait exceeded")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestDHistoricalRecoveryMySQL(t *testing.T) {
	ctx := context.Background()
	t.Run("claim_revocation_and_evidence_only_finish", func(t *testing.T) {
		db, _ := dProducerMySQLDB(t)
		f := newDIntegrationFixtureWithDB(t, db, false, true)
		f.advance("pending")
		identity := pd.Hash(strings.Repeat("a", 64))
		dRecoveryMySQLInstallIdentity(t, db, f.history, identity)
		a := &dRecoveryMySQLAuthority{f: f, identity: identity, epoch: "1", match: false, failAudit: true}
		s, err := pd.NewHistoricalRecovery(db, f.history.Scope, a)
		mustSQL(t, err)
		var now time.Time
		mustSQL(t, db.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&now))
		r := pd.RecoveryRequest{Scope: f.history.Scope, EvidenceID: f.history.Evidence.EvidenceID, ExpectedEvidenceVersion: "1", Nonce: "mysql-recovery-claim-1", ClaimExpiresAt: systemExecutionStamp(now.Add(90 * time.Second)), BudgetUntil: systemExecutionStamp(now.Add(120 * time.Second))}
		before := dMySQLSnapshot(t, db)
		if _, err = s.ClaimRecovery(ctx, r); err == nil {
			t.Fatal("owner cutoff ignored")
		}
		dMySQLUnchanged(t, db, before)
		dRecoveryMySQLWaitCutoff(t, db, f.history.OwnerWriteExpiresAt)
		if _, err = s.ClaimRecovery(ctx, r); err == nil {
			t.Fatal("result audit failure accepted")
		}
		dMySQLUnchanged(t, db, before)
		a.failAudit = false
		var claim *pd.RecoveryClaim
		var failures int
		// Distinct nonces race for the same expected row version. Only one CAS
		// may commit; the other must observe conflict after the row lock.
		candidates := make(chan struct {
			c *pd.RecoveryClaim
			e error
		}, 2)
		for i := 0; i < 2; i++ {
			request := r
			if i == 1 {
				request.Nonce = "mysql-recovery-claim-2"
			}
			go func() {
				c, e := s.ClaimRecovery(ctx, request)
				candidates <- struct {
					c *pd.RecoveryClaim
					e error
				}{c, e}
			}()
		}
		for i := 0; i < 2; i++ {
			v := <-candidates
			if v.e == nil {
				if claim != nil {
					t.Fatal("two claims committed")
				}
				claim = v.c
			} else {
				failures++
			}
		}
		if claim == nil || failures != 1 {
			t.Fatal("concurrent claim convergence", failures)
		}
		var rowVersion int
		var owner sql.NullString
		mustSQL(t, db.QueryRow("SELECT row_version,claim_owner FROM system_backup_v2_evidence WHERE public_id=?", r.EvidenceID).Scan(&rowVersion, &owner))
		if rowVersion != 2 || !owner.Valid {
			t.Fatal("claim CAS absent")
		}
		_, err = db.Exec("UPDATE system_backup_v2_producer_recovery_revocations SET revocation_epoch=2,row_version=2,updated_at=UTC_TIMESTAMP(6)")
		mustSQL(t, err)
		a.epoch = "1"
		var proofNow time.Time
		mustSQL(t, db.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&proofNow))
		result := pd.RecoveryFinishRequest{State: "write_unknown", ProofHash: pd.Hash(strings.Repeat("b", 64)), ObjectHash: f.history.Evidence.ObjectHash, ObjectBytes: f.history.Evidence.ObjectBytes, ObservedAt: systemExecutionStamp(proofNow), BudgetUntil: systemExecutionStamp(proofNow.Add(20 * time.Second))}
		if _, err = s.FinishRecovery(ctx, claim, result); !errors.Is(err, pd.ErrGuardRequired) {
			t.Fatal("old revocation epoch accepted", err)
		}
		// The sole change from the preceding snapshot is the out-of-band
		// revocation epoch; denied finish must not touch evidence or audits.
		var afterEpochState, afterEpochOwner string
		mustSQL(t, db.QueryRow("SELECT storage_state,claim_owner FROM system_backup_v2_evidence WHERE public_id=?", r.EvidenceID).Scan(&afterEpochState, &afterEpochOwner))
		if afterEpochState != "pending" || afterEpochOwner != owner.String {
			t.Fatal("revoked finish changed evidence")
		}
		a.epoch = "2"
		finished, err := s.FinishRecovery(ctx, claim, result)
		mustSQL(t, err)
		if finished.State != "write_unknown" {
			t.Fatal("404/timeout not bounded unknown")
		}
		if _, err = s.FinishRecovery(ctx, claim, result); err == nil {
			t.Fatal("consumed claim reused")
		}
		r.ExpectedEvidenceVersion, r.Nonce = "3", "mysql-recovery-claim-3"
		claim, err = s.ClaimRecovery(ctx, r)
		mustSQL(t, err)
		var readyNow time.Time
		mustSQL(t, db.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&readyNow))
		version := pd.Text("Exact.Version/1")
		result.State, result.ImmutableVersion, result.ObservedAt, result.BudgetUntil = "ready", &version, systemExecutionStamp(readyNow), systemExecutionStamp(readyNow.Add(20*time.Second))
		a.match = true
		finished, err = s.FinishRecovery(ctx, claim, result)
		mustSQL(t, err)
		if finished.State != "ready" || finished.ImmutableVersion == nil || *finished.ImmutableVersion != version {
			t.Fatal("matched Stat did not converge evidence to ready")
		}
		var finalState, finalVersion string
		var finalRowVersion int
		mustSQL(t, db.QueryRow("SELECT storage_state,storage_immutable_version,row_version FROM system_backup_v2_evidence WHERE public_id=?", r.EvidenceID).Scan(&finalState, &finalVersion, &finalRowVersion))
		if finalState != "ready" || finalVersion != string(version) || finalRowVersion != 5 {
			t.Fatal("evidence-only convergence", finalState, finalVersion, finalRowVersion)
		}
		var history pd.HistoricalBindingRecord
		f.load("system_backup_producer_evidence_bindings", &history)
		if !reflect.DeepEqual(history, f.history) {
			t.Fatal("immutable history changed")
		}
	})
	t.Run("commit_ack_loss_has_no_claim", func(t *testing.T) {
		db, lost := dProducerMySQLDB(t)
		f := newDIntegrationFixtureWithDB(t, db, false, true)
		f.advance("pending")
		identity := pd.Hash(strings.Repeat("c", 64))
		dRecoveryMySQLInstallIdentity(t, db, f.history, identity)
		a := &dRecoveryMySQLAuthority{f: f, identity: identity, epoch: "1"}
		s, err := pd.NewHistoricalRecovery(db, f.history.Scope, a)
		mustSQL(t, err)
		dRecoveryMySQLWaitCutoff(t, db, f.history.OwnerWriteExpiresAt)
		var now time.Time
		mustSQL(t, db.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&now))
		r := pd.RecoveryRequest{Scope: f.history.Scope, EvidenceID: f.history.Evidence.EvidenceID, ExpectedEvidenceVersion: "1", Nonce: "mysql-recovery-unknown", ClaimExpiresAt: systemExecutionStamp(now.Add(time.Minute)), BudgetUntil: systemExecutionStamp(now.Add(90 * time.Second))}
		lost.Store(true)
		claim, err := s.ClaimRecovery(ctx, r)
		if claim != nil || !errors.Is(err, pd.ErrCommitUnknown) {
			t.Fatal("unknown commit yielded a claim", claim, err)
		}
		var version int
		mustSQL(t, db.QueryRow("SELECT row_version FROM system_backup_v2_evidence WHERE public_id=?", r.EvidenceID).Scan(&version))
		if version != 2 {
			t.Fatal("committed claim not observable after lost acknowledgement", version)
		}
		if retry, err := s.ClaimRecovery(ctx, r); retry != nil || err == nil {
			t.Fatal("unknown commit retried mutation", err)
		}
	})
}
