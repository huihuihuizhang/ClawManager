//go:build systembackup_mysql

package systembackupevidence

import (
	"context"
	"database/sql"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

type historicalDeploymentTx struct{ *sql.Tx }

func (historicalDeploymentTx) LockRecord(context.Context, pd.RecordKey, any) (*pd.LockedRecord, error) {
	return nil, ErrDenied
}

// This uses the candidate DDL in a run-owned database. It validates A's real
// L0/L1a reads and final readback, not a production recovery authority.
func TestSystemHistoricalDeploymentGuardMySQL(t *testing.T) {
	db, _ := dProducerMySQLDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	scope := pd.Scope{ServerUUID: "11111111-2222-4333-8444-555555555555", Database: "synthetic", Installation: "installation_historical_deployment"}
	digest := func(c string) string { return strings.Repeat(c, 64) }
	decode := func(s string) []byte {
		v, err := hex.DecodeString(s)
		mustSQL(t, err)
		return v
	}
	profile, manager := digest("1"), digest("2")
	facts := SystemPeerFacts{Scope: scope, WorkloadIdentityHash: digest("a"), IssuerIdentityHash: digest("b"),
		SubjectHash: digest("c"), ActorIdentityHash: digest("d"), AdmissionHash: digest("e"),
		ClientCASHA256: digest("f"), CertificateSHA256: digest("0")}
	var now time.Time
	mustSQL(t, db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now))
	until := now.Add(time.Minute)
	facts.ExpiresAt = until
	key, err := pd.RecoveryScopeKey(scope)
	mustSQL(t, err)
	newGuard := func() *SystemHistoricalDeploymentGuard {
		g, err := NewSystemHistoricalDeploymentGuard(scope, profile, manager)
		mustSQL(t, err)
		return g
	}

	missingTx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	mustSQL(t, err)
	if err := newGuard().Lock(ctx, historicalDeploymentTx{missingTx}); err != ErrDenied {
		t.Fatalf("missing installation admitted: %v", err)
	}
	mustSQL(t, missingTx.Rollback())
	_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_installation_state
(origin_installation_id,active_config_version,last_effective_enabled_transition_at,matrix_key)
VALUES (?,1,UTC_TIMESTAMP(6),'k8s-cluster')`, string(scope.Installation))
	mustSQL(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_recovery_deployments
(scope_key,origin_installation_id,workload_identity_hash,issuer_identity_hash,subject_hash,management_issuer_identity_hash,actor_identity_hash,admission_hash,client_ca_sha256,certificate_sha256,stat_profile_hash,enabled,deployment_epoch,authorized_until,row_version)
VALUES (?,?,?,?,?,?,?,?,?,?,?,TRUE,1,?,1)`, key, string(scope.Installation),
		decode(facts.WorkloadIdentityHash), decode(facts.IssuerIdentityHash), decode(facts.SubjectHash), decode(manager),
		decode(facts.ActorIdentityHash), decode(facts.AdmissionHash), decode(facts.ClientCASHA256),
		decode(facts.CertificateSHA256), decode(profile), until)
	mustSQL(t, err)
	admission := pd.RecoveryAdmission{IdentityHash: pd.Hash(facts.WorkloadIdentityHash), RevocationEpoch: "1",
		IdentityExpiresAt: systemExecutionStamp(until), DeploymentExpiresAt: systemExecutionStamp(until), StatAllowed: true}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	mustSQL(t, err)
	defer tx.Rollback()
	guard := newGuard()
	if err := guard.Lock(ctx, historicalDeploymentTx{tx}); err != nil {
		t.Fatal("current deployment L0/L1a lock:", err)
	}
	if err := guard.Admit(facts, admission, now); err != nil {
		t.Fatal("matching current deployment rejected:", err)
	}
	if err := guard.Recheck(ctx, historicalDeploymentTx{tx}, facts, admission, now); err != nil {
		t.Fatal("unchanged deployment final readback:", err)
	}
	badFacts := facts
	badFacts.CertificateSHA256 = digest("3")
	if err := guard.Admit(badFacts, admission, now); err != ErrDenied {
		t.Fatalf("changed certificate accepted: %v", err)
	}
	badAdmission := admission
	badAdmission.RevocationEpoch = "2"
	if err := guard.Admit(facts, badAdmission, now); err != ErrDenied {
		t.Fatalf("changed L2 epoch accepted: %v", err)
	}
	_, err = tx.ExecContext(ctx, "UPDATE system_backup_v2_recovery_deployments SET row_version=2 WHERE scope_key=?", key)
	mustSQL(t, err)
	if err := guard.Recheck(ctx, historicalDeploymentTx{tx}, facts, admission, now); err != ErrDenied {
		t.Fatalf("changed deployment version accepted: %v", err)
	}
	mustSQL(t, tx.Rollback())
	var version int64
	mustSQL(t, db.QueryRowContext(ctx, "SELECT row_version FROM system_backup_v2_recovery_deployments WHERE scope_key=?", key).Scan(&version))
	if version != 1 {
		t.Fatalf("guard failure committed drift: version=%d", version)
	}
	_, err = db.ExecContext(ctx, `INSERT INTO system_backup_v2_producer_recovery_revocations
(scope_key,workload_identity_hash,revocation_epoch,revoked_at,row_version,updated_at)
VALUES (?,?,1,NULL,1,UTC_TIMESTAMP(6))`, key, decode(facts.WorkloadIdentityHash))
	mustSQL(t, err)
	// Exercise the non-test authority adapter against the same real L0/L1a
	// rows and D's locked L2 row. The delegated D/C policy remains a fixture.
	inner := &deploymentBoundInnerSession{admission: admission}
	authority := &historicalAuthorityFixture{session: inner, channel: ProducerEvidenceChannel{
		Root: "evidence", Store: KeyRef{Identity: digest("a"), Version: "store-v1"},
		Write: KeyRef{Identity: digest("b"), Version: "write-v1"}, RecoveryProfileHash: profile,
	}}
	bound, err := NewSystemDeploymentBoundHistoricalAuthority(authority, manager)
	mustSQL(t, err)
	r := pd.RecoveryRequest{Scope: scope, EvidenceID: "sev_11111111-2222-4333-8444-555555555555"}
	session, _, _, err := bound.PrepareHistoricalAuthority(ctx, r, "load", nil)
	mustSQL(t, err)
	boundTx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	mustSQL(t, err)
	defer boundTx.Rollback()
	if err := session.LockInstallation(ctx, historicalDeploymentTx{boundTx}, r); err != nil {
		t.Fatal("bound authority could not lock current deployment:", err)
	}
	admitted, err := session.Authorize(ctx, historicalDeploymentTx{boundTx}, r, pd.Hash(digest("4")), "load", facts, "binding")
	if err != nil {
		t.Fatal("bound authority rejected current deployment:", err)
	}
	var l2Epoch, l2Version int64
	var revoked sql.NullTime
	mustSQL(t, boundTx.QueryRowContext(ctx, systemHistoricalRevocationSelect+" FOR UPDATE", key, decode(facts.WorkloadIdentityHash)).Scan(&l2Epoch, &revoked, &l2Version))
	if l2Epoch != 1 || l2Version != 1 || revoked.Valid {
		t.Fatal("D L2 lock fixture is not current")
	}
	h := pd.HistoricalBindingRecord{Scope: scope}
	if err := session.LockReferences(ctx, historicalDeploymentTx{boundTx}, r, h); err != nil {
		t.Fatal("bound authority rejected D's current L2 row:", err)
	}
	if err := session.Recheck(ctx, historicalDeploymentTx{boundTx}, r, h, admitted, now); err != nil || !inner.checked {
		t.Fatal("bound authority skipped current deployment or delegated final guard:", err)
	}
	_, err = boundTx.ExecContext(ctx, "UPDATE system_backup_v2_producer_recovery_revocations SET row_version=2 WHERE scope_key=? AND workload_identity_hash=?", key, decode(facts.WorkloadIdentityHash))
	mustSQL(t, err)
	if err := session.Recheck(ctx, historicalDeploymentTx{boundTx}, r, h, admitted, now); err != ErrDenied {
		t.Fatalf("changed L2 row version accepted by final guard: %v", err)
	}
	mustSQL(t, boundTx.Rollback())
	_, err = db.ExecContext(ctx, "UPDATE system_backup_v2_recovery_deployments SET enabled=FALSE WHERE scope_key=?", key)
	mustSQL(t, err)
	disabledTx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	mustSQL(t, err)
	defer disabledTx.Rollback()
	if err := newGuard().Lock(ctx, historicalDeploymentTx{disabledTx}); err != ErrDenied {
		t.Fatalf("disabled current deployment admitted: %v", err)
	}
}
