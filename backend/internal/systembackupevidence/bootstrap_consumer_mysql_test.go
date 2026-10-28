//go:build systembackup_mysql

package systembackupevidence

// This probe exercises real InnoDB and the real A service/D consumer. Deployment,
// purpose mapping, provider observations and capacity are explicitly synthetic.
// It accepts only the existing fresh-migration namespace marker, never a DSN.

import (
	"bytes"
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

//go:embed testdata/bootstrap-consumer-mysql-inputs.json
var bootstrapConsumerMySQLInputs []byte

type bootstrapMySQLCapsule struct {
	Kind       string          `json:"kind"`
	Production bool            `json:"production_approved"`
	Migrations []string        `json:"migrations"`
	Catalog    string          `json:"migration_catalog_sha256"`
	DDL        string          `json:"candidate_ddl"`
	DDLSHA     string          `json:"candidate_ddl_sha256"`
	Vectors    string          `json:"producer_vectors"`
	Examples   string          `json:"evidence_examples"`
	Config     json.RawMessage `json:"config"`
}

func bootstrapMySQLInput(t *testing.T) bootstrapMySQLCapsule {
	t.Helper()
	var c bootstrapMySQLCapsule
	mustSQL(t, json.Unmarshal(bootstrapConsumerMySQLInputs, &c))
	if c.Kind != "d_bootstrap_consumer_mysql_synthetic_inputs.v1" || c.Production || len(c.Migrations) != 96 || c.Catalog != "0a2fc9ee709ffe6935679ed0923414f0607b2d34bf55ba615e7f431f8411bffe" || hash([]byte(c.DDL)) != c.DDLSHA || strings.Count(c.DDL, "CREATE TABLE ") != 8 {
		t.Fatal("pinned synthetic capsule differs")
	}
	return c
}

// Establish the compatible config digest profile BEFORE acquiring the original
// producer grant. No committed record or historical request is reinterpreted.
// The original published vectors are unchanged; only this owned runtime copy
// selects a synthetic disabled-config profile for a NEW producer lifecycle.
func bootstrapMySQLProfile(t *testing.T, capsule bootstrapMySQLCapsule) sec.BootstrapConfig {
	t.Helper()
	c, err := sec.DecodeBootstrapConfig(capsule.Config)
	mustSQL(t, err)
	var fields map[string]json.RawMessage
	mustSQL(t, json.Unmarshal(c.CanonicalJSON(), &fields))
	var tree any
	mustSQL(t, json.Unmarshal([]byte(capsule.Vectors), &tree))
	var patch func(any)
	patch = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if x["scenario"] == "unconfigured" {
				x["candidate_hash"], x["registry_set_hash"], x["ref_set_hash"] = c.SHA256(), hash(fields["registries"]), hash(fields["references"])
			}
			for _, child := range x {
				patch(child)
			}
		case []any:
			for _, child := range x {
				patch(child)
			}
		}
	}
	patch(tree)
	vector, err := json.Marshal(tree)
	mustSQL(t, err)
	root := t.TempDir()
	fixtures := filepath.Join(root, "contracts", "system-backup", "v12")
	cwd := filepath.Join(root, "a", "b", "c")
	mustSQL(t, os.MkdirAll(fixtures, 0700))
	mustSQL(t, os.MkdirAll(cwd, 0700))
	mustSQL(t, os.WriteFile(filepath.Join(fixtures, "producer-authority-vectors.json"), vector, 0600))
	mustSQL(t, os.WriteFile(filepath.Join(fixtures, "a-owned-redacted-examples.json"), []byte(capsule.Examples), 0600))
	t.Chdir(cwd)
	return c
}

type bootstrapMySQLAuthority struct {
	f                *dIntegrationFixture
	g                sec.OfflineBootstrapGrant
	c                sec.BootstrapConfig
	selection        []pd.BootstrapCandidateSelection
	original         systemPublicationOriginal
	until            time.Time
	deny             bool
	late             string
	capacity         *sec.BootstrapCandidateCapacity
	reportFile       string
	capacityMode     string
	preparedCapacity *sec.PreparedBootstrapCandidateCapacity
	reservation      *sec.BootstrapCandidateCapacityReservation
	priorReserved    int64
}

func (a *bootstrapMySQLAuthority) PrepareBootstrapCandidates(ctx context.Context, g sec.OfflineBootstrapGrant, c sec.BootstrapConfig, r pd.BootstrapConsumptionRequest) (sec.PreparedBootstrapCandidateAuthority, error) {
	if ctx.Err() != nil || a.deny || g != a.g || !bytes.Equal(c.CanonicalJSON(), a.c.CanonicalJSON()) || !reflect.DeepEqual(r.Candidates, a.selection) {
		return sec.PreparedBootstrapCandidateAuthority{}, pd.ErrGuardRequired
	}
	// The named synthetic collector supplies a NEW physical report before locks.
	// Never refresh the original producer observation or a report after BEGIN.
	if a.capacityMode == "missing" {
		if err := os.Remove(a.reportFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return sec.PreparedBootstrapCandidateAuthority{}, err
		}
	} else {
		sample := time.Now().UTC().Truncate(time.Microsecond)
		if a.capacityMode == "stale" {
			sample = sample.Add(-6 * time.Second)
		}
		report := sec.CapacityReport{ServerUUID: g.ServerUUID, Database: g.Database, ObservedAt: sample, AllocatedBytes: 0, AvailableBytes: 1 << 42}
		raw, err := json.Marshal(report)
		if err != nil {
			return sec.PreparedBootstrapCandidateAuthority{}, err
		}
		if err = os.WriteFile(a.reportFile, raw, 0600); err != nil {
			return sec.PreparedBootstrapCandidateAuthority{}, err
		}
	}
	prepared, err := a.capacity.PrepareAttempt(ctx, g, c)
	if err != nil {
		return sec.PreparedBootstrapCandidateAuthority{}, err
	}
	session := *a
	session.preparedCapacity, session.reservation = prepared, nil
	return sec.PreparedBootstrapCandidateAuthority{Session: &session, CapacityObservedAt: prepared.CapacityObservedAt()}, nil
}
func (a *bootstrapMySQLAuthority) Authorize(ctx context.Context, tx pd.BootstrapSQL, r pd.BootstrapConsumptionRequest, d pd.DomainRecord, now time.Time) (pd.BootstrapConsumptionAdmission, error) {
	if a.deny || !now.Before(a.until) || d.Admission.Unconfigured == nil || !reflect.DeepEqual(d.Admission, a.f.resultRequest.Admission) {
		return pd.BootstrapConsumptionAdmission{}, pd.ErrGuardRequired
	}
	h, err := pd.BootstrapConsumptionHash(r)
	if err != nil {
		return pd.BootstrapConsumptionAdmission{}, err
	}
	return pd.BootstrapConsumptionAdmission{BindingHash: h, IdentityExpiresAt: systemExecutionStamp(a.until), DependencyExpiresAt: systemExecutionStamp(a.until)}, nil
}
func (*bootstrapMySQLAuthority) LockHosts(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) error {
	return nil
}
func (*bootstrapMySQLAuthority) LockReferences(context.Context, pd.BootstrapSQL, pd.BootstrapConsumptionRequest, pd.BootstrapConsumptionFacts) error {
	return nil
}
func (a *bootstrapMySQLAuthority) Reserve(ctx context.Context, tx pd.BootstrapSQL, _ pd.BootstrapConsumptionRequest, _ pd.BootstrapConsumptionFacts) error {
	if a.preparedCapacity == nil {
		return pd.ErrGuardRequired
	}
	var err error
	a.reservation, err = a.preparedCapacity.Reserve(ctx, tx)
	if err != nil {
		return err
	}
	a.f.t.Log("BOOTSTRAP_CAPACITY_RESERVED helper=real_sql charge=73728 physical_report=synthetic")
	_, err = tx.ExecContext(ctx, "INSERT INTO synthetic_guard_marker (n) VALUES (99)")
	if err == nil && (a.late == "deadline_wait" || a.late == "capacity_wait") {
		var waited int
		seconds := 2.2
		if a.late == "capacity_wait" {
			seconds = 5.2
		}
		err = tx.QueryRowContext(ctx, "SELECT SLEEP(?)", seconds).Scan(&waited)
		if err == nil && waited != 0 {
			return pd.ErrGuardRequired
		}
	}
	if err != nil {
		return err
	}
	if a.reservation == nil {
		return pd.ErrGuardRequired
	}
	return a.reservation.Recheck(ctx, tx)
}
func (a *bootstrapMySQLAuthority) LockEvidence(ctx context.Context, tx pd.BootstrapSQL, _ pd.BootstrapConsumptionRequest, facts pd.BootstrapConsumptionFacts) ([]pd.ResultEvidence, error) {
	if len(facts.Candidates) != 1 {
		return nil, pd.ErrGuardRequired
	}
	r := a.original.copyRecord()
	b := a.f.resultRequest.Evidence
	row, found, err := loadSystemPublication(ctx, tx, r, string(*b.ImmutableVersion))
	if err != nil || !found || row.Claim.Valid || row.ClaimUntil.Valid {
		return nil, pd.ErrGuardRequired
	}
	r.State, r.Failure, r.RowVersion, r.Ref.ImmutableVersion = row.State, row.Failure, row.Version, string(*b.ImmutableVersion)
	if MatchProducerBinding(r, a.f.channel, b) != nil {
		return nil, pd.ErrGuardRequired
	}
	return []pd.ResultEvidence{{Evidence: b, RowVersion: pd.Counter(strconv.FormatInt(row.Version, 10)), State: row.State, Failure: row.Failure, RetentionExpiresAt: systemPublicationTimestamp(r.ExpiresAt), ProtectedUntil: systemPublicationTimestamp(r.ProtectedUntil)}}, nil
}
func (a *bootstrapMySQLAuthority) Recheck(ctx context.Context, tx pd.BootstrapReadSQL, _ pd.BootstrapConsumptionRequest, facts pd.BootstrapConsumptionFacts, _ time.Time) error {
	now, err := tx.SampleTime(ctx)
	if err != nil {
		return err
	}
	if a.deny || !now.Before(a.until) {
		return pd.ErrGuardRequired
	}
	if facts.Replayed {
		return nil
	}
	// A retained write capability is closed before Recheck. This deliberately
	// privileged, owned-schema function supplies a hostile SQL side effect through
	// SELECT instead. Verify the mutation really reached MySQL before requiring
	// the fixed independent A/D readback to reject it; SQL rejection is not proof.
	if strings.HasPrefix(a.late, "late_") {
		var changed int
		err = tx.QueryRowContext(ctx, "SELECT bootstrap_mutate()").Scan(&changed)
		if err != nil || changed != 1 {
			a.f.t.Fatal("hostile fixture mutation was not stored", a.late, changed, err)
		}
		a.f.t.Log("BOOTSTRAP_MUTATION_STORED kind=" + a.late + " rows=1")
	}
	if err != nil {
		return err
	}
	if a.reservation == nil {
		return pd.ErrGuardRequired
	}
	return a.reservation.Recheck(ctx, tx)
}

func bootstrapMySQLPlan(t *testing.T, f *dIntegrationFixture, c sec.BootstrapConfig) (sec.ConfigBootstrapService, *bootstrapMySQLAuthority) {
	t.Helper()
	g := sec.OfflineBootstrapGrant{InstallationID: string(f.command.Scope.Installation), ServerUUID: string(f.command.Scope.ServerUUID), Database: string(f.command.Scope.Database), Username: "bootstrap-probe", UserID: 42, MatrixKey: "k8s-cluster", ConfigSHA256: c.SHA256(), IdempotencyKey: "bootstrap-mysql-fixed-key-0001", ChangeReason: "synthetic isolated consumer transaction probe"}
	digests, err := pd.ResultHashes(f.resultRequest)
	mustSQL(t, err)
	var ref sec.BootstrapSecretRef
	for _, r := range c.References() {
		if r.Purpose == "artifact_write" {
			ref = r
		}
	}
	if ref.IdentityHash == "" {
		t.Fatal("missing fixed purpose mapping")
	}
	selections := []pd.BootstrapCandidateSelection{{Purpose: ref.Purpose, ReferenceIdentityHash: pd.Hash(ref.IdentityHash), ReferenceVersion: pd.RefVersion(ref.Version), MappingHash: digests.Target, Request: f.resultRequest, ResultVersion: "1"}}
	original, err := newSystemPublicationOriginal(f.prepared, f.channel, f.history)
	mustSQL(t, err)
	a := &bootstrapMySQLAuthority{f: f, g: g, c: c, selection: selections, original: original, until: f.until}
	a.reportFile = filepath.Join(t.TempDir(), "synthetic-capacity.json")
	a.capacity, err = sec.NewBootstrapCandidateCapacity(sec.DatabaseIdentity{ServerUUID: g.ServerUUID, Database: g.Database}, a.reportFile)
	mustSQL(t, err)
	plan, err := sec.NewConfigBootstrapCandidates(f.db, g, c.CanonicalJSON(), selections, a)
	mustSQL(t, err)
	return sec.ConfigBootstrapService{DB: f.db, Candidates: plan}, a
}

func TestDBootstrapConsumerMySQLSeed(t *testing.T) {
	capsule := bootstrapMySQLInput(t)
	c := bootstrapMySQLProfile(t, capsule)
	// Match the real-SQL fixture's short owner-write window locally, including
	// the original guard's rejection of a claim that extends that cutoff.
	f := newDIntegrationFixtureWithDB(t, nil, false, true)
	f.advance("pending")
	claim := f.claimRequest
	f.claimRequest.ExpiresAt = systemExecutionStamp(f.d.now.Add(45 * time.Second))
	if err := f.step("claim"); !errors.Is(err, pd.ErrExpired) {
		t.Fatal("claim beyond original owner-write cutoff accepted", err)
	}
	f.claimRequest = claim
	f.advance("claim", "finish", "result")
	_, a := bootstrapMySQLPlan(t, f, c)
	if a.original.record.Manifest.Identity.ID != string(f.resultRequest.Evidence.EvidenceID) || len(a.original.record.Manifest.Chunks) != 1 {
		t.Fatal("real manifest fixture missing")
	}
	sample := time.Now().UTC().Truncate(time.Microsecond)
	report, err := json.Marshal(sec.CapacityReport{ServerUUID: a.g.ServerUUID, Database: a.g.Database, ObservedAt: sample, AllocatedBytes: 0, AvailableBytes: 1 << 42})
	mustSQL(t, err)
	mustSQL(t, os.WriteFile(a.reportFile, report, 0600))
	prepared, err := a.capacity.PrepareAttempt(context.Background(), a.g, c)
	mustSQL(t, err)
	if prepared.CapacityObservedAt() == nil || !prepared.ObservedAt().Equal(sample) {
		t.Fatal("concrete capacity report preparation failed")
	}
	t.Log("PASS bootstrap-consumer-mysql-seed original_compatible_lifecycle=yes complete_manifest=yes capacity_report_prepare=real_helper migrations=96 candidate_tables=8 actual_mysql=not_run synthetic_authority=yes production=no")
}

func bootstrapMySQLFixture(t *testing.T, beforeC1 ...func(*sql.DB, sec.BootstrapConfig)) (sec.ConfigBootstrapService, *bootstrapMySQLAuthority, *atomic.Bool) {
	t.Helper()
	capsule := bootstrapMySQLInput(t)
	input, err := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	mustSQL(t, err)
	if !bytes.Equal(input, bootstrapConsumerMySQLInputs) || hash(input) != os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256") {
		t.Fatal("compiled capsule identity mismatch")
	}
	ddl := filepath.Join(t.TempDir(), "candidate.sql")
	mustSQL(t, os.WriteFile(ddl, []byte(capsule.DDL), 0600))
	t.Setenv("D_PROVIDER_REGISTRATION_DDL", ddl)
	t.Setenv("D_PROVIDER_REGISTRATION_DDL_SHA256", capsule.DDLSHA)
	c := bootstrapMySQLProfile(t, capsule)
	db, lost := dProducerMySQLDB(t, func(db *sql.DB) {
		bootstrapMySQLCanonicalA(t, db, capsule)
		for _, initialize := range beforeC1 {
			initialize(db, c)
		}
	})
	t.Log("BOOTSTRAP_FIXTURE migrations=96 candidate_tables=8 full_canonical_A_tables=8 clone=SHOW_CREATE_TABLE foreign_key_checks=required capacity_helper=real_sql synthetic_authority=yes")
	f := newDIntegrationFixtureWithDB(t, db, false, true)
	f.advance("pending", "claim", "finish", "result")
	dMySQLReceipt(t, f)
	svc, a := bootstrapMySQLPlan(t, f, c)
	return svc, a, lost
}

func bootstrapMySQLCanonicalA(t *testing.T, db *sql.DB, capsule bootstrapMySQLCapsule) {
	t.Helper()
	var checks int
	mustSQL(t, db.QueryRow("SELECT @@session.foreign_key_checks").Scan(&checks))
	if checks != 1 {
		t.Fatal("real FK checks required")
	}
	// Copy the FULL 96-migration A schema, including real FKs and newer columns.
	rows, err := db.Query("SELECT filename FROM clawmanager.schema_migrations ORDER BY filename")
	mustSQL(t, err)
	var actual []string
	for rows.Next() {
		var s string
		mustSQL(t, rows.Scan(&s))
		actual = append(actual, s)
	}
	mustSQL(t, rows.Err())
	mustSQL(t, rows.Close())
	if !reflect.DeepEqual(actual, capsule.Migrations) {
		t.Fatal("formal migration ledger differs")
	}
	for _, name := range []string{"users", "audit_logs", "system_backup_v2_evidence", "system_backup_v2_evidence_chunks", "system_backup_v2_configs", "system_backup_v2_installation_state", "system_backup_v2_operations", "system_backup_v2_metadata_reservations"} {
		var got, create string
		mustSQL(t, db.QueryRow("SHOW CREATE TABLE clawmanager."+name).Scan(&got, &create))
		if got != name || !strings.HasPrefix(create, "CREATE TABLE `"+name+"`") {
			t.Fatal("canonical table identity differs")
		}
		_, err = db.Exec(create)
		mustSQL(t, err)
	}
	_, err = db.Exec("INSERT INTO users (id,username,email,password_hash,role,is_active,auth_provider) VALUES (42,'bootstrap-probe','bootstrap-probe@example.invalid','synthetic-noncredential','admin',TRUE,'local')")
	mustSQL(t, err)
}

func bootstrapMySQLCall(svc sec.ConfigBootstrapService, a *bootstrapMySQLAuthority) (sec.ConfigBootstrapResult, error) {
	return svc.Bootstrap(context.Background(), a.g, a.c.CanonicalJSON())
}

// Keep each real SQL wait below the connector read timeout. Observe expiry from
// MySQL itself; the host clock never establishes a successful expired retry.
func bootstrapMySQLWaitUntil(t *testing.T, db *sql.DB, until time.Time) {
	t.Helper()
	for {
		var now time.Time
		mustSQL(t, db.QueryRow("SELECT UTC_TIMESTAMP(6)").Scan(&now))
		if !now.Before(until) {
			return
		}
		seconds := until.Sub(now).Seconds() + 0.02
		if seconds > 5 {
			seconds = 5
		}
		var waited int
		mustSQL(t, db.QueryRow("SELECT SLEEP(?)", seconds).Scan(&waited))
		if waited != 0 {
			t.Fatal("SQL expiry wait interrupted")
		}
	}
}

func bootstrapMySQLCommitted(t *testing.T, a *bootstrapMySQLAuthority) {
	t.Helper()
	var d pd.DomainRecord
	a.f.load("system_backup_producer_domains", &d)
	if d.State != "closed" || d.Epoch != "2" || d.RowVersion != "2" {
		t.Fatal("domain not consumed once", d.State, d.Epoch, d.RowVersion)
	}
	var version int
	var enabled bool
	var config string
	mustSQL(t, a.f.db.QueryRow("SELECT version,enabled,config_sha256 FROM system_backup_v2_configs").Scan(&version, &enabled, &config))
	if version != 1 || enabled || config != a.g.ConfigSHA256 {
		t.Fatal("disabled v1 mismatch")
	}
	var states, ops, audits, charges int
	mustSQL(t, a.f.db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_installation_state WHERE active_config_version=1 AND last_effective_enabled=FALSE").Scan(&states))
	mustSQL(t, a.f.db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_operations WHERE status='succeeded' AND result_config_version=1 AND http_status=201").Scan(&ops))
	mustSQL(t, a.f.db.QueryRow("SELECT COUNT(*) FROM audit_logs WHERE action LIKE 'system_backup.config_bootstrap.%'").Scan(&audits))
	mustSQL(t, a.f.db.QueryRow("SELECT COUNT(*) FROM synthetic_guard_marker WHERE n=99").Scan(&charges))
	if states != 1 || ops != 1 || audits != 2 || charges != 1 {
		t.Fatal("partial or repeated transaction", states, ops, audits, charges)
	}
	var reserved int64
	mustSQL(t, a.f.db.QueryRow("SELECT reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1").Scan(&reserved))
	if reserved != a.priorReserved+73728 {
		t.Fatal("real capacity ledger charged repeatedly or reset", reserved, a.priorReserved)
	}
	dMySQLReceipt(t, a.f)
}

func TestDBootstrapConsumerMySQL(t *testing.T) {
	for _, mode := range []string{"first_atomic", "commit_lost_readback", "replay_expired_observation", "admin_revoked", "authority_revoked", "fail_intent", "fail_config", "fail_state", "fail_operation", "fail_result_audit", "late_config", "late_operation", "late_audit", "late_evidence_chunk", "deadline_wait", "owner_cutoff_expired", "concurrent_same_key", "orphan_config", "replay_admin_revoked", "replay_authority_revoked", "missing_capacity_new_consume", "missing_capacity_replay", "stale_capacity_new_consume", "late_capacity_ledger", "capacity_wait", "capacity_preserves_outstanding"} {
		t.Run(mode, func(t *testing.T) {
			svc, a, lost := bootstrapMySQLFixture(t)
			db := a.f.db
			if mode == "replay_admin_revoked" || mode == "replay_authority_revoked" || mode == "missing_capacity_replay" {
				first, e := bootstrapMySQLCall(svc, a)
				mustSQL(t, e)
				bootstrapMySQLCommitted(t, a)
				switch mode {
				case "replay_admin_revoked":
					_, e = db.Exec("UPDATE users SET is_active=FALSE WHERE id=42")
					mustSQL(t, e)
				case "replay_authority_revoked":
					a.deny = true
				case "missing_capacity_replay":
					a.capacityMode = "missing"
				}
				before := dMySQLSnapshot(t, db)
				r, e := bootstrapMySQLCall(svc, a)
				if mode == "missing_capacity_replay" {
					mustSQL(t, e)
					if !r.Replayed || r.OperationPublicID != first.OperationPublicID {
						t.Fatal("resource absence blocked historical read", r)
					}
				} else if e == nil || r != (sec.ConfigBootstrapResult{}) {
					t.Fatal("revoked current authority replayed", r, e)
				}
				dMySQLUnchanged(t, db, before)
				return
			}
			if mode == "missing_capacity_new_consume" {
				a.capacityMode = "missing"
			}
			if mode == "stale_capacity_new_consume" {
				a.capacityMode = "stale"
			}
			if mode == "capacity_preserves_outstanding" {
				a.priorReserved = 77
				_, e := db.Exec("INSERT INTO system_backup_v2_metadata_reservations(id,sample_at,reserved_bytes) VALUES(1,UTC_TIMESTAMP(6),77)")
				mustSQL(t, e)
			}
			if strings.HasPrefix(mode, "fail_") {
				table, condition := "audit_logs", "TRUE"
				switch mode {
				case "fail_config":
					table = "system_backup_v2_configs"
				case "fail_state":
					table = "system_backup_v2_installation_state"
				case "fail_operation":
					table = "system_backup_v2_operations"
				case "fail_intent":
					condition = "NEW.action='system_backup.config_bootstrap.intent'"
				case "fail_result_audit":
					condition = "NEW.action='system_backup.config_bootstrap.result'"
				}
				_, err := db.Exec("CREATE TRIGGER bootstrap_fail BEFORE INSERT ON " + table + " FOR EACH ROW BEGIN IF " + condition + " THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic write fault'; END IF; END")
				mustSQL(t, err)
			}
			if mode == "admin_revoked" {
				_, err := db.Exec("UPDATE users SET is_active=FALSE WHERE id=42")
				mustSQL(t, err)
			}
			if mode == "authority_revoked" {
				a.deny = true
			}
			if strings.HasPrefix(mode, "late_") || mode == "deadline_wait" || mode == "capacity_wait" {
				a.late = mode
			}
			if strings.HasPrefix(mode, "late_") {
				// For late_operation, 202 satisfies the formal HTTP CHECK but
				// differs from the original 201 receipt required by fixed readback.
				q := map[string]string{
					"late_config":          "UPDATE system_backup_v2_configs SET alert_profile=IF(alert_profile='production','development','production')",
					"late_operation":       "UPDATE system_backup_v2_operations SET http_status=202 WHERE operation_type='config_update' AND target_type='system' AND http_status=201",
					"late_audit":           "UPDATE audit_logs SET resource_type='corrupted' WHERE action='system_backup.config_bootstrap.result'",
					"late_evidence_chunk":  "UPDATE system_backup_v2_evidence_chunks SET gcm_nonce=UNHEX('000000000000000000000000')",
					"late_capacity_ledger": "UPDATE system_backup_v2_metadata_reservations SET reserved_bytes=0 WHERE id=1",
				}[mode]
				_, e := db.Exec("CREATE FUNCTION bootstrap_mutate() RETURNS INT DETERMINISTIC MODIFIES SQL DATA BEGIN " + q + "; RETURN ROW_COUNT(); END")
				mustSQL(t, e)
			}
			if mode == "deadline_wait" {
				a.until = time.Now().UTC().Add(2 * time.Second).Truncate(time.Microsecond)
			}
			if mode == "owner_cutoff_expired" {
				until, err := a.f.history.OwnerWriteExpiresAt.Time()
				mustSQL(t, err)
				bootstrapMySQLWaitUntil(t, db, until)
			}
			if mode == "orphan_config" {
				_, err := bootstrapMySQLCall(svc, a)
				mustSQL(t, err)
				_, err = db.Exec("DELETE FROM system_backup_v2_installation_state")
				mustSQL(t, err)
			}
			before := dMySQLSnapshot(t, db)
			if mode == "commit_lost_readback" {
				lost.Store(true)
			}
			if mode == "concurrent_same_key" {
				// Two independent prepared sessions; do not share mutable test authority.
				svc2, a2 := bootstrapMySQLPlan(t, a.f, a.c)
				type reply struct {
					r sec.ConfigBootstrapResult
					e error
				}
				ch := make(chan reply, 2)
				go func() { r, e := bootstrapMySQLCall(svc, a); ch <- reply{r, e} }()
				go func() { r, e := bootstrapMySQLCall(svc2, a2); ch <- reply{r, e} }()
				x, y := <-ch, <-ch
				if x.e != nil && y.e != nil {
					t.Fatal("both concurrent attempts failed", x.e, y.e)
				}
				bootstrapMySQLCommitted(t, a)
				r, err := bootstrapMySQLCall(svc, a)
				mustSQL(t, err)
				if !r.Replayed {
					t.Fatal("concurrent readback not historical")
				}
				return
			}
			r, err := bootstrapMySQLCall(svc, a)
			negative := strings.HasPrefix(mode, "fail_") || strings.HasPrefix(mode, "late_") || mode == "deadline_wait" || mode == "admin_revoked" || mode == "authority_revoked" || mode == "orphan_config" || mode == "missing_capacity_new_consume" || mode == "stale_capacity_new_consume" || mode == "capacity_wait"
			if negative {
				if err == nil || r != (sec.ConfigBootstrapResult{}) {
					t.Fatal("negative path exposed success", mode, r, err)
				}
				dMySQLUnchanged(t, db, before)
				return
			}
			if mode == "commit_lost_readback" {
				if !errors.Is(err, sec.ErrRegistrationCommitUnknown) || r != (sec.ConfigBootstrapResult{}) {
					t.Fatal("commit loss not uncertain", r, err)
				}
			} else {
				mustSQL(t, err)
				if r.Replayed || r.Version != 1 {
					t.Fatal("first result differs", r)
				}
			}
			bootstrapMySQLCommitted(t, a)
			if mode == "replay_expired_observation" {
				until, e := a.f.resultRequest.ObservationExpiresAt.Time()
				mustSQL(t, e)
				bootstrapMySQLWaitUntil(t, db, until)
			}
			committed := dMySQLSnapshot(t, db)
			replay, e := bootstrapMySQLCall(svc, a)
			mustSQL(t, e)
			if !replay.Replayed || replay.Version != 1 || r.OperationPublicID != "" && replay.OperationPublicID != r.OperationPublicID {
				t.Fatal("exact same-key readback differs", r, replay)
			}
			dMySQLUnchanged(t, db, committed)
		})
	}
	t.Log("BOOTSTRAP_CONSUMER_CASES_COMPLETE cases=26 actual_mysql=yes capacity_helper=real_sql synthetic_authority=yes physical_capacity=no provider=no production=no")
}
