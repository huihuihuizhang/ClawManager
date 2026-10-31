package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	k "clawreef/internal/systembackupkms"
)

// Actual service production wrapper, signed original deployment, original
// 096/097/098/099 SQL constraints, official scoped controller role and actual
// AcquireWithReceipt. The historical schema approval/source exclusion bodies
// are explicit synthetic fixtures, NOT current source census/readiness proof.
func TestAControlEvidenceServiceOriginalPreparingClaimAndRegistration(t *testing.T) {
	store, _ := newANativePublicationStore(t, time.Minute)
	x := newAPublisherVerifierFixtureOptions(t, aPublisherVerifierFixtureOptions{FullService: true, PublicationTarget: &store.config, ControlEvidence: true})
	aUseActualPublicationDDL(t, x, store.config)
	h, ctx := x.history, context.Background()
	s := h.service
	s.Runtime = &PublicCapture{Owner: h.owner}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := h.admin.ExecContext(ctx, q, args...); err != nil {
			t.Fatal("owned control service fixture", err)
		}
	}
	conn, err := h.admin.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0"); err != nil {
		t.Fatal(err)
	}
	for _, item := range [][2]string{{"001_init_schema.sql", "users"}, {"001_init_schema.sql", "audit_logs"}, {"098_backup_v2_add_system_backup_task_execution_core.sql", "system_backup_v2_restore_drills"}, {"098_backup_v2_add_system_backup_task_execution_core.sql", "system_backup_v2_preflights"}, {"098_backup_v2_add_system_backup_task_execution_core.sql", "system_backup_v2_artifact_verifications"}, {"100_backup_v2_add_system_backup_promotion_authority.sql", "system_backup_v2_promotions"}, {"096_backup_v2_add_system_backup_control_metadata_core.sql", "system_backup_v2_dependency_health"}, {"096_backup_v2_add_system_backup_control_metadata_core.sql", "system_backup_v2_provider_capabilities"}, {"099_backup_v2_add_system_backup_coordination_observability.sql", "system_backup_v2_alert_states"}} {
		if _, err = conn.ExecContext(ctx, aPublicationActualTable(t, item[0], item[1])); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = conn.ExecContext(ctx, "RENAME TABLE system_backup_v2_installation_state TO system_backup_v2_installation_state_a_preparing_fixture"); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.ExecContext(ctx, aPublicationActualTable(t, "096_backup_v2_add_system_backup_control_metadata_core.sql", "system_backup_v2_installation_state")); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.ExecContext(ctx, "RENAME TABLE system_backup_v2_attempts TO system_backup_v2_attempts_a_prior_fixture"); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.ExecContext(ctx, aPublicationActualTable(t, "098_backup_v2_add_system_backup_task_execution_core.sql", "system_backup_v2_attempts")); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1"); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	exec(`INSERT INTO system_backup_v2_installation_state(origin_installation_id,active_config_version,last_effective_enabled,last_effective_enabled_transition_at,monitoring_armed,monitoring_armed_reason,matrix_key) VALUES(?,1,TRUE,UTC_TIMESTAMP(6),FALSE,'none','k8s-cluster')`, h.original.InstallationID)
	g := s.Forward.DeploymentBinding()
	// Complete the named prior fixture's already-recorded local stop/resume
	// observation before creating a new preparing task. This is test DATA setup,
	// not production release logic or a claim that physical writers were tested.
	var resumed int
	if h.admin.QueryRow("SELECT COUNT(*) FROM system_backup_v2_runtime_captures WHERE task_public_id=? AND collectors_stopped_at IS NOT NULL AND source_resumed_at IS NOT NULL", h.original.TaskPublicID).Scan(&resumed) != nil || resumed != 1 {
		t.Fatal("prior named source fixture not resumed")
	}
	exec("UPDATE system_backup_gate SET phase='idle',owner=NULL WHERE scope=? AND owner=?", s.Config.ApplicationScope, h.original.TaskPublicID)
	grants, err := c.ControlEvidenceGrantSQL(g.Database, strings.Split(g.DatabaseAccount, "@")[0], "127.0.0.1", false, false, false, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range grants {
		_, rest, ok := strings.Cut(q, "`.`")
		if !ok {
			t.Fatal("official table grant")
		}
		table, _, ok := strings.Cut(rest, "`")
		if !ok {
			t.Fatal("official table grant")
		}
		var exists int
		if h.admin.QueryRow("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=?", table).Scan(&exists) != nil {
			t.Fatal("table inventory")
		}
		if exists == 1 {
			exec(q)
		}
	}
	// A NEW preparing task uses the same original config/deployment. No stopped
	// historical capture or publisher claim is revived for a source read.
	backup := "sbk_00000000-0000-4000-8000-000000000019"
	var config []byte
	if h.db.QueryRow("SELECT config_snapshot_json FROM system_backup_v2_backups WHERE public_id=?", h.original.TaskPublicID).Scan(&config) != nil {
		t.Fatal("original config")
	}
	// Original 112 adds canonical_config_json after 097. Keep its real CHECK
	// and the exact original snapshot bytes used by SQLExecutionAuthority.Bind.
	migration, err := os.ReadFile(filepath.Join("..", "db", "migrations", "112_backup_v2_system-backup-d-config-canonical-081-proposal-20261014.sql"))
	if err != nil {
		t.Fatal(err)
	}
	conn, err = h.admin.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range strings.Split(string(migration), ";") {
		if strings.TrimSpace(statement) != "" {
			if _, err = conn.ExecContext(ctx, statement); err != nil {
				t.Fatal("actual 112 canonical migration", err)
			}
		}
	}
	conn.Close()
	exec("UPDATE system_backup_v2_configs SET canonical_config_json=? WHERE origin_installation_id=? AND version=1", config, g.InstallationID)
	exec(`INSERT INTO system_backup_v2_backups(public_id,origin_installation_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,request_id,status,config_version,config_snapshot_json,config_snapshot_size_bytes,config_snapshot_sha256,deadline_at,started_at,source_orchestrator,source_profile,matrix_key,runner,task_purpose,requested_parts,artifact_read_identity_hash,artifact_read_ref_version,artifact_ca_identity_hash,artifact_ca_ref_version,target_class,target_risks,target_failure_domain_id) SELECT ?,origin_installation_id,actor_type,actor_id,'OriginalControlEvidenceService','original-control-service',request_hash,'original-control-service','preparing',config_version,config_snapshot_json,config_snapshot_size_bytes,config_snapshot_sha256,deadline_at,UTC_TIMESTAMP(6),source_orchestrator,source_profile,matrix_key,runner,task_purpose,'mysql,redis,object_storage,workspace,deployment_resources,secret_bundle',artifact_read_identity_hash,artifact_read_ref_version,artifact_ca_identity_hash,artifact_ca_ref_version,target_class,target_risks,target_failure_domain_id FROM system_backup_v2_backups WHERE public_id=?`, backup, h.original.TaskPublicID)
	exec(`INSERT INTO system_backup_v2_attempts(target_type,target_public_id,attempt_no,phase,status,row_version) VALUES('backup',?,1,'capture','preparing',1)`, backup)
	exec(`INSERT INTO system_backup_v2_execution_inputs(origin_installation_id,task_public_id,task_type,profile_json,profile_sha256) SELECT origin_installation_id,?,'backup',profile_json,profile_sha256 FROM system_backup_v2_execution_inputs WHERE task_public_id=?`, backup, h.original.TaskPublicID)
	var version uint64
	if h.db.QueryRow("SELECT row_version FROM system_backup_v2_backups WHERE public_id=?", backup).Scan(&version) != nil {
		t.Fatal("new task")
	}
	claim, err := (c.SQLTaskClaimStore{DB: h.db, InstallationID: g.InstallationID}).AcquireWithReceipt(ctx, c.Target{Kind: c.TargetBackup, PublicID: backup}, g.ControllerOwner, version, c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second})
	if err != nil {
		t.Fatal("actual original preparing AcquireWithReceipt", err)
	}
	authority := h.original
	authority.TaskPublicID = backup
	authority.AttemptNo = 1
	authority.RequestID = "original-control-service"
	authority.ClaimOwner = claim.Owner
	authority.ClaimRowVersion = claim.RowVersion
	authority.MaintenanceOwner = ""
	authority.MaintenanceFencingToken = 0
	dir := filepath.Dir(s.ConfigPath)
	schema, err := os.ReadFile(filepath.Join("..", "systembackupbusinessa", "testdata", "schema-registry-historical-15.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if json.Unmarshal(schema, &document) != nil {
		t.Fatal("historical schema fixture")
	}
	document["contract_status"] = "frozen"
	schemaHash := document["schema_hash"].(map[string]any)
	schemaHash["status"] = "observed"
	schemaHash["hash"] = strings.Repeat("a", 64)
	schemaHash["evidence"] = map[string]any{"public_id": "sev_explicit_historical_fixture", "sha256": strings.Repeat("b", 64)}
	objects := document["objects"].([]any)
	summary := document["summary"].(map[string]any)
	summary["object_count"] = len(objects)
	summary["policy_recorded"] = len(objects)
	summary["policy_pending"] = 0
	summary["cross_review_pending"] = 0
	for _, v := range objects {
		object := v.(map[string]any)
		object["decision_status"] = "frozen"
		object["approved_cross_reviewers"] = object["required_cross_reviewers"]
	}
	schema, _ = json.Marshal(document)
	redaction, _ := ce.Canonical(ce.RedactionPolicy{Version: "system-backup-control-redaction-registry.v1", RegistryVersion: "original-redaction-fixture-r1", Contract: "system-backup-plan.v12", Status: "frozen", Projections: ce.ProjectionColumns()})
	input := ce.CaptureInput{SchemaRegistryFile: filepath.Join(dir, "historical-schema.json"), SchemaRegistrySHA256: hash(schema), RedactionRegistryFile: filepath.Join(dir, "redaction.json"), RedactionRegistrySHA256: hash(redaction), CoverageWindowSeconds: 3600}
	if os.WriteFile(input.SchemaRegistryFile, schema, 0600) != nil || os.WriteFile(input.RedactionRegistryFile, redaction, 0600) != nil {
		t.Fatal("owned policy fixture")
	}
	schemaPin, redactionPin, names, err := ce.ReadPolicies(schema, redaction, input)
	if err != nil {
		t.Fatal("explicit historical fixture policy", err)
	}
	sourceID, err := ce.SourceIdentity(s.Config.SourceServerUUID, s.Config.SourceDatabase)
	if err != nil {
		t.Fatal(err)
	}
	expected := ce.Expected{Scope: ce.Scope{Installation: g.InstallationID, Backup: backup, Attempt: 1}, ConfigSHA256: authority.ConfigSHA256, SourceIdentitySHA256: sourceID, SchemaRegistry: schemaPin, RedactionRegistry: redactionPin}
	sort.Strings(names)
	namesRaw, _ := ce.Canonical(names)
	sourceBody, _ := ce.Canonical(ce.SourceExclusionProof{Version: "system-backup-source-control-exclusion.v1", Scope: expected.Scope, ConfigSHA256: expected.ConfigSHA256, SourceIdentitySHA256: sourceID, Registry: schemaPin, ExcludedNamesSHA256: hash(namesRaw)})
	source := ce.RegisteredEvidence{PublicID: "sev_00000000-0000-4000-8000-000000000019", SHA256: hash(sourceBody), OwnerType: "backup", OwnerID: backup, Type: "verifier_report", Payload: sourceBody}
	tx, err := h.admin.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	if err = ce.RegisterSQL(ctx, tx, expected.Scope, []ce.RegisteredEvidence{source}, authority.DeadlineAt); err != nil {
		t.Fatal(err)
	}
	if tx.Commit() != nil {
		t.Fatal("register explicit source proof fixture")
	}
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(private)
	m := productionCaptureMaterials{Version: productionCaptureMaterialsVersion, Revision: "preparing-fixture-r1", InstallationID: g.InstallationID, ControllerOwner: g.ControllerOwner, DeploymentConfigSHA256: s.ConfigDigest, CaptureGrantSHA256: s.Forward.GrantSHA256(), Operations: map[string]productionCaptureOperation{}, MaxObjects: 100, MaxObjectBytes: 1024, MaxObjectTotalBytes: 4096, ResourceTypes: []productionResourceType{{Part: "deployment_resources", Group: "apps", Version: "v1", Resource: "deployments"}}, ControlEvidence: &input, ControlEvidenceSource: &worker.ControlEvidenceSourceMount{Endpoint: s.Config.ControlURL, GrantFile: filepath.Join(dir, "worker-source-grant.json"), ControllerGrantFile: filepath.Join(dir, "controller-source-grant.json"), GrantSHA256: strings.Repeat("a", 64), Issuer: pub}}
	permitPub, _, _ := ed25519.GenerateKey(rand.Reader)
	for _, op := range []string{"capture-database", "capture-workspace", "capture-source-redis", "capture-skill-objects", "capture-deployment-resources", "capture-secret-bundle", ce.Operation} {
		m.Operations[op] = productionCaptureOperation{Formal: worker.FormalCaptureSpec{Version: worker.FormalCaptureVersion, ConfigSHA256: strings.Repeat("a", 64), PermitDelivery: &k.PermitDeliveryPin{Version: k.PermitDeliveryVersion, Issuer: permitPub, IssuerGrantSHA256: strings.Repeat("b", 64)}}, Provider: k.Access{Operation: k.Generate}, Workload: kube.JobRequest{Identity: kube.Identity{Namespace: s.Config.Namespace}, Image: s.Config.WorkerImage, StagingClaim: s.Config.StagingClaim, ServiceAccount: s.Config.Security.ServiceAccountName, WorkerControl: &kube.WorkerControl{URL: s.Config.ControlURL}, FormalMaterials: &kube.FormalJobMaterials{ConfigMap: "original-materials"}}}
	}
	materialRaw, _ := json.Marshal(m)
	if err = s.publicationBinding(); err != nil {
		t.Fatal("original core binding before source material", err)
	}
	if err = s.validateProductionCapture(m); err != nil {
		t.Fatal("original source material shape", err)
	}
	if os.WriteFile(s.Config.CaptureModules.Path, materialRaw, 0600) != nil {
		t.Fatal("original material fixture")
	}
	if err = s.loadProductionCapture([]ProductionCaptureInput{{File: s.Config.CaptureModules.Path, SHA256: hash(materialRaw)}}); err != nil {
		t.Fatal("actual pinned material loader", err)
	}
	for i := 0; i < 121; i++ {
		exec(`INSERT INTO system_backup_v2_events(origin_installation_id,target_type,target_public_id,event_type,level,task_status,message,details_present) VALUES(?,'backup',?,?,'info','preparing','opaque secret excluded',FALSE)`, g.InstallationID, backup, c.TaskClaimAcquiredEvent)
	}
	in := d.Input{Authority: authority, ConfigSnapshot: config}
	if err = s.Forward.CheckDeployment(ctx, h.db); err != nil {
		t.Fatal("actual original signed deployment", err)
	}
	if err = h.owner.Gate.Authority.Check(ctx, authority); err != nil {
		t.Fatal("actual original preparing guard before producer", err)
	}
	locator, err := s.PrepareControlEvidenceLocator(ctx, in, ce.EvidenceRef{PublicID: source.PublicID, SHA256: source.SHA256})
	if err != nil {
		t.Fatal("actual original preparing source producer", err)
	}
	if locator.Expected != expected {
		t.Fatal("source scope changed")
	}
	entries := []ce.RegisteredEvidence{}
	tx, err = h.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, ref := range locator.Evidence {
		entry, err := ce.LoadRegisteredSQL(ctx, tx, expected.Scope, ref)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}
	rebuilt, err := ce.Rebuild(ctx, locator, entries)
	if err != nil {
		t.Fatal(err)
	}
	sidecar, err := ce.Verify(ctx, rebuilt.SidecarJSON, rebuilt.ProofsJSON, expected)
	if err != nil || sidecar.Groups["event"].Count < 121 || len(sidecar.Groups["event"].Evidence) < 4 {
		t.Fatal("complete actual service window", err)
	}
	encoded, _ := json.Marshal(locator)
	if bytes.Contains(encoded, []byte(`"payload"`)) || bytes.Contains(encoded, []byte(`"record_groups"`)) {
		t.Fatal("plaintext Job locator")
	}
	tx.Rollback()
	var maxExpiry time.Time
	if h.db.QueryRow("SELECT MAX(expires_at) FROM system_backup_v2_evidence WHERE owner_target_public_id=? AND public_id<>?", backup, source.PublicID).Scan(&maxExpiry) != nil || !maxExpiry.After(authority.DeadlineAt) {
		t.Fatal("data retention clipped to execution lease")
	}
	var before int
	if h.db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_evidence WHERE owner_target_public_id=?", backup).Scan(&before) != nil {
		t.Fatal("original proof count")
	}
	for _, fault := range []string{"missing-source", "wrong-source-digest", "changed-schema-file"} {
		t.Run(fault, func(t *testing.T) {
			ref := ce.EvidenceRef{PublicID: source.PublicID, SHA256: source.SHA256}
			switch fault {
			case "missing-source":
				ref.PublicID = "sev_00000000-0000-4000-8000-000000000999"
			case "wrong-source-digest":
				ref.SHA256 = strings.Repeat("f", 64)
			case "changed-schema-file":
				if os.WriteFile(input.SchemaRegistryFile, []byte(`{"changed":true}`), 0600) != nil {
					t.Fatal("policy replacement fixture")
				}
				defer os.WriteFile(input.SchemaRegistryFile, schema, 0600)
			}
			if out, err := s.PrepareControlEvidenceLocator(ctx, in, ref); err == nil || out.Version != "" {
				t.Fatal("invalid original source/policy admitted", err)
			}
			var after int
			if h.db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_evidence WHERE owner_target_public_id=?", backup).Scan(&after) != nil || after != before {
				t.Fatal("invalid source retained partial reports")
			}
		})
	}
	// Over-budget declared history must fail as capacity, with the earlier
	// registered immutable capture intact, rather than reducing the cutoff.
	for n := sidecar.Groups["event"].Count; n <= ce.MaxGroupRecords; n++ {
		exec(`INSERT INTO system_backup_v2_events(origin_installation_id,target_type,target_public_id,event_type,level,task_status,message,details_present) VALUES(?,'backup',?,?,'info','preparing','subsequent event',FALSE)`, g.InstallationID, backup, c.TaskClaimAcquiredEvent)
	}
	if out, err := s.PrepareControlEvidenceLocator(ctx, in, ce.EvidenceRef{PublicID: source.PublicID, SHA256: source.SHA256}); !errors.Is(err, ce.ErrCapacity) || out.Version != "" {
		t.Fatal("actual service truncated over-budget history", err)
	}
	var after int
	if h.db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_evidence WHERE owner_target_public_id=?", backup).Scan(&after) != nil || after != before {
		t.Fatal("capacity failure retained partial reports")
	}
	if _, err = ce.Verify(ctx, rebuilt.SidecarJSON, rebuilt.ProofsJSON, expected); err != nil {
		t.Fatal("new history altered original immutable bodies", err)
	}
	renewed, err := (c.ClaimCoordinator{Executor: h.db, InstallationID: g.InstallationID}).Renew(ctx, claim, c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second})
	if err != nil || renewed.RowVersion == claim.RowVersion {
		t.Fatal("actual preparing Renew", err)
	}
	if result, err := s.PrepareControlEvidenceLocator(ctx, in, ce.EvidenceRef{PublicID: source.PublicID, SHA256: source.SHA256}); err == nil || result.Version != "" {
		t.Fatal("old original preparing claim adopted renewed version")
	}
}
