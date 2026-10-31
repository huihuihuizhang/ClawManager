package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	appdb "clawreef/internal/db"
	root "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Explicit LOCAL owner/cross-review input, permitted only for this disposable
// task test. Every control name/classification comes from root.Policy, every
// column/PK from the actual original 172-migration schema. This never edits the
// repository draft or claims installed owner approvals/readiness.
func (f *dOriginalSixPartTask) installLocalOriginalControlApproval(ctx context.Context, t *testing.T, observed productionSQLSourceMetadata) {
	t.Helper()
	schemas, err := root.ObserveControlScopeSchemas(ctx, f.db, observed.Census.Control)
	if err != nil {
		t.Fatal("local independent finite control schema observation", err)
	}
	generated := false
	for _, table := range schemas {
		for _, column := range table.Columns {
			if column.GenerationExpression == "" {
				continue
			}
			generated = true
			if _, err := root.ReadTableSchema(ctx, f.db, table.Name); err == nil {
				t.Fatal("metadata-only observation weakened original generated-column export guard")
			}
			break
		}
		if generated {
			break
		}
	}
	if !generated {
		t.Fatal("original migrated control generated-column boundary was not exercised")
	}
	catalog, err := appdb.EmbeddedMigrationCatalog()
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := root.NewControlScopeProposal(f.server, f.database, catalog.Hash, schemas)
	if err != nil || len(proposal.Tables) != 95 || proposal.Status != "draft_requires_independent_owner_review" {
		t.Fatal("finite original control proposal", err)
	}
	proposalRaw, _ := json.Marshal(proposal)
	observation, _ := ce.Canonical(map[string]any{"schema_version": "explicit-local-original-control-shape-observation.v1", "installation_id": f.input.Authority.InstallationID, "backup_public_id": f.publicID, "attempt_no": f.input.Authority.AttemptNo, "server_uuid": f.server, "database": f.database, "migration_catalog_sha256": catalog.Hash, "control_table_count": len(proposal.Tables), "reviewed_policy_sha256": proposal.RegistrySHA256, "observed_shape_sha256": proposal.ObservedShapeSHA256, "offline_proposal_sha256": hash(proposalRaw), "approval_status": "explicit_local_fixture_only"})
	observationID := "sev_" + uuid.NewSHA1(uuid.NameSpaceOID, []byte(f.publicID+"\x00local-original-control-observation\x00"+hash(observation))).String()
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(f.directory, name)
		if os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("local original owner input")
		}
		return path
	}
	write("observed-control-proposal.json", proposalRaw)
	base, err := os.ReadFile(filepath.Join("..", "systembackupbusinessa", "testdata", "schema-registry-historical-15.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if json.Unmarshal(base, &document) != nil {
		t.Fatal("local approval historical business policy fixture")
	}
	objects := []any{}
	for _, entry := range document["objects"].([]any) {
		object := entry.(map[string]any)
		if object["object_type"] == "table" && object["category"] == "system_backup" {
			continue
		}
		object["decision_status"], object["approved_cross_reviewers"] = "frozen", object["required_cross_reviewers"]
		objects = append(objects, object)
	}
	for _, table := range proposal.Tables {
		policy := table.Policy
		objects = append(objects, map[string]any{"object_type": "table", "name": policy.Name, "owner": "D", "category": policy.Category, "data_classification": policy.Classification, "backup_strategy": policy.BackupStrategy, "restore_strategy": policy.RestoreStrategy, "decision_status": "frozen", "required_cross_reviewers": []string{"A", "B", "C"}, "approved_cross_reviewers": []string{"A", "B", "C"}, "redacted_explanation": "Explicit local test owner input; original finite classification and independently observed schema; never installed approval"})
	}
	sort.Slice(objects, func(i, j int) bool {
		return objects[i].(map[string]any)["name"].(string) < objects[j].(map[string]any)["name"].(string)
	})
	document["objects"], document["contract_status"] = objects, "frozen"
	document["schema_hash"] = map[string]any{"algorithm": "sha256-information-schema-canonical-v1", "status": "observed", "hash": proposal.ObservedShapeSHA256, "evidence": map[string]any{"public_id": observationID, "sha256": hash(observation)}}
	document["migration_catalog"] = map[string]any{"algorithm": catalog.Algorithm, "file_count": len(catalog.Filenames), "hash": catalog.Hash}
	document["summary"] = map[string]any{"object_count": len(objects), "policy_recorded": len(objects), "policy_pending": 0, "cross_review_pending": 0}
	schema, _ := json.Marshal(document)
	redaction, _ := ce.Canonical(ce.RedactionPolicy{Version: "system-backup-control-redaction-registry.v1", RegistryVersion: "explicit-local-original-projection-r1", Contract: "system-backup-plan.v12", Status: "frozen", Projections: ce.ProjectionColumns()})
	input := ce.CaptureInput{SchemaRegistryFile: write("local-owner-control-registry.json", schema), SchemaRegistrySHA256: hash(schema), RedactionRegistryFile: write("local-owner-control-redaction.json", redaction), RedactionRegistrySHA256: hash(redaction), CoverageWindowSeconds: 3600}
	schemaPin, redactionPin, names, err := ce.ReadPolicies(schema, redaction, input)
	if err != nil || validateOriginalControlPolicy(schema, names, observed.Census.Control) != nil {
		t.Fatal("original frozen reader rejected finite explicit local owner input", err)
	}
	// Both missing original and unexpected/future names fail the same importer.
	if validateOriginalControlPolicy(schema, names[1:], observed.Census.Control) == nil || validateOriginalControlPolicy(schema, append(append([]string{}, names...), "system_backup_v2_unreviewed"), observed.Census.Control) == nil {
		t.Fatal("incomplete or unknown control approval scope accepted")
	}
	for _, fault := range []string{"classification", "unknown-name", "business-name"} {
		var changed map[string]any
		json.Unmarshal(schema, &changed)
		for _, entry := range changed["objects"].([]any) {
			object := entry.(map[string]any)
			if object["category"] != "system_backup" {
				continue
			}
			switch fault {
			case "classification":
				object["data_classification"] = "public"
			case "unknown-name":
				object["name"] = "system_backup_v2_unreviewed"
			case "business-name":
				object["name"] = "users"
			}
			break
		}
		raw, _ := json.Marshal(changed)
		if validateOriginalControlPolicy(raw, names, observed.Census.Control) == nil {
			t.Fatal("control policy importer changed original classification/scope", fault)
		}
	}
	identity, err := ce.SourceIdentity(f.server, f.database)
	if err != nil {
		t.Fatal(err)
	}
	s := f.service
	expected := ce.Expected{Scope: ce.Scope{Installation: f.input.Authority.InstallationID, Backup: f.publicID, Attempt: 1}, ConfigSHA256: f.input.Authority.ConfigSHA256, SourceIdentitySHA256: identity, SchemaRegistry: schemaPin, RedactionRegistry: redactionPin}
	tx, err := f.control.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	guard, err := f.owner.Gate.Authority.Bind(ctx, tx, f.input.Authority)
	if err != nil {
		t.Fatal("original observation registration authority", err)
	}
	if err := ce.RegisterSQL(ctx, tx, expected.Scope, []ce.RegisteredEvidence{{PublicID: observationID, SHA256: hash(observation), OwnerType: "backup", OwnerID: f.publicID, Type: "verifier_report", Payload: observation}}, f.input.Authority.DeadlineAt.Add(time.Hour)); err != nil {
		t.Fatal("original actual schema observation registration", err)
	}
	if guard.Recheck(ctx, tx) != nil || tx.Commit() != nil {
		t.Fatal("original observation registration commit")
	}
	scopeSHA, err := worker.ControlEvidenceSourceScopeSHA256(expected, s.Config.ControlURL)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	record, _ := json.Marshal(worker.ControlEvidenceSourceGrant{Version: worker.ControlEvidenceSourceGrantVersion, InstallationID: expected.Installation, ConfigSHA256: expected.ConfigSHA256, WorkerNamespace: s.Config.Namespace, WorkerServiceAccountUID: s.Config.Security.ServiceAccountUID, Operation: ce.Operation, ScopeSHA256: scopeSHA, NotBefore: now.Add(-time.Minute), Until: now.Add(time.Hour)})
	grantRaw, _ := json.Marshal(worker.SignedControlEvidenceSourceGrant{Record: record, Signature: ed25519.Sign(f.metadataSigner, append([]byte(worker.ControlEvidenceSourceGrantDomain), record...))})
	m := s.captureMaterials
	m.ControlEvidence = &input
	m.ControlEvidenceSource = &worker.ControlEvidenceSourceMount{Endpoint: s.Config.ControlURL, GrantFile: write("original-control-worker-grant.json", grantRaw), ControllerGrantFile: write("original-control-controller-grant.json", grantRaw), GrantSHA256: hash(grantRaw), Issuer: f.metadataSigner.Public().(ed25519.PublicKey)}
	_, _, _, _, templates := productionModuleFixture(t)
	op := templates[ce.Operation]
	op.Workload.Identity.Namespace, op.Workload.Image, op.Workload.StagingClaim, op.Workload.ServiceAccount = s.Config.Namespace, s.Config.WorkerImage, s.Config.StagingClaim, s.Config.Security.ServiceAccountName
	op.Workload.WorkerControl.URL = s.Config.ControlURL
	caInput, caPin := f.originalPublicCAInput(ctx, t)
	op.Workload.FormalMaterials.Inputs = []kube.FormalInputMount{caInput}
	op.MountIdentities = []kube.MountIdentity{{Volume: "formal-mapping", Kind: "ConfigMap", Name: op.Workload.FormalMaterials.ConfigMap, UID: "control-mapping-uid", SHA256: hash([]byte(ce.Operation))}, caPin}
	m.Operations[ce.Operation] = op
	f.repinOriginalMetadataSource(t)
	for _, fact := range f.sourceInventory.TeamFacts.Teams {
		if fact.PVC == "" {
			continue
		}
		claim := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: fact.PVC, Namespace: fact.Namespace, UID: "original-six-team-pvc-uid"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "original-six-team-pv"}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound}}
		if _, err := f.owner.Client.CoreV1().PersistentVolumeClaims(fact.Namespace).Create(ctx, claim, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.owner.Client.CoreV1().PersistentVolumes().Create(ctx, &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "original-six-team-pv", UID: "original-six-team-pv-uid"}, Spec: corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Name: fact.PVC, Namespace: fact.Namespace, UID: claim.UID}}}, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *dOriginalSixPartTask) repinOriginalMetadataSource(t *testing.T) {
	t.Helper()
	s, m := f.service, f.service.captureMaterials
	raw, err := os.ReadFile(m.Discovery.GrantFile)
	var envelope signedSourceMetadataGrant
	var grant originalSourceMetadataGrant
	if err != nil || json.Unmarshal(raw, &envelope) != nil || json.Unmarshal(envelope.Record, &grant) != nil {
		t.Fatal("original metadata grant fixture")
	}
	grant.ScopeSHA256, err = sourceMetadataScope(*m)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Record, _ = json.Marshal(grant)
	envelope.Signature = ed25519.Sign(f.metadataSigner, append([]byte(sourceMetadataGrantDomain), envelope.Record...))
	raw, _ = json.Marshal(envelope)
	if os.WriteFile(m.Discovery.GrantFile, raw, 0600) != nil {
		t.Fatal("local owner grant repin")
	}
	m.Discovery.GrantSHA256 = hash(raw)
	raw, _ = json.Marshal(m)
	if os.WriteFile(s.Config.CaptureModules.Path, raw, 0600) != nil {
		t.Fatal("original immutable material fixture")
	}
	if err := s.loadProductionCapture([]ProductionCaptureInput{{File: s.Config.CaptureModules.Path, SHA256: hash(raw)}}); err != nil {
		t.Fatal("same-task original extended source loader", err)
	}
}

func (f *dOriginalSixPartTask) checkOriginalFrozenDiscovery(ctx context.Context, t *testing.T, discovery b.Discovery) {
	t.Helper()
	var source b.SourceInventory
	if decodeMetadataCanonical(discovery.Source, &source) != nil || hash(discovery.Source) != discovery.SourceSHA256 || len(discovery.Parts) != 10 || len(discovery.Writers) != 4 || source.Teams == nil || len(source.Teams.Teams) != 1 {
		t.Fatal("original Prepare did not return complete same-task frozen source")
	}
	var metadata productionCaptureMetadata
	if decodeMetadataCanonical(source.CaptureMetadata, &metadata) != nil || metadata.ControlEvidence.Version != "system-backup-control-evidence-source.v1" || metadata.ControlEvidence.Finalization != nil {
		t.Fatal("original Prepare full Source did not retain V1 base")
	}
	f.frozenWriters = append([]b.FrozenWriter{}, discovery.Writers...)
	if err := f.service.productionInventory(ctx, f.input, discovery); err != nil {
		t.Fatal("same-task original frozen source/parts/V2 inventory guard", err)
	}
	var controls int
	if f.control.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_runtime_controls WHERE task_public_id=? AND attempt_no=1", f.publicID).Scan(&controls) != nil || controls != 2 {
		t.Fatal("original Prepare did not retain both runtime custody capsules")
	}
	var stoppedRaw []byte
	if f.control.QueryRowContext(ctx, "SELECT spec_json FROM system_backup_v2_runtime_controls WHERE task_public_id=? AND instance_id=9", f.publicID).Scan(&stoppedRaw) != nil {
		t.Fatal("original stopped custody")
	}
	var stopped b.RuntimeWriterSpec
	if json.Unmarshal(stoppedRaw, &stopped) != nil || stopped.Kind != "stopped" || stopped.Stopped.Running {
		t.Fatal("original stopped runtime became running")
	}
	authority, err := f.service.sourceMetadataAuthority(ctx, f.owner, f.input)
	if err != nil {
		t.Fatal(err)
	}
	sqlMetadata, err := authority.sqlMetadata(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	mounts, identities, records, err := authority.instanceMountMetadata(ctx, source, discovery.Writers, sqlMetadata, metadata.Skills, &metadata)
	if err != nil || len(mounts) != 2 || len(identities) != 2 || len(records) != 2 || mounts[0].Skills == nil || mounts[1].Skills != nil {
		t.Fatal("original frozen custody/image/PVC/Skill workspace recheck", err)
	}
	var before int
	if f.control.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_evidence WHERE owner_target_public_id=?", f.publicID).Scan(&before) != nil {
		t.Fatal("original evidence census")
	}
	teams, current, err := f.service.freezeProductionSource(ctx, f.owner, f.input, f.sourceInventory, discovery.Writers, &metadata)
	if err != nil || teams == nil || !bytes.Equal(source.CaptureMetadata, current) {
		t.Fatal("original CheckFrozenSources changed source/base cutoff", err)
	}
	var after int
	if f.control.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_evidence WHERE owner_target_public_id=?", f.publicID).Scan(&after) != nil || after != before {
		t.Fatal("original frozen source recheck registered another cutoff")
	}
	f.sourceInventory = source
}
