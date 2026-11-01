package systembackupexecution

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	root "clawreef/internal/systembackup"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	cd "clawreef/internal/systembackupcapturedescription"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	security "clawreef/internal/systembackupsecurity"
)

// Assembly DATA only, with explicit test-local private receipts and placeholder
// physical bytes/signature. This cannot demonstrate C, current SQL, a native
// upload Job, fixed remote versions or acceptance; those require the real path.
func publicationAssemblyData(t *testing.T) (publicationVerifiedCapture, originalPublicationCaptureCertificate, publicationContainerFileSet, []byte, publicationRecoveryFacts, PublicationTargetMaterials, time.Time) {
	t.Helper()
	x := newPublicationRecoveryData(t)
	target := PublicationTargetMaterials{InstallationID: x.binding.InstallationID, Endpoint: "https://localhost:443", Bucket: "named-DATA", Region: "local-1", Root: "installation_DATA/artifacts/", RemoteStagingRoot: "installation_DATA/staging/"}
	x.target = publicationRecoveryTargetSHA(target)
	x.statement.TargetSHA256 = x.target
	schema, facts, sqlCounts := publicationSQLCategoryData(t)
	policy := root.SecretCapturePolicy{SchemaVersion: root.SecretCapturePolicyVersion, RegistryVersion: "secret-data-r1", RegistryKind: "secret_allowlist", NamespaceScope: "installation_namespace", CaptureMode: "encrypted_full_object", Entries: []root.SecretCapturePolicyEntry{{ID: "required", SecretName: "required", Required: true, ExpectedType: "Opaque", Purpose: "application_secret"}}}
	rawPolicy, _ := ce.Canonical(policy)
	secretPolicy, err := root.DecodeSecretCapturePolicy(rawPolicy, policy.RegistryVersion, hash(rawPolicy))
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]json.RawMessage
	json.Unmarshal(x.config, &config)
	var pins []security.BootstrapRegistryRef
	json.Unmarshal(config["registries"], &pins)
	for i, p := range pins {
		if p.Kind == "secret_allowlist" {
			pins[i].Version = policy.RegistryVersion
			pins[i].SHA256 = hash(rawPolicy)
		}
	}
	config["registries"], _ = ce.Canonical(pins)
	x.config, _ = ce.Canonical(config)
	x.policy.Policy.ConfigSHA256 = hash(x.config)
	x.statement.ConfigSHA256 = hash(x.config)
	owner, sig, att, cap := x.signed(t)
	recovery, err := verifyPublicationRecoveryEvidence(x.config, x.policy, x.trust, x.binding, x.ownerKey.Public().(ed25519.PublicKey), owner, sig, att, cap, x.target, x.now)
	if err != nil {
		t.Fatal("original signed recovery DATA", err)
	}
	facts.PublicationPolicy = &x.policy
	metadata := productionCaptureMetadata{Version: productionCaptureMetadataVersion, SQLSchema: schema, PublicationFacts: &facts, Secrets: worker.ResourceCaptureSpec{Part: "secret_bundle", Namespace: "source", SecretPolicy: &secretPolicy, Selections: []root.KubernetesSelection{{Version: "v1", Resource: "secrets", Name: "required", UID: "data-secret-uid"}}}}
	source := b.SourceInventory{}
	source.CaptureMetadata, _ = json.Marshal(metadata)
	sourceRaw, _ := json.Marshal(source)
	capture := publicationVerifiedCapture{SourceFacts: facts, DescriptionSHA256: hash([]byte("named description DATA")), CaptureContextSHA256: hash([]byte("named context DATA")), CaptureResultSHA256: hash([]byte("named full result DATA")), PlanSHA256: hash([]byte("named plan DATA"))}
	capture.Input = c.HistoricalCaptureInput{InstallationID: x.binding.InstallationID, TaskPublicID: "sbk_11111111-1111-4111-8111-111111111111", ConfigVersion: 1, CaptureAttemptNo: 1, ConfigSnapshot: x.config, ConfigSHA256: hash(x.config), SourceSnapshot: sourceRaw, SourceSHA256: hash(sourceRaw), Backup: d.BackupSpec{TaskPurpose: "acceptance", DatasourceTopology: "in_cluster", SourceOrchestrator: "kubernetes", SourceProfile: "cluster", Runner: "k8s", MatrixKey: "k8s-cluster", RequestedParts: append([]string{}, publicationRequestedParts...)}}
	mf := publicationManifestDataV12(t)
	mf.Installation = capture.Input.InstallationID
	mf.Backup = capture.Input.TaskPublicID
	mf.Config.SHA256 = capture.Input.ConfigSHA256
	mf.CaptureContext = capture.CaptureContextSHA256
	mf.KEK = recovery.KEK
	payload := publicationCaptureCertificatePayload{Version: "system-backup-capture-certificate.v1", Installation: mf.Installation, Backup: mf.Backup, Attempt: 1, Context: mf.CaptureContext, IssuedAt: x.now.Add(-30 * time.Second), CompletedAt: x.now.Add(-time.Minute), ExpiresAt: x.now.Add(time.Hour), Checkpoints: []publicationCertificateCheckpoint{}}
	bootstrap := publicationBootstrapManifestData(t, mf, &payload)
	var public cd.Bootstrap
	json.Unmarshal(bootstrap, &public)
	files := publicationContainerFileSet{Version: "system-backup-original-publication-container-files.v1", PlanSHA256: hash([]byte("named durable plan DATA")), Files: []publicationContainerFile{}}
	operations := map[string]string{"mysql": "capture-database", "redis": "capture-source-redis", "object_storage": "capture-skill-objects", "workspace": "capture-workspace", "deployment_resources": "capture-deployment-resources", "secret_bundle": "capture-secret-bundle"}
	for i, name := range publicationRequestedParts {
		p := publicationVerifiedPart{Part: name, Operation: operations[name], RequestedPart: name, Category: "instances", Index: uint32(i), InvocationSHA256: hash([]byte("named invocation DATA " + name)), CipherSHA256: hash([]byte("named logical cipher DATA " + name)), Counts: ownedPayloadCounts{Version: "system-backup-inert-payload-counts.v1", Complete: true, Items: 1, ContentBytes: 5}}
		if name == "mysql" {
			p.Counts = sqlCounts
		}
		if name == "workspace" {
			p.Counts.ArchiveEntries = 2
		}
		p.Counts.Kind = map[string]string{"mysql": "sql_raw_cell_bytes", "redis": "redis_key_dump_group_bytes", "object_storage": "object_payload_bytes", "workspace": "archive_entry_bytes", "deployment_resources": "kubernetes_captured_json_bytes", "secret_bundle": "kubernetes_captured_json_bytes"}[name]
		if name == "secret_bundle" {
			p.Counts.SecretPolicy = &ownedSecretPolicyCoverage{Version: "system-backup-secret-policy-coverage.v1", RegistryVersion: policy.RegistryVersion, RegistrySHA256: hash(rawPolicy), RequiredEntries: 1, CapturedEntries: 1, Complete: true}
		}
		cp := b.Checkpoint{SchemaVersion: "system-backup-b-checkpoint.v1", InstallationID: mf.Installation, TaskPublicID: mf.Backup, ConfigVersion: 1, ConfigSHA256: mf.Config.SHA256, AttemptNo: 1, Phase: "capture", InventorySHA256: capture.Input.SourceSHA256, Part: name, JobUID: "DATA-" + name, JobGeneration: 1, InvocationSHA256: p.InvocationSHA256, SealedRef: "DATA-original-seal", ContentSHA256: p.CipherSHA256}
		p.Checkpoint, _ = json.Marshal(cp)
		capture.Parts = append(capture.Parts, p)
		data := []byte("named physical container DATA " + name)
		files.Files = append(files.Files, publicationContainerFile{Part: name, Path: "parts/" + name + "/container.enc", Receipt: staging.Receipt{Name: "container-" + name, Size: int64(len(data)), SHA256: hash(data)}})
	}
	public.SourceInventorySHA256 = capture.Input.SourceSHA256
	for i := range public.Members {
		member := &public.Members[i]
		var cp b.Checkpoint
		json.Unmarshal(member.CheckpointJSON, &cp)
		cp.InventorySHA256 = capture.Input.SourceSHA256
		member.CheckpointJSON, _ = json.Marshal(cp)
		capture.Parts = append(capture.Parts, publicationVerifiedPart{Part: member.Part, Operation: member.Operation, Index: member.PartIndex, CipherPath: member.CipherPath, EnvelopePath: member.EnvelopePath, CipherSHA256: member.CipherSHA256, EnvelopeSHA256: member.EnvelopeSHA256, CipherBytes: member.CipherBytes, EnvelopeBytes: member.EnvelopeBytes, Checkpoint: member.CheckpointJSON})
	}
	payload.Checkpoints = []publicationCertificateCheckpoint{}
	checkpointPins := map[string]string{}
	for _, p := range capture.Parts {
		cp, _ := ce.Canonical(json.RawMessage(p.Checkpoint))
		sum := hash(cp)
		payload.Checkpoints = append(payload.Checkpoints, publicationCertificateCheckpoint{Part: p.Part, SHA256: sum})
		checkpointPins[p.Part] = sum
	}
	bootstrap, err = cd.EncodeBootstrap(public, checkpointPins)
	if err != nil {
		t.Fatal(err)
	}
	for i := range capture.Parts {
		p := &capture.Parts[i]
		p.ResultEvidenceRef = "sev_named_DATA_" + p.Part
		r := d.ModuleResult{SchemaVersion: "system-backup-part-result.v1", Part: p.Part, Category: p.Category, Status: "completed", Checkpoint: p.Checkpoint, Statistics: map[string]uint64{}, Warnings: []d.Warning{}, EvidenceIDs: []string{}, FailureCategory: "none"}
		p.ResultJSON, _ = json.Marshal(r)
		p.ResultSHA256 = hash(p.ResultJSON)
	}
	capture.receipt = &publicationVerifiedCaptureReceipt{sha256: publicationVerifiedCaptureHash(capture)}
	var env originalCaptureCertificateEnvelope
	env.Payload, _ = ce.Canonical(payload)
	certRaw, _ := ce.Canonical(env)
	certificate := originalPublicationCaptureCertificate{bytes: certRaw, sha256: hash(certRaw), captureSHA256: capture.receipt.sha256, issued: payload.IssuedAt, expires: payload.ExpiresAt}
	recovery.captureSHA256 = capture.receipt.sha256
	recovery.targetSHA256 = publicationRecoveryTargetSHA(target)
	return capture, certificate, files, bootstrap, recovery, target, x.now
}

func TestOriginalManifestAssemblerRequiresCompleteBoundInputsData(t *testing.T) {
	for _, mode := range []string{"current", "missing-current-c", "changed-capture", "missing-file", "duplicate-file", "logical-hash-instead-of-physical", "expired-recovery", "recovery-target-drift", "wrong-module-result", "missing-bootstrap", "budget"} {
		t.Run(mode, func(t *testing.T) {
			capture, cert, files, bootstrap, recovery, target, now := publicationAssemblyData(t)
			limits := ArtifactReadLimits{MaxArtifactBytes: 16 << 20, MaxIndexBytes: 1 << 20}
			switch mode {
			case "missing-current-c":
				capture.receipt = nil
			case "changed-capture":
				capture.Parts[0].CipherSHA256 = hash([]byte("changed DATA"))
			case "missing-file":
				files.Files = files.Files[1:]
			case "duplicate-file":
				files.Files[0] = files.Files[1]
			case "logical-hash-instead-of-physical":
				files.Files[0].Receipt.SHA256 = "invalid"
			case "expired-recovery":
				recovery.until = now
			case "recovery-target-drift":
				target.Bucket = "other"
			case "wrong-module-result":
				capture.Parts[0].ResultJSON = []byte("{}")
				capture.receipt = &publicationVerifiedCaptureReceipt{sha256: publicationVerifiedCaptureHash(capture)}
				cert.captureSHA256 = capture.receipt.sha256
				recovery.captureSHA256 = capture.receipt.sha256
			case "missing-bootstrap":
				bootstrap = nil
			case "budget":
				limits.MaxArtifactBytes = 1
			}
			assembled, err := assembleOriginalPublicationManifest(capture, cert, files, bootstrap, recovery, target, limits, now)
			if mode != "current" {
				if err == nil || len(assembled.Manifest) != 0 {
					t.Fatal("incomplete/changed input assembled", mode)
				}
				return
			}
			if err != nil {
				t.Fatal("complete named assembly DATA rejected", err)
			}
			m, err := decodePublicationManifestV12(assembled.Manifest)
			if err != nil || len(m.Parts) != 6 || len(assembled.Objects) != 15 || len(m.Eligibility.Disqualifiers) != 0 {
				t.Fatal("wrong complete DTO", err)
			}
			for _, f := range files.Files {
				if m.Parts[f.Part].CipherSHA256 != f.Receipt.SHA256 {
					t.Fatal("logical member hash replaced physical container")
				}
			}
			if m.Business["instances"].Objects < 2 || m.Parts["workspace"].Objects != 2 {
				t.Fatal("workspace not accounted in its original instances category")
			}
			again, err := assembleOriginalPublicationManifest(capture, cert, files, bootstrap, recovery, target, limits, now.Add(time.Second))
			if err != nil || !bytes.Equal(again.Manifest, assembled.Manifest) || !bytes.Equal(again.Index, assembled.Index) {
				t.Fatal("same inputs regenerated clocks or bytes", err)
			}
		})
	}
}
