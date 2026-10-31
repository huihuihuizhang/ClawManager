package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	api "clawreef/internal/systembackupdeployment"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	k "clawreef/internal/systembackupkms"
	w "clawreef/internal/systembackupwire"
)

// The real two startup paths and original signed identities are used. SQL
// identity/SHOW GRANTS are a strict read-only transport fixture; no source,
// staging, Kubernetes or provider is opened by this file-binding test.
func TestProductionCaptureMaterialsBothStartupPaths(t *testing.T) {
	cfg := runtimeDeploymentFixture(t)
	cfg.InstallationID = "installation_capture_bootstrap"
	cfg.CaptureScope = "six-part"
	dir := t.TempDir()
	cfg.KeyDirectory, cfg.ProfileFile = dir, filepath.Join(dir, "profile.json")
	cfg.CaptureModules = &ProductionCaptureReference{Protocol: productionCaptureMaterialsVersion, Path: filepath.Join(dir, "capture.json")}
	cfg.FormalVerifier = &FormalVerifierReference{Protocol: formalVerifierMaterialsVersion, Path: filepath.Join(dir, "verifier.json")}
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(private)
	cfg.ForwardGrant = GrantReference{filepath.Join(dir, "forward.json"), base64.StdEncoding.EncodeToString(pub)}
	cfg.RecoveryGrant = GrantReference{filepath.Join(dir, "recovery.json"), base64.StdEncoding.EncodeToString(pub)}
	write := func(path string, raw []byte) {
		t.Helper()
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	profile := api.ExecutionProfile{InstallationID: cfg.InstallationID, Revision: "r1", Orchestrator: "kubernetes", Profile: "cluster", TargetClass: "dr-ready-external", TargetRisks: []string{}, FailureDomain: "local", RestoreTargetRef: "isolated", RestoreTargetHash: strings.Repeat("f", 64)}
	profileRaw, profileSHA, err := profile.CanonicalIdentity()
	if err != nil {
		t.Fatal(err)
	}
	write(cfg.ProfileFile, profileRaw)
	core, _ := json.Marshal(cfg)
	coreFile := filepath.Join(dir, "core.json")
	write(coreFile, core)
	key := make([]byte, 32)
	rand.Read(key)
	defer clear(key)
	write(filepath.Join(dir, "record-v1"), key)
	now := time.Now().UTC()
	grant := c.ExecutionGrant{Version: "system-backup-execution-grant.v1", InstallationID: cfg.InstallationID, ControllerOwner: cfg.ControllerOwner, DatabaseAccount: "local_controller@127.0.0.1", Database: "local_control", ServerUUID: "local-server", ConfigVersion: 1, ConfigSHA256: strings.Repeat("a", 64), ProfileSHA256: profileSHA, DeploymentConfigSHA256: hash(core), WorkerIssuerSHA256: strings.Repeat("e", 64), NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), Actions: []string{"prepare", "capture", "issue_worker"}, RecordKeys: []c.ExecutionRecordKey{{Ref: "record-v1", SHA256: hash(key)}}}
	sign := func(g c.ExecutionGrant, path string) (*c.PinnedExecutionIdentity, string) {
		t.Helper()
		raw, _ := json.Marshal(g)
		signed, _ := json.Marshal(map[string]string{"payload_base64": base64.StdEncoding.EncodeToString(raw), "signature_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(private, raw))})
		write(path, signed)
		identity, e := c.NewPinnedExecutionIdentity(path, hash(signed), dir, pub)
		if e != nil {
			t.Fatal(e)
		}
		return identity, hash(signed)
	}
	forward, forwardSHA := sign(grant, cfg.ForwardGrant.Path)
	recoveryGrant := grant
	recoveryGrant.Actions = []string{"recover"}
	recoveryGrant.WorkerIssuerSHA256 = ""
	recovery, recoverySHA := sign(recoveryGrant, cfg.RecoveryGrant.Path)
	workload := a.ControllerVerifierWorkload{Namespace: cfg.Namespace, PodName: "controller", PodUID: "controller-uid", ServiceAccountName: "controller", ServiceAccountUID: "controller-sa-uid", OwnerKind: "Deployment", OwnerUID: "controller-owner", ControllerOwner: cfg.ControllerOwner, ConfigVersion: 1, ConfigSHA256: grant.ConfigSHA256, GrantSHA256: strings.Repeat("b", 64)}
	formal := FormalVerifierDeploymentConfig{Version: formalVerifierMaterialsVersion, Database: reg.DatabaseIdentity{ServerUUID: grant.ServerUUID, Database: grant.Database}, Binding: reg.Binding{InstallationID: cfg.InstallationID, Key: w.KeyBinding{Provider: "external-kms", IdentityHash: strings.Repeat("c", 64), RegistryVersion: "r1", ProviderKeyID: "original-key", ProviderVersion: "1"}, Provider: reg.ProviderBinding{CAPEMSHA256: strings.Repeat("d", 64)}}, GenerateCapability: a.ProviderCapabilityPin{Issuer: pub}, UnwrapCapability: a.ProviderCapabilityPin{Issuer: pub}, InstallationIssuer: pub, CAFile: filepath.Join(dir, "unopened-ca"), JWTFile: filepath.Join(dir, "unopened-jwt"), Workload: workload, Grant: a.ControllerVerifierGrantMount{File: filepath.Join(dir, "unopened-verifier-grant"), SHA256: workload.GrantSHA256, Issuer: pub}}
	formalRaw, _ := json.Marshal(formal)
	write(cfg.FormalVerifier.Path, formalRaw)
	m := productionCaptureMaterials{Version: productionCaptureMaterialsVersion, Revision: "r1", InstallationID: cfg.InstallationID, ControllerOwner: cfg.ControllerOwner, DeploymentConfigSHA256: hash(core), CaptureGrantSHA256: forward.GrantSHA256(), Operations: map[string]productionCaptureOperation{}, MaxObjects: 100, MaxObjectBytes: 1024, MaxObjectTotalBytes: 4096, ResourceTypes: []productionResourceType{{Part: "deployment_resources", Group: "apps", Version: "v1", Resource: "deployments"}}}
	for _, operation := range []string{"capture-database", "capture-workspace", "capture-source-redis", "capture-skill-objects", "capture-deployment-resources", "capture-secret-bundle"} {
		m.Operations[operation] = productionCaptureOperation{Formal: worker.FormalCaptureSpec{Version: worker.FormalCaptureVersion, ConfigSHA256: strings.Repeat("a", 64), PermitDelivery: &k.PermitDeliveryPin{Version: k.PermitDeliveryVersion, Issuer: pub, IssuerGrantSHA256: strings.Repeat("b", 64)}}, Provider: k.Access{Operation: k.Generate}, Workload: kube.JobRequest{DeadlineSeconds: 30, Identity: kube.Identity{Namespace: cfg.Namespace}, Image: cfg.WorkerImage, StagingClaim: cfg.StagingClaim, ServiceAccount: cfg.Security.ServiceAccountName, WorkerControl: &kube.WorkerControl{URL: cfg.ControlURL}, FormalMaterials: &kube.FormalJobMaterials{ConfigMap: "original-materials"}}}
	}
	materialRaw, _ := json.Marshal(m)
	write(cfg.CaptureModules.Path, materialRaw)
	inputs := DeploymentStartupInputs{FormalVerifier: []FormalVerifierInput{{File: cfg.FormalVerifier.Path, SHA256: hash(formalRaw)}}, CaptureModules: []ProductionCaptureInput{{File: cfg.CaptureModules.Path, SHA256: hash(materialRaw)}}}
	grants, err := c.FormalCaptureGrantSQL(grant.Database, "local_controller", "127.0.0.1", false, true)
	if err != nil {
		t.Fatal(err)
	}
	for i := range grants {
		grants[i] = strings.TrimSuffix(grants[i], ";")
	}
	pool := sql.OpenDB(providerAdmissionConnector{grant: grant, grants: grants})
	defer pool.Close()
	for _, mode := range []string{"valid", "control-valid", "control-base-role", "control-missing-source", "control-generate-issuer", "missing", "wrong-pin", "wrong-file", "extra", "replaced", "unknown-field", "wrong-grant", "missing-operation", "optional-worker-command", "recovery"} {
		t.Run(mode, func(t *testing.T) {
			defer write(cfg.CaptureModules.Path, materialRaw)
			in := inputs
			in.CaptureModules = append([]ProductionCaptureInput{}, inputs.CaptureModules...)
			selectedPool := pool
			if strings.HasPrefix(mode, "control-") {
				var changed productionCaptureMaterials
				json.Unmarshal(materialRaw, &changed)
				sourcePub, _, _ := ed25519.GenerateKey(rand.Reader)
				changed.ControlEvidence = &ce.CaptureInput{SchemaRegistryFile: filepath.Join(dir, "schema.json"), SchemaRegistrySHA256: strings.Repeat("a", 64), RedactionRegistryFile: filepath.Join(dir, "redaction.json"), RedactionRegistrySHA256: strings.Repeat("b", 64), CoverageWindowSeconds: 3600}
				changed.ControlEvidenceSource = &worker.ControlEvidenceSourceMount{Endpoint: cfg.ControlURL, GrantFile: filepath.Join(dir, "worker-source-grant.json"), ControllerGrantFile: filepath.Join(dir, "controller-source-grant.json"), GrantSHA256: strings.Repeat("c", 64), Issuer: sourcePub}
				changed.Operations[ce.Operation] = changed.Operations["capture-workspace"]
				if mode == "control-missing-source" {
					changed.ControlEvidenceSource = nil
				}
				if mode == "control-generate-issuer" {
					changed.ControlEvidenceSource.Issuer = pub
				}
				raw, _ := json.Marshal(changed)
				write(cfg.CaptureModules.Path, raw)
				in.CaptureModules[0].SHA256 = hash(raw)
				if mode != "control-base-role" {
					controlGrants, e := c.ControlEvidenceGrantSQL(grant.Database, "local_controller", "127.0.0.1", false, true, false, false)
					if e != nil {
						t.Fatal(e)
					}
					for i := range controlGrants {
						controlGrants[i] = strings.TrimSuffix(controlGrants[i], ";")
					}
					selectedPool = sql.OpenDB(providerAdmissionConnector{grant: grant, grants: controlGrants})
					defer selectedPool.Close()
				}
			}
			switch mode {
			case "missing":
				in.CaptureModules = nil
			case "wrong-pin":
				in.CaptureModules[0].SHA256 = strings.Repeat("0", 64)
			case "wrong-file":
				in.CaptureModules[0].File += ".other"
			case "extra":
				in.CaptureModules = append(in.CaptureModules, in.CaptureModules[0])
			case "replaced":
				write(cfg.CaptureModules.Path, append(append([]byte{}, materialRaw...), ' '))
			case "unknown-field":
				raw := append([]byte(`{"untrusted":true,`), materialRaw[1:]...)
				write(cfg.CaptureModules.Path, raw)
				in.CaptureModules[0].SHA256 = hash(raw)
			case "wrong-grant", "missing-operation", "optional-worker-command":
				var changed productionCaptureMaterials
				json.Unmarshal(materialRaw, &changed)
				if mode == "wrong-grant" {
					changed.CaptureGrantSHA256 = strings.Repeat("0", 64)
				}
				if mode == "missing-operation" {
					delete(changed.Operations, "capture-source-redis")
				}
				if mode == "optional-worker-command" {
					x := changed.Operations["capture-skill-objects"]
					x.Workload.Command = []string{"arbitrary"}
					changed.Operations["capture-team-objects"] = x
				}
				raw, _ := json.Marshal(changed)
				write(cfg.CaptureModules.Path, raw)
				in.CaptureModules[0].SHA256 = hash(raw)
			case "recovery":
				os.Remove(cfg.CaptureModules.Path)
				os.Remove(cfg.FormalVerifier.Path)
				defer write(cfg.FormalVerifier.Path, formalRaw)
			}
			want := mode == "valid" || mode == "control-valid" || mode == "recovery"
			s := DeploymentService{ConfigPath: coreFile, ConfigDigest: hash(core), Forward: forward, Recovery: recovery, ForwardEnabled: mode != "recovery"}
			if err := s.bindDeploymentStartupInputs(in); (err == nil) != (want || mode == "control-base-role") {
				t.Fatal("actual file binding", err)
			}
			if err := CheckDeploymentDatabaseWithInputs(context.Background(), selectedPool, coreFile, hash(core), forwardSHA, recoverySHA, mode != "recovery", in); (err == nil) != want {
				t.Fatal("actual early database admission", err)
			}
			if !want && mode != "control-base-role" && (s.captureMaterials != nil || s.captureInput != nil) {
				t.Fatal("failed input retained usable capture material")
			}
			if mode == "valid" || mode == "control-valid" {
				if err := s.checkProductionCaptureMaterials(); err != nil {
					t.Fatal(err)
				}
				original, _ := os.ReadFile(cfg.CaptureModules.Path)
				write(cfg.CaptureModules.Path, append(append([]byte{}, original...), ' '))
				if s.checkProductionCaptureMaterials() == nil {
					t.Fatal("replaced independent material accepted after startup")
				}
			}
			if mode == "recovery" && (s.captureMaterials != nil || s.formalVerifier != nil) {
				t.Fatal("recovery depended on forward materials")
			}
		})
	}
}

func TestProductionCaptureEnvironmentKeepsIncompletePins(t *testing.T) {
	for _, p := range []struct{ file, digest string }{{"", ""}, {"original.json", ""}, {"", strings.Repeat("a", 64)}, {"original.json", strings.Repeat("a", 64)}} {
		t.Setenv("SYSTEM_BACKUP_CAPTURE_MATERIALS_FILE", p.file)
		t.Setenv("SYSTEM_BACKUP_CAPTURE_MATERIALS_SHA256", p.digest)
		got := ProductionCaptureInputsFromEnvironment()
		if p.file == "" && p.digest == "" {
			if len(got) != 0 {
				t.Fatal("absent inputs manufactured")
			}
			continue
		}
		if len(got) != 1 || got[0].File != p.file || got[0].SHA256 != p.digest {
			t.Fatal("partial independent pin silently discarded")
		}
	}
}
