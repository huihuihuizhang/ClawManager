package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	deployment "clawreef/internal/systembackupdeployment"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
	w "clawreef/internal/systembackupwire"
)

// Real common material loader plus both real production startup entrypoints.
// Only DB identity/SHOW GRANTS use the existing read-only transport fixture;
// no task, source pause, provider grant or readiness flag is fabricated.
func TestOriginalPublicationPolicyBeforeBothStartupEntries(t *testing.T) {
	for _, mode := range []string{"valid-policy", "missing", "missing-file", "wrong-hash", "wrong-installation", "wrong-config", "wrong-target", "legacy-no-policy", "recovery-no-policy"} {
		t.Run(mode, func(t *testing.T) {
			cfg := runtimeDeploymentFixture(t)
			cfg.InstallationID = "installation_policy_startup"
			cfg.CaptureScope = "six-part"
			directory := t.TempDir()
			cfg.KeyDirectory = directory
			cfg.ProfileFile = filepath.Join(directory, "profile.json")
			cfg.CaptureModules = &ProductionCaptureReference{Protocol: productionCaptureMaterialsVersion, Path: filepath.Join(directory, "capture.json")}
			cfg.FormalVerifier = &FormalVerifierReference{Protocol: formalVerifierMaterialsVersion, Path: filepath.Join(directory, "formal.json")}
			if mode != "legacy-no-policy" {
				cfg.PublicationTarget = &PublicationTargetReference{Protocol: publicationTargetVersion, Path: filepath.Join(directory, "target-not-loaded-before-policy.json")}
			}
			public, key, _ := ed25519.GenerateKey(rand.Reader)
			defer clear(key)
			cfg.ForwardGrant = GrantReference{filepath.Join(directory, "forward.json"), base64.StdEncoding.EncodeToString(public)}
			cfg.RecoveryGrant = GrantReference{filepath.Join(directory, "recovery.json"), base64.StdEncoding.EncodeToString(public)}
			write := func(path string, raw []byte) {
				t.Helper()
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			profile := deployment.ExecutionProfile{InstallationID: cfg.InstallationID, Revision: "r1", Orchestrator: "kubernetes", Profile: "cluster", TargetClass: "dr-ready-external", TargetRisks: []string{}, FailureDomain: "local", RestoreTargetRef: "isolated", RestoreTargetHash: strings.Repeat("f", 64)}
			profileRaw, profileSHA, err := profile.CanonicalIdentity()
			if err != nil {
				t.Fatal(err)
			}
			write(cfg.ProfileFile, profileRaw)
			core, _ := json.Marshal(cfg)
			coreFile := filepath.Join(directory, "core.json")
			write(coreFile, core)
			recordKey := make([]byte, 32)
			rand.Read(recordKey)
			defer clear(recordKey)
			write(filepath.Join(directory, "record-v1"), recordKey)
			now := time.Now().UTC()
			grant := c.ExecutionGrant{Version: "system-backup-execution-grant.v1", InstallationID: cfg.InstallationID, ControllerOwner: cfg.ControllerOwner, DatabaseAccount: "local_controller@127.0.0.1", Database: "local_control", ServerUUID: "local-server", ConfigVersion: 1, ConfigSHA256: strings.Repeat("a", 64), ProfileSHA256: profileSHA, DeploymentConfigSHA256: hash(core), WorkerIssuerSHA256: strings.Repeat("e", 64), NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), Actions: []string{"prepare", "capture", "issue_worker"}, RecordKeys: []c.ExecutionRecordKey{{Ref: "record-v1", SHA256: hash(recordKey)}}}
			sign := func(g c.ExecutionGrant, file string) (*c.PinnedExecutionIdentity, string) {
				t.Helper()
				raw, _ := json.Marshal(g)
				envelope, _ := json.Marshal(map[string]string{"payload_base64": base64.StdEncoding.EncodeToString(raw), "signature_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))})
				write(file, envelope)
				identity, err := c.NewPinnedExecutionIdentity(file, hash(envelope), directory, public)
				if err != nil {
					t.Fatal(err)
				}
				return identity, hash(envelope)
			}
			forward, forwardSHA := sign(grant, cfg.ForwardGrant.Path)
			recoveryGrant := grant
			recoveryGrant.Actions = []string{"recover"}
			recoveryGrant.WorkerIssuerSHA256 = ""
			recovery, recoverySHA := sign(recoveryGrant, cfg.RecoveryGrant.Path)
			workload := a.ControllerVerifierWorkload{Namespace: cfg.Namespace, PodName: "controller", PodUID: "controller-uid", ServiceAccountName: "controller", ServiceAccountUID: "controller-sa-uid", OwnerKind: "Deployment", OwnerUID: "controller-owner", ControllerOwner: cfg.ControllerOwner, ConfigVersion: 1, ConfigSHA256: grant.ConfigSHA256, GrantSHA256: strings.Repeat("b", 64)}
			formal := FormalVerifierDeploymentConfig{Version: formalVerifierMaterialsVersion, Database: reg.DatabaseIdentity{ServerUUID: grant.ServerUUID, Database: grant.Database}, Binding: reg.Binding{InstallationID: cfg.InstallationID, Key: w.KeyBinding{Provider: "external-kms", IdentityHash: strings.Repeat("c", 64), RegistryVersion: "r1", ProviderKeyID: "original-key", ProviderVersion: "1"}, Provider: reg.ProviderBinding{CAPEMSHA256: strings.Repeat("d", 64)}}, GenerateCapability: a.ProviderCapabilityPin{Issuer: public}, UnwrapCapability: a.ProviderCapabilityPin{Issuer: public}, InstallationIssuer: public, CAFile: filepath.Join(directory, "unopened-ca"), JWTFile: filepath.Join(directory, "unopened-jwt"), Workload: workload, Grant: a.ControllerVerifierGrantMount{File: filepath.Join(directory, "unopened-grant"), SHA256: workload.GrantSHA256, Issuer: public}}
			formalRaw, _ := json.Marshal(formal)
			write(cfg.FormalVerifier.Path, formalRaw)
			materials := productionCaptureMaterials{Version: productionCaptureMaterialsVersion, Revision: "r1", InstallationID: cfg.InstallationID, ControllerOwner: cfg.ControllerOwner, DeploymentConfigSHA256: hash(core), CaptureGrantSHA256: forward.GrantSHA256(), Operations: map[string]productionCaptureOperation{}, MaxObjects: 100, MaxObjectBytes: 1024, MaxObjectTotalBytes: 4096, ResourceTypes: []productionResourceType{{Part: "deployment_resources", Group: "apps", Version: "v1", Resource: "deployments"}}}
			for _, op := range []string{"capture-database", "capture-workspace", "capture-source-redis", "capture-skill-objects", "capture-deployment-resources", "capture-secret-bundle"} {
				materials.Operations[op] = productionCaptureOperation{Formal: worker.FormalCaptureSpec{Version: worker.FormalCaptureVersion, ConfigSHA256: strings.Repeat("a", 64), PermitDelivery: &kms.PermitDeliveryPin{Version: kms.PermitDeliveryVersion, Issuer: public, IssuerGrantSHA256: strings.Repeat("b", 64)}}, Provider: kms.Access{Operation: kms.Generate}, Workload: kube.JobRequest{DeadlineSeconds: 30, Identity: kube.Identity{Namespace: cfg.Namespace}, Image: cfg.WorkerImage, StagingClaim: cfg.StagingClaim, ServiceAccount: cfg.Security.ServiceAccountName, WorkerControl: &kube.WorkerControl{URL: cfg.ControlURL}, FormalMaterials: &kube.FormalJobMaterials{ConfigMap: "original-materials"}}}
			}
			_, source, _, _, _ := productionModuleFixture(t)
			var metadata productionCaptureMetadata
			json.Unmarshal(source.CaptureMetadata, &metadata)
			discoveryIssuer, _, _ := ed25519.GenerateKey(rand.Reader)
			writer := cfg.Writers[0]
			discovery := &productionSourceDiscovery{Issuer: discoveryIssuer, GrantFile: filepath.Join(directory, "source-grant"), GrantSHA256: strings.Repeat("a", 64), ControllerDeployment: "controller", ControllerDeploymentUID: "controller-uid", ControllerServiceAccount: "controller", ControllerServiceAccountUID: "controller-sa", SourceAPIServiceAccount: "metadata", SourceAPIServiceAccountUID: "metadata-sa", SourceAPI: worker.ResourceSourceMount{Server: "https://metadata.invalid", CAFile: filepath.Join(directory, "source-ca"), TokenFile: filepath.Join(directory, "source-token"), CASHA256: strings.Repeat("a", 64)}, SourceAPITokenSHA256: strings.Repeat("b", 64), Redis: metadata.Redis, RuntimePolicies: []worker.RuntimePolicy{metadata.Mounts[0].Policy}, ResourceActors: map[string]productionSourceActor{"deployment_resources": {Name: "resources", UID: "resources-uid"}, "secret_bundle": {Name: "secrets", UID: "secrets-uid"}}, TeamPlatformUnits: map[string][]string{"deployment/" + writer.Namespace + "/" + writer.Name: append([]string{}, b.TeamsWorkUnits()...)}}
			materials.Discovery = discovery
			if mode != "missing" && mode != "legacy-no-policy" && mode != "recovery-no-policy" {
				p := originalPublicationPolicy{Version: originalPublicationPolicyVersion, Installation: cfg.InstallationID, ConfigSHA256: grant.ConfigSHA256, FailureDomains: ce.RegistryPin{Version: "r1", SHA256: strings.Repeat("c", 64)}, Target: publicationManifestTarget{Class: profile.TargetClass, Domain: profile.FailureDomain, Risks: []string{}}, RecoveryEvidenceStatus: "not_provided"}
				if mode == "wrong-installation" {
					p.Installation = "installation_other"
				}
				if mode == "wrong-config" {
					p.ConfigSHA256 = strings.Repeat("0", 64)
				}
				if mode == "wrong-target" {
					p.Target.Domain = "other"
				}
				raw, _ := ce.Canonical(p)
				file := filepath.Join(directory, "policy.json")
				write(file, raw)
				discovery.PublicationPolicy = &originalPublicationPolicyReference{Protocol: originalPublicationPolicyVersion, Path: file, SHA256: hash(raw)}
				if mode == "wrong-hash" {
					discovery.PublicationPolicy.SHA256 = strings.Repeat("0", 64)
				}
				if mode == "missing-file" {
					os.Remove(file)
				}
			}
			materialRaw, _ := json.Marshal(materials)
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
			enabled := mode != "recovery-no-policy"
			service := &DeploymentService{Config: cfg, ConfigPath: coreFile, ConfigDigest: hash(core), Forward: forward, Recovery: recovery, ForwardEnabled: enabled}
			if mode == "valid-policy" {
				if err = service.loadProductionCapture(inputs.CaptureModules); err != nil {
					t.Fatal("valid policy rejected by actual common material loader", err)
				}
			}
			fileErr := service.bindDeploymentStartupInputs(inputs)
			databaseErr := CheckDeploymentDatabaseWithInputs(context.Background(), pool, coreFile, hash(core), forwardSHA, recoverySHA, enabled, inputs)
			switch mode {
			case "legacy-no-policy", "recovery-no-policy":
				if fileErr != nil || databaseErr != nil {
					t.Fatal("non-publication/recovery boundary changed", fileErr, databaseErr)
				}
			case "valid-policy":
				if errors.Is(fileErr, ErrOriginalPublicationPolicy) || errors.Is(databaseErr, ErrOriginalPublicationPolicy) {
					t.Fatal("valid policy failed material scope check", fileErr, databaseErr)
				}
				// This named fixture intentionally provides no target/publisher material;
				// it must still fail their later checks, rather than reporting ready.
				if fileErr == nil || databaseErr == nil {
					t.Fatal("missing later publication inputs reported ready")
				}
			default:
				if !errors.Is(fileErr, ErrOriginalPublicationPolicy) || !errors.Is(databaseErr, ErrOriginalPublicationPolicy) || service.captureMaterials != nil {
					t.Fatal("missing/changed policy passed either real startup entry", mode, fileErr, databaseErr)
				}
			}
		})
	}
}
