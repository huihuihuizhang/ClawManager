package systembackupexecution

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	api "clawreef/internal/systembackupdeployment"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	w "clawreef/internal/systembackupwire"
)

func TestFormalVerifierFileBootstrapHasNoForwardGrantHashCycle(t *testing.T) {
	cfg := testDeploymentConfiguration(t)
	cfg.InstallationID = "installation_file_bootstrap"
	dir := t.TempDir()
	materialFile := filepath.Join(dir, "derived-materials.json")
	cfg.FormalVerifier = &FormalVerifierReference{Protocol: formalVerifierMaterialsVersion, Path: materialFile}
	issuer, private, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(private)
	grantFile := filepath.Join(dir, "forward.json")
	cfg.KeyDirectory = dir
	cfg.ForwardGrant = GrantReference{Path: grantFile, PublicKey: base64.StdEncoding.EncodeToString(issuer)}
	recoveryIssuer, recoveryKey, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(recoveryKey)
	cfg.RecoveryGrant = GrantReference{Path: filepath.Join(dir, "recovery.json"), PublicKey: base64.StdEncoding.EncodeToString(recoveryIssuer)}
	profile := api.ExecutionProfile{InstallationID: cfg.InstallationID, Revision: "r1", Orchestrator: "kubernetes", Profile: "cluster", TargetClass: "dr-ready-external", TargetRisks: []string{}, FailureDomain: "local-test", RestoreTargetRef: "isolated-target", RestoreTargetHash: strings.Repeat("f", 64)}
	profileRaw, profileHash, err := profile.CanonicalIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if os.WriteFile(cfg.ProfileFile, profileRaw, 0600) != nil {
		t.Fatal("profile file failed")
	}
	core, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	coreFile := filepath.Join(dir, "deployment.json")
	if os.WriteFile(coreFile, core, 0600) != nil {
		t.Fatal("core file write failed")
	}
	_, err = LoadDeploymentConfig(coreFile, hash(core))
	if err != nil {
		t.Fatal("actual pinned core file load", err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	defer clear(key)
	if os.WriteFile(filepath.Join(dir, "record-v1"), key, 0600) != nil {
		t.Fatal("record key fixture failed")
	}
	now := time.Now().UTC()
	forward := c.ExecutionGrant{Version: "system-backup-execution-grant.v1", InstallationID: cfg.InstallationID, ControllerOwner: cfg.ControllerOwner, DatabaseAccount: "local_controller@127.0.0.1", Database: "local_control", ServerUUID: "b9c4d686-d4d3-11f1-9eb5-745d22085e06", ConfigVersion: 1, ConfigSHA256: strings.Repeat("a", 64), ProfileSHA256: profileHash, DeploymentConfigSHA256: hash(core), WorkerIssuerSHA256: strings.Repeat("e", 64), NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), Actions: []string{"prepare", "capture", "issue_worker"}, RecordKeys: []c.ExecutionRecordKey{{Ref: "record-v1", SHA256: hash(key)}}}
	payload, _ := json.Marshal(forward)
	envelope, _ := json.Marshal(map[string]string{"payload_base64": base64.StdEncoding.EncodeToString(payload), "signature_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))})
	if os.WriteFile(grantFile, envelope, 0600) != nil {
		t.Fatal("forward file failed")
	}
	identity, err := c.NewPinnedExecutionIdentity(grantFile, hash(envelope), dir, issuer)
	if err != nil {
		t.Fatal("actual signed Forward identity load", err)
	}
	recovery := forward
	recovery.Actions = []string{"recover"}
	recovery.WorkerIssuerSHA256 = ""
	recoveryBody, _ := json.Marshal(recovery)
	recoveryEnvelope, _ := json.Marshal(map[string]string{"payload_base64": base64.StdEncoding.EncodeToString(recoveryBody), "signature_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(recoveryKey, recoveryBody))})
	if os.WriteFile(cfg.RecoveryGrant.Path, recoveryEnvelope, 0600) != nil {
		t.Fatal("recovery file failed")
	}
	recoveryIdentity, err := deploymentIdentity(cfg.RecoveryGrant, hash(recoveryEnvelope), dir)
	if err != nil {
		t.Fatal(err)
	}
	workload := a.ControllerVerifierWorkload{Namespace: "controller", PodName: "controller-pod", PodUID: "controller-pod-uid", ServiceAccountName: "controller", ServiceAccountUID: "controller-sa-uid", OwnerKind: "Deployment", OwnerUID: "deployment-uid", ControllerOwner: cfg.ControllerOwner, ConfigVersion: 1, ConfigSHA256: forward.ConfigSHA256}
	verifierIssuer, verifierKey, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(verifierKey)
	verifierGrant := a.ControllerVerifierGrant{Version: "system-backup-controller-verifier-grant.v1", InstallationID: cfg.InstallationID, Database: reg.DatabaseIdentity{ServerUUID: forward.ServerUUID, Database: forward.Database}, DatabaseAccount: forward.DatabaseAccount, Workload: workload, CaptureGrantSHA256: identity.GrantSHA256(), NotBefore: forward.NotBefore, Until: forward.ExpiresAt}
	verifierRaw, _ := json.Marshal(verifierGrant)
	verifierEnvelope, _ := json.Marshal(a.SignedControllerVerifierGrant{Record: verifierRaw, Signature: ed25519.Sign(verifierKey, append([]byte(a.ControllerVerifierGrantDomain), verifierRaw...))})
	verifierFile := filepath.Join(dir, "verifier.json")
	if os.WriteFile(verifierFile, verifierEnvelope, 0600) != nil {
		t.Fatal("verifier file failed")
	}
	workload.GrantSHA256 = hash(verifierEnvelope)
	materials := FormalVerifierDeploymentConfig{Version: formalVerifierMaterialsVersion, Database: verifierGrant.Database, Binding: reg.Binding{InstallationID: cfg.InstallationID, Key: w.KeyBinding{Provider: "external-kms", IdentityHash: strings.Repeat("c", 64), RegistryVersion: "r1", ProviderKeyID: "original-key", ProviderVersion: "1"}, Provider: reg.ProviderBinding{CAPEMSHA256: strings.Repeat("d", 64)}}, GenerateCapability: a.ProviderCapabilityPin{Issuer: issuer}, UnwrapCapability: a.ProviderCapabilityPin{Issuer: issuer}, InstallationIssuer: issuer, CAFile: filepath.Join(dir, "ca.crt"), JWTFile: filepath.Join(dir, "controller.jwt"), Workload: workload, Grant: a.ControllerVerifierGrantMount{File: verifierFile, SHA256: workload.GrantSHA256, Issuer: verifierIssuer}}
	materialRaw, _ := json.Marshal(materials)
	if os.WriteFile(materialFile, materialRaw, 0600) != nil {
		t.Fatal("material file failed")
	}
	service := DeploymentService{ConfigPath: coreFile, ConfigDigest: hash(core), Forward: identity, Recovery: recoveryIdentity, ForwardEnabled: true}
	if err = service.bindDeploymentFileInputs([]FormalVerifierInput{{File: materialFile, SHA256: hash(materialRaw)}}); err != nil {
		t.Fatal("independent startup bundle could not load after Forward existed", err)
	}
	if identity.DeploymentBinding().DeploymentConfigSHA256 != hash(core) || hash(verifierEnvelope) != service.formalVerifier.Workload.GrantSHA256 || verifierGrant.CaptureGrantSHA256 != identity.GrantSHA256() {
		t.Fatal("original dependency binding lost")
	}
	if _, err = LoadDeploymentConfig(coreFile, hash(core)); err != nil {
		t.Fatal("derived grant changed core digest", err)
	}
	for _, fault := range []string{"core-original-pin", "signed-forward-config", "signed-forward-profile"} {
		t.Run(fault, func(t *testing.T) {
			defer os.WriteFile(coreFile, core, 0600)
			defer os.WriteFile(grantFile, envelope, 0600)
			current := identity
			if fault == "core-original-pin" {
				if os.WriteFile(coreFile, append(append([]byte{}, core...), ' '), 0600) != nil {
					t.Fatal("core change fixture")
				}
			} else {
				changed := forward
				if fault == "signed-forward-config" {
					changed.DeploymentConfigSHA256 = strings.Repeat("0", 64)
				} else {
					changed.ProfileSHA256 = strings.Repeat("0", 64)
				}
				body, _ := json.Marshal(changed)
				signed, _ := json.Marshal(map[string]string{"payload_base64": base64.StdEncoding.EncodeToString(body), "signature_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(private, body))})
				if os.WriteFile(grantFile, signed, 0600) != nil {
					t.Fatal("signed forward fixture")
				}
				var err error
				current, err = deploymentIdentity(cfg.ForwardGrant, hash(signed), dir)
				if err != nil {
					t.Fatal("negative must have a VALID original issuer signature", err)
				}
			}
			s := DeploymentService{ConfigPath: coreFile, ConfigDigest: hash(core), Forward: current, Recovery: recoveryIdentity, ForwardEnabled: true}
			if s.bindDeploymentFileInputs([]FormalVerifierInput{{File: materialFile, SHA256: hash(materialRaw)}}) == nil || s.formalVerifier != nil {
				t.Fatal("wrong cross-layer core/Forward binding reached verifier material loading")
			}
		})
	}
	for _, fault := range []string{"missing", "wrong-hash", "wrong-file", "duplicate-key", "unknown-field"} {
		t.Run(fault, func(t *testing.T) {
			testRaw := append([]byte(nil), materialRaw...)
			switch fault {
			case "duplicate-key":
				testRaw = append([]byte(`{"schema_version":"ignored",`), testRaw[1:]...)
			case "unknown-field":
				testRaw = append([]byte(`{"untrusted":true,`), testRaw[1:]...)
			}
			if os.WriteFile(materialFile, testRaw, 0600) != nil {
				t.Fatal("fixture write")
			}
			inputs := []FormalVerifierInput{{File: materialFile, SHA256: hash(testRaw)}}
			switch fault {
			case "missing":
				inputs = nil
			case "wrong-hash":
				inputs[0].SHA256 = strings.Repeat("0", 64)
			case "wrong-file":
				inputs[0].File = filepath.Join(dir, "another.json")
			}
			s := DeploymentService{ConfigPath: coreFile, ConfigDigest: hash(core), Forward: identity, Recovery: recoveryIdentity, ForwardEnabled: true}
			if s.bindDeploymentFileInputs(inputs) == nil {
				t.Fatal("invalid independently pinned material bundle admitted", fault)
			}
		})
	}
}
