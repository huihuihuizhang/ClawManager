package host

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"clawreef/internal/systembackup/profile"
	"clawreef/internal/systembackup/quiesce"
	"clawreef/internal/systembackup/worker"
)

func hostFixture(t *testing.T) Config {
	root := t.TempDir()
	path := func(name string) string { return filepath.Join(root, name) }
	return Config{Owner: "fixture", Listen: "127.0.0.1:9443", ControlDatabase: path("control.json"), StagingPath: path("stage"), EvidencePath: path("evidence"), ArtifactPath: path("artifacts"), Relay: TLSFiles{path("ca"), path("cert"), path("key")}, NodeProof: TLSFiles{path("ca"), path("cert"), path("key")}, IssuerCertificate: path("issuer-cert"), IssuerKey: path("issuer-key"), TrustDomain: "fixture.local", KeysFile: path("keys"), NodeEndpoints: map[string]quiesce.ProofEndpoint{"fixture": {URL: "https://127.0.0.1:9444", ServerURI: "spiffe://fixture/node/fixture"}}, Profiles: []Profile{{SourceCredential: path("source"), SourceAdminCredential: path("source-admin"), TargetAdminCredential: path("target"), Config: profile.Config{ID: "fixture", Namespace: "source", TargetNamespace: "cm-drill-fixture", WorkerImage: "worker@sha256:" + strings.Repeat("a", 64), ServiceAccount: "worker", ControlURL: "https://127.0.0.1:9443/worker/v1", Source: worker.DatabaseSpec{Name: "source", ServerUUID: "source"}, Target: worker.DatabaseSpec{Name: "cm_drill_fixture", ServerUUID: "target"}, TargetStorageClass: "fixture", TargetStorageSize: "1Gi", Staging: map[string]profile.Claim{"source": {Name: "stage", UID: "uid1"}, "cm-drill-fixture": {Name: "stage", UID: "uid2"}}, Evidence: profile.Claim{Name: "evidence", UID: "uid3"}, PolicyVersion: "policy-v1", KeyVersion: "key-v1", SignerID: "signer-v1", MaxFiles: 10, MaxFileBytes: 1024, MaxArchiveBytes: 2048, MaxCompressedBytes: 4096}}}}
}
func TestLoadIsOfflineAndRejectsAmbiguousConfiguration(t *testing.T) {
	c := hostFixture(t)
	raw, _ := json.Marshal(c)
	path := filepath.Join(t.TempDir(), "controller.json")
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	// None of the credentials, CA files, kubeconfig or databases exist. Loading
	// structure must not connect to anything or create those files.
	if _, e := Load(path); e != nil {
		t.Fatal(e)
	}
	c.Profiles = append(c.Profiles, c.Profiles[0])
	if c.Validate() == nil {
		t.Fatal("duplicate driver accepted")
	}
	if e := os.WriteFile(path, append(raw, []byte(" {}")...), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Load(path); e == nil {
		t.Fatal("trailing config accepted")
	}
	raw = []byte(`{"UnknownCredential":"do-not-echo"}`)
	os.WriteFile(path, raw, 0600)
	if _, e := Load(path); e == nil || strings.Contains(e.Error(), "do-not-echo") {
		t.Fatal("unknown/secret config accepted or echoed")
	}
}
func TestTargetProfileHasNoSourceCredentialDependency(t *testing.T) {
	c := hostFixture(t)
	c.Profiles[0].Config.Mode = "target"
	c.Profiles[0].SourceCredential = ""
	c.Profiles[0].SourceAdminCredential = ""
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	m := (&profile.Driver{Config: c.Profiles[0].Config}).Metadata()
	if len(m.Kinds) != 2 || m.Kinds[0] != "drill" {
		t.Fatal("target profile advertised backup")
	}
}

func TestDeploymentExampleCanBeCheckedOfflineOnDevelopmentHost(t *testing.T) {
	path, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "examples", "backup-controller", "controller.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal("Linux deployment example failed offline structural validation", err)
	}
	if len(c.Profiles[0].Config.Applications) == 0 || c.Profiles[0].Config.WriterProofURL == "" {
		t.Fatal("coverage prerequisites missing from example")
	}
}
