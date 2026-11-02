package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/worker"
	cd "clawreef/internal/systembackupcapturedescription"
	"clawreef/internal/systembackupinstallationowner/install"
	k "clawreef/internal/systembackupkms"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// Actual A enrollment/B sequence; additional signed DB/Teams declarations are
// explicit component fixtures, not native source permission observations.
func completeMappingComponentsFixture(t *testing.T, invalidPath ...string) (*OriginalCaptureSequence, OriginalCaptureMappingDefinition) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	f := newMaterialProducerComponent(t, ctx)
	var m productionCaptureMaterials
	if json.Unmarshal(f.definition.Materials, &m) != nil {
		t.Fatal("original declaration")
	}
	_, _, _, _, templates := productionModuleFixture(t)
	m.Operations["capture-team-objects"] = templates["capture-team-objects"]
	m.Operations[cd.Operation] = m.Operations["capture-workspace"]
	if len(invalidPath) != 0 {
		for name, operation := range m.Operations {
			input := operation.Workload.FormalMaterials.Inputs[0]
			input.Items = append(append([]corev1.KeyToPath(nil), input.Items...), corev1.KeyToPath{Key: "extra", Path: invalidPath[0]})
			operation.Workload.FormalMaterials.Inputs = []kube.FormalInputMount{input}
			m.Operations[name] = operation
		}
	}
	f.definition.Materials, _ = json.Marshal(m)
	raw, _ := json.Marshal(f.definition)
	f.definitionSHA = hash(raw)
	if err := os.WriteFile(f.definitionFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := BeginOriginalCaptureSequence(ctx, f.installer, f.password, f.enrollment, f.definitionFile, f.definitionSHA, f.privateFile)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(s.materials.Redis.Redis.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	d := OriginalCaptureMappingDefinition{Version: OriginalCaptureMappingDefinitionVersion, OriginalDefinitionSHA256: f.definitionSHA, KMS: map[string]k.Config{}}
	for name, op := range s.materials.Operations {
		d.KMS[name] = k.Config{InstallationID: s.core.InstallationID, Endpoint: op.Provider.Endpoint, KeyName: op.Provider.KeyName, Key: op.Provider.Request.Key, CAPEM: ca, CASHA256: hash(ca), NotBefore: s.definition.NotBefore, NotAfter: s.definition.Until}
	}
	key, err := install.ReadPrivateFile(f.privateFile, ed25519.PrivateKeySize)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	directory := filepath.Dir(f.definitionFile)
	issue := func(name string, mount worker.FormalSourceMount) worker.FormalSourceMount {
		t.Helper()
		mount.GrantFile = filepath.Join(directory, name+"-component-grant.json")
		mount.Issuer = append(ed25519.PublicKey(nil), s.materials.Discovery.Issuer...)
		mount.CredentialFile = filepath.Join(directory, name+"-component-credential.json")
		credential := []byte(`{"username":"component-source","password":"Y29tcG9uZW50LW9ubHk="}`)
		if name == "capture-team-objects" {
			credential = []byte(`{"access_key":"component-team-source","secret_key":"Y29tcG9uZW50LW9ubHk="}`)
		}
		if err := os.WriteFile(mount.CredentialFile, credential, 0600); err != nil {
			t.Fatal(err)
		}
		mount.CredentialSHA256 = hash(credential)
		request := s.materials.Operations[name].Request
		request.Operation = name
		scope, err := worker.FormalSourceScopeSHA256(worker.Invocation{Request: request}, mount)
		if name == "capture-team-objects" {
			scope, err = worker.TeamObjectsSourceScopeSHA256(mount)
		}
		if err != nil {
			t.Fatal(err)
		}
		record, _ := json.Marshal(worker.FormalSourceGrant{Version: worker.FormalSourceGrantVersion, InstallationID: s.core.InstallationID, ConfigSHA256: s.definition.ConfigSHA256, WorkerNamespace: s.core.Namespace, WorkerServiceAccountUID: s.core.Security.ServiceAccountUID, Operation: name, ScopeSHA256: scope, CredentialSHA256: mount.CredentialSHA256, NotBefore: s.definition.NotBefore, Until: s.definition.Until})
		raw, _ := json.Marshal(worker.SignedFormalSourceGrant{Record: record, Signature: ed25519.Sign(ed25519.PrivateKey(key), append([]byte(worker.FormalSourceGrantDomain), record...))})
		if err := os.WriteFile(mount.GrantFile, raw, 0600); err != nil {
			t.Fatal(err)
		}
		mount.GrantSHA256 = hash(raw)
		d.Files = append(d.Files, OriginalCaptureMappingFile{WorkerPath: mount.GrantFile, File: mount.GrantFile, SHA256: mount.GrantSHA256})
		return mount
	}
	d.DatabaseSource = issue("capture-database", worker.FormalSourceMount{})
	team := issue("capture-team-objects", worker.FormalSourceMount{Objects: s.materials.Objects.Objects, ObjectPrefixes: []worker.ObjectSourcePrefix{{Bucket: "original-team-source", Prefix: "owned/teams/"}}})
	d.TeamsSource = &team
	return s, d
}

func TestOriginalCaptureMappingHandlesAllNineOriginalOperationsComponent(t *testing.T) {
	s, d := completeMappingComponentsFixture(t)
	if _, err := newProductionCapturePlan(s.materials.Operations, s.materials.Revision); err != nil || len(s.materials.Operations) != 9 {
		t.Fatal("complete original plan", err)
	}
	for name, operation := range s.materials.Operations {
		m, err := s.mappingComponents(name, operation, d)
		if err != nil {
			t.Fatal("legitimate original operation mapping", name, err)
		}
		if name == cd.Operation && (m.Sources != nil || m.Resources != nil || m.ControlEvidence != nil) {
			t.Fatal("description acquired another source scope")
		}
		if name == "capture-team-objects" && (m.Sources == nil || m.Sources.GrantFile != d.TeamsSource.GrantFile || m.Sources.GrantFile == s.materials.Objects.GrantFile) {
			t.Fatal("Teams borrowed another operation grant")
		}
	}
	d.TeamsSource = &s.materials.Objects
	if _, err := s.mappingComponents("capture-team-objects", s.materials.Operations["capture-team-objects"], d); err == nil {
		t.Fatal("Skill grant reused for Teams")
	}
}

func TestOriginalCaptureMappingRejectsZeroKMSWindowBeforeConsumptionComponent(t *testing.T) {
	s, d := completeMappingComponentsFixture(t)
	name := "capture-workspace"
	config := d.KMS[name]
	config.NotBefore = time.Time{}
	d.KMS[name] = config
	if _, err := s.mappingComponents(name, s.materials.Operations[name], d); err == nil {
		t.Fatal("zero KMS NotBefore survived materialization")
	}
}

func TestOriginalCaptureMappingRejectsBuilderInvalidProjectionBeforeCreateComponent(t *testing.T) {
	s, d := completeMappingComponentsFixture(t, "bad:name")
	raw, _ := json.Marshal(d)
	file := filepath.Join(filepath.Dir(s.privateFile), "bad-projection-components.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleClientset()
	_, err := s.MaterializeMappings(s.ctx, client, file, hash(raw), filepath.Join(filepath.Dir(s.privateFile), "bad-projection-intermediate.json"))
	if err == nil || len(client.Actions()) != 0 {
		t.Fatal("builder-invalid projection reached an API create/read", err)
	}
}
