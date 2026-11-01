package systembackupexecution

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"testing"

	cd "clawreef/internal/systembackupcapturedescription"
	s "clawreef/internal/systembackupsecurity"
)

// The actual readonly renderer and actual startup loader use the SAME pinned
// material. Resource shape is DATA; it grants no controller or key permission.
func TestDescriptionPublisherRBACRenderingDoesNotRequireRuntimeMemory(t *testing.T) {
	original := debug.SetMemoryLimit(math.MaxInt64)
	defer debug.SetMemoryLimit(original)
	cfg, formal, input := verifierAccessFixture(t)
	cfg.NamespaceUID = formal.KubernetesReads.NamespaceUID
	cfg.PublisherVerifier = &PublisherVerifierReference{Protocol: PublisherVerifierMaterialsVersion, Path: filepath.Join(t.TempDir(), "publisher.json")}
	workload := formal.Workload
	workload.ControllerOwner = "public:" + workload.PodUID
	material := PublisherVerifierMaterials{Version: PublisherVerifierMaterialsVersion, Database: formal.Database, Binding: formal.Binding, GenerateCapability: formal.GenerateCapability, UnwrapCapability: formal.UnwrapCapability, InstallationIssuer: formal.InstallationIssuer, CAFile: formal.CAFile, JWTFile: formal.JWTFile, Workload: workload, KubernetesReads: *formal.KubernetesReads, Grant: s.PublisherCaptureGrantMount{File: formal.Grant.File, SHA256: workload.GrantSHA256, Issuer: formal.Grant.Issuer}}
	inputs := DeploymentStartupInputs{FormalVerifier: []FormalVerifierInput{input}, PublisherVerifier: []PublisherVerifierInput{{File: cfg.PublisherVerifier.Path}}}
	render := func() []byte {
		t.Helper()
		raw, _ := json.Marshal(material)
		if os.WriteFile(cfg.PublisherVerifier.Path, raw, 0600) != nil {
			t.Fatal("material")
		}
		inputs.PublisherVerifier[0].SHA256 = hash(raw)
		objects, err := CaptureKubernetesGrantsWithInputs(cfg, workload.ServiceAccountName, inputs)
		if err != nil || len(objects) == 0 {
			t.Fatal("actual RBAC renderer", err)
		}
		encoded, _ := json.Marshal(objects)
		return encoded
	}
	legacy := render()
	material.DescriptionMaxPlaintextBytes = 16 << 20
	current := render()
	if !reflect.DeepEqual(legacy, current) {
		t.Fatal("resource-cap opt-in changed execution permissions")
	}
	service := &DeploymentService{Config: cfg}
	if err := service.loadPublisherVerifierInput(inputs.PublisherVerifier); !errors.Is(err, cd.ErrMemoryDeclaration) {
		t.Fatal("same input was not rejected at real runtime startup", err)
	}
	if service.publisherVerifier != nil || service.publisherVerifierInput != nil {
		t.Fatal("failed startup retained executable publisher input")
	}
}
