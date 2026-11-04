package systembackupexecution

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	ce "clawreef/internal/systembackupcontrolevidence"
	ma "clawreef/internal/systembackupminioauthority"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The existing component fixture uses modeled SQL/Kube and local native
// transports. This does not qualify B's actual whole-cold recovery source.
func TestMinIORecoveryLocatorPreservesOriginalTerminalBinding(t *testing.T) {
	f := newMinioSeptemberTerminalComponent(t, "")
	descriptor := ma.MinIORecoveryDescriptor{Version: ma.MinIORecoveryDescriptorVersion, ProjectionFile: filepath.Join(filepath.Dir(f.input.GrantFile), "future-recovery-projection.json"), Pin: f.input.Pin, Actor: f.declaration.Actor, DefinitionSHA256: ma.Digest(f.input.DefinitionSHA256), PermissionSourceFile: f.input.PermissionSource.File, PermissionSourceSHA256: ma.Digest(f.input.PermissionSource.SHA256), PermissionProfile: f.declaration.PermissionSource.Profile}
	raw, e := ce.Canonical(descriptor)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(filepath.Dir(f.input.GrantFile), "recovery-locator.json")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	locator := &MinIORecoveryProjectionInput{File: path, SHA256: hash(raw)}
	input := f.input
	input.RecoverySource = locator
	recovered, e := NewMinIOBootstrapTerminalResource(f.kube, input)
	if e != nil {
		t.Fatal("preinstalled locator incorrectly requires future projection", e)
	}
	oldSHA, e := f.resource.BindingSHA256()
	if e != nil {
		t.Fatal(e)
	}
	newSHA, e := recovered.BindingSHA256()
	if e != nil || oldSHA != newSHA {
		t.Fatal("independent locator rewrote original immutable terminal binding", e)
	}
	locator.File = "mutated-by-caller"
	if recovered.input.RecoverySource.File != path {
		t.Fatal("retained mutable caller locator")
	}
	descriptor.Pin.Target.InstallationID = "foreign"
	raw, e = ce.Canonical(descriptor)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	input.RecoverySource = &MinIORecoveryProjectionInput{File: path, SHA256: hash(raw)}
	if _, e = NewMinIOBootstrapTerminalResource(f.kube, input); e == nil {
		t.Fatal("different original SQL identity accepted")
	}
}
func TestMinIORecoveryAbsentLocatorKeepsOriginalPodIdentityEnforcement(t *testing.T) {
	f := newMinioSeptemberTerminalComponent(t, "")
	ctx := context.Background()
	production, e := readMinIOPermissionProductionInputs(f.input.DefinitionFile, f.input.DefinitionSHA256)
	if e != nil {
		t.Fatal(e)
	}
	defer production.clear()
	if _, e = minioCurrentRecoveryResources(ctx, f.kube, production.configuration, production.grant.Provider, nil); e != nil {
		t.Fatal("original generic native reader changed", e)
	}
	pod, e := f.kube.CoreV1().Pods(production.configuration.Namespace).Get(ctx, production.grant.Provider.Pod.Name, metav1.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	pod.UID = "replacement-without-recovery-proof"
	if _, e = f.kube.CoreV1().Pods(production.configuration.Namespace).Update(ctx, pod, metav1.UpdateOptions{}); e != nil {
		t.Fatal(e)
	}
	if _, e = minioCurrentRecoveryResources(ctx, f.kube, production.configuration, production.grant.Provider, nil); e == nil {
		t.Fatal("generic old Pod UID relaxed without dedicated proof")
	}
}
