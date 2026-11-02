package systembackupbootstrapmaterials

import (
	"path/filepath"
	"testing"

	refs "clawreef/internal/systembackupbootstrapsecurity"
	"clawreef/internal/systembackupinstallationowner/install"
	sec "clawreef/internal/systembackupsecurity"
)

func TestCaptureConsumerMaterialsCompositionDefersInputsAndKeepsOtherOwnersMissing(t *testing.T) {
	f := setupMaterials(t)
	directory := t.TempDir()
	source := install.NewCaptureSigningConsumer(filepath.Join(directory, "not-installed.json"), filepath.Join(directory, "not-installed.sha256"))
	issuers := refs.NewIssuers(directory)
	base := sec.BootstrapOwnerAdapters{Registries: map[string]sec.BootstrapResourceValidator{"rbac_bindings": refs.NewRBAC(directory), "strong_auth_issuers": issuers, "provider_proof_issuers": issuers}}
	owners, materials, e := NewEnrolledInstallationMaterials(base, f.inner, source, f.n, f.a, f.e)
	if e != nil || materials == nil || len(owners.References) != 4 || len(sec.MissingBootstrapOwnerAdapters(owners)) != 23 || len(base.References) != 0 {
		t.Fatal("deferred source changed remaining requirements or read missing inputs", e)
	}
	if _, _, e := NewEnrolledInstallationMaterials(base, nil, source, f.n, f.a, f.e); e == nil {
		t.Fatal("missing original authority replaced")
	}
	if _, _, e := NewEnrolledInstallationMaterials(owners, f.inner, source, f.n, f.a, f.e); e == nil {
		t.Fatal("existing owners overwritten")
	}
	if _, e := source.Prepare(f.ctx, f.g, f.c); e == nil {
		t.Fatal("uninstalled source became provider admission")
	}
}
