package systembackupbootstrapmaterials

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	refs "clawreef/internal/systembackupbootstrapsecurity"
	"clawreef/internal/systembackupinstallationowner/install"
	sec "clawreef/internal/systembackupsecurity"
)

func TestEnrolledTerminalOwnersKeepOneDirectAuthorityWithoutCaptureWrapper(t *testing.T) {
	f := setupMaterials(t)
	directory := t.TempDir()
	capture := install.NewCaptureSigningConsumer(filepath.Join(directory, "missing-consumer.json"), filepath.Join(directory, "missing-consumer.sha256"))
	issuers := refs.NewIssuers(directory)
	base := sec.BootstrapOwnerAdapters{Registries: map[string]sec.BootstrapResourceValidator{"rbac_bindings": refs.NewRBAC(directory), "strong_auth_issuers": issuers, "provider_proof_issuers": issuers}}
	files := install.BootstrapTerminalFiles{MappingFile: filepath.Join(directory, "missing-original.json"), MappingSHA256: strings.Repeat("a", 64), SignatureFile: filepath.Join(directory, "missing-original.sig"), EvidenceFile: filepath.Join(directory, "missing-evidence.json"), RegistryDirectory: directory}
	owners, terminal, err := NewEnrolledTerminalInstallationOwners(base, capture, files, f.n, f.a, f.e)
	if err != nil || terminal == nil || len(sec.MissingBootstrapOwnerAdapters(owners)) != 23 || len(terminal.MissingTerminalResources()) != 23 {
		t.Fatal("concrete terminal composition", err)
	}
	terminalOwners, err := terminal.Owners()
	if err != nil || terminalOwners.References["nonce_hmac"] != owners.References["nonce_hmac"] || terminalOwners.References["artifact_ca"] != owners.References["artifact_ca"] || terminalOwners.References["evidence_ca"] != owners.References["evidence_ca"] || owners.References["capture_signing"] != capture {
		t.Fatal("terminal/owner maps do not share actual owner instances", err)
	}
	candidates, err := sec.NewBootstrapDeploymentCandidates(f.r.Candidates, terminal)
	if err != nil {
		t.Fatal("direct actual terminal candidate construction", err)
	}
	// Inspect the actual immutable candidate state without exposing its private
	// authority as a new production API. Pointer equality excludes BOTH legacy
	// captureConsumerAuthority and Materials wrappers around this terminal.
	state := reflect.ValueOf(candidates).Elem().FieldByName("state").Elem()
	authority := state.FieldByName("authority").Elem()
	if authority.Type() != reflect.TypeOf(terminal) || authority.Pointer() != reflect.ValueOf(terminal).Pointer() {
		t.Fatal("terminal was wrapped/replaced in actual candidate state")
	}
	if _, err := terminal.PrepareBootstrapCandidates(f.ctx, f.g, f.c, f.r); err == nil || f.handshakes.Load() != 0 || len(f.inner.phases) != 0 {
		t.Fatal("missing owners became admission or invoked a synthetic Original", err)
	}
	if len(base.References) != 0 || base.Candidates != nil {
		t.Fatal("composition mutated caller maps")
	}
	if _, _, err := NewEnrolledTerminalInstallationOwners(owners, capture, files, f.n, f.a, f.e); err == nil {
		t.Fatal("existing owner bindings overwritten")
	}
}
