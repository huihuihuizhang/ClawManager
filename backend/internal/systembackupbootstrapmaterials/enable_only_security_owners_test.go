package systembackupbootstrapmaterials

import (
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	registry "clawreef/internal/systembackupbootstrapsecurity"
	ca "clawreef/internal/systembackupcatrust"
	"clawreef/internal/systembackupinstallationowner/install"
	nonce "clawreef/internal/systembackupnoncebootstrap"
	sec "clawreef/internal/systembackupsecurity"
)

func TestEnableOnlySecurityCompositionRequiresFiveExactSources(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "absent-original-input")
	digest := strings.Repeat("a", 64)
	start := time.Now().UTC().Add(-time.Minute)
	end := start.Add(time.Hour)
	capture := install.NewCaptureSigningConsumer(path, filepath.Join(dir, "capture.pin"))
	files := install.BootstrapTerminalFiles{MappingFile: filepath.Join(dir, "mapping.json"), MappingSHA256: digest, SignatureFile: filepath.Join(dir, "mapping.signature")}
	makeCA := func(purpose string) *ca.Validator {
		v, e := ca.New(ca.Binding{InstallationID: "installation_original", ServerUUID: "11111111-2222-3333-4444-555555555555", Database: "original", ConfigSHA256: digest, Purpose: purpose, ProviderIdentityHash: digest, ScopeHash: digest, DescriptorFile: path, DescriptorSHA256: digest, CAFile: path, CASHA256: digest, Endpoint: "https://original.invalid", TargetIP: netip.MustParseAddr("127.0.0.1"), NotBefore: start, ExpiresAt: end})
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	artifact, evidence := makeCA("artifact_ca"), makeCA("evidence_ca")
	nonces, e := nonce.New(nonce.Binding{InstallationID: "installation_original", ServerUUID: "11111111-2222-3333-4444-555555555555", Database: "original", ConfigSHA256: digest, NotBefore: start, ExpiresAt: end, Keys: []nonce.Key{{IdentityHash: digest, Version: "v1", ProviderIdentityHash: digest, ScopeHash: digest, DescriptorFile: path, DescriptorSHA256: digest, MaterialFile: path, MaterialSHA256: digest, ProtectedUntil: end}}})
	if e != nil {
		t.Fatal(e)
	}
	issuers := registry.NewIssuers(dir)
	owner, e := NewEnableOnlySecurityOwners(capture, files, artifact, evidence, nonces, issuers)
	if e != nil {
		t.Fatal(e)
	}
	refs, regs := owner.References(), owner.Registries()
	if len(refs) != 3 || len(regs) != 2 {
		t.Fatal("five concrete aliases missing")
	}
	for _, source := range refs {
		if source != owner {
			t.Fatal("reference owner differs")
		}
	}
	for _, source := range regs {
		if source != owner {
			t.Fatal("registry owner differs")
		}
	}
	if _, e := NewEnableOnlySecurityOwners(capture, files, evidence, artifact, nonces, issuers); e == nil {
		t.Fatal("CA purposes relabeled")
	}
	if _, e := NewEnableOnlySecurityOwners(capture, files, artifact, evidence, nil, issuers); e == nil {
		t.Fatal("missing nonce accepted")
	}
	// Absent source files cannot be observed. Empty input must reject before
	// any file/provider/SQL use, rather than creating a prepared approval DTO.
	if _, e := owner.Prepare(context.Background(), sec.ConfigMutationResourceInput{}); e == nil {
		t.Fatal("missing mutation snapshots accepted")
	}
	o := &enableOnlySecurityObservation{}
	if !o.ValidUntil().IsZero() {
		t.Fatal("deadline data became readiness")
	}
	if _, e := json.Marshal(o); e == nil {
		t.Fatal("observation exported")
	}
}
