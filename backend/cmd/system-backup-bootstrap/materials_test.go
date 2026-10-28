package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ca "clawreef/internal/systembackupcatrust"
	nonce "clawreef/internal/systembackupnoncebootstrap"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

// Constructor model only; it must never be linked by main.
type materialCompositionAuthority struct{}

func (*materialCompositionAuthority) PrepareBootstrapCandidates(context.Context, sec.OfflineBootstrapGrant, sec.BootstrapConfig, pd.BootstrapConsumptionRequest) (sec.PreparedBootstrapCandidateAuthority, error) {
	return sec.PreparedBootstrapCandidateAuthority{}, sec.ErrRegistrationUnavailable
}

func TestBootstrapMaterialCompositionCannotBypassMissingAuthorityOrOwners(t *testing.T) {
	var output bytes.Buffer
	if code := runWithBootstrapMaterials(context.Background(), []string{"--apply"}, &output, linkedOwnerAdapters(), bootstrapMaterialInputs{}); code != 1 || output.Len() != 0 {
		t.Fatal("missing original authority reached run")
	}
	root := t.TempDir()
	now := time.Now().UTC()
	hash := strings.Repeat("a", 64)
	n := nonce.Binding{InstallationID: "installation_model", ServerUUID: "11111111-2222-3333-4444-555555555555", Database: "model", ConfigSHA256: hash, NotBefore: now, ExpiresAt: now.Add(time.Hour), Keys: []nonce.Key{{IdentityHash: hash, Version: "v1", ProviderIdentityHash: hash, ScopeHash: hash, DescriptorFile: filepath.Join(root, "nonce.json"), DescriptorSHA256: hash, MaterialFile: filepath.Join(root, "nonce.key"), MaterialSHA256: hash, ProtectedUntil: now.Add(2 * time.Hour)}}}
	a := ca.Binding{InstallationID: n.InstallationID, ServerUUID: n.ServerUUID, Database: n.Database, ConfigSHA256: hash, Purpose: "artifact_ca", ProviderIdentityHash: hash, ScopeHash: hash, DescriptorFile: filepath.Join(root, "ca.json"), DescriptorSHA256: hash, CAFile: filepath.Join(root, "ca.pem"), CASHA256: hash, Endpoint: "https://model.example", TargetIP: netip.MustParseAddr("127.0.0.1"), NotBefore: now, ExpiresAt: now.Add(time.Hour)}
	e := a
	e.Purpose = "evidence_ca"
	inputs := bootstrapMaterialInputs{Original: &materialCompositionAuthority{}, Nonce: n, ArtifactCA: a, EvidenceCA: e}
	// The constructor must reject a missing selection; merely adding the three
	// validators is not a candidate route or approval. No files/TLS/SQL exist.
	if _, err := composeBootstrapMaterials(linkedOwnerAdapters(), inputs); err == nil {
		t.Fatal("missing candidate selection accepted")
	}
	materials, _, err := composeBootstrapMaterialOwners(linkedOwnerAdapters(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	if missing := sec.MissingBootstrapOwnerAdapters(materials); len(missing) != 24 {
		t.Fatal("remaining owners bypassed", missing)
	}
	if materials.Candidates != nil {
		t.Fatal("candidate route fabricated")
	}
	if _, err := json.Marshal(inputs.Nonce); err == nil {
		t.Fatal("private mapping serializable")
	}
}
