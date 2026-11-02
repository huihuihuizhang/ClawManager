package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	registry "clawreef/internal/systembackupbootstrapsecurity"
	ca "clawreef/internal/systembackupcatrust"
	nonce "clawreef/internal/systembackupnoncebootstrap"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

func terminalSevenConcreteSources(t *testing.T) (*CaptureSigningConsumer, BootstrapTerminalFiles, map[string]sec.BootstrapTerminalResource) {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "absent-original-input")
	digest := strings.Repeat("a", 64)
	start := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	end := start.Add(time.Hour)
	rbac, issuers := registry.NewRBAC(directory), registry.NewIssuers(directory)
	n, err := nonce.New(nonce.Binding{InstallationID: "installation_original", ServerUUID: "11111111-2222-3333-4444-555555555555", Database: "original", ConfigSHA256: digest, NotBefore: start, ExpiresAt: end, Keys: []nonce.Key{{IdentityHash: digest, Version: "v1", ProviderIdentityHash: digest, ScopeHash: digest, DescriptorFile: path, DescriptorSHA256: digest, MaterialFile: path, MaterialSHA256: digest, ProtectedUntil: end}}})
	if err != nil {
		t.Fatal(err)
	}
	resources := map[string]sec.BootstrapTerminalResource{"registry:rbac_bindings": rbac, "registry:provider_proof_issuers": issuers, "registry:strong_auth_issuers": issuers, "reference:nonce_hmac": n}
	for _, purpose := range []string{"artifact_ca", "evidence_ca"} {
		v, err := ca.New(ca.Binding{InstallationID: "installation_original", ServerUUID: "11111111-2222-3333-4444-555555555555", Database: "original", ConfigSHA256: digest, Purpose: purpose, ProviderIdentityHash: digest, ScopeHash: digest, DescriptorFile: path, DescriptorSHA256: digest, CAFile: path, CASHA256: digest, Endpoint: "https://original.invalid", TargetIP: netip.MustParseAddr("127.0.0.1"), NotBefore: start, ExpiresAt: end})
		if err != nil {
			t.Fatal(err)
		}
		resources["reference:"+purpose] = v
	}
	return NewCaptureSigningConsumer(path, path+".sha256"), BootstrapTerminalFiles{MappingFile: path, MappingSHA256: digest, SignatureFile: path, EvidenceFile: path, RegistryDirectory: directory}, resources
}

func TestBootstrapTerminalOriginalKeepsTwentyThreeMissingOwnersClosed(t *testing.T) {
	capture, files, resources := terminalSevenConcreteSources(t)
	original, err := NewBootstrapTerminalOriginal(capture, files, resources)
	if err != nil {
		t.Fatal(err)
	}
	missing := original.MissingTerminalResources()
	if len(missing) != 23 {
		t.Fatal("only seven concrete implementation slots are present", missing)
	}
	owners, err := original.Owners()
	if err != nil || !reflect.DeepEqual(sec.MissingBootstrapOwnerAdapters(owners), missing) || owners.KEK != nil || owners.Candidates != nil {
		t.Fatal("metadata created another executable owner or independent KEK source", err)
	}
	// Construction above touches no absent input. Missing compiled owners close
	// preparation before input/credential/provider/SQL work; no fake success
	// adapters are supplied for the remaining twenty-three slots.
	delete(resources, "registry:rbac_bindings")
	if len(original.MissingTerminalResources()) != 23 {
		t.Fatal("caller map mutated trusted composition")
	}
	if prepared, err := original.PrepareBootstrapCandidates(context.Background(), sec.OfflineBootstrapGrant{}, sec.BootstrapConfig{}, pd.BootstrapConsumptionRequest{}); err != ErrInstall || prepared.Session != nil {
		t.Fatal("incomplete Original prepared a usable attempt", err)
	}
}

func TestBootstrapTerminalOriginalRejectsWrongConcretePurpose(t *testing.T) {
	capture, files, resources := terminalSevenConcreteSources(t)
	for _, key := range []string{"reference:kek", "reference:artifact_ca", "cross_resources", "registry:unknown", "reference:capture_signing"} {
		if _, err := NewBootstrapTerminalOriginal(capture, files, map[string]sec.BootstrapTerminalResource{key: resources["registry:rbac_bindings"]}); err == nil {
			t.Fatal("RBAC supplied a different resource owner", key)
		}
	}
	var absent *registry.RBAC
	if _, err := NewBootstrapTerminalOriginal(capture, files, map[string]sec.BootstrapTerminalResource{"registry:rbac_bindings": absent}); err == nil {
		t.Fatal("typed-nil owner filled a slot")
	}
}

func originalMappingTransportFixture(t *testing.T) (SignedBootstrapOriginalMapping, ed25519.PublicKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	digest := strings.Repeat("a", 64)
	start := time.Now().UTC().Truncate(time.Microsecond)
	mapping := BootstrapOriginalMapping{SchemaVersion: BootstrapOriginalMappingVersion, PlanSHA256: digest, CaptureRecordSHA256: digest, SelectionSHA256: digest, ProducerIssuerIdentitySHA256: digest, EvidenceSourceSHA256: digest, NotBefore: start, Until: start.Add(time.Minute), Hosts: []BootstrapOriginalHost{{WorkloadIdentitySHA256: digest, PodSpecSHA256: digest}}}
	raw, err := canonical(mapping)
	if err != nil {
		t.Fatal(err)
	}
	return SignedBootstrapOriginalMapping{Record: raw, Signature: ed25519.Sign(private, append([]byte(BootstrapOriginalMappingDomain), raw...))}, public
}

func TestBootstrapOriginalMappingSignatureAndTransportNeverCreateAuthority(t *testing.T) {
	signed, public := originalMappingTransportFixture(t)
	if _, err := verifyBootstrapOriginalMapping(signed.Record, signed.Signature, public); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"raw", "signature", "issuer", "trailing"} {
		raw, signature, issuer := bytes.Clone(signed.Record), bytes.Clone(signed.Signature), bytes.Clone(public)
		switch mode {
		case "raw":
			raw[len(raw)/2] ^= 1
		case "signature":
			signature[0] ^= 1
		case "issuer":
			issuer[0] ^= 1
		case "trailing":
			raw = append(raw, []byte("{}")...)
		}
		if _, err := verifyBootstrapOriginalMapping(raw, signature, issuer); err == nil {
			t.Fatal("untrusted mapping accepted", mode)
		}
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := SaveFrozenBootstrapOriginalMapping(directory, signed); err != nil {
		t.Fatal(err)
	}
	for name, expected := range map[string][]byte{"bootstrap-original.record.json": signed.Record, "bootstrap-original.signature": signed.Signature, "bootstrap-original.sha256": []byte(hash(signed.Record))} {
		actual, err := ReadPrivateFile(filepath.Join(directory, name), 262144)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("frozen transport bytes changed", name, err)
		}
	}
	if SaveFrozenBootstrapOriginalMapping(directory, signed) == nil {
		t.Fatal("overwrote original frozen output")
	}
	// A well-signed transport fixture still has no actual plan/enrollment,
	// current SQL, finite host association or thirty source bindings.
	var body map[string]any
	if json.Unmarshal(signed.Record, &body) != nil || body["SchemaVersion"] != BootstrapOriginalMappingVersion {
		t.Fatal("strict signed comparison shape")
	}
}
