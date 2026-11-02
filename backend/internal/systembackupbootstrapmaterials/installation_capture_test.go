package systembackupbootstrapmaterials

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	refs "clawreef/internal/systembackupbootstrapsecurity"
	owner "clawreef/internal/systembackupinstallationowner"
	a "clawreef/internal/systembackupkekadapter"
	sec "clawreef/internal/systembackupsecurity"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

// Constructor-only comparison fixture. No fixture below asserts actual Vault,
// Kubernetes, SQL identity, original mapping or full deployment authorization.
func TestInstallationMaterialsComposeExactlyFourConcreteResources(t *testing.T) {
	f := setupMaterials(t)
	ca, e := os.ReadFile(f.a.CAFile)
	if e != nil {
		t.Fatal(e)
	}
	directory := t.TempDir()
	observer, e := owner.NewCaptureSigningObserver(owner.SigningObserverConfig{Endpoint: f.a.Endpoint, CASHA256: f.a.CASHA256, CAPEM: ca, ObserverPolicy: "capture-observer", ObserverTokenFile: filepath.Join(directory, "metadata.token"), ObserverTokenSHA256: strings.Repeat("a", 64), RuntimeJWTFile: filepath.Join(directory, "runtime.jwt"), Trust: a.VaultJWTTrust{Issuer: "https://kubernetes.default.svc.cluster.local", ValidationPublicKeys: []string{"constructor comparison key"}, Algorithms: []string{"RS256"}}, Kubernetes: kubefake.NewSimpleClientset()})
	if e != nil {
		t.Fatal(e)
	}
	defer observer.Close()
	pin := owner.TrustPin{InstallationID: f.n.InstallationID, EnrollmentID: "original-enrollment", IssuerID: "original-issuer", EnrollmentRevision: 1, MinimumHeadRevision: 1, Issuer: make(ed25519.PublicKey, ed25519.PublicKeySize), ClusterID: "original-cluster", NamespaceUID: "original-namespace", OwnerSubject: "original-owner", ServerUUID: f.n.ServerUUID, Database: f.n.Database, DatabaseAccount: "bootstrap@localhost", GrantID: "original-grant", GrantRevision: 1, RecordSHA256: strings.Repeat("a", 64)}
	capture, e := owner.NewCaptureSigningValidator(pin, owner.RecordFiles{RecordFile: filepath.Join(directory, "record"), SignatureFile: filepath.Join(directory, "signature")}, observer)
	if e != nil {
		t.Fatal(e)
	}
	m, e := NewInstallationMaterials(f.inner, capture, f.n, f.a, f.e)
	if e != nil {
		t.Fatal(e)
	}
	issuers := refs.NewIssuers(directory)
	base := sec.BootstrapOwnerAdapters{Registries: map[string]sec.BootstrapResourceValidator{"rbac_bindings": refs.NewRBAC(directory), "strong_auth_issuers": issuers, "provider_proof_issuers": issuers}}
	owners, e := m.Owners(base)
	if e != nil || len(owners.Registries) != 3 || len(owners.References) != 4 || len(sec.MissingBootstrapOwnerAdapters(owners)) != 23 || len(base.References) != 0 {
		t.Fatal("installation composition filled unrelated owners or mutated original maps", e)
	}
	if _, e = m.Owners(owners); e == nil {
		t.Fatal("installation resources overwritten")
	}
	if _, e = NewInstallationMaterials(nil, capture, f.n, f.a, f.e); e == nil {
		t.Fatal("missing Original authority replaced")
	}
	if _, e = NewInstallationMaterials(f.inner, nil, f.n, f.a, f.e); e == nil {
		t.Fatal("missing capture owner replaced")
	}
}
