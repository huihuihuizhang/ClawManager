package systembackupkekadapter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
)

func TestOriginalGeneratePermitIssuerDelegation(t *testing.T) {
	root, key, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(key)
	public, signingKey, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(signingKey)
	mapping, _, _ := ownerRecordFixture(t)
	now := time.Now().UTC()
	w := ControllerVerifierWorkload{Namespace: "control", PodName: "controller", PodUID: "original-controller-pod", ServiceAccountName: "controller", ServiceAccountUID: "original-controller-sa", OwnerKind: "Deployment", OwnerUID: "original-deployment", ControllerOwner: "original-owner", ConfigVersion: 1, ConfigSHA256: strings.Repeat("a", 64)}
	database := reg.DatabaseIdentity{ServerUUID: "original-server", Database: "original_db"}
	grant := ProviderPermitIssuerGrant{Version: "system-backup-provider-permit-issuer-grant.v1", Binding: mapping.Binding, Database: database, DatabaseAccount: "original_issuer@original-host", Workload: w, SigningPublicKey: public, WorkerNamespace: "backup", WorkerServiceAccountName: "capture", WorkerServiceAccountUID: "original-capture-sa", WorkerJWTIdentityFile: filepath.Join(t.TempDir(), "projected.jwt"), NotBefore: now.Add(-time.Minute), Until: now.Add(time.Minute)}
	permission, _, permissionKey := providerCapabilityFixture(t, mapping.Binding, kms.Generate)
	clear(permissionKey)
	grant.GeneratePermission = permission.Facts.Permission
	base := ProviderPermitIssuerConfig{Binding: mapping.Binding, Capabilities: &SQLProviderCapabilityPreparation{database: database}, Workload: w, CaptureGrantSHA256: strings.Repeat("f", 64)}
	sign := func(t *testing.T, g ProviderPermitIssuerGrant, transform func([]byte) []byte) ProviderPermitIssuerConfig {
		t.Helper()
		record, _ := json.Marshal(g)
		if transform != nil {
			record = transform(record)
		}
		raw, _ := json.Marshal(SignedProviderPermitIssuerGrant{Record: record, Signature: ed25519.Sign(key, append([]byte(ProviderPermitIssuerGrantDomain), record...))})
		h := sha256.Sum256(raw)
		cfg := base
		cfg.GrantMount = ProviderPermitIssuerGrantMount{File: filepath.Join(t.TempDir(), "owner-delegation.json"), SHA256: hex.EncodeToString(h[:]), Issuer: root}
		cfg.Workload.GrantSHA256 = cfg.GrantMount.SHA256
		if err := os.WriteFile(cfg.GrantMount.File, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	cfg := sign(t, grant, nil)
	if _, err := readPermitIssuerGrant(context.Background(), cfg); err != nil {
		t.Fatal("independent original Generate delegation rejected", err)
	}
	// No future Forward hash appears in signed delegation: changing the current
	// capture grant at composition never changes this independent issuer pin.
	other := cfg
	other.CaptureGrantSHA256 = strings.Repeat("e", 64)
	if _, err := readPermitIssuerGrant(context.Background(), other); err != nil {
		t.Fatal("issuer delegation incorrectly depends on future Forward digest", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*ProviderPermitIssuerGrant)
	}{
		{"revoked", func(g *ProviderPermitIssuerGrant) { g.Revoked = true }},
		{"expired", func(g *ProviderPermitIssuerGrant) { g.Until = now.Add(-time.Second) }},
		{"future", func(g *ProviderPermitIssuerGrant) { g.NotBefore = now.Add(time.Second) }},
		{"overlong", func(g *ProviderPermitIssuerGrant) { g.Until = g.NotBefore.Add(25 * time.Hour) }},
		{"other_mapping", func(g *ProviderPermitIssuerGrant) { g.Binding.Key.ProviderVersion = "9" }},
		{"other_database", func(g *ProviderPermitIssuerGrant) { g.Database.Database = "other" }},
		{"empty_account", func(g *ProviderPermitIssuerGrant) { g.DatabaseAccount = "" }},
		{"other_controller", func(g *ProviderPermitIssuerGrant) { g.Workload.ControllerOwner = "other" }},
		{"other_workload", func(g *ProviderPermitIssuerGrant) { g.Workload.PodUID = "other" }},
		{"self_hash_cycle", func(g *ProviderPermitIssuerGrant) { g.Workload.GrantSHA256 = strings.Repeat("a", 64) }},
		{"empty_worker", func(g *ProviderPermitIssuerGrant) { g.WorkerServiceAccountUID = "" }},
		{"relative_jwt", func(g *ProviderPermitIssuerGrant) { g.WorkerJWTIdentityFile = "untrusted-relative.jwt" }},
		{"root_key_reuse", func(g *ProviderPermitIssuerGrant) { g.SigningPublicKey = root }},
		{"verifier_observation_as_generate_owner", func(g *ProviderPermitIssuerGrant) { g.GeneratePermission.ControllerVerifier = &w }},
	} {
		t.Run(test.name, func(t *testing.T) {
			g := grant
			test.mutate(&g)
			cfg := sign(t, g, nil)
			if _, err := readPermitIssuerGrant(context.Background(), cfg); err == nil {
				t.Fatal("invalid independent Generate delegation admitted")
			}
		})
	}
	for _, test := range []struct {
		name      string
		transform func([]byte) []byte
	}{
		{"duplicate_json", func(raw []byte) []byte { return append([]byte(`{"Revoked":false,`), raw[1:]...) }},
		{"unknown_json", func(raw []byte) []byte { return append([]byte(`{"Override":true,`), raw[1:]...) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := sign(t, grant, test.transform)
			if _, err := readPermitIssuerGrant(context.Background(), cfg); err == nil {
				t.Fatal("ambiguous signed delegation admitted")
			}
		})
	}
	t.Run("private_signer_pin", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "dedicated-signing-key")
		if os.WriteFile(path, signingKey, 0600) != nil {
			t.Fatal("private fixture")
		}
		got, err := readPermitSigningKey(path, public)
		if err != nil || !bytes.Equal(got, signingKey) {
			t.Fatal("dedicated delegated signer rejected", err)
		}
		clear(got)
		if _, err := readPermitSigningKey(path, root); err == nil {
			t.Fatal("another purpose's signer accepted")
		}
		bad := bytes.Clone(signingKey)
		bad[0] ^= 1
		if os.WriteFile(path, bad, 0600) != nil {
			t.Fatal("private fixture")
		}
		clear(bad)
		if _, err := readPermitSigningKey(path, public); err == nil {
			t.Fatal("noncanonical private/public signer admitted")
		}
	})
	t.Run("issuer_substitution", func(t *testing.T) {
		other := cfg
		other.GrantMount.Issuer = public
		if _, err := readPermitIssuerGrant(context.Background(), other); err == nil {
			t.Fatal("another signing purpose issued Generate authority")
		}
	})
}

func TestOriginalGeneratePodProjectionCannotEscapeSignedPath(t *testing.T) {
	root := t.TempDir()
	template := filepath.Join(root, "workers", "{pod_uid}", "token")
	first, err := workerJWTIdentityPath(template, "original-pod-1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := workerJWTIdentityPath(template, "original-pod-2")
	if err != nil || first == second || first != filepath.Join(root, "workers", "original-pod-1", "token") {
		t.Fatal("distinct admitted Pods shared a projection")
	}
	static := filepath.Join(root, "static-token")
	if got, err := workerJWTIdentityPath(static, "original-pod-1"); err != nil || got != static {
		t.Fatal("static container path changed")
	}
	for _, item := range []struct{ path, uid string }{
		{template, "../other"}, {template, `..\other`}, {template, ".."}, {template, ""}, {template, "pod/other"},
		{filepath.Join(root, "prefix-{pod_uid}", "token"), "pod"},
		{filepath.Join(root, "{pod_uid}", "{pod_uid}", "token"), "pod"},
		{filepath.Join(root, "{other}", "{pod_uid}", "token"), "pod"},
		{filepath.Join(root, "{pod_uid}", "token}"), "pod"},
		{"relative/{pod_uid}/token", "pod"},
	} {
		if _, err := workerJWTIdentityPath(item.path, item.uid); err == nil {
			t.Errorf("invalid signed projection admitted: %q %q", item.path, item.uid)
		}
	}
}
