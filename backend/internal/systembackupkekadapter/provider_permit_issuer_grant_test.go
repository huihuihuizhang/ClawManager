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
	t.Run("prepared_current_file_and_bounds", func(t *testing.T) {
		proof, err := authenticatePermitIssuerGrant(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		original, err := os.ReadFile(cfg.GrantMount.File)
		if err != nil {
			t.Fatal(err)
		}
		check := func(current ProviderPermitIssuerConfig, at time.Time, allowed bool) {
			t.Helper()
			if got := proof.recheck(context.Background(), current, at); (got == nil) != allowed {
				t.Fatalf("prepared current delegation allowed=%v: %v", allowed, got)
			}
		}
		compareCurrent := func(current ProviderPermitIssuerConfig, allowed bool) {
			t.Helper()
			check(current, now, allowed)
			if _, err := readPermitIssuerGrant(context.Background(), current); (err == nil) != allowed {
				t.Fatalf("full current authentication allowed=%v: %v", allowed, err)
			}
		}
		check(cfg, now, true)
		check(cfg, grant.NotBefore, true)
		check(cfg, grant.NotBefore.Add(-time.Nanosecond), false)
		check(cfg, grant.Until, false)
		check(cfg, time.Time{}, false)
		for _, tc := range []struct {
			name string
			edit func(*ProviderPermitIssuerConfig)
		}{
			{"issuer", func(c *ProviderPermitIssuerConfig) { c.GrantMount.Issuer = public }},
			{"capture_purpose", func(c *ProviderPermitIssuerConfig) { c.CaptureGrantSHA256 = c.GrantMount.SHA256 }},
			{"workload_digest", func(c *ProviderPermitIssuerConfig) { c.Workload.GrantSHA256 = strings.Repeat("b", 64) }},
			{"controller", func(c *ProviderPermitIssuerConfig) { c.Workload.PodUID = "other" }},
			{"binding", func(c *ProviderPermitIssuerConfig) { c.Binding.Key.ProviderVersion = "other" }},
			{"database", func(c *ProviderPermitIssuerConfig) {
				v := *c.Capabilities
				v.database.Database = "other"
				c.Capabilities = &v
			}},
		} {
			t.Run(tc.name, func(t *testing.T) { current := cfg; tc.edit(&current); compareCurrent(current, false) })
		}
		for _, tc := range []struct {
			name string
			raw  []byte
		}{
			{"empty", nil}, {"corrupt", []byte("broken")},
			{"trailing", append(bytes.Clone(original), '\n')},
			{"oversize", bytes.Repeat([]byte("x"), 65537)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if err := os.WriteFile(cfg.GrantMount.File, tc.raw, 0600); err != nil {
					t.Fatal(err)
				}
				compareCurrent(cfg, false)
			})
		}
		if err := os.Remove(cfg.GrantMount.File); err != nil {
			t.Fatal(err)
		}
		compareCurrent(cfg, false)
		if err := os.Mkdir(cfg.GrantMount.File, 0700); err != nil {
			t.Fatal(err)
		}
		compareCurrent(cfg, false)
		if err := os.Remove(cfg.GrantMount.File); err != nil {
			t.Fatal(err)
		}
		for _, revoked := range []bool{false, true} {
			changed := grant
			changed.Until = changed.Until.Add(time.Minute)
			changed.Revoked = revoked
			fresh := sign(t, changed, nil)
			raw, err := os.ReadFile(fresh.GrantMount.File)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(cfg.GrantMount.File, raw, 0600); err != nil {
				t.Fatal(err)
			}
			check(cfg, now, false)
			fresh.GrantMount.File = cfg.GrantMount.File
			check(fresh, now, false) // Even replacing both pin and valid signed bytes cannot renew a prepared request.
			if _, err := readPermitIssuerGrant(context.Background(), fresh); (err == nil) == revoked {
				t.Fatalf("independent signed replacement revoked=%v: %v", revoked, err)
			}
		}
		if err := os.WriteFile(cfg.GrantMount.File, original, 0600); err != nil {
			t.Fatal(err)
		}
		check(cfg, now, true)
		// Mutating an independently read public DTO cannot change prepared data.
		read, err := readPermitIssuerGrant(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		read.SigningPublicKey[0] ^= 1
		read.Binding.GenerateRef.RawJSON[0] ^= 1
		check(cfg, now, true)
		before, err := json.Marshal(proof.grant)
		if err != nil {
			t.Fatal(err)
		}
		savedIssuer := bytes.Clone(cfg.GrantMount.Issuer)
		cfg.Binding.GenerateRef.RawJSON[0] ^= 1
		cfg.GrantMount.Issuer[0] ^= 1
		after, err := json.Marshal(proof.grant)
		if err != nil || !bytes.Equal(before, after) || !bytes.Equal(proof.raw, original) || !bytes.Equal(proof.issuer, savedIssuer) {
			t.Fatal("caller input mutated authenticated data", err)
		}
		cfg.Binding.GenerateRef.RawJSON[0] ^= 1
		cfg.GrantMount.Issuer[0] ^= 1
		check(cfg, now, true)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if proof.recheck(ctx, cfg, now) == nil || proof.recheck(nil, cfg, now) == nil || (*authenticatedPermitIssuerGrant)(nil).recheck(context.Background(), cfg, now) == nil {
			t.Fatal("invalid prepared context or nil proof admitted")
		}
	})
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
	t.Run("prepared_real_expiry", func(t *testing.T) {
		short := grant
		short.Until = time.Now().Add(2 * time.Second)
		current := sign(t, short, nil)
		proof, err := authenticatePermitIssuerGrant(context.Background(), current)
		if err != nil {
			t.Fatal(err)
		}
		if proof.recheck(context.Background(), current, time.Now()) != nil {
			t.Fatal("live original grant rejected")
		}
		time.Sleep(time.Until(short.Until) + 20*time.Millisecond)
		if time.Now().Before(short.Until) {
			t.Fatal("expiry fixture did not cross actual wall clock")
		}
		if proof.recheck(context.Background(), current, now) == nil {
			t.Fatal("stale supplied clock revived expired original grant")
		}
		if _, err := readPermitIssuerGrant(context.Background(), current); err == nil {
			t.Fatal("full current authentication revived expired original grant")
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
