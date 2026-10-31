package systembackupkekadapter

import (
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
)

func TestControllerVerifierOriginalGrant(t *testing.T) {
	issuer, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	now := time.Now().UTC()
	w := ControllerVerifierWorkload{Namespace: "control", PodName: "controller-0", PodUID: "original-pod", ServiceAccountName: "controller", ServiceAccountUID: "original-sa", OwnerKind: "StatefulSet", OwnerUID: "original-owner", ControllerOwner: "original-controller", ConfigSHA256: strings.Repeat("b", 64), ConfigVersion: 7}
	db := reg.DatabaseIdentity{ServerUUID: "original-server", Database: "original_database"}
	capture := strings.Repeat("c", 64)
	original := ControllerVerifierGrant{Version: "system-backup-controller-verifier-grant.v1", InstallationID: "installation_original", Database: db, DatabaseAccount: "controller@original-host", Workload: w, CaptureGrantSHA256: capture, NotBefore: now.Add(-time.Minute), Until: now.Add(time.Minute)}
	sign := func(t *testing.T, grant ControllerVerifierGrant, transform func([]byte) []byte) (ControllerVerifierGrantMount, ControllerVerifierWorkload) {
		t.Helper()
		record, _ := json.Marshal(grant)
		if transform != nil {
			record = transform(record)
		}
		raw, _ := json.Marshal(SignedControllerVerifierGrant{Record: record, Signature: ed25519.Sign(key, append([]byte(ControllerVerifierGrantDomain), record...))})
		h := sha256.Sum256(raw)
		m := ControllerVerifierGrantMount{File: filepath.Join(t.TempDir(), "original-grant.json"), SHA256: hex.EncodeToString(h[:]), Issuer: issuer}
		if err := os.WriteFile(m.File, raw, 0600); err != nil {
			t.Fatal(err)
		}
		workload := w
		workload.GrantSHA256 = m.SHA256
		return m, workload
	}
	m, workload := sign(t, original, nil)
	got, err := readControllerVerifierGrant(context.Background(), m, workload, original.InstallationID, capture, db)
	if err != nil || got.DatabaseAccount != original.DatabaseAccount || !got.Until.Equal(original.Until) {
		t.Fatal("independent original workload grant rejected", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*ControllerVerifierGrant)
	}{
		{"revoked", func(g *ControllerVerifierGrant) { g.Revoked = true }},
		{"expired", func(g *ControllerVerifierGrant) { g.Until = now.Add(-time.Second) }},
		{"future", func(g *ControllerVerifierGrant) { g.NotBefore = now.Add(time.Second) }},
		{"overlong", func(g *ControllerVerifierGrant) { g.Until = g.NotBefore.Add(25 * time.Hour) }},
		{"other_installation", func(g *ControllerVerifierGrant) { g.InstallationID = "other" }},
		{"other_database", func(g *ControllerVerifierGrant) { g.Database.Database = "other" }},
		{"other_server", func(g *ControllerVerifierGrant) { g.Database.ServerUUID = "other" }},
		{"empty_account", func(g *ControllerVerifierGrant) { g.DatabaseAccount = "" }},
		{"other_pod", func(g *ControllerVerifierGrant) { g.Workload.PodUID = "other" }},
		{"other_sa", func(g *ControllerVerifierGrant) { g.Workload.ServiceAccountUID = "other" }},
		{"other_owner", func(g *ControllerVerifierGrant) { g.Workload.OwnerUID = "other" }},
		{"other_controller", func(g *ControllerVerifierGrant) { g.Workload.ControllerOwner = "other" }},
		{"other_config", func(g *ControllerVerifierGrant) { g.Workload.ConfigVersion++ }},
		{"self_asserted_grant_hash", func(g *ControllerVerifierGrant) { g.Workload.GrantSHA256 = capture }},
		{"other_capture_grant", func(g *ControllerVerifierGrant) { g.CaptureGrantSHA256 = strings.Repeat("d", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			g := original
			test.mutate(&g)
			m, w := sign(t, g, nil)
			if _, err := readControllerVerifierGrant(context.Background(), m, w, original.InstallationID, capture, db); err == nil {
				t.Fatal("mismatched original business authority admitted")
			}
		})
	}
	for _, test := range []struct {
		name      string
		transform func([]byte) []byte
	}{
		{"duplicate_field", func(raw []byte) []byte { return append([]byte(`{"Revoked":false,`), raw[1:]...) }},
		{"unknown_field", func(raw []byte) []byte { return append([]byte(`{"Override":true,`), raw[1:]...) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			m, w := sign(t, original, test.transform)
			if _, err := readControllerVerifierGrant(context.Background(), m, w, original.InstallationID, capture, db); err == nil {
				t.Fatal("ambiguous signed grant admitted")
			}
		})
	}
	t.Run("issuer_substitution", func(t *testing.T) {
		other, _, _ := ed25519.GenerateKey(rand.Reader)
		bad := m
		bad.Issuer = other
		if _, err := readControllerVerifierGrant(context.Background(), bad, workload, original.InstallationID, capture, db); err == nil {
			t.Fatal("substituted issuer admitted")
		}
	})
	t.Run("capture_grant_reuse", func(t *testing.T) {
		if _, err := readControllerVerifierGrant(context.Background(), m, workload, original.InstallationID, m.SHA256, db); err == nil {
			t.Fatal("capture grant reused")
		}
	})
	t.Run("mounted_bytes_changed", func(t *testing.T) {
		if err := os.WriteFile(m.File, []byte(`{}`), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readControllerVerifierGrant(context.Background(), m, workload, original.InstallationID, capture, db); err == nil {
			t.Fatal("replaced material admitted")
		}
	})
}
