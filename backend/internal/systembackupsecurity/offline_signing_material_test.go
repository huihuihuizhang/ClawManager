package systembackupsecurity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// All keys/signatures in this test are ephemeral local fixtures. No listener,
// credential file, SQL connection or provider client is constructed.
func TestOfflineSigningMaterialRefusals(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for _, change := range []string{"valid", "identity", "purpose", "registry_version", "provider_version", "revoked", "expired_key", "future_key", "expired_record", "future_record", "shared_role", "shared_policy", "root_policy", "missing", "signature", "pin", "revision", "duplicate_json"} {
		t.Run(change, func(t *testing.T) {
			pub, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			r := InstallationSigningRecord{InstallationID: "local_test_only", Revision: 1, NotBefore: now.Add(-time.Hour), Until: now.Add(time.Hour)}
			for _, p := range []string{"capture_certificate", "acceptance_record", "catalog_record"} {
				key, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				r.Keys = append(r.Keys, ArtifactSigningPublicKey{InstallationID: r.InstallationID, Purpose: p, KeyID: p, KeyVersion: "registry-r1", PublicKey: key, NotBefore: r.NotBefore, NotAfter: r.Until})
				r.Permissions = append(r.Permissions, InstallationSigningPermission{Binding: TransitSigningBinding{InstallationID: r.InstallationID, Purpose: p, KeyID: p, KeyVersion: "registry-r1", Endpoint: "https://unused.invalid", KeyName: p, ProviderVersion: "7"}, AuthMount: "jwt", Role: p + "-role", Policy: p + "-policy", CASHA256: strings.Repeat("a", 64)})
			}
			switch change {
			case "identity":
				r.Permissions[0].Binding.InstallationID = "foreign"
			case "purpose":
				r.Permissions[0].Binding.Purpose = "catalog_record"
			case "registry_version":
				r.Permissions[0].Binding.KeyVersion = "registry-r2"
			case "provider_version":
				r.Permissions[0].Binding.ProviderVersion = "latest"
			case "revoked":
				r.Keys[0].Revoked = true
			case "expired_key":
				r.Keys[0].NotAfter = now
			case "future_key":
				r.Keys[0].NotBefore = now.Add(time.Minute)
			case "expired_record":
				r.Until = now
			case "future_record":
				r.NotBefore = now.Add(time.Minute)
			case "shared_role":
				r.Permissions[0].Role = r.Permissions[1].Role
			case "shared_policy":
				r.Permissions[0].Policy = r.Permissions[1].Policy
			case "root_policy":
				r.Permissions[0].Policy = "ROOT"
			case "missing":
				r.Permissions = r.Permissions[:2]
			}
			raw, _ := json.Marshal(r)
			if change == "duplicate_json" {
				raw = []byte(strings.Replace(string(raw), `"Revision":1`, `"Revision":1,"Revision":1`, 1))
			}
			sum := sha256.Sum256(raw)
			pin := InstallationSigningPin{InstallationID: r.InstallationID, Revision: 1, RecordSHA256: hex.EncodeToString(sum[:]), Issuer: pub}
			sig := ed25519.Sign(private, append([]byte(InstallationSigningDomain), raw...))
			if change == "signature" {
				sig[0] ^= 1
			}
			if change == "pin" {
				pin.RecordSHA256 = strings.Repeat("f", 64)
			}
			if change == "revision" {
				pin.Revision++
			}
			err = InspectInstallationSigningMaterial(raw, sig, pin, now)
			if (err == nil) != (change == "valid") {
				t.Fatalf("inspection mismatch: %v", err)
			}
		})
	}
}
