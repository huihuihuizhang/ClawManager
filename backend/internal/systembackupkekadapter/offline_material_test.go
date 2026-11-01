package systembackupkekadapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func TestOfflineKEKMaterialRefusals(t *testing.T) {
	for _, change := range []string{"valid", "identity", "revision", "reference", "pin", "signature", "generate_revoked", "unwrap_revoked", "expired", "future", "wrong_purpose", "wrong_version"} {
		t.Run(change, func(t *testing.T) {
			r, pub, key := ownerRecordFixture(t)
			now := time.Now().UTC()
			installation, revision, ref := r.Binding.InstallationID, r.Revision, r.Binding.ConfigRef
			switch change {
			case "identity":
				installation = "foreign"
			case "revision":
				revision = "r2"
			case "reference":
				ref.Version = "other"
			case "generate_revoked":
				r.GenerateRevoked = true
			case "unwrap_revoked":
				r.UnwrapRevoked = true
			case "expired":
				r.Until = now
			case "future":
				r.NotBefore = now.Add(time.Minute)
			case "wrong_purpose":
				r.Binding.UnwrapRef = r.Binding.GenerateRef
			case "wrong_version":
				r.Binding.Key.ProviderVersion = "latest"
			}
			b, _ := json.Marshal(r.Binding)
			hash := sha256.Sum256(b)
			r.Source.ContentSHA256 = hex.EncodeToString(hash[:])
			raw, sig := signOwner(r, key)
			hash = sha256.Sum256(raw)
			digest := hex.EncodeToString(hash[:])
			if change == "signature" {
				sig[0] ^= 1
			}
			if change == "pin" {
				digest = ""
			}
			err := InspectOriginalKEKMaterial(raw, sig, pub, digest, installation, revision, ref, now)
			if (err == nil) != (change == "valid") {
				t.Fatalf("inspection mismatch: %v", err)
			}
		})
	}
}
