package systembackupkekadapter

import (
	"encoding/json"
	"testing"
	"time"

	kms "clawreef/internal/systembackupkms"
)

func TestInspectOriginalRecoveryCapabilityMaterialDoesNotPrepareGrant(t *testing.T) {
	for _, mode := range []string{"current", "revoked", "expired", "wrong-key", "wrong-operation", "wrong-source", "signature", "unknown-envelope"} {
		t.Run(mode, func(t *testing.T) {
			owner, _, _ := ownerRecordFixture(t)
			record, pin, key := providerCapabilityFixture(t, owner.Binding, kms.Unwrap)
			defer clear(key)
			now := time.Now().UTC()
			switch mode {
			case "revoked":
				record.Revoked = true
			case "expired":
				record.Until = now
			case "wrong-key":
				owner.Binding.Key.ProviderVersion = "99"
			case "wrong-operation":
				record.Facts.Operation = kms.Generate
			case "wrong-source":
				pin.Source.RecordVersion = "other"
			}
			evidence := signCapabilityFixture(t, record, key)
			if mode == "signature" {
				var signed SignedProviderCapabilityRecord
				json.Unmarshal(evidence.raw, &signed)
				signed.Signature[0] ^= 1
				evidence.raw, _ = json.Marshal(signed)
			}
			if mode == "unknown-envelope" {
				var fields map[string]json.RawMessage
				json.Unmarshal(evidence.raw, &fields)
				fields["PreparedCapability"] = json.RawMessage("true")
				evidence.raw, _ = json.Marshal(fields)
			}
			got, err := InspectProviderCapabilityMaterial(evidence.raw, pin, owner.Binding, kms.Unwrap, evidence.until, now)
			if mode == "current" {
				if err != nil || got.Facts.Operation != kms.Unwrap || got.Source != pin.Source {
					t.Fatal("original inert permission observation rejected", err)
				}
				return
			}
			if err == nil || got.Revision != "" {
				t.Fatal("invalid original observation accepted", mode)
			}
		})
	}
}
