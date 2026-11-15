package install

import (
	"bytes"
	"testing"
	"time"

	q "clawreef/internal/systembackup/quiesce"
)

func TestOriginalWriterSelectionRetainsPreKeeperWire(t *testing.T) {
	old, err := canonical(OriginalWriterSetSelection{Version: OriginalWriterSetSelectionVersion})
	if err != nil || bytes.Contains(old, []byte(`"LonghornHostDefinition"`)) {
		t.Fatal("absent keeper material changed the original pinned writer bytes", err)
	}
	var decoded OriginalWriterSetSelection
	if decodeExact(old, &decoded) != nil {
		t.Fatal("pre-keeper writer cannot pass strict native readback")
	}
	decoded.LonghornHostDefinition = BootstrapSourceFilePin{File: "/original/host.json", SHA256: "selected"}
	selected, err := canonical(decoded)
	if err != nil || !bytes.Contains(selected, []byte(`"LonghornHostDefinition"`)) {
		t.Fatal("explicit keeper material lost its wire binding", err)
	}
}

func TestOriginalLonghornFrozenClaimPreservesRegistrationAndRejectsReacquisition(t *testing.T) {
	now := time.Now().UTC()
	original := q.LonghornExt4Claim{OriginalOperationID: "operation", OriginalReservationID: "reservation", Owner: "owner", MaintenanceOwner: "owner", EntryRowVersion: 7, LeaseObservedAt: now, LeaseExpiresAt: now.Add(time.Minute)}
	for _, fault := range []string{"none", "reacquired", "owner", "reservation", "expired", "shortened", "rewound"} {
		t.Run(fault, func(t *testing.T) {
			fresh := original
			fresh.LeaseObservedAt = now.Add(time.Second)
			fresh.LeaseExpiresAt = now.Add(2 * time.Minute)
			switch fault {
			case "reacquired":
				fresh.EntryRowVersion++
			case "owner":
				fresh.Owner = "replacement"
			case "reservation":
				fresh.OriginalReservationID = "replacement"
			case "expired":
				fresh.LeaseObservedAt = original.LeaseExpiresAt
			case "shortened":
				fresh.LeaseExpiresAt = original.LeaseExpiresAt.Add(-time.Second)
			case "rewound":
				fresh.LeaseObservedAt = now.Add(-time.Second)
			}
			got, err := originalLonghornFrozenClaim(original, fresh)
			if (err == nil) != (fault == "none") {
				t.Fatalf("%s: %v", fault, err)
			}
			if err == nil && got != original {
				t.Fatal("registration claim was renewed")
			}
		})
	}
}

func TestOriginalLonghornIntentsParticipateInRecoveryBoundary(t *testing.T) {
	for _, action := range []string{"register", "qualify", "acquire", "register-client", "sync-client", "release"} {
		if !originalSourceMutationIntent("longhorn_" + action + "_intent") {
			t.Fatal("untracked native mutation", action)
		}
		if originalSourceMutationIntent("longhorn_" + action + "_observed") {
			t.Fatal("response became dispatch", action)
		}
	}
}
