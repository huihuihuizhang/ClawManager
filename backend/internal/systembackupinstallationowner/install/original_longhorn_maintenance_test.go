package install

import (
	"testing"
	"time"

	q "clawreef/internal/systembackup/quiesce"
)

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
