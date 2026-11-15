package quiesce

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func originalLonghornClaimFixture() (LonghornExt4Claim, ObservationBinding) {
	now := time.Unix(100, 0).UTC()
	op, reservation := strings.Repeat("a", 32), strings.Repeat("b", 32)
	c := LonghornExt4Claim{OriginalOperationID: op, OriginalReservationID: reservation,
		Owner: "adoption:" + op, MaintenanceOwner: "adoption:" + op, EntryRowVersion: 7,
		LeaseObservedAt: now, LeaseExpiresAt: now.Add(time.Minute)}
	b := ObservationBinding{Kind: LonghornExt4Protocol, InstallationID: "installation",
		OperationID: op, ReservationID: reservation, InventorySHA256: strings.Repeat("c", 64),
		Namespace: "tenant", NamespaceUID: "tenant-uid", Node: "node", NodeUID: "node-uid",
		Generation: 3, ExpiresAt: now.Add(2 * time.Minute)}
	return c, b
}

func TestLonghornOriginalClaimCannotMasqueradeAsTask(t *testing.T) {
	c, b := originalLonghornClaimFixture()
	if !c.matchesBinding(b) || !c.keeperBinding(b) || c.TaskPublicID != "" {
		t.Fatal("original acquiring gate with zero epoch rejected")
	}
	for _, mutate := range []func(*LonghornExt4Claim){
		func(c *LonghornExt4Claim) { c.TaskPublicID = "task" },
		func(c *LonghornExt4Claim) { c.OriginalOperationID = "" },
		func(c *LonghornExt4Claim) { c.OriginalReservationID = "" },
		func(c *LonghornExt4Claim) { c.OriginalOperationID = strings.Repeat("A", 32) },
		func(c *LonghornExt4Claim) { c.Owner = "controller" },
		func(c *LonghornExt4Claim) { c.MaintenanceOwner = "task" },
		func(c *LonghornExt4Claim) { c.EntryRowVersion = 0 },
		func(c *LonghornExt4Claim) { c.LeaseExpiresAt = c.LeaseObservedAt.Add(301 * time.Second) },
	} {
		changed := c
		mutate(&changed)
		if changed.valid() || changed.matchesBinding(b) || changed.keeperBinding(b) {
			t.Fatal("mixed or malformed original claim accepted")
		}
	}
	for _, mutate := range []func(*ObservationBinding){
		func(b *ObservationBinding) { b.OperationID = "task" },
		func(b *ObservationBinding) { b.ReservationID = strings.Repeat("d", 32) },
		func(b *ObservationBinding) { b.Kind = "other" },
		func(b *ObservationBinding) { b.InstallationID = "" },
		func(b *ObservationBinding) { b.NamespaceUID = "" },
		func(b *ObservationBinding) { b.NodeUID = "" },
		func(b *ObservationBinding) { b.Generation = 0 },
		func(b *ObservationBinding) { b.InventorySHA256 = "" },
		func(b *ObservationBinding) { b.ExpiresAt = c.LeaseObservedAt },
	} {
		changed := b
		mutate(&changed)
		if c.matchesBinding(changed) || c.keeperBinding(changed) {
			t.Fatal("foreign or incomplete original binding accepted")
		}
	}
	// Expiry stops forward work via the existing deadline checks. Structural
	// matching must still permit exact expired records to be recovered.
	if !c.matchesBinding(b) || !longhornExt4ForwardUntil(b, c).Equal(c.LeaseExpiresAt) {
		t.Fatal("expired original recovery correlation lost")
	}
}

func TestLonghornTaskClaimRetainsOriginalWireDigest(t *testing.T) {
	// This is the pre-change wire layout retained in existing Node journals.
	old := struct {
		TaskPublicID, Owner, MaintenanceOwner string
		EntryRowVersion                       uint64
		LeaseObservedAt, LeaseExpiresAt       time.Time
	}{"task", "controller", "task", 3, time.Unix(100, 0).UTC(), time.Unix(160, 0).UTC()}
	c := LonghornExt4Claim{TaskPublicID: old.TaskPublicID, Owner: old.Owner,
		MaintenanceOwner: old.MaintenanceOwner, EntryRowVersion: old.EntryRowVersion,
		LeaseObservedAt: old.LeaseObservedAt, LeaseExpiresAt: old.LeaseExpiresAt}
	before, _ := json.Marshal(old)
	after, _ := json.Marshal(c)
	if string(before) != string(after) || observationDigest(old) != observationDigest(c) || !c.valid() {
		t.Fatal("existing task journal identity changed")
	}
}
