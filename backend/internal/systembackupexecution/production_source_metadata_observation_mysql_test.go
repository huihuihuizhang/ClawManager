package systembackupexecution

import (
	"context"
	"reflect"
	"testing"
	"time"

	d "clawreef/internal/systembackupdispatch"
)

// Actual SAN/TLS least-privilege SQL with the existing finite TLS/RESP/S3/API
// protocol servers. This is transport metadata coverage, not live provider or
// physical stopped-writer evidence. Keep the complete original instance9 data.
func TestSourceMetadataTasklessOriginalTransportsAndInventoryMySQL(t *testing.T) {
	f, capture := sourceSQLObservationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	before := sourceObservationControlCounts(t, f)
	facts, err := f.service.ObserveSourceMetadata(ctx)
	if err != nil || facts.inventory == nil || facts.inventory.source.TeamFacts == nil || facts.inventory.source.Skills == nil || facts.SHA256() == "" || !facts.CheckedAt().Before(facts.ValidUntil()) || len(facts.skills.Objects) != 2 || len(facts.deployment.Selections) == 0 || len(facts.secrets.Selections) == 0 {
		t.Fatal("actual original source metadata", err)
	}
	if !reflect.DeepEqual(facts.inventory.source.Users, f.sourceInventory.Users) || !reflect.DeepEqual(facts.inventory.source.Instances, f.sourceInventory.Instances) {
		t.Fatal("complete actual source keysets changed")
	}
	stopped := false
	for _, instance := range facts.inventory.source.Instances {
		stopped = stopped || instance.ID == 9 && instance.Status == "stopped"
	}
	if !stopped {
		t.Fatal("stopped SQL fixture omitted; metadata is not physical stopped proof")
	}
	if _, err := f.db.ExecContext(ctx, "UPDATE system_backup_v2_backups SET controller_lease_expires_at=UTC_TIMESTAMP(6) WHERE public_id=?", f.publicID); err != nil {
		t.Fatal(err)
	}
	if capture.Recheck(ctx) == nil {
		t.Fatal("capture lost its real task authority check")
	}
	if _, err := f.service.sourceMetadataAuthority(ctx, f.owner, d.Input{}); err == nil {
		t.Fatal("empty task entered capture authority")
	}
	if _, err := f.service.ObserveSourceMetadata(ctx); err != nil {
		t.Fatal("metadata observation borrowed the expired capture claim", err)
	}
	if !reflect.DeepEqual(before, sourceObservationControlCounts(t, f)) {
		t.Fatal("metadata observation wrote task/control rows")
	}
	revokeSourceObservationGrant(t, f)
	if facts, err := f.service.ObserveSourceMetadata(ctx); err == nil || facts.SHA256() != "" || facts.inventory != nil {
		t.Fatal("revoked delegation produced partial/positive metadata facts")
	}
}
