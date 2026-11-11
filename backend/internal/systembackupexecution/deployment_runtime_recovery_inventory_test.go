package systembackupexecution

import (
	"context"
	"encoding/json"
	"testing"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/team"
	d "clawreef/internal/systembackupdispatch"
)

func TestTenantRecoveryInventoryRetainsOriginalPlanWithoutForwardMaterials(t *testing.T) {
	source := b.SourceInventory{Database: "business", ServerUUID: "server-original", Users: []int{1},
		Instances: []b.InstanceIdentity{{ID: 2, UserID: 1, Generation: 7, Mode: "pro", OS: "linux", Status: "running", Namespace: "test-user-1", Pod: "old-pod", Workspace: "/workspace"}},
		TeamFacts: &team.SourceFacts{}, CaptureMetadata: json.RawMessage(`{"Version":"original-metadata"}`)}
	writers := []b.FrozenWriter{{ID: "deployment/test-user-1/pro"}}
	raw, _ := json.Marshal(source)
	discovery := b.Discovery{Source: raw, SourceSHA256: hash(raw), Writers: writers}
	for _, material := range []*productionCaptureMaterials{nil, {Version: "revoked-forward"}} {
		service := &DeploymentService{captureMaterials: material}
		// No current signed source exists. Fresh discovery must still refuse.
		if service.validateRuntimeWriterInventory(context.Background(), nil, d.Input{}, source, nil) == nil {
			t.Fatal("forward inventory bypassed signed source admission")
		}
		if err := matchOriginalRuntimeInventory(source, writers, discovery); err != nil {
			t.Fatal("original frozen inventory could not bind for recovery", err)
		}
	}
	for _, fault := range []string{"instance", "generation", "pod", "namespace", "volume", "writer", "subset", "hash", "unfrozen"} {
		t.Run(fault, func(t *testing.T) {
			var changed b.SourceInventory
			if json.Unmarshal(raw, &changed) != nil {
				t.Fatal("fixture")
			}
			frozen := append([]b.FrozenWriter{}, writers...)
			saved := discovery
			switch fault {
			case "instance":
				changed.Instances[0].ID++
			case "generation":
				changed.Instances[0].Generation++
			case "pod":
				changed.Instances[0].Pod = "replacement-pod"
			case "namespace":
				changed.Instances[0].Namespace = "test-user-2"
			case "volume":
				changed.CaptureMetadata = json.RawMessage(`{"Volume":"replacement"}`)
			case "writer":
				frozen[0].ID = "deployment/test-user-1/replacement"
			case "subset":
				frozen = []b.FrozenWriter{}
			case "hash":
				saved.SourceSHA256 = hash([]byte("changed"))
			case "unfrozen":
				frozen = nil
			}
			if matchOriginalRuntimeInventory(changed, frozen, saved) == nil {
				t.Fatal("changed identity borrowed recovery authority")
			}
		})
	}
}

func TestRecoveryInventoryGuardUsesCompleteSavedDiscovery(t *testing.T) {
	saved := b.Discovery{Source: json.RawMessage(`{"Database":"original"}`), Writers: []b.FrozenWriter{{ID: "deployment/tenant/original"}}, Parts: []b.JobPart{{Part: "workspace"}}}
	if err := matchOriginalRecoveryDiscovery(saved, saved); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"writer", "part", "source"} {
		var changed b.Discovery
		raw, _ := json.Marshal(saved)
		if json.Unmarshal(raw, &changed) != nil {
			t.Fatal("fixture")
		}
		switch fault {
		case "writer":
			changed.Writers[0].ID = "deployment/tenant/replacement"
		case "part":
			changed.Parts = nil
		case "source":
			changed.Source = json.RawMessage(`{"Database":"changed"}`)
		}
		if matchOriginalRecoveryDiscovery(changed, saved) == nil {
			t.Fatal("changed discovery accepted", fault)
		}
	}
	service := &DeploymentService{} // recovery-only restart, no forward materials
	if service.inventory(context.Background(), d.Input{Authority: d.Authority{TaskType: "backup"}}, saved) == nil {
		t.Fatal("missing original recovery owner accepted")
	}
}
