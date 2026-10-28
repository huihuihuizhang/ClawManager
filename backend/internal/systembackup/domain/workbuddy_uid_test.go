package domain

import (
	"context"
	"errors"
	"testing"
)

func TestWorkBuddyUIDRestorePreservesReservationsAndHighWater(t *testing.T) {
	s, target, p := observedWorkBuddyFixture(true)
	p.WorkBuddy = WorkBuddyUIDSchema()
	// A deleted user's historical reservation is also retained, not reassigned.
	s.Tables[len(s.Tables)-2].Rows[1]["user_id"] = Text("998")
	state := isolatedTarget(target)
	for i := range state.tables {
		if state.tables[i].Name == workBuddyAllocator {
			state.tables[i].Rows = []Row{{"id": Text("1"), "next_uid": Text("10000")}}
		}
	}
	db := database(state)
	defer db.Close()
	before, _ := Digest(s)
	if e := PreflightDrill(context.Background(), db, targetProof()); !errors.Is(e, ErrNotEmpty) {
		t.Fatalf("unversioned preflight admitted seed: %v", e)
	}
	if e := PreflightDrillWithPolicy(context.Background(), db, targetProof(), p); e != nil {
		t.Fatal(e)
	}
	plan, e := RestoreDrill(context.Background(), db, targetProof(), s, p)
	if e != nil {
		t.Fatal(e)
	}
	if len(find(plan.Data, workBuddyIdentities).Rows) != 2 || find(plan.Data, workBuddyIdentities).Rows[1]["user_id"].String() != "998" || find(plan.Data, workBuddyAllocator).Rows[0]["next_uid"].String() != "21010" {
		t.Fatal("identity reservation/high-water lost")
	}
	if !find(plan.Data, "instances").Rows[0]["workbuddy_storage_identity"].Null {
		t.Fatal("storage identity fabricated")
	}
	if e = VerifyDrill(context.Background(), db, targetProof(), plan); e != nil {
		t.Fatal(e)
	}
	after, _ := Digest(s)
	if before != after {
		t.Fatal("source changed")
	}
	if _, e = RestoreDrill(context.Background(), db, targetProof(), s, p); !errors.Is(e, ErrNotEmpty) {
		t.Fatal("nonempty restore accepted", e)
	}
}

func TestWorkBuddyUIDRejectsInvalidDataBeforeTargetWrites(t *testing.T) {
	for _, attack := range []string{"duplicate-uid", "uid-low", "uid-high", "owner", "missing-live", "collision-non-wb", "storage-nonnull", "pro", "allocator-regression", "allocator-missing", "allocator-multiple", "allocator-high", "unknown-layout", "fingerprint", "target-index", "target-fk", "target-bootstrap-advanced", "unrelated-orphan"} {
		t.Run(attack, func(t *testing.T) {
			s, target, p := observedWorkBuddyFixture(true)
			p.WorkBuddy = WorkBuddyUIDSchema()
			ident := &s.Tables[len(s.Tables)-2]
			allocator := &s.Tables[len(s.Tables)-1]
			switch attack {
			case "duplicate-uid":
				ident.Rows[1]["linux_uid"] = Text("21000")
			case "uid-low":
				ident.Rows[0]["linux_uid"] = Text("9999")
			case "uid-high":
				ident.Rows[0]["linux_uid"] = Text("65534")
			case "owner":
				ident.Rows[0]["user_id"] = Text("1")
			case "missing-live":
				ident.Rows = ident.Rows[1:]
			case "collision-non-wb":
				s.Tables[2].Rows[0]["type"] = Text("openclaw")
			case "storage-nonnull":
				s.Tables[2].Rows[0]["workbuddy_storage_identity"] = Text("")
			case "pro":
				s.Tables[2].Rows[0]["instance_mode"] = Text("pro")
				s.Tables[2].Rows[0]["runtime_type"] = Text("desktop")
			case "allocator-regression":
				allocator.Rows[0]["next_uid"] = Text("21001")
			case "allocator-missing":
				allocator.Rows = nil
			case "allocator-multiple":
				allocator.Rows = append(allocator.Rows, Row{"id": Text("2"), "next_uid": Text("30000")})
			case "allocator-high":
				allocator.Rows[0]["next_uid"] = Text("65535")
			case "unknown-layout":
				p.WorkBuddy.Layout = "guess"
			case "fingerprint":
				p.WorkBuddy.AllocatorSHA256 = "bad"
			case "target-index":
				target[len(target)-2].UniqueKeys = nil
			case "target-fk":
				target[len(target)-2].ForeignKeys = []ForeignKey{{Column: "instance_id", Table: "instances", Reference: "id"}}
			case "unrelated-orphan":
				s.Tables[4].Rows[0]["instance_id"] = Text("987")
			}
			state := isolatedTarget(target)
			if attack == "target-bootstrap-advanced" {
				for i := range state.tables {
					if state.tables[i].Name == workBuddyAllocator {
						state.tables[i].Rows = []Row{{"id": Text("1"), "next_uid": Text("21011")}}
					}
				}
			}
			before, _ := Digest(Snapshot{Version: Version, Tables: state.tables})
			db := database(state)
			defer db.Close()
			if _, e := RestoreDrill(context.Background(), db, targetProof(), s, p); e == nil {
				t.Fatal("unsafe restore accepted")
			}
			after, _ := Digest(Snapshot{Version: Version, Tables: state.tables})
			if state.writes != 0 || state.commits != 0 || before != after {
				t.Fatal("target mutated before rejection")
			}
		})
	}
}

func TestWorkBuddyUIDRollbackAndExhaustion(t *testing.T) {
	for _, failure := range []string{"insert", "evidence"} {
		t.Run(failure, func(t *testing.T) {
			s, target, p := observedWorkBuddyFixture(true)
			p.WorkBuddy = WorkBuddyUIDSchema()
			state := isolatedTarget(target)
			for i := range state.tables {
				if state.tables[i].Name == workBuddyAllocator {
					state.tables[i].Rows = []Row{{"id": Text("1"), "next_uid": Text("10000")}}
				}
			}
			before, _ := Digest(Snapshot{Version: Version, Tables: state.tables})
			if failure == "insert" {
				state.failInsert = workBuddyIdentities
			}
			db := database(state)
			defer db.Close()
			_, e := RestoreDrillWithEvidence(context.Background(), db, targetProof(), s, p, func(context.Context, RestorePlan) error {
				if failure == "evidence" {
					return ErrIsolation
				}
				return nil
			})
			after, _ := Digest(Snapshot{Version: Version, Tables: state.tables})
			if e == nil || state.commits != 0 || before != after {
				t.Fatal("failure did not roll back admin/allocator/identity", e)
			}
		})
	}
	s, target, p := observedWorkBuddyFixture(true)
	p.WorkBuddy = WorkBuddyUIDSchema()
	s.Tables[len(s.Tables)-2].Rows[1]["linux_uid"] = Text("65533")
	s.Tables[len(s.Tables)-1].Rows[0]["next_uid"] = Text("65534")
	plan, e := Normalize(context.Background(), s, target, p)
	if e != nil || find(plan.Data, workBuddyAllocator).Rows[0]["next_uid"].String() != "65534" {
		t.Fatal("exhausted allocator was reset", e)
	}
}
