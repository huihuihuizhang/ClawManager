package publicadapter

import (
	"context"
	"encoding/json"
	"testing"

	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/team"
)

func TestPublicRunnerRejectsTeamsWithoutFrozenWriterCoverage(t *testing.T) {
	f, r, _ := setup(t)
	_, b, _ := teamsModuleFixture(t)
	f.x.Source, _ = json.Marshal(b.Source)
	f.x.SourceSHA256 = digest(f.x.Source)
	if _, err := r.Prepare(context.Background(), f.in, f); err == nil {
		t.Fatal("public runner accepted nonempty Teams with no C writer coverage")
	}
	if f.ensures != 0 {
		t.Fatal("invalid inventory dispatched work")
	}
}

func teamsWriterFixture(t *testing.T) (SourceInventory, []FrozenWriter) {
	_, b, _ := teamsModuleFixture(t)
	b.Source.Teams.Writers = []team.WriterBinding{
		{ID: "deployment/cm/platform", Kind: "platform", UID: "platform-original", Generation: 3, Running: true, Checkpoint: "original-replicas", Units: TeamsWorkUnits()},
		{ID: "gateway/runtime-original/7", Kind: "gateway", UID: "runtime-original", Generation: 7, Running: true, Checkpoint: "original-runtime", InstanceID: 7},
	}
	var frozen []FrozenWriter
	for _, w := range b.Source.Teams.Writers {
		frozen = append(frozen, FrozenWriter{w.ID, flow.State{UID: w.UID, Generation: w.Generation, Running: w.Running, Checkpoint: w.Checkpoint}})
	}
	return b.Source, frozen
}

func TestTeamsFrozenCoverageUsesOriginalNativeWriters(t *testing.T) {
	for _, mode := range []string{"valid", "missing-platform", "missing-unit", "missing-runtime", "duplicate", "uid", "generation", "checkpoint", "power", "foreign-instance", "participant-as-platform", "wrong-native-id", "unknown-unit", "stopped", "stopped-but-running", "running-writer-for-stopped"} {
		t.Run(mode, func(t *testing.T) {
			source, frozen := teamsWriterFixture(t)
			switch mode {
			case "missing-platform":
				source.Teams.Writers = source.Teams.Writers[1:]
			case "missing-unit":
				source.Teams.Writers[0].Units = source.Teams.Writers[0].Units[1:]
			case "missing-runtime":
				source.Teams.Writers = source.Teams.Writers[:1]
			case "duplicate":
				source.Teams.Writers = append(source.Teams.Writers, source.Teams.Writers[1])
			case "uid":
				frozen[1].Original.UID = "replacement"
			case "generation":
				frozen[1].Original.Generation++
			case "checkpoint":
				frozen[1].Original.Checkpoint = "replacement"
			case "power":
				frozen[1].Original.Running = false
			case "running-writer-for-stopped":
				for n := range source.Instances {
					if source.Instances[n].ID == 7 {
						source.Instances[n].Status = "stopped"
					}
				}
			case "foreign-instance":
				source.Teams.Writers[1].InstanceID = 9
			case "participant-as-platform":
				source.Teams.Writers[0].ID = "gate/registered"
				frozen[0].ID = "gate/registered"
			case "wrong-native-id":
				source.Teams.Writers[1].ID = "gateway/runtime-original/99"
				frozen[1].ID = "gateway/runtime-original/99"
			case "unknown-unit":
				source.Teams.Writers[0].Units = append(source.Teams.Writers[0].Units, "new.unreviewed_writer")
			case "stopped", "stopped-but-running":
				for n := range source.Instances {
					if source.Instances[n].ID == 7 {
						source.Instances[n].Status = "stopped"
					}
				}
				source.Teams.Writers[1].Kind, source.Teams.Writers[1].ID, source.Teams.Writers[1].Running = "stopped", "stopped/7", false
				frozen[1].ID, frozen[1].Original.Running = "stopped/7", false
				if mode == "stopped-but-running" {
					source.Teams.Writers[1].Running = true
					frozen[1].Original.Running = true
				}
			}
			err := ValidateTeamsWriters(source, frozen)
			if (err == nil) != (mode == "valid" || mode == "stopped") {
				t.Fatalf("coverage error = %v", err)
			}
		})
	}
}

func TestTeamsCoverageIsEnforcedByActualPublicPrepare(t *testing.T) {
	f, r, _ := setup(t)
	source, frozen := teamsWriterFixture(t)
	f.x.Source, _ = json.Marshal(source)
	f.x.SourceSHA256, f.x.Writers = digest(f.x.Source), frozen
	if _, err := r.Prepare(context.Background(), f.in, f); err != nil {
		t.Fatal(err)
	}
	source.Teams.Writers[0].Units = nil
	f.x.Source, _ = json.Marshal(source)
	f.x.SourceSHA256 = digest(f.x.Source)
	if _, err := r.Prepare(context.Background(), f.in, f); err == nil || f.ensures != 0 {
		t.Fatal("missing writer delta admitted or work dispatched")
	}
}
