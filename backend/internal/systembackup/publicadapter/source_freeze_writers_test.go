package publicadapter

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/team"
	d "clawreef/internal/systembackupdispatch"
)

func TestOriginalWriterSourceFreezeFailsBeforeModuleFactory(t *testing.T) {
	for _, fault := range []string{"observe", "freeze", "mixed-hook", "legacy-parts-only"} {
		t.Run(fault, func(t *testing.T) {
			f, _, _ := setup(t)
			profile := linuxFixture(t, f, &sourceFixture{})
			cfg := profile.cfg
			observed, resolved, built := 0, 0, 0
			if fault == "observe" {
				observed = 1
			}
			cfg.BuildWriters = func(context.Context, d.Input, SourceInventory, []FrozenWriter) ([]flow.Writer, error) {
				return []flow.Writer{onceObservedWriter{Writer: fixtureWriter{f}, calls: &observed, state: f.x.Writers[0].Original}}, nil
			}
			cfg.FreezeSourcesWithWriters = func(context.Context, d.Input, SourceInventory, []FrozenWriter) (*team.Inventory, json.RawMessage, error) {
				resolved++
				return nil, nil, errors.New("source metadata unavailable")
			}
			cfg.BuildPartsWithWriters = func(d.Input, SourceInventory, time.Time, []FrozenWriter) ([]JobPart, error) {
				built++
				return f.x.Parts, nil
			}
			if fault == "mixed-hook" {
				cfg.FreezeSources = func(context.Context, d.Input, SourceInventory) (*team.Inventory, json.RawMessage, error) {
					t.Fatal("mixed resolver called")
					return nil, nil, nil
				}
			}
			if fault == "legacy-parts-only" {
				cfg.BuildPartsWithWriters = nil
			}
			profile, err := NewLinuxProfile(cfg)
			if fault == "mixed-hook" || fault == "legacy-parts-only" {
				if err == nil {
					t.Fatal("invalid resolver ordering accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			result, err := profile.Discover(context.Background(), f.in)
			if err == nil || built != 0 || len(result.Source) != 0 || len(result.Parts) != 0 {
				t.Fatal("failed source reached module factory", err)
			}
			if fault == "observe" && resolved != 0 {
				t.Fatal("failed original writer allowed source reads")
			}
			if fault == "freeze" && resolved != 1 {
				t.Fatal("source failure did not close module construction")
			}
		})
	}
}
