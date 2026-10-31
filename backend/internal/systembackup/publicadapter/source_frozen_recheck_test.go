package publicadapter

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/team"
	d "clawreef/internal/systembackupdispatch"
)

func TestOriginalSourceRecheckReusesFrozenLocatorWithoutProducingAgain(t *testing.T) {
	for _, fault := range []string{"valid", "remote-drift", "sql-drift"} {
		t.Run(fault, func(t *testing.T) {
			f, _, _ := setup(t)
			sqlFixture := &sourceFixture{}
			cfg := linuxFixture(t, f, sqlFixture).cfg
			produced, rechecked, observed := 0, 0, 0
			cfg.ReadTeamFacts = func(context.Context, *sql.Tx, SourceInventory) (*team.SourceFacts, error) {
				return &team.SourceFacts{Version: team.SourceFactsVersion, SchemaSHA256: team.SchemaSHA256(), Teams: []team.TeamSQLFacts{}, Members: []team.MemberSQLFacts{}}, nil
			}
			cfg.BuildWriters = func(context.Context, d.Input, SourceInventory, []FrozenWriter) ([]flow.Writer, error) {
				return []flow.Writer{onceObservedWriter{Writer: fixtureWriter{f}, calls: &observed, state: f.x.Writers[0].Original}}, nil
			}
			cfg.FreezeSourcesWithWriters = func(context.Context, d.Input, SourceInventory, []FrozenWriter) (*team.Inventory, json.RawMessage, error) {
				produced++
				return &team.Inventory{Version: team.InventoryVersion, SchemaSHA256: team.SchemaSHA256(), Teams: []team.SourceTeam{}, Mounts: []team.SharedMount{}, Redis: []team.RedisScope{}, Objects: []team.ObjectRef{}}, json.RawMessage(`{"locator":"original-registered-cutoff"}`), nil
			}
			cfg.BuildPartsWithWriters = func(d.Input, SourceInventory, time.Time, []FrozenWriter) ([]JobPart, error) { return f.x.Parts, nil }
			cfg.CheckFrozenSources = func(_ context.Context, _ d.Input, current, frozen SourceInventory, writers []FrozenWriter) error {
				rechecked++
				if current.TeamFacts == nil || frozen.Teams == nil || string(frozen.CaptureMetadata) != `{"locator":"original-registered-cutoff"}` || len(writers) != 1 {
					t.Fatal("missing original frozen source")
				}
				frozen.CaptureMetadata[0] = 'x'
				writers[0].Original.Checkpoint = "mutated callback clone"
				if fault == "remote-drift" {
					return errors.New("named source metadata drift fixture")
				}
				return nil
			}
			profile, err := NewLinuxProfile(cfg)
			if err != nil {
				t.Fatal(err)
			}
			selection, err := profile.Discover(context.Background(), f.in)
			if err != nil {
				t.Fatal(err)
			}
			before := append([]byte{}, selection.Source...)
			if fault == "sql-drift" {
				sqlFixture.wrongOwner = true
			}
			err = profile.CheckSource(context.Background(), f.in, selection)
			if (err == nil) != (fault == "valid") || produced != 1 || observed != 1 || string(selection.Source) != string(before) {
				t.Fatal("source recheck produced a new cutoff/writer or mutated original", fault, err, produced, observed)
			}
			if fault != "sql-drift" && rechecked != 1 {
				t.Fatal("original remote recheck omitted")
			}
		})
	}
}
