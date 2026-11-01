package systembackupresources

import (
	"context"
	"database/sql"
	"testing"
)

func bridgeSourceFixture() NorthboundRestoreSource {
	i := northboundNormalizeFixture()
	return NorthboundRestoreSource{Settings: exportBridgeTable(i.Source), Audit: NorthboundRestoreTable{Columns: restoreFieldColumns()["northbound_settings_audit"], Rows: []map[string]*string{{"id": fieldString("9223372036854775807"), "actor_user_id": nil, "action": fieldString("api_key.update"), "before_json": nil, "after_json": fieldString(`{"private":"original-raw-body","version":9}`), "created_at": fieldString("2026-10-22 01:02:03.000001")}}}, Bindings: []NorthboundRestoreBinding{{Kind: "user", Source: 7, Target: 7}, {Kind: "northbound_settings_audit", Source: 9223372036854775807, Target: 9223372036854775807}}}
}

func TestNorthboundBridgeBoundBeforeCopyAndRawSourceBinding(t *testing.T) {
	ctx := context.Background()
	source := bridgeSourceFixture()
	budget := restoreFieldBudget{Rows: 2, Bytes: 4096}
	if e := boundNorthboundSource(ctx, source, budget); e != nil {
		t.Fatal(e)
	}
	for _, b := range []restoreFieldBudget{{Rows: 1, Bytes: 4096}, {Rows: 2, Bytes: 1}} {
		if e := boundNorthboundSource(ctx, source, b); e == nil {
			t.Fatal("source exceeded capacity before copying")
		}
	}
	settings, audit, bindings, e := freezeNorthboundSource(source)
	if e != nil {
		t.Fatal(e)
	}
	p := &NorthboundCASCandidate{tx: &sql.Tx{}, sourceSettings: settings, sourceAudit: audit, sourceBindings: bindings, budget: budget}
	if p.MatchesSource(source) != nil {
		t.Fatal("exact original rows refused")
	}
	// Both originals would have the same target redaction. Correspondence is
	// checked against original source bodies, never just the redacted projection.
	source.Audit.Rows[0]["after_json"] = fieldString(`{"private":"different-body","version":9}`)
	if p.MatchesSource(source) == nil {
		t.Fatal("same-redaction different raw source accepted")
	}
	source = bridgeSourceFixture()
	source.Bindings[0].Source = 8
	source.Bindings[0].Target = 8
	if p.MatchesSource(source) == nil {
		t.Fatal("different stable identity mappings accepted")
	}
	source = bridgeSourceFixture()
	source.Settings.Rows[0]["version"] = fieldString("78")
	if p.MatchesSource(source) == nil {
		t.Fatal("original settings changed")
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if boundNorthboundSource(ctx, bridgeSourceFixture(), budget) == nil {
		t.Fatal("source cancellation ignored")
	}
}

func TestNorthboundBridgeRequiresControlledTransactionAndRealDeletion(t *testing.T) {
	ctx := context.Background()
	tx, other := &sql.Tx{}, &sql.Tx{}
	observation := &NorthboundTargetObservation{}
	if _, e := PrepareNorthboundRestoreInTransaction(ctx, tx, observation, bridgeSourceFixture(), NorthboundRestoreBudget{Rows: 10, Bytes: 4096}); e == nil {
		t.Fatal("arbitrary external TX accepted")
	}
	p := &NorthboundCASCandidate{tx: tx, bootstrapActors: map[string]bool{"1": true}}
	if p.CheckBefore(ctx, other, NorthboundRestoreScope{}) == nil {
		t.Fatal("candidate reused across TX")
	}
	if ApplyNorthboundSettingsCAS(ctx, tx, p, NorthboundRestoreTable{}) == nil {
		t.Fatal("manual actor NULL substituted for actual users deletion")
	}
	if p.CheckApplied(ctx, tx) == nil {
		t.Fatal("unexecuted candidate could complete")
	}
	if DeleteNorthboundBootstrapInTransaction(ctx, other, p) == nil {
		t.Fatal("deletion reused across TX")
	}
}
