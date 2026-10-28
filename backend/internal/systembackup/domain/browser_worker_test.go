package domain

import (
	"context"
	"testing"
)

// Metadata is from backup's migration 064_add_instance_browser_workers.sql;
// rows are synthetic, with an active source state that must never be replayed.
func browserWorkerFixture() Table {
	return Table{
		Name: "instance_browser_workers", Engine: "InnoDB", PrimaryKey: []string{"instance_id"},
		ForeignKeys: []ForeignKey{{"instance_id", "instances", "id"}},
		Columns: []Column{
			{Name: "instance_id", Type: "int"},
			{Name: "enabled", Type: "tinyint(1)"},
			{Name: "status", Type: "varchar(32)"},
			{Name: "resource_profile", Type: "varchar(32)"},
			{Name: "display_width", Type: "int"},
			{Name: "display_height", Type: "int"},
			{Name: "retain_profile", Type: "tinyint(1)"},
			{Name: "browser_image", Type: "varchar(512)"},
			{Name: "cdp_proxy_image", Type: "varchar(512)"},
			{Name: "generation", Type: "int"},
			{Name: "observed_generation", Type: "int"},
			{Name: "last_error", Type: "text", Nullable: true},
			{Name: "created_at", Type: "timestamp"},
			{Name: "updated_at", Type: "timestamp"},
		},
		Rows: []Row{{
			"instance_id": Text("7"), "enabled": Text("1"), "status": Text("ready"),
			"resource_profile": Text("standard"), "display_width": Text("1440"), "display_height": Text("900"),
			"retain_profile": Text("1"), "browser_image": Text("example.invalid/browser:test"),
			"cdp_proxy_image": Text("example.invalid/cdp:test"), "generation": Text("12"),
			"observed_generation": Text("12"), "last_error": Text("synthetic source diagnostic"),
			"created_at": Text("2026-10-01 00:00:00"), "updated_at": Text("2026-10-02 00:00:00"),
		}},
	}
}

func TestBrowserWorkerRestoreKeepsSettingsAndDisablesRuntime(t *testing.T) {
	source, target, policy := fixture()
	browser := browserWorkerFixture()
	source.Tables = append(source.Tables, browser)
	target = append(target, browser)
	before, _ := Digest(source)
	state := isolatedTarget(target)
	db := database(state)
	defer db.Close()
	if err := PreflightRestoreDrill(context.Background(), db, targetProof(), source, policy); err != nil {
		t.Fatal(err)
	}
	plan, err := RestoreDrill(context.Background(), db, targetProof(), source, policy)
	if err != nil {
		t.Fatal(err)
	}
	rows := find(plan.Data, browser.Name).Rows
	if len(rows) != 1 {
		t.Fatal("browser settings were dropped")
	}
	r := rows[0]
	for field, want := range map[string]string{
		"enabled": "0", "status": "disabled", "generation": "1", "observed_generation": "0",
	} {
		if r[field].String() != want {
			t.Errorf("%s = %q, want %q", field, r[field].String(), want)
		}
	}
	if !r["last_error"].Null {
		t.Fatal("source diagnostics restored")
	}
	for _, field := range []string{"instance_id", "resource_profile", "display_width", "display_height", "retain_profile", "browser_image", "cdp_proxy_image", "created_at", "updated_at"} {
		if r[field].String() != browser.Rows[0][field].String() {
			t.Errorf("browser setting lost: %s", field)
		}
	}
	if err := VerifyDrill(context.Background(), db, targetProof(), plan); err != nil {
		t.Fatal(err)
	}
	after, _ := Digest(source)
	if before != after {
		t.Fatal("source browser state changed")
	}
}

func TestBrowserWorkerRestoreRejectsOrphanAndUnknownColumns(t *testing.T) {
	for _, name := range []string{"orphan", "unknown-source", "unknown-target", "missing-target"} {
		t.Run(name, func(t *testing.T) {
			source, target, policy := fixture()
			browser := browserWorkerFixture()
			dest := browser
			dest.Columns = append([]Column(nil), browser.Columns...)
			switch name {
			case "orphan":
				browser.Rows[0]["instance_id"] = Text("999")
			case "unknown-source":
				browser.Columns = append(browser.Columns, Column{Name: "auto_start", Type: "int"})
				browser.Rows[0]["auto_start"] = Text("1")
			case "unknown-target":
				dest.Columns = append(dest.Columns, Column{Name: "auto_start", Type: "int", Default: strptr("1")})
			}
			source.Tables = append(source.Tables, browser)
			if name != "missing-target" {
				target = append(target, dest)
			}
			state := isolatedTarget(target)
			db := database(state)
			defer db.Close()
			if _, err := RestoreDrill(context.Background(), db, targetProof(), source, policy); err == nil {
				t.Fatal("unsafe browser restore accepted")
			}
			if state.writes != 0 || state.commits != 0 {
				t.Fatal("invalid browser metadata reached target writes")
			}
		})
	}
}
