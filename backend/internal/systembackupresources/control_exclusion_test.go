package systembackupresources

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type fixtureTargetProof struct{ err error }

func (p fixtureTargetProof) VerifyReadOnlyTarget(context.Context, *sql.Tx) error { return p.err }

func controlFixture() *countFixture {
	fixture := &countFixture{engines: map[string]string{}, rows: map[string]int64{}}
	for table := range controlExclusionTables {
		fixture.engines[table] = "InnoDB"
		fixture.rows[table] = 0
	}
	return fixture
}

func TestControlExclusionContractMatchesAllowlist(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "system-backup", "v12", "verifier-contract.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Defs struct {
			ControlExclusionCheck struct {
				AllOf []struct {
					Properties struct {
						ID struct {
							Enum []string `json:"enum"`
						} `json:"id"`
					} `json:"properties"`
				} `json:"allOf"`
			} `json:"ControlExclusionCheck"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	got := document.Defs.ControlExclusionCheck.AllOf[1].Properties.ID.Enum
	want := make([]string, 0, len(controlExclusionTables))
	for table := range controlExclusionTables {
		want = append(want, "control_plane.empty."+table)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("control exclusion contract IDs differ from verifier allowlist: got=%v want=%v", got, want)
	}
}

func TestControlExclusionRejectsRegistryDrift(t *testing.T) {
	for _, tc := range []struct {
		name, object, field string
		value               any
	}{
		{"new control name", "system_backup_configs", "name", "system_backup_new_control"},
		{"missing migration identity", "schema_migrations", "name", "schema_migrations_old"},
		{"control strategy drift", "system_backup_configs", "backup_strategy", "mysql_dump"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			document := frozenFixture(t)
			resourceObject(t, document, tc.object)[tc.field] = tc.value
			data, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if tables, err := ControlExclusionAllowlist(data); err == nil || tables != nil {
				t.Fatalf("registry drift admitted: tables=%v err=%v", tables, err)
			}
		})
	}
}

func TestControlExclusionEmptyTarget(t *testing.T) {
	state := controlFixture()
	verifier := SQLControlExclusionVerifier{DB: countDatabase(t, state), Proof: fixtureTargetProof{}}
	checks, err := verifier.VerifyRestoreTarget(context.Background(), frozenRegistryBytes(t), "sev_control_fixture")
	if err != nil || len(checks) != len(controlExclusionTables) {
		t.Fatalf("checks=%d err=%v", len(checks), err)
	}
	for _, check := range checks {
		if check.Status != "passed" || check.FailureCategory != "none" || !strings.HasPrefix(check.ID, "control_plane.empty.") {
			t.Fatalf("unexpected check: %+v", check)
		}
	}
	if state.commits != 1 || state.rollbacks != 0 || len(state.queries) != 2*len(controlExclusionTables) {
		t.Fatalf("incomplete read-only snapshot: %+v", state)
	}
	if !state.begin.ReadOnly || state.begin.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		t.Fatalf("wrong target transaction isolation: %+v", state.begin)
	}
	for _, query := range state.queries {
		if !strings.HasPrefix(query, "SELECT ") {
			t.Fatalf("write-capable query: %s", query)
		}
	}
}

func TestControlExclusionDetectsSourceRows(t *testing.T) {
	state := controlFixture()
	state.rows["system_backup_configs"] = 2
	verifier := SQLControlExclusionVerifier{DB: countDatabase(t, state), Proof: fixtureTargetProof{}}
	checks, err := verifier.VerifyRestoreTarget(context.Background(), frozenRegistryBytes(t), "sev_control_fixture")
	if err != nil {
		t.Fatal(err)
	}
	failed := 0
	for _, check := range checks {
		if check.Status == "failed" {
			failed++
			if check.ID != "control_plane.empty.system_backup_configs" || check.FailureCategory != "normalization_failed" {
				t.Fatalf("unexpected failure: %+v", check)
			}
		}
	}
	if failed != 1 {
		t.Fatalf("failed=%d, want 1", failed)
	}
}

func TestControlExclusionFailsClosed(t *testing.T) {
	state := controlFixture()
	draftRegistry, err := json.Marshal(currentRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	if checks, err := (SQLControlExclusionVerifier{DB: countDatabase(t, state), Proof: fixtureTargetProof{}}).VerifyRestoreTarget(context.Background(), draftRegistry, "sev_control_fixture"); err == nil || checks != nil || len(state.queries) != 0 {
		t.Fatalf("draft registry reached target database: checks=%v err=%v queries=%v", checks, err, state.queries)
	}
	for _, tc := range []struct {
		name  string
		proof TargetReadProofVerifier
		alter func(*countFixture)
	}{
		{"missing proof", nil, func(*countFixture) {}},
		{"rejected proof", fixtureTargetProof{errors.New("wrong target")}, func(*countFixture) {}},
		{"missing table", fixtureTargetProof{}, func(f *countFixture) { delete(f.engines, "system_backup_configs") }},
		{"nontransactional", fixtureTargetProof{}, func(f *countFixture) { f.engines["system_backup_configs"] = "MyISAM" }},
		{"count failed", fixtureTargetProof{}, func(f *countFixture) { f.failure = "count:system_backup_configs" }},
		{"commit failed", fixtureTargetProof{}, func(f *countFixture) { f.failure = "commit" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := controlFixture()
			tc.alter(state)
			checks, err := (SQLControlExclusionVerifier{DB: countDatabase(t, state), Proof: tc.proof}).VerifyRestoreTarget(context.Background(), frozenRegistryBytes(t), "sev_control_fixture")
			if err == nil || checks != nil {
				t.Fatalf("incomplete control check accepted: checks=%v err=%v", checks, err)
			}
		})
	}
}
