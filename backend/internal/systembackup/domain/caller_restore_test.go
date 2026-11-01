package domain

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// Named synthetic SQL fixture, not a production schema pin or authority proof.
func callerRestoreFixture() (Snapshot, []Table, Policy) {
	s, _, p := fixture()
	for i := range s.Tables {
		if s.Tables[i].Name != "users" {
			continue
		}
		for _, name := range []string{"email", "created_at", "updated_at"} {
			s.Tables[i].Columns = append(s.Tables[i].Columns, Column{Name: name, Type: "text"})
		}
		for _, row := range s.Tables[i].Rows {
			row["email"] = Text(row["username"].String() + "@example.invalid")
			row["created_at"], row["updated_at"] = Text("2026-10-01 01:02:03"), Text("2026-10-01 01:02:04")
		}
	}
	caller := table("northbound_caller_policies", Row{
		"user_id": Text("4"), "enabled": Text("1"), "scopes_json": Text(`[ "pro-instances:create", "lite-instances:read" ]`),
		"created_at": Text("2026-10-01 01:02:03.123456"), "updated_at": Text("2026-10-01 01:02:04.123456"),
		"updated_by": Text("1"), "api_keys_json": Text(`[{"id":"historical-key","secret_hash":"named-source-hash","scopes":["teams:read"],"enabled":true}]`), "api_keys_version": Text("9223372036854775807"),
	})
	caller.PrimaryKey = []string{"user_id"}
	caller.ForeignKeys = []ForeignKey{{"user_id", "users", "id"}, {"updated_by", "users", "id"}}
	s.Tables = append(s.Tables, caller)
	a := TableAdapter{SchemaSHA256: SchemaDigest(caller), Normalizer: CallerPolicy066Normalizer, Columns: map[string]string{}}
	for _, name := range strings.Fields(caller066Columns) {
		a.Columns[name] = "preserve"
	}
	p.Dependencies = map[string]TableAdapter{caller.Name: a}
	return s, copyTables(s.Tables), p
}

func TestCaller066CommonSQLNormalization(t *testing.T) {
	for _, nullKeys := range []bool{false, true} {
		s, target, p := callerRestoreFixture()
		row := find(s, "northbound_caller_policies").Rows[0]
		if nullKeys {
			row["api_keys_json"], row["updated_by"] = Cell{Null: true}, Cell{Null: true}
			row["api_keys_version"] = Text("0")
		}
		before, _ := Digest(s)
		plan, err := Normalize(context.Background(), s, target, p)
		if err != nil {
			t.Fatal(err)
		}
		got := find(plan.Data, "northbound_caller_policies").Rows[0]
		if got["enabled"].String() != "0" || got["api_keys_json"].String() != "[]" || got["scopes_json"].String() != row["scopes_json"].String() {
			t.Fatal("caller credentials/execution not quarantined")
		}
		for _, name := range strings.Fields("user_id created_at updated_at updated_by api_keys_version") {
			if !reflect.DeepEqual(got[name], row[name]) {
				t.Fatalf("original %s lost", name)
			}
		}
		after, _ := Digest(s)
		if before != after {
			t.Fatal("source evidence mutated")
		}
	}
}

func TestCaller066CommonSQLRejectsUnsafeInput(t *testing.T) {
	for _, mode := range []string{"unknown-normalizer", "wrong-table", "source-schema", "target-schema", "fixed-before-validation", "missing-user-field", "bad-actor", "bad-scope", "bad-keys", "null-version", "negative-version", "bad-enabled", "old-schema"} {
		t.Run(mode, func(t *testing.T) {
			s, target, p := callerRestoreFixture()
			a := p.Dependencies["northbound_caller_policies"]
			row := find(s, "northbound_caller_policies").Rows[0]
			switch mode {
			case "unknown-normalizer":
				a.Normalizer = "guess"
			case "wrong-table":
				p.Dependencies["user_quotas"] = a
			case "source-schema":
				s.Tables[len(s.Tables)-1].UniqueKeys = []UniqueKey{{Name: "unexpected", Columns: []string{"updated_by"}}}
			case "target-schema":
				target[len(target)-1].PrimaryKey = []string{"updated_by"}
			case "fixed-before-validation":
				row["api_keys_json"] = Text("invalid")
				a.Columns["api_keys_json"] = "fixed:[]"
			case "missing-user-field":
				delete(s.Tables[0].Rows[0], "email")
			case "bad-actor":
				row["updated_by"] = Text("777")
			case "bad-scope":
				row["scopes_json"] = Text(`["system-backup:admin"]`)
			case "bad-keys":
				row["api_keys_json"] = Text(`{"hash":"synthetic"}`)
			case "null-version":
				row["api_keys_version"] = Cell{Null: true}
			case "negative-version":
				row["api_keys_version"] = Text("-1")
			case "bad-enabled":
				row["enabled"] = Text("2")
			case "old-schema":
				delete(row, "api_keys_version")
			}
			p.Dependencies["northbound_caller_policies"] = a
			if _, err := Normalize(context.Background(), s, target, p); err == nil {
				t.Fatal("unsafe caller accepted")
			}
		})
	}
}

func TestCaller066IndependentExpectedProjectionRejectsCredentials(t *testing.T) {
	for _, mode := range []string{"enabled", "keys", "null-keys", "bad-actor"} {
		t.Run(mode, func(t *testing.T) {
			s, target, p := callerRestoreFixture()
			plan, err := Normalize(context.Background(), s, target, p)
			if err != nil {
				t.Fatal(err)
			}
			row := find(plan.Data, "northbound_caller_policies").Rows[0]
			switch mode {
			case "enabled":
				row["enabled"] = Text("1")
			case "keys":
				row["api_keys_json"] = Text(`[{"id":"unexpected"}]`)
			case "null-keys":
				row["api_keys_json"] = Cell{Null: true}
			case "bad-actor":
				row["updated_by"] = Text("777")
			}
			if err := VerifyCallerQuarantine(context.Background(), plan.Data); err == nil {
				t.Fatal("unsafe expected projection accepted")
			}
		})
	}
}
