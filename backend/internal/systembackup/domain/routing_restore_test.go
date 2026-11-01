package domain

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func routingRestoreFixture() (Snapshot, []Table, Policy) {
	s, _, p := fixture()
	routing := table("routing_classifier_settings", Row{"id": Text("1"), "base_url": Text("https://source-classifier.invalid/private"), "timeout_ms": Text("5000"), "encrypted_api_key": Text("named-source-ciphertext"), "updated_at": Text("2026-10-01 01:02:03"), "routing_mode": Text("hybrid")})
	for i := range routing.Columns {
		routing.Columns[i].Nullable = false
	}
	s.Tables = append(s.Tables, routing)
	a := TableAdapter{SchemaSHA256: SchemaDigest(routing), Normalizer: RoutingClassifier061Normalizer, Columns: map[string]string{}}
	for _, name := range strings.Fields(routing061Columns) {
		a.Columns[name] = "preserve"
	}
	p.Dependencies = map[string]TableAdapter{routing.Name: a}
	return s, copyTables(s.Tables), p
}

func TestRouting061CommonSQLConsumesOwnerRule(t *testing.T) {
	for _, mode := range []string{"", "rules", "hybrid", "laya"} {
		s, target, p := routingRestoreFixture()
		original := find(s, "routing_classifier_settings").Rows[0]
		original["routing_mode"] = Text(mode)
		before, _ := Digest(s)
		plan, err := Normalize(context.Background(), s, target, p)
		if err != nil {
			t.Fatal(err)
		}
		row := find(plan.Data, "routing_classifier_settings").Rows[0]
		if row["routing_mode"].String() != "rules" || row["base_url"].Null || row["base_url"].String() != "" || row["encrypted_api_key"].Null || row["encrypted_api_key"].String() != "" {
			t.Fatal("classifier can contact source")
		}
		for _, name := range []string{"id", "timeout_ms", "updated_at"} {
			if !reflect.DeepEqual(row[name], original[name]) {
				t.Fatal("history field lost", name)
			}
		}
		after, _ := Digest(s)
		if before != after {
			t.Fatal("source changed")
		}
	}
}

func TestRouting061CommonSQLRejectsUnsupportedSchemaAndData(t *testing.T) {
	for _, mode := range []string{"no-adapter", "bad-pin", "unknown-column", "nullable-credential", "fixed-secret", "clock", "bad-mode", "bad-id", "bad-timeout", "null-time"} {
		t.Run(mode, func(t *testing.T) {
			s, target, p := routingRestoreFixture()
			a := p.Dependencies["routing_classifier_settings"]
			row := find(s, "routing_classifier_settings").Rows[0]
			switch mode {
			case "bad-pin":
				a.SchemaSHA256 = strings.Repeat("0", 64)
			case "unknown-column":
				target[len(target)-1].Columns = append(target[len(target)-1].Columns, Column{Name: "future_secret", Type: "text"})
			case "nullable-credential":
				for i := range target[len(target)-1].Columns {
					if target[len(target)-1].Columns[i].Name == "encrypted_api_key" {
						target[len(target)-1].Columns[i].Nullable = true
					}
				}
			case "fixed-secret":
				a.Columns["encrypted_api_key"] = "fixed:"
			case "clock":
				a.InterruptedAt = operationFixtureTime
			case "bad-mode":
				row["routing_mode"] = Text("unregistered")
			case "bad-id":
				row["id"] = Text("2")
			case "bad-timeout":
				row["timeout_ms"] = Text("99")
			case "null-time":
				row["updated_at"] = Cell{Null: true}
			}
			p.Dependencies["routing_classifier_settings"] = a
			if mode == "no-adapter" {
				p.Dependencies = nil
			}
			if _, err := Normalize(context.Background(), s, target, p); err == nil {
				t.Fatal("unsafe classifier accepted")
			}
		})
	}
}

func TestRouting061VerifierRejectsExpectedSourceEndpointAndKeys(t *testing.T) {
	for _, field := range []string{"routing_mode", "base_url", "encrypted_api_key"} {
		s, target, p := routingRestoreFixture()
		plan, err := Normalize(context.Background(), s, target, p)
		if err != nil {
			t.Fatal(err)
		}
		find(plan.Data, "routing_classifier_settings").Rows[0][field] = Text("laya")
		if VerifyRoutingQuarantine(context.Background(), plan.Data) == nil {
			t.Fatal("unsafe expected classifier accepted", field)
		}
	}
}
