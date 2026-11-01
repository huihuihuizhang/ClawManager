package domain

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const operationFixtureTime = "2026-11-01T08:00:00.123456Z"

func operationRestoreFixture() (Snapshot, []Table, Policy) {
	s, _, p := fixture()
	base := Row{
		"id": Text("9007199254740993"), "operation_id": Text("source-operation-0"), "user_id": Text("4"),
		"session_id": Text("archived-session"), "operation_type": Text("owner_team_create"),
		"idempotency_key_hash": Text(strings.Repeat("a", 64)), "request_hash": Text(strings.Repeat("b", 64)),
		"request_payload": Text(`{ "message": "保留原始参数", "api_token": "named-source-secret" }`), "status": Text("queued"),
		"available_at": Text("2026-10-01 01:02:03.123456"), "instance_id": Text("7"), "attempt_count": Text("3"),
		"lease_owner": Text("source-worker"), "lease_expires_at": Text("2026-10-01 01:03:04.123456"),
		"error_code": Text("OWNER_TEAM_RUNTIME_WAITING"), "error_message": Text("原始错误"),
		"created_at": Text("2026-10-01 01:02:03.123456"), "started_at": Cell{Null: true}, "finished_at": Cell{Null: true},
		"updated_at": Text("2026-10-01 01:02:04.123456"), "api_key_id": Text("archived-key"), "auth_scope": Text("teams:create"),
		"owner": Text("owner-case-sensitive"), "team_id": Text("999"), "template_id": Text("888"), "owner_request_key": Cell{Null: true},
	}
	op := table("northbound_operations", base)
	op.UniqueKeys = []UniqueKey{{Name: "uk_northbound_operation_id", Columns: []string{"operation_id"}}, {Name: "uk_northbound_operation_idempotency", Columns: []string{"user_id", "operation_type", "idempotency_key_hash"}}, {Name: "uk_owner_team_request", Columns: []string{"owner_request_key"}}}
	op.ForeignKeys = []ForeignKey{{"user_id", "users", "id"}, {"instance_id", "instances", "id"}}
	for i, status := range []string{"processing", "batch_pending", "succeeded", "failed", "canceled"} {
		row := cloneRow(base)
		row["id"], row["operation_id"], row["status"] = Text(strconv.FormatInt(9007199254740994+int64(i), 10)), Text("source-operation-"+strconv.Itoa(i+1)), Text(status)
		row["idempotency_key_hash"] = Text(strings.Repeat(strconv.Itoa(i+1), 64))
		if status == "processing" || status == "succeeded" {
			row["finished_at"] = Text("2026-10-01 01:02:04.654321")
		}
		op.Rows = append(op.Rows, row)
	}
	s.Tables = append(s.Tables, op)
	a := TableAdapter{SchemaSHA256: SchemaDigest(op), Normalizer: NorthboundOperation077Normalizer, InterruptedAt: operationFixtureTime, Columns: map[string]string{}}
	for _, name := range strings.Fields(operation077Columns) {
		a.Columns[name] = "preserve"
	}
	p.Dependencies = map[string]TableAdapter{op.Name: a}
	p.Configs = JSONRegistry{"northbound_operations.request_payload": {{Path: []string{"message"}, Action: "preserve"}, {Path: []string{"api_token"}, Action: "stub"}}}
	return s, copyTables(s.Tables), p
}

func TestOperation077CommonSQLPreservesTerminalHistoryAndClearsLeases(t *testing.T) {
	s, target, p := operationRestoreFixture()
	before, _ := Digest(s)
	plan, err := Normalize(context.Background(), s, target, p)
	if err != nil {
		t.Fatal(err)
	}
	source := find(s, "northbound_operations")
	got := find(plan.Data, "northbound_operations")
	if len(got.Rows) != 6 {
		t.Fatal("operation history lost")
	}
	for i, row := range got.Rows {
		wantStatus := source.Rows[i]["status"].String()
		if i < 3 {
			wantStatus = "failed"
		}
		if row["status"].String() != wantStatus || !row["lease_owner"].Null || !row["lease_expires_at"].Null {
			t.Fatal("operation remains runnable")
		}
		for name, value := range source.Rows[i] {
			if name == "request_payload" {
				if strings.Contains(row[name].String(), "named-source-secret") || !strings.Contains(row[name].String(), "保留原始参数") {
					t.Fatal("operation Secret policy not consumed")
				}
				continue
			}
			if name == "status" || name == "lease_owner" || name == "lease_expires_at" {
				continue
			}
			if name == "finished_at" && i < 3 && value.Null {
				if row[name].String() != "2026-11-01 08:00:00.123456" {
					t.Fatal("frozen interruption time lost")
				}
				continue
			}
			if !reflect.DeepEqual(value, row[name]) {
				t.Fatal("history bytes changed", name)
			}
		}
	}
	after, _ := Digest(s)
	if before != after {
		t.Fatal("source changed")
	}
}

func TestOperation077CommonSQLFailsClosed(t *testing.T) {
	for _, mode := range []string{"missing-clock", "clock-offset", "clock-submicrosecond", "clock-before-source", "unknown-state", "negative-attempts", "invalid-payload", "missing-owner-column", "fixed-status", "missing-unique", "old-primary-key", "missing-secret-policy", "unknown-secret-field"} {
		t.Run(mode, func(t *testing.T) {
			s, target, p := operationRestoreFixture()
			a := p.Dependencies["northbound_operations"]
			row := find(s, "northbound_operations").Rows[0]
			switch mode {
			case "missing-secret-policy":
				p.Configs = nil
			case "unknown-secret-field":
				row["request_payload"] = Text(`{"unregistered_credential":"secret"}`)
			case "missing-clock":
				a.InterruptedAt = ""
			case "clock-offset":
				a.InterruptedAt = "2026-11-01T08:00:00+00:00"
			case "clock-submicrosecond":
				a.InterruptedAt = "2026-11-01T08:00:00.1234567Z"
			case "clock-before-source":
				a.InterruptedAt = "2026-09-01T08:00:00Z"
			case "unknown-state":
				row["status"] = Text("unreviewed")
			case "negative-attempts":
				row["attempt_count"] = Text("-1")
			case "invalid-payload":
				row["request_payload"] = Text("not-json")
			case "missing-owner-column":
				delete(row, "owner")
			case "fixed-status":
				a.Columns["status"] = "fixed:failed"
			case "missing-unique":
				target[len(target)-1].UniqueKeys = nil
			case "old-primary-key":
				target[len(target)-1].PrimaryKey = []string{"operation_id"}
			}
			p.Dependencies["northbound_operations"] = a
			if _, err := Normalize(context.Background(), s, target, p); err == nil {
				t.Fatal("unsafe operation accepted")
			}
		})
	}
}

func TestOperation077VerifierRejectsExecutableExpectedData(t *testing.T) {
	for _, field := range []string{"status", "lease_owner", "lease_expires_at"} {
		s, target, p := operationRestoreFixture()
		plan, err := Normalize(context.Background(), s, target, p)
		if err != nil {
			t.Fatal(err)
		}
		find(plan.Data, "northbound_operations").Rows[0][field] = Text("processing")
		if VerifyOperationQuarantine(context.Background(), plan.Data) == nil {
			t.Fatal("executable expected plan accepted", field)
		}
	}
}
