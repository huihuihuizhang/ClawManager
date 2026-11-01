package domain

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// Independent migration067 SQL projection; the later native fixture must use
// the unchanged actual migration and SQL raw cells, not this literal as proof.
func northboundOwnerFixture() Table {
	types := map[string]string{
		"id": "bigint unsigned", "record_type": "varchar(24)", "record_key": "char(64)", "scope_id": "bigint unsigned", "owner": "varchar(128)", "owner_normalized": "varchar(128)", "instance_id": "bigint unsigned", "runtime_type": "varchar(32)", "instance_mode": "varchar(16)", "source_kind": "varchar(32)", "source_key": "varchar(255)", "session_key": "varchar(255)", "question_key": "varchar(255)", "status": "varchar(24)", "occurred_at": "datetime(6)", "created_at": "datetime(6)", "updated_at": "datetime(6)", "version": "bigint unsigned", "schema_version": "smallint unsigned", "rule_version": "varchar(64)", "payload": "json", "prompt_tokens": "bigint unsigned", "completion_tokens": "bigint unsigned", "total_tokens": "bigint unsigned", "invocation_count": "bigint unsigned", "question_count": "bigint unsigned", "session_count": "bigint unsigned", "active_day_count": "int unsigned", "xp_value": "bigint", "level_value": "int unsigned", "streak_days": "int unsigned", "longest_streak_days": "int unsigned", "rank_position": "bigint unsigned", "rank_score": "decimal(24,6)", "last_activity_at": "datetime(6)", "business_date": "date", "timezone": "varchar(64)", "period_type": "varchar(16)", "period_start": "date", "period_end": "date", "category_key": "varchar(64)", "revision": "int unsigned", "expires_at": "datetime(6)", "active_work_seconds": "bigint unsigned", "login_day_count": "int unsigned", "login_streak_days": "int unsigned", "last_login_date": "date", "task_completed_count": "bigint unsigned", "interval_start": "datetime(6)", "interval_end": "datetime(6)", "task_code": "varchar(64)", "definition_version": "varchar(64)", "progress_value": "bigint unsigned", "target_value": "bigint unsigned", "completed_at": "datetime(6)", "rewarded_at": "datetime(6)",
	}
	row := Row{}
	required := strings.Fields("id record_type record_key scope_id status created_at updated_at version schema_version timezone revision")
	for name := range types {
		row[name] = Cell{Null: true}
	}
	for _, name := range required {
		row[name] = Text("0")
	}
	row["id"] = Text("18446744073709551615")
	row["record_type"] = Text("activity_window")
	row["record_key"] = Text(strings.Repeat("a", 64))
	row["status"] = Text("observed")
	row["created_at"], row["updated_at"] = Text("2026-01-02 03:04:05.000001"), Text("2026-01-02 03:04:05.000002")
	row["schema_version"] = Text("1")
	row["timezone"] = Text("Asia/Shanghai")
	row["owner"] = Text("原始私有名称")
	row["owner_normalized"] = Text("原始私有名称")
	row["instance_id"] = Text("18446744073709551615")
	row["version"] = Text("18446744073709551615")
	row["rank_position"] = Text("18446744073709551615")
	row["rank_score"] = Text("-999999999999999999.999999")
	row["xp_value"] = Text("-9223372036854775808")
	row["payload"] = Text(`{"private_text":"原始私密问题","bitmap":18446744073709551615,"source_key":"workspace-token-digest"}`)
	table := Table{Name: "northbound_owner_records", Engine: "InnoDB", PrimaryKey: []string{"id"}, UniqueKeys: []UniqueKey{{Name: "uk_owner_record", Columns: []string{"record_type", "record_key"}}}, Rows: []Row{row}}
	for _, name := range sortedKeys(row) {
		nullable := true
		for _, n := range required {
			if n == name {
				nullable = false
			}
		}
		table.Columns = append(table.Columns, Column{Name: name, Type: types[name], Nullable: nullable})
	}
	return table
}

func TestNorthboundOwnerUnsignedNullPrivateHistoryAndBitmapStayExact(t *testing.T) {
	table := northboundOwnerFixture()
	before := cloneRow(table.Rows[0])
	if e := validateNorthboundOwnerRows(context.Background(), table); e != nil {
		t.Fatal(e)
	}
	for name, want := range before {
		got := table.Rows[0][name]
		if got.Null != want.Null || !bytes.Equal(got.Bytes, want.Bytes) {
			t.Fatal("owner data validator rewrote source", name)
		}
	}
	row := cloneRow(table.Rows[0])
	row["id"] = Text("9223372036854775808")
	row["record_type"] = Text("recent_question")
	row["record_key"] = Text(strings.Repeat("b", 64))
	row["version"] = Text("0")
	row["scope_id"] = Text("0")
	row["rank_score"] = Cell{Null: true}
	row["prompt_tokens"] = Cell{Null: true}
	table.Rows = append(table.Rows, row)
	if e := validateNorthboundOwnerRows(context.Background(), table); e != nil {
		t.Fatal("global scope/version0/unmeasured metrics rejected", e)
	}
}

func TestNorthboundOwnerRejectsFutureShapeOverflowAndNeverInventsLiveParent(t *testing.T) {
	for _, mode := range []string{"unknown-column", "signed-id-schema", "new-fk", "wrong-unique-order", "uint64-overflow", "uint32-overflow", "negative-unsigned", "overprecise-rank", "negative-zero-rank", "noncanonical-time", "future-schema-version", "duplicate-key", "payload-null-versus-SQL-NULL"} {
		t.Run(mode, func(t *testing.T) {
			table := northboundOwnerFixture()
			row := table.Rows[0]
			switch mode {
			case "unknown-column":
				table.Columns = append(table.Columns, Column{Name: "future_actor_secret", Type: "text", Nullable: true})
				row["future_actor_secret"] = Cell{Null: true}
			case "signed-id-schema":
				for n := range table.Columns {
					if table.Columns[n].Name == "id" {
						table.Columns[n].Type = "bigint"
					}
				}
			case "new-fk":
				table.ForeignKeys = []ForeignKey{{Column: "instance_id", Table: "instances", Reference: "id"}}
			case "wrong-unique-order":
				table.UniqueKeys[0].Columns = []string{"record_key", "record_type"}
			case "uint64-overflow":
				row["version"] = Text("18446744073709551616")
			case "uint32-overflow":
				row["revision"] = Text("4294967296")
			case "negative-unsigned":
				row["scope_id"] = Text("-1")
			case "overprecise-rank":
				row["rank_score"] = Text("1.0000001")
			case "negative-zero-rank":
				row["rank_score"] = Text("-0.000000")
			case "noncanonical-time":
				row["updated_at"] = Text("2026-01-02 03:04:05")
			case "future-schema-version":
				row["schema_version"] = Text("2")
			case "duplicate-key":
				second := cloneRow(row)
				second["id"] = Text("1")
				table.Rows = append(table.Rows, second)
			case "payload-null-versus-SQL-NULL":
				row["payload"] = Cell{Null: true, Bytes: []byte("null")}
			}
			if validateNorthboundOwnerRows(context.Background(), table) == nil {
				t.Fatal("unsupported owner data accepted", mode)
			}
		})
	}
	table := northboundOwnerFixture()
	table.Rows = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if validateNorthboundOwnerRows(ctx, table) == nil {
		t.Fatal("empty owner table ignored cancellation")
	}
}
