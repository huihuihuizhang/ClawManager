package systembackupresources

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func auditNormalizeFixture() restoreAuditInput {
	columns := restoreFieldColumns()
	return restoreAuditInput{
		Audit: restoreFieldTable{Name: "audit_logs", Columns: columns["audit_logs"], Rows: []restoreFieldRow{{
			"id": fieldString("1"), "user_id": fieldString("7"), "action": fieldString("settings.update"), "resource_type": fieldString("instance"), "resource_id": fieldString("7"),
			"details": fieldString(`{"nested":{"token":"private-secret"}}`), "ip_address": fieldString("private-secret"), "created_at": fieldString("2026-10-22 01:02:03"),
		}}},
		Northbound: restoreFieldTable{Name: "northbound_settings_audit", Columns: columns["northbound_settings_audit"], Rows: []restoreFieldRow{{
			"id": fieldString("1"), "actor_user_id": fieldString("7"), "action": fieldString("external_node_port.update"),
			"before_json": fieldString(`null`), "after_json": fieldString(`"private-secret"`), "created_at": fieldString("2026-10-22 01:02:03.000001"),
		}}},
		Bindings:      []restoreIDBinding{{restoreAuditID, 1, 21}, {restoreNBAuditID, 1, 9223372036854775807}, {restoreUserID, 7, 17}, {restoreInstanceID, 7, 27}},
		OccupiedAudit: []int64{22}, OccupiedNorthbound: []int64{23}, SourceAuditMaxID: restoreTestID(1), Budget: fieldTestBudget,
	}
}

func TestNormalizeRestoreAuditCompleteColumnsAndHistory(t *testing.T) {
	input := auditNormalizeFixture()
	got, err := normalizeRestoreAudit(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Audit.Rows) != 1 || len(got.Northbound.Rows) != 1 || len(got.History) != 2 || *got.SourceAuditMaxID != 1 {
		t.Fatal("incomplete candidate")
	}
	a, n := got.Audit.Rows[0], got.Northbound.Rows[0]
	if *a["id"] != "21" || *n["id"] != "9223372036854775807" || *a["user_id"] != "17" || *a["resource_id"] != "27" || *n["actor_user_id"] != "17" {
		t.Fatal("mapping namespaces mixed")
	}
	for _, column := range []string{"details"} {
		if *a[column] != `"[REDACTED]"` {
			t.Fatal("raw audit body retained")
		}
	}
	if *a["ip_address"] != "[REDACTED]" || *n["before_json"] != `"[REDACTED]"` || *n["after_json"] != `"[REDACTED]"` {
		t.Fatal("raw body retained")
	}
	if *a["action"] != *input.Audit.Rows[0]["action"] || *n["created_at"] != *input.Northbound.Rows[0]["created_at"] {
		t.Fatal("historical values changed")
	}
	if !reflect.DeepEqual(got.Audit.Columns, input.Audit.Columns) || !reflect.DeepEqual(got.Northbound.Columns, input.Northbound.Columns) {
		t.Fatal("columns omitted")
	}
	h := got.History[0]
	if h.SourceID != 1 || h.TargetID != 21 || *h.SourceUserID != 7 || *h.SourceResourceID != 7 || *h.SourceResourceType != "instance" || *h.SourceCreatedAt != "2026-10-22 01:02:03" {
		t.Fatal("historical association lost")
	}
	for _, row := range []restoreFieldRow{a, n} {
		for _, value := range row {
			if value != nil && strings.Contains(*value, "private-secret") {
				t.Fatal("secret survived")
			}
		}
	}
	// Every returned pointer/map/column slice is independent of the source.
	*a["action"] = "changed"
	*h.SourceCreatedAt = "changed"
	got.Audit.Columns[0] = "changed"
	*got.SourceAuditMaxID = 99
	*h.SourceUserID = 99
	if *input.Audit.Rows[0]["action"] != "settings.update" || *input.Audit.Rows[0]["created_at"] != "2026-10-22 01:02:03" || input.Audit.Columns[0] != "id" || *input.SourceAuditMaxID != 1 || input.Bindings[2].Source != 7 {
		t.Fatal("caller data aliased")
	}
}

func TestNormalizeRestoreAuditFailuresDiscardBothTables(t *testing.T) {
	cases := map[string]func(*restoreAuditInput){
		"missing_actor_mapping":     func(i *restoreAuditInput) { i.Bindings = i.Bindings[:2] },
		"wrong_reference_namespace": func(i *restoreAuditInput) { i.Bindings = i.Bindings[:3] },
		"missing_history_mapping":   func(i *restoreAuditInput) { i.Bindings = i.Bindings[1:] },
		"unknown_resource": func(i *restoreAuditInput) {
			i.Audit.Rows[0]["resource_type"] = fieldString("unknown")
			i.Audit.Rows[0]["resource_id"] = nil
		},
		"null_resource_type":  func(i *restoreAuditInput) { i.Audit.Rows[0]["resource_type"] = nil },
		"control_id_rebound":  func(i *restoreAuditInput) { i.Audit.Rows[0]["resource_type"] = fieldString("system_backup") },
		"invalid_actor":       func(i *restoreAuditInput) { i.Northbound.Rows[0]["actor_user_id"] = fieldString("01") },
		"occupied_audit":      func(i *restoreAuditInput) { i.OccupiedAudit = []int64{21} },
		"occupied_northbound": func(i *restoreAuditInput) { i.OccupiedNorthbound = []int64{9223372036854775807} },
		"duplicate_occupied":  func(i *restoreAuditInput) { i.OccupiedAudit = []int64{22, 22} },
		"invalid_occupied":    func(i *restoreAuditInput) { i.OccupiedAudit = []int64{0} },
		"cutoff_missing":      func(i *restoreAuditInput) { i.SourceAuditMaxID = nil },
		"cutoff_changed":      func(i *restoreAuditInput) { i.SourceAuditMaxID = restoreTestID(21) },
		"duplicate_source_id": func(i *restoreAuditInput) { i.Audit.Rows = append(i.Audit.Rows, i.Audit.Rows[0]) },
		"missing_column":      func(i *restoreAuditInput) { delete(i.Northbound.Rows[0], "action") },
		"extra_column":        func(i *restoreAuditInput) { i.Audit.Rows[0]["extra"] = nil },
		"wrong_table":         func(i *restoreAuditInput) { i.Northbound.Name = "users" },
		"null_action":         func(i *restoreAuditInput) { i.Northbound.Rows[0]["action"] = nil },
		"long_action":         func(i *restoreAuditInput) { i.Northbound.Rows[0]["action"] = fieldString(strings.Repeat("界", 65)) },
		"invalid_utf8_action": func(i *restoreAuditInput) { i.Audit.Rows[0]["action"] = fieldString(string([]byte{255})) },
		"invalid_json":        func(i *restoreAuditInput) { i.Northbound.Rows[0]["before_json"] = fieldString("private-secret") },
		"invalid_details":     func(i *restoreAuditInput) { i.Audit.Rows[0]["details"] = fieldString("{private-secret") },
		"invalid_timestamp":   func(i *restoreAuditInput) { i.Audit.Rows[0]["created_at"] = fieldString("2026-02-30 00:00:00") },
		"timestamp_precision": func(i *restoreAuditInput) {
			i.Northbound.Rows[0]["created_at"] = fieldString("2026-10-22 01:02:03.1234567")
		},
		"missing_required_time": func(i *restoreAuditInput) { i.Northbound.Rows[0]["created_at"] = nil },
		"row_budget":            func(i *restoreAuditInput) { i.Budget.Rows = 1 },
		"byte_budget":           func(i *restoreAuditInput) { i.Budget.Bytes = 1 },
		"invalid_budget":        func(i *restoreAuditInput) { i.Budget.Rows = 0 },
		"merged_mapping":        func(i *restoreAuditInput) { i.Bindings = append(i.Bindings, restoreIDBinding{restoreAuditID, 2, 21}) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			input := auditNormalizeFixture()
			mutate(&input)
			got, err := normalizeRestoreAudit(context.Background(), input)
			if err == nil || !reflect.DeepEqual(got, restoreAuditCandidate{}) || strings.Contains(err.Error(), "private-secret") {
				t.Fatalf("partial or unsafe failure: %v", err)
			}
		})
	}
}

func TestNormalizeRestoreAuditNullEmptyAndReferences(t *testing.T) {
	for _, resource := range []string{"user", "instance", "system_backup"} {
		i := auditNormalizeFixture()
		i.Audit.Rows[0]["resource_type"] = fieldString(resource)
		i.Audit.Rows[0]["resource_id"] = nil
		i.Audit.Rows[0]["user_id"] = nil
		i.Audit.Rows[0]["details"] = nil
		i.Audit.Rows[0]["ip_address"] = nil
		i.Audit.Rows[0]["created_at"] = nil
		i.Northbound.Rows[0]["actor_user_id"] = nil
		i.Northbound.Rows[0]["before_json"] = nil
		got, err := normalizeRestoreAudit(context.Background(), i)
		if err != nil {
			t.Fatal(err)
		}
		for _, column := range []string{"resource_id", "user_id", "details", "ip_address", "created_at"} {
			if got.Audit.Rows[0][column] != nil {
				t.Fatal("SQL NULL changed")
			}
		}
		if got.Northbound.Rows[0]["actor_user_id"] != nil || got.Northbound.Rows[0]["before_json"] != nil {
			t.Fatal("SQL NULL changed")
		}
	}
	i := auditNormalizeFixture()
	i.Audit.Rows[0]["ip_address"] = fieldString("")
	i.Audit.Rows[0]["details"] = fieldString(`""`)
	got, err := normalizeRestoreAudit(context.Background(), i)
	if err != nil || *got.Audit.Rows[0]["ip_address"] != "[REDACTED]" || !json.Valid([]byte(*got.Audit.Rows[0]["details"])) {
		t.Fatal("empty body not redacted")
	}
	i = auditNormalizeFixture()
	i.Audit.Rows = nil
	i.Northbound.Rows = nil
	i.SourceAuditMaxID = nil
	got, err = normalizeRestoreAudit(context.Background(), i)
	if err != nil || got.SourceAuditMaxID != nil || len(got.History) != 0 || len(got.Audit.Columns) != 8 || len(got.Northbound.Columns) != 6 {
		t.Fatal("empty tables lost")
	}
	i.SourceAuditMaxID = restoreTestID(1)
	if _, err = normalizeRestoreAudit(context.Background(), i); err == nil {
		t.Fatal("empty audit accepted cutoff")
	}
}

func TestNormalizeRestoreAuditCapacityAndCancellation(t *testing.T) {
	i := auditNormalizeFixture()
	i.Audit.Rows[0]["details"] = fieldString(`0`)
	i.Audit.Rows[0]["ip_address"] = fieldString("")
	i.Northbound.Rows[0]["before_json"] = fieldString(`0`)
	i.Northbound.Rows[0]["after_json"] = fieldString(`0`)
	var sourceBytes int64
	for _, table := range []restoreFieldTable{i.Audit, i.Northbound} {
		for _, row := range table.Rows {
			for _, v := range row {
				if v != nil {
					sourceBytes += int64(len(*v))
				}
			}
		}
	}
	i.Budget.Bytes = sourceBytes
	if got, err := normalizeRestoreAudit(context.Background(), i); err == nil || !reflect.DeepEqual(got, restoreAuditCandidate{}) {
		t.Fatal("redaction expansion escaped capacity")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := normalizeRestoreAudit(ctx, auditNormalizeFixture()); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, restoreAuditCandidate{}) {
		t.Fatal("cancellation lost")
	}
}
