package systembackupresources

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func northboundNormalizeFixture() restoreNorthboundInput {
	row := restoreFieldRow{}
	for _, column := range restoreFieldColumns()["northbound_admin_settings"] {
		row[column] = fieldString("1")
	}
	for column, bounds := range restoreNorthboundBounds() {
		row[column] = fieldString(strconv.FormatInt(bounds.Min, 10))
	}
	for _, column := range []string{"lite_cpu_cores", "pro_cpu_cores", "workbuddy_pro_cpu_cores"} {
		row[column] = fieldString("0.10")
	}
	row["external_node_port"] = fieldString("30100")
	row["version"] = fieldString("77")
	row["updated_by"] = fieldString("7")
	row["require_explicit_callers"] = fieldString("0")
	row["created_at"] = fieldString("2026-10-22 01:02:03.000001")
	row["updated_at"] = fieldString("2026-10-22 01:02:03.000002")
	row["allowed_lite_types"] = fieldString(`["openclaw","hermes"]`)
	row["allowed_pro_types"] = fieldString(`["workbuddy"]`)
	return restoreNorthboundInput{
		Source:   restoreFieldTable{Name: "northbound_admin_settings", Columns: restoreFieldColumns()["northbound_admin_settings"], Rows: []restoreFieldRow{row}},
		Bindings: []restoreIDBinding{{restoreUserID, 7, 17}}, Budget: fieldTestBudget,
		Policy: &restoreNorthboundPolicy{ObservedVersion: restoreTestID(5), ExternalNodePort: 30200, Limits: restoreNorthboundBounds(), AllowedLiteTypes: []string{"openclaw", "hermes"}, AllowedProTypes: []string{"workbuddy"}, ProjectedLiteTypesJSON: `["openclaw", "hermes"]`, ProjectedProTypesJSON: `["workbuddy"]`},
	}
}
func TestNormalizeRestoreNorthboundCompleteClosedCandidate(t *testing.T) {
	i := northboundNormalizeFixture()
	got, err := normalizeRestoreNorthbound(context.Background(), i)
	if err != nil {
		t.Fatal(err)
	}
	row := got.Table.Rows[0]
	if len(row) != 33 || !reflect.DeepEqual(got.Table.Columns, i.Source.Columns) || *row["api_enabled"] != "0" || *row["require_explicit_callers"] != "1" || *row["version"] != "6" || *row["external_node_port"] != "30200" || *row["updated_by"] != "17" || *got.SourceVersion != 77 || *got.ObservedTargetVersion != 5 {
		t.Fatal("incomplete/misbound candidate")
	}
	if *row["allowed_lite_types"] != i.Policy.ProjectedLiteTypesJSON || *row["lite_cpu_cores"] != "0.10" {
		t.Fatal("target SQL representation or exact decimal lost")
	}
	for _, column := range []string{"id", "created_at", "updated_at"} {
		if *row[column] != *i.Source.Rows[0][column] {
			t.Fatal("historical values changed")
		}
	}
	*row["created_at"] = "changed"
	got.Table.Columns[0] = "changed"
	*got.ObservedTargetVersion = 99
	*got.SourceVersion = 99
	if i.Source.Columns[0] != "id" || *i.Source.Rows[0]["created_at"] != "2026-10-22 01:02:03.000001" || *i.Source.Rows[0]["version"] != "77" || *i.Policy.ObservedVersion != 5 {
		t.Fatal("candidate aliases input")
	}
	i = northboundNormalizeFixture()
	i.Policy.ObservedVersion = nil
	i.Policy.ExternalNodePort = 0
	i.Source.Rows[0]["updated_by"] = nil
	i.Source.Rows[0]["version"] = fieldString("9223372036854775807")
	got, err = normalizeRestoreNorthbound(context.Background(), i)
	if err != nil || *got.Table.Rows[0]["version"] != "1" || *got.Table.Rows[0]["external_node_port"] != "0" || got.Table.Rows[0]["updated_by"] != nil || got.ObservedTargetVersion != nil || *got.SourceVersion != 9223372036854775807 {
		t.Fatal("source version became target authority or NULL changed")
	}
}
func TestNormalizeRestoreNorthboundEveryNumericBound(t *testing.T) {
	for column, bounds := range restoreNorthboundBounds() {
		for _, which := range []string{"below", "above", "target_stricter"} {
			t.Run(column+"/"+which, func(t *testing.T) {
				i := northboundNormalizeFixture()
				value := bounds.Min - 1
				if which == "above" {
					value = bounds.Max + 1
				}
				if which == "target_stricter" {
					limit := i.Policy.Limits[column]
					limit.Min++
					i.Policy.Limits[column] = limit
					value = bounds.Min
				}
				text := strconv.FormatInt(value, 10)
				if strings.HasSuffix(column, "cpu_cores") {
					text = strconv.FormatInt(value/100, 10) + "." + strconv.FormatInt(value%100+100, 10)[1:]
				}
				i.Source.Rows[0][column] = fieldString(text)
				if got, err := normalizeRestoreNorthbound(context.Background(), i); err == nil || !reflect.DeepEqual(got, restoreNorthboundCandidate{}) {
					t.Fatal("range bypassed")
				}
			})
		}
	}
}
func TestNormalizeRestoreNorthboundFailuresDiscardCandidate(t *testing.T) {
	cases := map[string]func(*restoreNorthboundInput){
		"missing_policy": func(i *restoreNorthboundInput) { i.Policy = nil },
		"missing_limit":  func(i *restoreNorthboundInput) { delete(i.Policy.Limits, "login_rate_per_minute") },
		"unknown_limit": func(i *restoreNorthboundInput) {
			delete(i.Policy.Limits, "login_rate_per_minute")
			i.Policy.Limits["unknown"] = restoreNorthboundRange{1, 2}
		},
		"loose_limit": func(i *restoreNorthboundInput) {
			i.Policy.Limits["login_rate_per_minute"] = restoreNorthboundRange{1, 10001}
		},
		"inverted_limit": func(i *restoreNorthboundInput) {
			i.Policy.Limits["login_rate_per_minute"] = restoreNorthboundRange{10, 1}
		},
		"unknown_target_type":     func(i *restoreNorthboundInput) { i.Policy.AllowedProTypes = []string{"private-secret"} },
		"duplicate_target_type":   func(i *restoreNorthboundInput) { i.Policy.AllowedProTypes = []string{"workbuddy", "workbuddy"} },
		"empty_target_types":      func(i *restoreNorthboundInput) { i.Policy.AllowedLiteTypes = nil },
		"target_port":             func(i *restoreNorthboundInput) { i.Policy.ExternalNodePort = 29999 },
		"version_zero":            func(i *restoreNorthboundInput) { i.Policy.ObservedVersion = restoreTestID(0) },
		"version_overflow":        func(i *restoreNorthboundInput) { i.Policy.ObservedVersion = restoreTestID(9223372036854775807) },
		"multiple_rows":           func(i *restoreNorthboundInput) { i.Source.Rows = append(i.Source.Rows, i.Source.Rows[0]) },
		"singleton_id":            func(i *restoreNorthboundInput) { i.Source.Rows[0]["id"] = fieldString("2") },
		"source_switch":           func(i *restoreNorthboundInput) { i.Source.Rows[0]["api_enabled"] = fieldString("true") },
		"source_version":          func(i *restoreNorthboundInput) { i.Source.Rows[0]["version"] = fieldString("0") },
		"source_port":             func(i *restoreNorthboundInput) { i.Source.Rows[0]["external_node_port"] = fieldString("-1") },
		"integer_alias":           func(i *restoreNorthboundInput) { i.Source.Rows[0]["operation_lease_seconds"] = fieldString("05") },
		"CPU_float":               func(i *restoreNorthboundInput) { i.Source.Rows[0]["lite_cpu_cores"] = fieldString("1e0") },
		"CPU_precision":           func(i *restoreNorthboundInput) { i.Source.Rows[0]["lite_cpu_cores"] = fieldString("0.101") },
		"time_null":               func(i *restoreNorthboundInput) { i.Source.Rows[0]["created_at"] = nil },
		"time_invalid":            func(i *restoreNorthboundInput) { i.Source.Rows[0]["updated_at"] = fieldString("2026-02-30 00:00:00") },
		"missing_mapping":         func(i *restoreNorthboundInput) { i.Bindings = nil },
		"wrong_mapping_namespace": func(i *restoreNorthboundInput) { i.Bindings = []restoreIDBinding{{restoreInstanceID, 7, 17}} },
		"source_JSON_null":        func(i *restoreNorthboundInput) { i.Source.Rows[0]["allowed_lite_types"] = fieldString(`null`) },
		"source_JSON_empty":       func(i *restoreNorthboundInput) { i.Source.Rows[0]["allowed_lite_types"] = fieldString(`[]`) },
		"source_JSON_type":        func(i *restoreNorthboundInput) { i.Source.Rows[0]["allowed_lite_types"] = fieldString(`[1]`) },
		"source_JSON_duplicate": func(i *restoreNorthboundInput) {
			i.Source.Rows[0]["allowed_lite_types"] = fieldString(`["openclaw","\u006fpenclaw"]`)
		},
		"source_JSON_alias": func(i *restoreNorthboundInput) { i.Source.Rows[0]["allowed_lite_types"] = fieldString(`["OpenClaw"]`) },
		"source_JSON_trailing": func(i *restoreNorthboundInput) {
			i.Source.Rows[0]["allowed_lite_types"] = fieldString(`["openclaw"] []`)
		},
		"source_JSON_utf8": func(i *restoreNorthboundInput) {
			i.Source.Rows[0]["allowed_lite_types"] = fieldString(string([]byte{255}))
		},
		"source_type_disallowed": func(i *restoreNorthboundInput) { i.Policy.AllowedLiteTypes = []string{"hermes"} },
		"projection_missing":     func(i *restoreNorthboundInput) { i.Policy.ProjectedLiteTypesJSON = "" },
		"projection_reordered":   func(i *restoreNorthboundInput) { i.Policy.ProjectedLiteTypesJSON = `["hermes","openclaw"]` },
		"projection_expanded":    func(i *restoreNorthboundInput) { i.Policy.ProjectedProTypesJSON = `["workbuddy","openclaw"]` },
		"projection_capacity": func(i *restoreNorthboundInput) {
			i.Policy.ProjectedLiteTypesJSON = strings.Repeat(" ", 100001) + `["openclaw","hermes"]`
		},
		"missing_column": func(i *restoreNorthboundInput) { delete(i.Source.Rows[0], "version") },
		"extra_column":   func(i *restoreNorthboundInput) { i.Source.Rows[0]["extra"] = nil },
		"wrong_table":    func(i *restoreNorthboundInput) { i.Source.Name = "users" },
		"byte_budget":    func(i *restoreNorthboundInput) { i.Budget.Bytes = 1 },
		"invalid_budget": func(i *restoreNorthboundInput) { i.Budget.Rows = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			i := northboundNormalizeFixture()
			mutate(&i)
			got, err := normalizeRestoreNorthbound(context.Background(), i)
			if err == nil || !reflect.DeepEqual(got, restoreNorthboundCandidate{}) || strings.Contains(err.Error(), "private-secret") {
				t.Fatalf("unsafe candidate %v", err)
			}
		})
	}
}
func TestNormalizeRestoreNorthboundEmptyCapacityAndCancellation(t *testing.T) {
	i := northboundNormalizeFixture()
	i.Source.Rows = nil
	got, err := normalizeRestoreNorthbound(context.Background(), i)
	if err != nil || len(got.Table.Rows) != 0 || len(got.Table.Columns) != 33 || got.SourceVersion != nil {
		t.Fatal("empty source created defaults")
	}
	i = northboundNormalizeFixture()
	i.Policy.ObservedVersion = restoreTestID(999999999999999)
	var size int64
	for _, v := range i.Source.Rows[0] {
		if v != nil {
			size += int64(len(*v))
		}
	}
	i.Budget.Bytes = size
	if got, err = normalizeRestoreNorthbound(context.Background(), i); err == nil || !reflect.DeepEqual(got, restoreNorthboundCandidate{}) {
		t.Fatal("output growth escaped budget")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err = normalizeRestoreNorthbound(ctx, northboundNormalizeFixture()); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, restoreNorthboundCandidate{}) {
		t.Fatal("cancellation lost")
	}
}
