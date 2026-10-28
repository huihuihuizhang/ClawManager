package systembackupresources

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func egressNormalizeFixture() restoreEgressInput {
	return restoreEgressInput{
		Source: restoreFieldTable{Name: "egress_private_exceptions", Columns: restoreFieldColumns()["egress_private_exceptions"], Rows: []restoreFieldRow{{
			"id": fieldString("1"), "scope_type": fieldString("instance"), "scope_id": fieldString("7"), "cidr": fieldString("10.2.0.0/16"), "port": fieldString("443"), "enabled": fieldString("1"), "description": fieldString("private-secret"), "created_by": fieldString("7"), "created_at": fieldString("2026-10-22 01:02:03"), "updated_at": fieldString("2026-10-22 01:02:03.000001"),
		}}}, Bindings: []restoreIDBinding{{restoreUserID, 7, 17}, {restoreInstanceID, 7, 27}}, OccupiedIDs: []int64{2},
		Policy: &restoreEgressPolicy{Allowed: []restoreNetworkAllowance{{netip.MustParsePrefix("10.0.0.0/8"), 443}}, Denied: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}}, Budget: fieldTestBudget,
	}
}
func TestNormalizeRestoreEgressCompleteDisabledCandidate(t *testing.T) {
	i := egressNormalizeFixture()
	got, err := normalizeRestoreEgress(context.Background(), i)
	if err != nil {
		t.Fatal(err)
	}
	row := got.Rows[0]
	if !reflect.DeepEqual(got.Columns, i.Source.Columns) || len(row) != 10 || *row["id"] != "1" || *row["scope_id"] != "27" || *row["created_by"] != "17" || *row["enabled"] != "0" || *row["description"] != "[REDACTED]" {
		t.Fatal("incomplete/misbound enabled candidate")
	}
	for _, column := range []string{"created_at", "updated_at", "scope_type", "port"} {
		if *row[column] != *i.Source.Rows[0][column] {
			t.Fatal("source history changed")
		}
	}
	*row["created_at"] = "changed"
	got.Columns[0] = "changed"
	if *i.Source.Rows[0]["created_at"] != "2026-10-22 01:02:03" || i.Source.Columns[0] != "id" || *i.Source.Rows[0]["enabled"] != "1" {
		t.Fatal("candidate aliases caller")
	}
	i = egressNormalizeFixture()
	i.Source.Rows[0]["scope_type"] = fieldString("user")
	got, err = normalizeRestoreEgress(context.Background(), i)
	if err != nil || *got.Rows[0]["scope_id"] != "17" {
		t.Fatal("user and instance namespace mixed")
	}
}
func TestNormalizeRestoreEgressFailuresDiscardCandidate(t *testing.T) {
	cases := map[string]func(*restoreEgressInput){
		"missing_policy":          func(i *restoreEgressInput) { i.Policy = nil },
		"no_allowances":           func(i *restoreEgressInput) { i.Policy.Allowed = nil },
		"missing_mapping":         func(i *restoreEgressInput) { i.Bindings = i.Bindings[:1] },
		"missing_creator_mapping": func(i *restoreEgressInput) { i.Bindings = i.Bindings[1:] },
		"scope_alias":             func(i *restoreEgressInput) { i.Source.Rows[0]["scope_type"] = fieldString("Instance") },
		"null_scope":              func(i *restoreEgressInput) { i.Source.Rows[0]["scope_id"] = nil },
		"scope_zero":              func(i *restoreEgressInput) { i.Source.Rows[0]["scope_id"] = fieldString("0") },
		"occupied_id":             func(i *restoreEgressInput) { i.OccupiedIDs = []int64{1} },
		"duplicate_occupied":      func(i *restoreEgressInput) { i.OccupiedIDs = []int64{2, 2} },
		"bad_occupied":            func(i *restoreEgressInput) { i.OccupiedIDs = []int64{-1} },
		"host_bits":               func(i *restoreEgressInput) { i.Source.Rows[0]["cidr"] = fieldString("10.2.0.1/16") },
		"overbroad_prefix":        func(i *restoreEgressInput) { i.Source.Rows[0]["cidr"] = fieldString("10.0.0.0/7") },
		"denied_subnet":           func(i *restoreEgressInput) { i.Source.Rows[0]["cidr"] = fieldString("10.0.0.0/8") },
		"wrong_port":              func(i *restoreEgressInput) { i.Source.Rows[0]["port"] = fieldString("80") },
		"zero_port":               func(i *restoreEgressInput) { i.Source.Rows[0]["port"] = fieldString("0") },
		"port_alias":              func(i *restoreEgressInput) { i.Source.Rows[0]["port"] = fieldString("0443") },
		"overflow_port":           func(i *restoreEgressInput) { i.Source.Rows[0]["port"] = fieldString("65536") },
		"link_local":              func(i *restoreEgressInput) { i.Source.Rows[0]["cidr"] = fieldString("169.254.0.0/16") },
		"mapped_ipv4":             func(i *restoreEgressInput) { i.Source.Rows[0]["cidr"] = fieldString("::ffff:10.2.0.0/112") },
		"bad_allowance": func(i *restoreEgressInput) {
			i.Policy.Allowed = append(i.Policy.Allowed, restoreNetworkAllowance{netip.MustParsePrefix("0.0.0.0/0"), 443})
		},
		"bad_exclusion": func(i *restoreEgressInput) {
			i.Policy.Denied = append(i.Policy.Denied, netip.MustParsePrefix("10.9.0.1/16"))
		},
		"invalid_enabled": func(i *restoreEgressInput) { i.Source.Rows[0]["enabled"] = fieldString("true") },
		"invalid_time":    func(i *restoreEgressInput) { i.Source.Rows[0]["updated_at"] = fieldString("2026-02-30 00:00:00") },
		"missing_column":  func(i *restoreEgressInput) { delete(i.Source.Rows[0], "description") },
		"extra_column":    func(i *restoreEgressInput) { i.Source.Rows[0]["extra"] = nil },
		"duplicate_row":   func(i *restoreEgressInput) { i.Source.Rows = append(i.Source.Rows, i.Source.Rows[0]) },
		"wrong_table":     func(i *restoreEgressInput) { i.Source.Name = "users" },
		"byte_budget":     func(i *restoreEgressInput) { i.Budget.Bytes = 1 },
		"invalid_budget":  func(i *restoreEgressInput) { i.Budget.Rows = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			i := egressNormalizeFixture()
			mutate(&i)
			got, err := normalizeRestoreEgress(context.Background(), i)
			if err == nil || !reflect.DeepEqual(got, restoreFieldTable{}) || strings.Contains(err.Error(), "private-secret") {
				t.Fatalf("unsafe candidate %v", err)
			}
		})
	}
}
func TestNormalizeRestoreEgressEmptyNullIPv6AndBudgets(t *testing.T) {
	i := egressNormalizeFixture()
	i.Source.Rows[0]["created_by"] = nil
	i.Source.Rows[0]["description"] = nil
	i.Source.Rows[0]["created_at"] = nil
	i.Source.Rows[0]["updated_at"] = nil
	i.Source.Rows[0]["cidr"] = fieldString("fd00:0000::/64")
	i.Policy.Allowed = []restoreNetworkAllowance{{netip.MustParsePrefix("fc00::/7"), 443}}
	got, err := normalizeRestoreEgress(context.Background(), i)
	if err != nil || *got.Rows[0]["cidr"] != "fd00::/64" {
		t.Fatalf("IPv6 normalization failed %v", err)
	}
	for _, column := range []string{"created_by", "description", "created_at", "updated_at"} {
		if got.Rows[0][column] != nil {
			t.Fatal("SQL NULL lost")
		}
	}
	i = egressNormalizeFixture()
	i.Source.Rows = nil
	i.Policy.Allowed = nil
	got, err = normalizeRestoreEgress(context.Background(), i)
	if err != nil || len(got.Rows) != 0 || len(got.Columns) != 10 {
		t.Fatal("empty table lost")
	}
	i.Policy.Denied = []netip.Prefix{{}}
	if _, err = normalizeRestoreEgress(context.Background(), i); err == nil {
		t.Fatal("empty table bypassed invalid policy")
	}
	i = egressNormalizeFixture()
	i.Source.Rows[0]["description"] = fieldString("")
	var size int64
	for _, v := range i.Source.Rows[0] {
		if v != nil {
			size += int64(len(*v))
		}
	}
	i.Budget.Bytes = size
	if got, err = normalizeRestoreEgress(context.Background(), i); err == nil || !reflect.DeepEqual(got, restoreFieldTable{}) {
		t.Fatal("output growth escaped budget")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err = normalizeRestoreEgress(ctx, egressNormalizeFixture()); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, restoreFieldTable{}) {
		t.Fatal("cancellation lost")
	}
}
