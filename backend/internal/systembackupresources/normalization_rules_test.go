package systembackupresources

import (
	"encoding/json"
	"math"
	"net/netip"
	"strings"
	"testing"
)

func restoreTestID(value int64) *int64 { return &value }

func TestRestoreTypedMapping(t *testing.T) {
	bindings := []restoreIDBinding{
		{restoreUserID, 1, 11}, {restoreInstanceID, 1, 21},
		{restoreScanJobID, 1, 31}, {restoreSkillID, 1, 41},
		{restoreScanResultID, 1, 51}, {restoreAuditID, 1, 61},
		{restoreNBAuditID, 1, math.MaxInt64},
	}
	mapping, err := newRestoreIDMap(bindings)
	if err != nil {
		t.Fatal(err)
	}
	// Neither the caller's slice nor a returned ID can change the frozen map.
	bindings[0].Target = 999
	for _, entry := range []struct {
		kind   restoreIDKind
		target int64
	}{
		{restoreUserID, 11}, {restoreInstanceID, 21}, {restoreScanJobID, 31},
		{restoreSkillID, 41}, {restoreScanResultID, 51}, {restoreAuditID, 61}, {restoreNBAuditID, math.MaxInt64},
	} {
		t.Run(string(entry.kind), func(t *testing.T) {
			id, err := mapping.nullable(entry.kind, restoreTestID(1))
			if err != nil || id == nil || *id != entry.target {
				t.Fatalf("wrong typed target: %v %v", id, err)
			}
			*id = 999
			id, _ = mapping.nullable(entry.kind, restoreTestID(1))
			if *id != entry.target {
				t.Fatal("returned pointer mutated mapping")
			}
			if id, err := mapping.nullable(entry.kind, nil); err != nil || id != nil {
				t.Fatal("SQL NULL changed")
			}
			if id, err := mapping.nullable(entry.kind, restoreTestID(2)); err == nil || id != nil {
				t.Fatal("missing mapping accepted")
			}
		})
	}
	for name, entries := range map[string][]restoreIDBinding{
		"duplicate_identical": {{restoreUserID, 1, 2}, {restoreUserID, 1, 2}},
		"ambiguous_source":    {{restoreUserID, 1, 2}, {restoreUserID, 1, 3}},
		"merged_target":       {{restoreUserID, 1, 3}, {restoreUserID, 2, 3}},
		"unknown_kind":        {{"asset", 1, 2}},
		"zero_source":         {{restoreUserID, 0, 2}},
		"negative_target":     {{restoreUserID, 1, -2}},
		"int_overflow":        {{restoreUserID, 1, math.MaxInt32 + 1}},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := newRestoreIDMap(entries); err == nil || got != nil {
				t.Fatal("invalid map accepted")
			}
		})
	}
	for name, bad := range map[string]*restoreIDMap{"nil": nil, "zero_value": {}} {
		t.Run(name, func(t *testing.T) {
			if _, err := bad.nullable(restoreUserID, nil); err == nil {
				t.Fatal("absent map accepted")
			}
		})
	}
	if _, err := mapping.nullable("unknown", nil); err == nil {
		t.Fatal("unknown nullable kind accepted")
	}
	if _, err := mapping.nullable(restoreUserID, restoreTestID(0)); err == nil {
		t.Fatal("zero reference accepted")
	}
	if _, err := mapping.nullable(restoreUserID, restoreTestID(math.MaxInt32+1)); err == nil {
		t.Fatal("overflow reference accepted")
	}
}

func TestRestoreAuditReferencesAndOccupiedHistory(t *testing.T) {
	mapping, _ := newRestoreIDMap([]restoreIDBinding{{restoreUserID, 1, 11}, {restoreInstanceID, 1, 21}, {restoreAuditID, 1, 31}, {restoreNBAuditID, 1, 41}})
	for _, kind := range []string{"user", "instance", "system_backup"} {
		if value, err := mapping.auditReference(kind, nil); err != nil || value != nil {
			t.Fatal("known NULL reference rejected")
		}
	}
	for _, entry := range []struct {
		kind string
		want int64
	}{{"user", 11}, {"instance", 21}} {
		value, err := mapping.auditReference(entry.kind, restoreTestID(1))
		if err != nil || value == nil || *value != entry.want {
			t.Fatal("wrong audit target")
		}
	}
	for _, kind := range []string{"system_backup", "unknown", "User", " user", "skill"} {
		t.Run(kind, func(t *testing.T) {
			if _, err := mapping.auditReference(kind, restoreTestID(1)); err == nil {
				t.Fatal("unsupported audit reference accepted")
			}
		})
	}
	if _, err := mapping.auditReference("unknown", nil); err == nil {
		t.Fatal("unknown NULL type accepted")
	}
	for _, kind := range []restoreIDKind{restoreAuditID, restoreNBAuditID} {
		if err := mapping.validateHistoryTargets(kind, []int64{100}); err != nil {
			t.Fatal(err)
		}
		if err := mapping.validateHistoryTargets(kind, nil); err != nil {
			t.Fatal(err)
		}
		id, _ := mapping.nullable(kind, restoreTestID(1))
		if err := mapping.validateHistoryTargets(kind, []int64{*id}); err == nil {
			t.Fatal("target history overwritten")
		}
		if err := mapping.validateHistoryTargets(kind, []int64{100, 100}); err == nil {
			t.Fatal("duplicate occupancy accepted")
		}
		if err := mapping.validateHistoryTargets(kind, []int64{0}); err == nil {
			t.Fatal("bad occupancy accepted")
		}
	}
	if err := mapping.validateHistoryTargets(restoreUserID, nil); err == nil {
		t.Fatal("wrong history namespace")
	}
}

func TestRestoreWholeBodyRedaction(t *testing.T) {
	if redactRestoreJSON(nil) != nil || redactRestoreText(nil) != nil {
		t.Fatal("SQL NULL changed")
	}
	for _, raw := range []string{"", "null", `{"nested":{"password":"secret","address":"10.0.0.1"}}`, "invalid JSON\xff", `{"caller":{"user_id":12,"enabled":true}}`, `{"external_node_port":30001}`} {
		t.Run(raw, func(t *testing.T) {
			body, text := redactRestoreJSON(&raw), redactRestoreText(&raw)
			var value string
			if body == nil || json.Unmarshal([]byte(*body), &value) != nil || value != "[REDACTED]" || text == nil || *text != "[REDACTED]" {
				t.Fatal("body not completely redacted")
			}
			if body == &raw || text == &raw {
				t.Fatal("source alias")
			}
		})
	}
}

func TestRestoreTargetNorthboundCASAndDecimal(t *testing.T) {
	if next, err := nextRestoreNorthboundVersion(nil); err != nil || next != 1 {
		t.Fatal("wrong absent-row version")
	}
	for _, observed := range []int64{1, 2, math.MaxInt64 - 1} {
		if next, err := nextRestoreNorthboundVersion(&observed); err != nil || next != observed+1 {
			t.Fatal("wrong target generation")
		}
	}
	for _, observed := range []int64{-1, 0, math.MaxInt64} {
		if next, err := nextRestoreNorthboundVersion(&observed); err == nil || next != 0 {
			t.Fatal("invalid generation accepted")
		}
	}
	for raw, want := range map[string]int64{"0.01": 1, "1.10": 110, "2.00": 200, "99.99": 9999} {
		if got, err := restoreCPUHundredths(raw); err != nil || got != want {
			t.Fatalf("decimal %q: %d %v", raw, got, err)
		}
	}
	for _, raw := range []string{"0.00", "0", "2", "2.0", "2.001", "100.00", "02.00", ".01", "+1.00", "-1.00", "1e0", "NaN", " 2.00", "2.00 ", "１.00"} {
		t.Run(raw, func(t *testing.T) {
			if _, err := restoreCPUHundredths(raw); err == nil {
				t.Fatal("invalid decimal accepted")
			}
		})
	}
}

func TestRestoreWholeNetworkAdmission(t *testing.T) {
	allowed := []restoreNetworkAllowance{{netip.MustParsePrefix("10.0.0.0/8"), 443}, {netip.MustParsePrefix("fc00::/7"), 8443}}
	denied := []netip.Prefix{netip.MustParsePrefix("10.1.2.3/32"), netip.MustParsePrefix("fd00:1::/64")}
	for _, item := range []struct {
		prefix string
		port   int
	}{{"10.2.0.0/16", 443}, {"10.1.2.4/32", 443}, {"fd00:2::/64", 8443}} {
		if err := validateRestoreNetwork(item.prefix, item.port, allowed, denied); err != nil {
			t.Fatal(err)
		}
	}
	for name, item := range map[string]struct {
		prefix string
		port   int
	}{
		"wide_private_start": {"10.0.0.0/7", 443}, "nested_denial": {"10.1.0.0/16", 443},
		"whole_allowed_block": {"10.0.0.0/8", 443}, "blocked_host": {"10.1.2.3/32", 443},
		"host_bits": {"10.2.3.4/16", 443}, "wrong_port": {"10.2.0.0/16", 80},
		"zero_port": {"10.2.0.0/16", 0}, "large_port": {"10.2.0.0/16", 65536},
		"metadata": {"169.254.169.254/32", 443}, "ipv6_link_local": {"fe80::/64", 8443},
		"mapped_ipv6": {"::ffff:10.2.0.0/112", 443}, "wide_ipv6": {"fc00::/6", 8443},
		"ipv6_nested_denial": {"fd00::/8", 8443}, "public": {"8.8.8.8/32", 443},
		"outside_allowance": {"192.168.0.0/16", 443}, "no_prefix": {"10.2.3.4", 443},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateRestoreNetwork(item.prefix, item.port, allowed, denied); err == nil {
				t.Fatal("unsafe prefix accepted")
			}
		})
	}
	if err := validateRestoreNetwork("10.2.0.0/16", 443, nil, denied); err == nil {
		t.Fatal("missing allowances accepted")
	}
	for _, bad := range []restoreNetworkAllowance{{netip.Prefix{}, 443}, {netip.MustParsePrefix("10.0.0.0/7"), 443}, {netip.MustParsePrefix("10.0.0.0/8"), 0}} {
		if err := validateRestoreNetwork("10.2.0.0/16", 443, append(append([]restoreNetworkAllowance{}, allowed...), bad), denied); err == nil {
			t.Fatal("malformed unused allowance ignored")
		}
	}
	for _, bad := range []netip.Prefix{{}, netip.MustParsePrefix("10.1.2.3/16"), netip.MustParsePrefix("::ffff:10.0.0.0/104")} {
		if err := validateRestoreNetwork("10.2.0.0/16", 443, allowed, append(append([]netip.Prefix{}, denied...), bad)); err == nil {
			t.Fatal("malformed exclusion ignored")
		}
	}
}

func TestRestoreStrictScanScope(t *testing.T) {
	mapping, _ := newRestoreIDMap([]restoreIDBinding{{restoreSkillID, 1, 41}, {restoreUserID, 2, 99}})
	for _, raw := range []string{`{"scan_scope":"full","asset_id":1}`, `{"asset_id":1,"scan_scope":"full"}`} {
		got, err := parseRestoreScanScope(raw, mapping)
		if err != nil || got.ScanScope != "full" || got.AssetID == nil || *got.AssetID != 41 {
			t.Fatal("valid scope rejected")
		}
	}
	for _, value := range []string{"full", "incremental"} {
		got, err := parseRestoreScanScope(`{"scan_scope":"`+value+`"}`, mapping)
		if err != nil || got.ScanScope != value || got.AssetID != nil {
			t.Fatal("valid unscoped asset rejected")
		}
	}
	for name, raw := range map[string]string{
		"null": `null`, "empty": ``, "object_empty": `{}`, "array": `[]`, "missing_scope": `{"asset_id":1}`,
		"null_scope": `{"scan_scope":null}`, "numeric_scope": `{"scan_scope":1}`,
		"unknown_scope": `{"scan_scope":"quick"}`, "case_alias": `{"scan_scope":"Full"}`,
		"unknown_key":       `{"scan_scope":"full","credential":"secret"}`,
		"duplicate_scope":   `{"scan_scope":"full","scan_scope":"incremental"}`,
		"escaped_duplicate": `{"scan_scope":"full","scan_\u0073cope":"full"}`,
		"duplicate_asset":   `{"scan_scope":"full","asset_id":1,"asset_id":1}`,
		"asset_null":        `{"scan_scope":"full","asset_id":null}`, "asset_string": `{"scan_scope":"full","asset_id":"1"}`,
		"asset_zero": `{"scan_scope":"full","asset_id":0}`, "asset_negative": `{"scan_scope":"full","asset_id":-1}`,
		"asset_fraction": `{"scan_scope":"full","asset_id":1.0}`, "asset_exponent": `{"scan_scope":"full","asset_id":1e0}`,
		"wrong_domain": `{"scan_scope":"full","asset_id":2}`, "overflow": `{"scan_scope":"full","asset_id":2147483648}`,
		"trailing": `{"scan_scope":"full"}{}`, "truncated": `{"scan_scope":"full"`,
		"oversize": strings.Repeat(" ", 4097) + `{"scan_scope":"full"}`, "bad_utf8": "{\"scan_scope\":\"full\",\"\xff\":1}",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parseRestoreScanScope(raw, mapping)
			if err == nil || got.ScanScope != "" || got.AssetID != nil {
				t.Fatal("invalid scope yielded a candidate")
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("source leaked into error")
			}
		})
	}
	if _, err := parseRestoreScanScope(`{"scan_scope":"full","asset_id":1}`, nil); err == nil {
		t.Fatal("missing asset map accepted")
	}
}
