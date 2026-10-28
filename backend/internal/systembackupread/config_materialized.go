package systembackupread

import (
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
)

// Every identifier here comes from the pinned ConfigValues contract. No
// request or database value is interpolated into the SQL projection.
var configMaterializedColumns = buildConfigMaterializedColumns()

func buildConfigMaterializedColumns() []string {
	columns := []string{"enabled", "alert_profile", "minimum_recovery_points"}
	for group, bounds := range configNumericBounds {
		for name := range bounds {
			if group == "preflight_limits" {
				name = "preflight_" + name
			}
			columns = append(columns, name)
		}
	}
	for kind := range configRegistryKinds {
		columns = append(columns, kind+"_registry_version", kind+"_registry_sha256")
	}
	for purpose := range configReferencePurposes {
		columns = append(columns, purpose+"_identity_hash", purpose+"_ref_version")
	}
	sort.Strings(columns)
	return columns
}

func configMaterializedSelect() string {
	columns := make([]string, 0, len(configMaterializedColumns))
	for _, name := range configMaterializedColumns {
		columns = append(columns, "c."+name)
	}
	return strings.Join(columns, ",")
}

func configExpectedMaterialized(raw []byte) ([]string, bool) {
	if _, ok := validConfigValues(raw); !ok {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := configParseJSON(dec, 0)
	if err != nil {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	root := value.(map[string]any) // validConfigValues already checked this shape.
	expected := map[string]string{}
	if root["enabled"].(bool) {
		expected["enabled"] = "1"
	} else {
		expected["enabled"] = "0"
	}
	expected["alert_profile"] = root["alert_profile"].(string)
	expected["minimum_recovery_points"] = string(root["minimum_recovery_points"].(json.Number))
	for group, bounds := range configNumericBounds {
		members := root[group].(map[string]any)
		for name, bound := range bounds {
			value := members[name].(json.Number)
			column := name
			if group == "preflight_limits" {
				column = "preflight_" + name
			}
			expected[column] = string(value)
			if bound.scale == 100 {
				scaled, _ := configBoundedNumber(value, bound)
				expected[column] = strconv.FormatInt(scaled/100, 10) + "." + strconv.FormatInt(100+scaled%100, 10)[1:]
			}
		}
	}
	for _, value := range root["registries"].([]any) {
		item := value.(map[string]any)
		kind := item["registry_kind"].(string)
		expected[kind+"_registry_version"] = item["version"].(string)
		expected[kind+"_registry_sha256"] = item["sha256"].(string)
	}
	for _, value := range root["references"].([]any) {
		item := value.(map[string]any)
		purpose := item["purpose"].(string)
		expected[purpose+"_identity_hash"] = item["identity_hash"].(string)
		expected[purpose+"_ref_version"] = item["version"].(string)
	}
	values := make([]string, len(configMaterializedColumns))
	for i, column := range configMaterializedColumns {
		value, ok := expected[column]
		if !ok {
			return nil, false
		}
		values[i] = value
	}
	return values, true
}

func configMaterializedMatch(raw []byte, stored []any) bool {
	expected, ok := configExpectedMaterialized(raw)
	if !ok || len(stored) != len(expected) {
		return false
	}
	for i, value := range stored {
		var text string
		switch v := value.(type) {
		case []byte:
			text = string(v)
		case string:
			text = v
		case int64:
			text = strconv.FormatInt(v, 10)
		case uint64:
			text = strconv.FormatUint(v, 10)
		case bool:
			if v {
				text = "1"
			} else {
				text = "0"
			}
		default:
			return false
		}
		if text != expected[i] {
			return false
		}
	}
	return true
}
