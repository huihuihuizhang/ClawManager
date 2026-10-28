package systembackupresources

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"unicode/utf8"
)

type restoreNorthboundRange struct{ Min, Max int64 }

// Offline declarations only. B must authenticate target absence/observed row
// version, port, stricter limits, supported types and target SQL JSON projection
// on the exact target/transaction; these values cannot establish those facts.
type restoreNorthboundPolicy struct {
	ObservedVersion                               *int64
	ExternalNodePort                              int64
	Limits                                        map[string]restoreNorthboundRange // CPU uses exact hundredths.
	AllowedLiteTypes, AllowedProTypes             []string
	ProjectedLiteTypesJSON, ProjectedProTypesJSON string
}
type restoreNorthboundInput struct {
	Source   restoreFieldTable
	Bindings []restoreIDBinding
	Policy   *restoreNorthboundPolicy
	Budget   restoreFieldBudget
}
type restoreNorthboundCandidate struct {
	Table                 restoreFieldTable
	SourceVersion         *int64 // Protected history, never used as the target version.
	ObservedTargetVersion *int64 // nil requires B to prove absence for INSERT.
}

// Intersection of the current service's bounds and migration column limits.
// DECIMAL(4,2) cannot represent the service's Pro upper bound of 128 CPUs.
func restoreNorthboundBounds() map[string]restoreNorthboundRange {
	return map[string]restoreNorthboundRange{
		"challenge_ttl_seconds": {15, 600}, "access_token_ttl_seconds": {60, 86400}, "refresh_token_ttl_seconds": {3600, 2592000}, "core_request_timeout_seconds": {5, 120},
		"challenge_rate_per_minute": {1, 10000}, "login_rate_per_minute": {1, 10000}, "account_login_rate_per_minute": {1, 10000}, "create_rate_per_minute": {1, 10000}, "query_rate_per_minute": {1, 100000}, "share_rate_per_minute": {1, 10000},
		"max_pending_operations": {1, 1000}, "operation_tick_milliseconds": {100, 60000}, "operation_lease_seconds": {5, 600}, "operation_max_attempts": {1, 20},
		"lite_memory_gb": {1, 128}, "lite_disk_gb": {1, 2048}, "pro_memory_gb": {1, 512}, "pro_disk_gb": {1, 4096}, "workbuddy_pro_memory_gb": {1, 512}, "workbuddy_pro_disk_gb": {1, 4096},
		"lite_cpu_cores": {10, 6400}, "pro_cpu_cores": {10, 9999}, "workbuddy_pro_cpu_cores": {10, 9999},
	}
}

func normalizeRestoreNorthbound(ctx context.Context, input restoreNorthboundInput) (restoreNorthboundCandidate, error) {
	zero := restoreNorthboundCandidate{}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if input.Source.Name != "northbound_admin_settings" || input.Policy == nil || input.Budget.Rows <= 0 || input.Budget.Bytes <= 0 || len(input.Source.Rows) > 1 {
		return zero, errors.New("resources northbound input is invalid")
	}
	var shape []restoreFieldTable
	for table, columns := range restoreFieldColumns() {
		entry := restoreFieldTable{Name: table, Columns: columns}
		if table == input.Source.Name {
			entry = input.Source
		}
		shape = append(shape, entry)
	}
	if _, err := indexRestoreFields(ctx, shape, input.Budget); err != nil {
		return zero, err
	}
	policy := input.Policy
	bounds := restoreNorthboundBounds()
	if len(policy.Limits) != len(bounds) {
		return zero, errors.New("resources northbound target limits are incomplete")
	}
	for column, base := range bounds {
		limit, exists := policy.Limits[column]
		if !exists || limit.Min < base.Min || limit.Max > base.Max || limit.Min > limit.Max {
			return zero, errors.New("resources northbound target limits are invalid")
		}
	}
	if policy.ExternalNodePort != 0 && (policy.ExternalNodePort < 30000 || policy.ExternalNodePort > 32767) {
		return zero, errors.New("resources northbound target port is invalid")
	}
	for _, types := range [][]string{policy.AllowedLiteTypes, policy.AllowedProTypes} {
		if !validRestoreNorthboundTypes(types, nil) {
			return zero, errors.New("resources northbound target types are invalid")
		}
	}
	nextVersion, err := nextRestoreNorthboundVersion(policy.ObservedVersion)
	if err != nil {
		return zero, err
	}
	mapping, err := newRestoreIDMap(input.Bindings)
	if err != nil {
		return zero, err
	}
	result := restoreNorthboundCandidate{Table: restoreFieldTable{Name: input.Source.Name, Columns: append([]string(nil), input.Source.Columns...)}}
	if policy.ObservedVersion != nil {
		v := *policy.ObservedVersion
		result.ObservedTargetVersion = &v
	}
	if len(input.Source.Rows) == 0 {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		return result, nil
	}
	source := input.Source.Rows[0]
	if *source["id"] != "1" {
		return zero, errors.New("resources northbound singleton ID is invalid")
	}
	for _, column := range []string{"api_enabled", "require_explicit_callers"} {
		if source[column] == nil || (*source[column] != "0" && *source[column] != "1") {
			return zero, errors.New("resources northbound source switch is invalid")
		}
	}
	sourceVersion, err := parseRestoreNorthboundInteger(source["version"])
	if err != nil || sourceVersion < 1 {
		return zero, errors.New("resources northbound source version is invalid")
	}
	port, err := parseRestoreNorthboundInteger(source["external_node_port"])
	if err != nil || port < 0 || port > 65535 {
		return zero, errors.New("resources northbound source port is invalid")
	}
	for column, base := range bounds {
		value := source[column]
		var parsed int64
		if column == "lite_cpu_cores" || column == "pro_cpu_cores" || column == "workbuddy_pro_cpu_cores" {
			if value == nil {
				return zero, errors.New("resources northbound CPU is required")
			}
			parsed, err = restoreCPUHundredths(*value)
		} else {
			parsed, err = parseRestoreNorthboundInteger(value)
		}
		limit := policy.Limits[column]
		if err != nil || parsed < base.Min || parsed > base.Max || parsed < limit.Min || parsed > limit.Max {
			return zero, errors.New("resources northbound source value exceeds service or target limits")
		}
	}
	for _, column := range []string{"created_at", "updated_at"} {
		if !validRestoreAuditTime(source[column], true) {
			return zero, errors.New("resources northbound source time is invalid")
		}
	}
	lite, err := restoreNorthboundTypesJSON(source["allowed_lite_types"], policy.AllowedLiteTypes)
	if err != nil {
		return zero, err
	}
	pro, err := restoreNorthboundTypesJSON(source["allowed_pro_types"], policy.AllowedProTypes)
	if err != nil {
		return zero, err
	}
	// Accept only a target SQL rendering of exactly the same ordered values.
	// No case folding, duplicate removal, implicit defaults or runtime expansion.
	projectionRemaining := input.Budget.Bytes
	for _, projection := range []struct {
		text              string
		expected, allowed []string
	}{
		{policy.ProjectedLiteTypesJSON, lite, policy.AllowedLiteTypes}, {policy.ProjectedProTypesJSON, pro, policy.AllowedProTypes},
	} {
		if int64(len(projection.text)) > projectionRemaining {
			return zero, errors.New("resources northbound target JSON projection exceeds capacity")
		}
		projectionRemaining -= int64(len(projection.text))
		actual, err := restoreNorthboundTypesJSON(&projection.text, projection.allowed)
		if err != nil || len(actual) != len(projection.expected) {
			return zero, errors.New("resources northbound target JSON projection differs")
		}
		for i := range actual {
			if actual[i] != projection.expected[i] {
				return zero, errors.New("resources northbound target JSON projection differs")
			}
		}
	}
	actor, err := parseRestoreAuditReference(source["updated_by"], restoreUserID)
	if err != nil {
		return zero, err
	}
	targetActor, err := mapping.nullable(restoreUserID, actor)
	if err != nil {
		return zero, err
	}
	row := cloneRestoreAuditRow(source)
	disabled, explicit, version, targetPort := "0", "1", strconv.FormatInt(nextVersion, 10), strconv.FormatInt(policy.ExternalNodePort, 10)
	row["api_enabled"] = &disabled
	row["require_explicit_callers"] = &explicit
	row["version"] = &version
	row["external_node_port"] = &targetPort
	row["updated_by"] = restoreAuditIDText(targetActor)
	liteJSON, proJSON := policy.ProjectedLiteTypesJSON, policy.ProjectedProTypesJSON
	row["allowed_lite_types"] = &liteJSON
	row["allowed_pro_types"] = &proJSON
	result.Table.Rows = []restoreFieldRow{row}
	result.SourceVersion = &sourceVersion
	for i := range shape {
		if shape[i].Name == result.Table.Name {
			shape[i] = result.Table
		}
	}
	if _, err := indexRestoreFields(ctx, shape, input.Budget); err != nil {
		return zero, err
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	return result, nil
}

func parseRestoreNorthboundInteger(raw *string) (int64, error) {
	if raw == nil {
		return 0, errors.New("resources northbound integer is required")
	}
	value, err := strconv.ParseInt(*raw, 10, 64)
	if err != nil || strconv.FormatInt(value, 10) != *raw {
		return 0, errors.New("resources northbound integer is invalid")
	}
	return value, nil
}
func validRestoreNorthboundTypes(values, allowed []string) bool {
	if len(values) == 0 || len(values) > 5 {
		return false
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		switch value {
		case "openclaw", "hermes", "opencode", "deepseek-harness", "workbuddy":
		default:
			return false
		}
		if seen[value] {
			return false
		}
		seen[value] = true
		if allowed != nil {
			found := false
			for _, a := range allowed {
				if a == value {
					found = true
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}
func restoreNorthboundTypesJSON(raw *string, allowed []string) ([]string, error) {
	if raw == nil || !utf8.ValidString(*raw) {
		return nil, errors.New("resources northbound runtime list is invalid")
	}
	var values []string
	if json.Unmarshal([]byte(*raw), &values) != nil || !validRestoreNorthboundTypes(values, allowed) {
		return nil, errors.New("resources northbound runtime list is invalid")
	}
	return values, nil
}
