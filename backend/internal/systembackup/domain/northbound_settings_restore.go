package domain

import (
	"context"
	"math"
	"slices"
	"strings"
)

const NorthboundSettings077Normalizer = "northbound-admin-settings.077"
const NorthboundAudit057Normalizer = "northbound-settings-audit.057"

const northboundSettingsColumns = "id api_enabled external_node_port require_explicit_callers challenge_ttl_seconds access_token_ttl_seconds refresh_token_ttl_seconds core_request_timeout_seconds challenge_rate_per_minute login_rate_per_minute account_login_rate_per_minute create_rate_per_minute query_rate_per_minute share_rate_per_minute max_pending_operations operation_tick_milliseconds operation_lease_seconds operation_max_attempts allowed_lite_types allowed_pro_types lite_cpu_cores lite_memory_gb lite_disk_gb pro_cpu_cores pro_memory_gb pro_disk_gb workbuddy_pro_cpu_cores workbuddy_pro_memory_gb workbuddy_pro_disk_gb version updated_by created_at updated_at owner_teams_enabled owner_team_creation_user_id"
const northboundAuditColumns = "id actor_user_id action before_json after_json created_at"

func northboundSettingsShape(t Table) error {
	if t.Name != "northbound_admin_settings" || t.Engine != "InnoDB" || len(t.Columns) != 35 || !slices.Equal(t.PrimaryKey, []string{"id"}) || len(t.UniqueKeys) != 0 || len(t.ForeignKeys) != 1 || t.ForeignKeys[0] != (ForeignKey{Column: "updated_by", Table: "users", Reference: "id"}) {
		return ErrSchema
	}
	seen := map[string]bool{}
	for _, c := range t.Columns {
		kind, nullable := "int", false
		switch c.Name {
		case "id":
			kind = "tinyint"
		case "api_enabled", "require_explicit_callers", "owner_teams_enabled":
			kind = "tinyint(1)"
		case "version":
			kind = "bigint"
		case "updated_by":
			nullable = true
		case "allowed_lite_types", "allowed_pro_types":
			kind = "json"
		case "lite_cpu_cores", "pro_cpu_cores", "workbuddy_pro_cpu_cores":
			kind = "decimal(4,2)"
		case "created_at", "updated_at":
			kind = "datetime(6)"
		}
		if seen[c.Name] || !slices.Contains(strings.Fields(northboundSettingsColumns), c.Name) || c.Type != kind || c.Nullable != nullable || generatedColumn(c.Extra) {
			return ErrSchema
		}
		seen[c.Name] = true
	}
	return nil
}
func northboundAuditShape(t Table) error {
	if t.Name != "northbound_settings_audit" || t.Engine != "InnoDB" || len(t.Columns) != 6 || !slices.Equal(t.PrimaryKey, []string{"id"}) || len(t.UniqueKeys) != 0 || len(t.ForeignKeys) != 1 || t.ForeignKeys[0] != (ForeignKey{Column: "actor_user_id", Table: "users", Reference: "id"}) {
		return ErrSchema
	}
	seen := map[string]bool{}
	for _, c := range t.Columns {
		kind, nullable := "json", true
		switch c.Name {
		case "id":
			kind = "bigint"
			nullable = false
		case "actor_user_id":
			kind = "int"
		case "action":
			kind = "varchar(64)"
			nullable = false
		case "created_at":
			kind = "datetime(6)"
			nullable = false
		case "before_json", "after_json":
		default:
			return ErrSchema
		}
		if seen[c.Name] || c.Type != kind || c.Nullable != nullable || generatedColumn(c.Extra) {
			return ErrSchema
		}
		seen[c.Name] = true
	}
	return nil
}

func northboundSourceUsers(s Snapshot) map[string]bool {
	users := map[string]bool{}
	for _, table := range s.Tables {
		if table.Name == "users" {
			for _, row := range table.Rows {
				users[row["id"].String()] = true
			}
		}
	}
	return users
}

// Audit JSON is heterogeneous historical data, never a current settings row,
// deployment receipt or a one-to-one record of settings versions. Actual FK
// actor NULLs are preserved; JSON's old actor IDs are not live FK references.
func validateNorthboundAuditSource(ctx context.Context, t Table, s Snapshot) error {
	if northboundAuditShape(t) != nil {
		return ErrSchema
	}
	users := northboundSourceUsers(s)
	for _, row := range t.Rows {
		if e := ctx.Err(); e != nil {
			return e
		}
		if len(row) != 6 {
			return ErrData
		}
		for _, column := range t.Columns {
			c, ok := row[column.Name]
			if !ok || c.Null && (!column.Nullable || len(c.Bytes) > 0) {
				return ErrData
			}
		}
		if gatewayNumber(row["id"], math.MaxInt64, false) != nil || gatewayNumber(row["actor_user_id"], math.MaxInt32, true) != nil || northboundText(row["action"], 64, false) != nil || northboundTime(row["created_at"], false, false) != nil {
			return ErrData
		}
		if !row["actor_user_id"].Null && !users[row["actor_user_id"].String()] {
			return ErrData
		}
		for _, name := range []string{"before_json", "after_json"} {
			if c := row[name]; !c.Null && (len(c.Bytes) > 8<<20 || strictJSON(c.Bytes) != nil) {
				return ErrData
			}
		}
	}
	return ctx.Err()
}

func validateNorthboundScalarAdapter(a TableAdapter, t Table) error {
	var fields string
	switch a.Normalizer {
	case NorthboundSettings077Normalizer:
		if northboundSettingsShape(t) != nil {
			return ErrSchema
		}
		fields = northboundSettingsColumns
	case NorthboundAudit057Normalizer:
		if northboundAuditShape(t) != nil {
			return ErrSchema
		}
		fields = northboundAuditColumns
	default:
		return ErrSchema
	}
	if len(a.LLMSecrets) != 0 || a.InterruptedAt != "" {
		return ErrSchema
	}
	for _, name := range strings.Fields(fields) {
		if a.Columns[name] != "preserve" {
			return ErrSchema
		}
	}
	return nil
}
