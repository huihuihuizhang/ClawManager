package systembackupresources

import (
	"context"
	"errors"
	"strconv"
	"strings"
)

// This private offline comparator does not authenticate a candidate, normalize
// rows or grant restore eligibility. The future reader must obtain complete
// isolated SELECT-only rows and verify its schema against this exact column set.
// Values are lossless SQL text: nil means SQL NULL, DECIMAL never passes through
// float64, and both sides use the same UTC/time/JSON representation. Unexpected
// representations fail closed rather than silently coercing values.
type restoreFieldRow map[string]*string
type restoreFieldTable struct {
	Name    string
	Columns []string // Required even for an empty table.
	Rows    []restoreFieldRow
}

// These are application migration columns, not API projections. In particular,
// northbound_settings_audit.actor is a joined display field and is excluded.
func restoreFieldColumns() map[string][]string {
	definitions := map[string]string{
		"audit_logs":                "id user_id action resource_type resource_id details ip_address created_at",
		"egress_private_exceptions": "id scope_type scope_id cidr port enabled description created_by created_at updated_at",
		"northbound_admin_settings": "id api_enabled external_node_port require_explicit_callers challenge_ttl_seconds access_token_ttl_seconds refresh_token_ttl_seconds core_request_timeout_seconds challenge_rate_per_minute login_rate_per_minute account_login_rate_per_minute create_rate_per_minute query_rate_per_minute share_rate_per_minute max_pending_operations operation_tick_milliseconds operation_lease_seconds operation_max_attempts allowed_lite_types allowed_pro_types lite_cpu_cores lite_memory_gb lite_disk_gb pro_cpu_cores pro_memory_gb pro_disk_gb workbuddy_pro_cpu_cores workbuddy_pro_memory_gb workbuddy_pro_disk_gb version updated_by created_at updated_at",
		"northbound_settings_audit": "id actor_user_id action before_json after_json created_at",
		"security_scan_configs":     "id default_mode quick_analyzers_json deep_analyzers_json quick_timeout_seconds deep_timeout_seconds allow_fallback updated_by created_at updated_at",
		"security_scan_jobs":        "id asset_type scan_mode status requested_by scope_json total_items completed_items failed_items current_item_name started_at finished_at created_at updated_at",
		"security_scan_job_items":   "id job_id asset_type asset_id asset_name status progress_pct risk_level summary scan_result_id cached_result error_message started_at finished_at created_at updated_at",
		"security_scan_reports":     "id job_id summary_json created_at updated_at",
		"system_image_settings":     "id instance_type runtime_type runtime_variant display_name image is_enabled created_at updated_at",
	}
	result := make(map[string][]string, len(definitions))
	for table, columns := range definitions {
		result[table] = strings.Fields(columns)
	}
	return result
}

// Bounds apply across all nine tables on each side, including all value bytes.
// Callers supply measured budgets; overflow or cancellation returns no success.
type restoreFieldBudget struct{ Rows, Bytes int64 }

func compareRestoreFields(ctx context.Context, expected, observed []restoreFieldTable, budget restoreFieldBudget) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if budget.Rows <= 0 || budget.Bytes <= 0 {
		return errors.New("resources field budget is required")
	}
	left, err := indexRestoreFields(ctx, expected, budget)
	if err != nil {
		return err
	}
	right, err := indexRestoreFields(ctx, observed, budget)
	if err != nil {
		return err
	}
	for table, rows := range left {
		if len(rows) != len(right[table]) {
			return errors.New("resources field row set differs")
		}
		for id, row := range rows {
			if err := ctx.Err(); err != nil {
				return err
			}
			other, exists := right[table][id]
			if !exists {
				return errors.New("resources field row set differs")
			}
			for column, value := range row {
				actual := other[column]
				if (value == nil) != (actual == nil) || (value != nil && *value != *actual) {
					// Neither row identity nor sensitive source values enter errors.
					return errors.New("resources field value differs")
				}
			}
		}
	}
	return ctx.Err()
}

func indexRestoreFields(ctx context.Context, tables []restoreFieldTable, budget restoreFieldBudget) (map[string]map[string]restoreFieldRow, error) {
	columns := restoreFieldColumns()
	if len(tables) != len(columns) {
		return nil, errors.New("resources field table set is incomplete")
	}
	result := make(map[string]map[string]restoreFieldRow, len(columns))
	for _, table := range tables {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		required, known := columns[table.Name]
		_, duplicate := result[table.Name]
		if !known || duplicate {
			return nil, errors.New("resources field table set is invalid")
		}
		if len(table.Columns) != len(required) {
			return nil, errors.New("resources field column set differs")
		}
		seen := make(map[string]bool, len(required))
		for _, column := range table.Columns {
			seen[column] = true
		}
		for _, column := range required {
			if !seen[column] {
				return nil, errors.New("resources field column set differs")
			}
		}
		rows := make(map[string]restoreFieldRow)
		for _, row := range table.Rows {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if budget.Rows == 0 {
				return nil, errors.New("resources field row budget exceeded")
			}
			budget.Rows--
			if len(row) != len(required) {
				return nil, errors.New("resources field row columns differ")
			}
			for _, column := range required {
				value, exists := row[column]
				if !exists {
					return nil, errors.New("resources field row columns differ")
				}
				if value != nil {
					if int64(len(*value)) > budget.Bytes {
						return nil, errors.New("resources field byte budget exceeded")
					}
					budget.Bytes -= int64(len(*value))
				}
			}
			id := row["id"]
			if id == nil {
				return nil, errors.New("resources field row identity is invalid")
			}
			parsed, err := strconv.ParseInt(*id, 10, 64)
			maxID := int64(2147483647)
			if table.Name == "northbound_settings_audit" {
				maxID = 9223372036854775807
			}
			if err != nil || parsed <= 0 || parsed > maxID || strconv.FormatInt(parsed, 10) != *id {
				return nil, errors.New("resources field row identity is invalid")
			}
			if _, exists := rows[*id]; exists {
				return nil, errors.New("resources field row identity is duplicated")
			}
			rows[*id] = row
		}
		result[table.Name] = rows
	}
	return result, nil
}
