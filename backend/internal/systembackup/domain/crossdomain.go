package domain

// Explicit current-repository columns, reviewed against embedded migrations and
// repository schemas. Additional source versions must use exact TableAdapter.
var crossDomainColumns = map[string]string{
	"model_invocations":         "id trace_id session_id request_id user_id instance_id instance_mode runtime_type gateway_id runtime_pod_id model_id provider_type requested_model actual_provider_model traffic_class request_payload response_payload prompt_tokens completion_tokens total_tokens cached_tokens reasoning_tokens latency_ms is_streaming status error_message created_at completed_at",
	"audit_events":              "id trace_id session_id request_id user_id instance_id instance_mode runtime_type gateway_id runtime_pod_id invocation_id event_type traffic_class severity message details created_at",
	"cost_records":              "id trace_id session_id request_id user_id instance_id instance_mode runtime_type gateway_id runtime_pod_id invocation_id model_id provider_type model_name currency prompt_tokens completion_tokens total_tokens input_unit_price output_unit_price estimated_cost actual_cost internal_cost recorded_at",
	"risk_hits":                 "id trace_id session_id request_id user_id instance_id instance_mode runtime_type gateway_id runtime_pod_id invocation_id rule_id rule_name severity action match_summary created_at",
	"risk_rules":                "id rule_id display_name description pattern severity action is_enabled sort_order created_at updated_at",
	"system_image_settings":     "id instance_type runtime_type runtime_variant display_name image is_enabled created_at updated_at",
	"egress_private_exceptions": "id scope_type scope_id cidr port enabled description created_by created_at updated_at",
	"security_scan_configs":     "id default_mode quick_analyzers_json deep_analyzers_json quick_timeout_seconds deep_timeout_seconds allow_fallback updated_by created_at updated_at",
	"security_scan_jobs":        "id asset_type scan_mode status requested_by scope_json total_items completed_items failed_items current_item_name started_at finished_at created_at updated_at",
	"security_scan_job_items":   "id job_id asset_type asset_id asset_name status progress_pct risk_level summary scan_result_id cached_result error_message started_at finished_at created_at updated_at",
	"security_scan_reports":     "id job_id summary_json created_at updated_at",
	"audit_logs":                "id user_id action resource_type resource_id details ip_address created_at",
}

func normalizeCrossDomain(table string, r Row) {
	switch table {
	case "model_invocations":
		// Archive retains original status; target cannot resume a live call.
		if r["status"].String() != "succeeded" && r["status"].String() != "completed" && r["status"].String() != "failed" && r["status"].String() != "blocked" {
			set(r, "status", Text("failed"))
		}
		clearFields(r, "runtime_pod_id gateway_id")
	case "risk_rules", "system_image_settings":
		set(r, "is_enabled", Text("0"))
	case "egress_private_exceptions":
		set(r, "enabled", Text("0"))
	case "security_scan_jobs", "security_scan_job_items":
		if r["status"].String() != "completed" && r["status"].String() != "failed" {
			set(r, "status", Text("failed"))
		}
	}
}
