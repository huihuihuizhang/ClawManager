package domain

// Owner-table adapters must bind uniqueness as well as column/PK/FK metadata.
// This does not authenticate the complete database schema: collations, checks,
// triggers and nonunique indexes remain covered by the separate schema census.
// Keep this explicit; new tables do not inherit a preserve policy.
func requiresUniqueCatalog(table string) bool {
	switch table {
	case "workbuddy_linux_identities", "workbuddy_linux_identity_allocator",
		"gateway_keys", "gateway_key_budget_reservations", "gateway_key_budget_ledger",
		"gateway_image_artifacts", "gateway_image_jobs", "llm_model_user_grants",
		"routing_classifier_settings", "northbound_admin_settings", "northbound_caller_policies",
		"northbound_owner_records", "northbound_settings_audit", "northbound_operations":
		return true
	}
	return false
}
