package schemaobjects

// These six exact external/historical variants were already admitted by
// teamDataHistoricalOperationTable. They have no current embedded migration.
// Presence still requires capture and its exact SELECT grant. Linux Lite
// WorkBuddy facts additionally require its two original UID tables.
func OptionalBusinessTables() []string {
	return []string{"runtime_rollout_instances", "workbuddy_browser_grants", "workbuddy_instance_recoveries", "workbuddy_linux_identities", "workbuddy_linux_identity_allocator", "workbuddy_pod_terminations"}
}
