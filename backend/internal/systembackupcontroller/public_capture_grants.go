package systembackupcontroller

import (
	"context"
	"database/sql"
)

// Exact table/verb inventory of public-v1 workspace capture. No business table,
// config update, DDL, wildcard, deletion, provider or restore rights are present.
// Independent API/source/capacity accounts retain their separate grant sets.
var publicCaptureTableGrants = map[string][]string{
	"schema_migrations":                      {"SELECT"},
	"system_backup_gate":                     {"SELECT", "UPDATE"},
	"system_backup_gate_admissions":          {"SELECT", "UPDATE"},
	"system_backup_participants":             {"SELECT", "INSERT", "UPDATE"},
	"system_backup_mutation_leases":          {"SELECT"},
	"system_backup_capture_plans":            {"SELECT", "UPDATE"},
	"system_backup_v2_engine_bindings":       {"SELECT", "UPDATE"},
	"system_backup_v2_installation_state":    {"SELECT", "UPDATE"},
	"system_backup_v2_configs":               {"SELECT"},
	"system_backup_v2_execution_inputs":      {"SELECT"},
	"system_backup_v2_execution_plans":       {"SELECT"},
	"system_backup_v2_execution_readiness":   {"SELECT", "INSERT", "UPDATE"},
	"system_backup_v2_execution_records":     {"SELECT", "INSERT"},
	"system_backup_v2_maintenance_locks":     {"SELECT", "UPDATE"},
	"system_backup_v2_attempts":              {"SELECT", "INSERT", "UPDATE"},
	"system_backup_v2_backups":               {"SELECT", "UPDATE"},
	"system_backup_v2_job_observations":      {"SELECT", "INSERT", "UPDATE"},
	"system_backup_v2_job_send_intents":      {"SELECT", "INSERT", "UPDATE"},
	"system_backup_v2_external_actions":      {"SELECT"},
	"system_backup_v2_operations":            {"SELECT", "UPDATE"},
	"system_backup_v2_events":                {"SELECT", "INSERT"},
	"system_backup_v2_metadata_reservations": {"SELECT", "INSERT", "UPDATE"},
	"system_backup_v2_runtime_captures":      {"SELECT", "INSERT", "UPDATE"},
	"system_backup_v2_runtime_resources":     {"SELECT", "INSERT", "UPDATE"},
	"system_backup_v2_runtime_stop_proofs":   {"SELECT", "INSERT"},
	"system_backup_v2_runtime_writers":       {"SELECT", "INSERT", "UPDATE"},
}

func PublicCaptureGrantSQL(schema, user, host string, allowAnyHost bool) ([]string, error) {
	return controllerGrantSQL(schema, user, host, allowAnyHost, publicCaptureTableGrants)
}
func ValidatePublicCaptureGrants(schema string, statements []string) error {
	return validateControllerGrants(schema, statements, publicCaptureTableGrants)
}

type SQLPublicCaptureGrantProbe struct {
	DB           *sql.DB
	Schema, User string
}

func (p SQLPublicCaptureGrantProbe) Check(ctx context.Context) error {
	return (SQLControllerGrantProbe{DB: p.DB, Schema: p.Schema, User: p.User}).check(ctx, publicCaptureTableGrants)
}
