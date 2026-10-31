package systembackupcontroller

import (
	"context"
	"database/sql"
)

// Fixed metadata projections only. These grants never belong to the worker;
// the controller serves exact registered redacted proof bodies over its
// original authenticated current-Job mTLS pull. No business-table SELECT is
// added to this account and no source/config/audit write is introduced.
func controlEvidenceTableGrants(runtime, providerPermits, publication bool) map[string][]string {
	grants := formalCaptureTableGrants(runtime)
	if providerPermits {
		grants = formalProviderPermitTableGrants(runtime)
	}
	if publication {
		grants = publicationTableGrants(runtime, providerPermits)
	}
	for _, table := range []string{"audit_logs", "system_backup_v2_restore_drills", "system_backup_v2_preflights", "system_backup_v2_artifact_verifications", "system_backup_v2_promotions", "system_backup_v2_dependency_health", "system_backup_v2_provider_capabilities", "system_backup_v2_alert_states"} {
		grants[table] = []string{"SELECT"}
	}
	return grants
}
func ControlEvidenceGrantSQL(schema, user, host string, allowAnyHost, runtime, providerPermits, publication bool) ([]string, error) {
	return controllerGrantSQL(schema, user, host, allowAnyHost, controlEvidenceTableGrants(runtime, providerPermits, publication))
}

type SQLControlEvidenceGrantProbe struct {
	DB                                    *sql.DB
	Schema, User                          string
	Runtime, ProviderPermits, Publication bool
}

func (p SQLControlEvidenceGrantProbe) Check(ctx context.Context) error {
	return (SQLControllerGrantProbe{DB: p.DB, Schema: p.Schema, User: p.User}).check(ctx, controlEvidenceTableGrants(p.Runtime, p.ProviderPermits, p.Publication))
}
