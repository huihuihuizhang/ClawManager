package systembackupcontroller

import (
	"context"
	"database/sql"
)

// A separately selected publication role adds only the original immutable
// journal writes and bounded frozen-signature chunks. No DDL, DELETE, config
// mutation, signing authority mutation or business-source privilege is added.
func publicationTableGrants(runtime, providerPermits bool) map[string][]string {
	grants := formalCaptureTableGrants(runtime)
	if providerPermits {
		grants = formalProviderPermitTableGrants(runtime)
	}
	grants["system_backup_v2_external_actions"] = []string{"SELECT", "INSERT", "UPDATE"}
	grants["system_backup_v2_evidence_chunks"] = []string{"SELECT", "INSERT"}
	return grants
}
func PublicationGrantSQL(schema, user, host string, allowAnyHost, runtime, providerPermits bool) ([]string, error) {
	return controllerGrantSQL(schema, user, host, allowAnyHost, publicationTableGrants(runtime, providerPermits))
}
func ValidatePublicationGrants(schema string, statements []string, runtime, providerPermits bool) error {
	return validateControllerGrants(schema, statements, publicationTableGrants(runtime, providerPermits))
}

type SQLPublicationGrantProbe struct {
	DB                       *sql.DB
	Schema, User             string
	Runtime, ProviderPermits bool
}

func (p SQLPublicationGrantProbe) Check(ctx context.Context) error {
	return (SQLControllerGrantProbe{DB: p.DB, Schema: p.Schema, User: p.User}).check(ctx, publicationTableGrants(p.Runtime, p.ProviderPermits))
}
