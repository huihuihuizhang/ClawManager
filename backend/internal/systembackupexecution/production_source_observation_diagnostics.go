package systembackupexecution

import (
	d "clawreef/internal/systembackupdispatch"
	"log"
)

type sourceObservationStage uint8

const (
	sourceObserverBindings sourceObservationStage = iota
	sourceObserverGrant
	sourceObserverProfile
	sourceObserverConfigState
	sourceObserverController
	sourceObserverStaging
	sourceObserverSQLIdentity
	sourceObserverSQLMetadata
	sourceObserverInventory
	sourceObserverTransport
	sourceObserverSkillObjects
	sourceObserverResources
)

// Fixed code labels only; no errors, paths, tokens, queries, source rows or
// credential-derived identity hashes enter logs. Public error stays identical.
func sourceObservationRejected(stage sourceObservationStage) error {
	names := [...]string{"observer-bindings", "original-owner-grant", "original-profile", "current-config-state", "controller-workload", "staging-carrier", "source-sql-identity-grants", "source-sql-schema-metadata", "source-inventory", "metadata-transports", "skill-object-metadata", "resource-metadata"}
	name := "unknown-source-boundary"
	if int(stage) < len(names) {
		name = names[stage]
	}
	log.Printf("[system-backup-source] stage=%s status=rejected", name)
	return d.ErrNotReady
}
