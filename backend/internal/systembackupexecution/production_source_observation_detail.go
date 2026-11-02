package systembackupexecution

import (
	d "clawreef/internal/systembackupdispatch"
	"log"
)

type sourceObservationDetail uint8

const (
	sourceSQLInput sourceObservationDetail = iota
	sourceSQLOriginal
	sourceSQLBegin
	sourceSQLSnapshotIdentity
	sourceSQLInstancesRead
	sourceSQLInstancesShape
	sourceSQLClockRead
	sourceSQLClockIdentity
	sourceSQLClockWindow
	sourceSQLProjection
	sourceSQLCommit
	sourceSQLOriginalTail
	sourceSQLDeadline
	sourceInventoryBaseline
	sourceInventoryBegin
	sourceInventoryOriginal
	sourceInventoryIdentity
	sourceInventoryUsersRead
	sourceInventoryUsersShape
	sourceInventoryUsersEOF
	sourceInventoryInstancesRead
	sourceInventoryInstancesDrift
	sourceInventoryRuntime
	sourceInventoryInstanceOwner
	sourceInventoryTeams
	sourceInventorySkills
	sourceInventoryMetadataRead
	sourceInventoryMetadataDrift
	sourceInventoryIdentityTail
	sourceInventoryCommit
	sourceInventoryOriginalTail
	sourceInventoryDeadline
	sourceInventoryProjection
)

// Both fields come only from this closed code table. No runtime error, SQL,
// row, identifier, credential, path, hash or elapsed time can enter the log.
// Logging never substitutes a query, changes a guard or changes public error.
func sourceObservationDetailRejected(detail sourceObservationDetail) error {
	labels := [...]struct{ stage, boundary string }{
		{"source-sql-observation", "observer-input"},
		{"source-sql-observation", "original-before-snapshot"},
		{"source-sql-observation", "begin-snapshot"},
		{"source-sql-observation", "snapshot-identity-grants"},
		{"source-sql-observation", "instances-read"},
		{"source-sql-observation", "instances-shape"},
		{"source-sql-observation", "clock-read"},
		{"source-sql-observation", "clock-identity"},
		{"source-sql-observation", "clock-original-window"},
		{"source-sql-observation", "instances-projection"},
		{"source-sql-observation", "snapshot-commit"},
		{"source-sql-observation", "original-after-snapshot"},
		{"source-sql-observation", "original-deadline"},
		{"source-inventory", "baseline-observation"},
		{"source-inventory", "begin-snapshot"},
		{"source-inventory", "original-before-snapshot"},
		{"source-inventory", "snapshot-identity-grants"},
		{"source-inventory", "users-read"},
		{"source-inventory", "users-shape"},
		{"source-inventory", "users-eof"},
		{"source-inventory", "instances-read"},
		{"source-inventory", "instances-drift"},
		{"source-inventory", "runtime-inventory"},
		{"source-inventory", "instance-owner"},
		{"source-inventory", "teams-facts"},
		{"source-inventory", "skills-inventory"},
		{"source-inventory", "metadata-read"},
		{"source-inventory", "metadata-drift"},
		{"source-inventory", "identity-grants-tail"},
		{"source-inventory", "snapshot-commit"},
		{"source-inventory", "original-after-snapshot"},
		{"source-inventory", "original-deadline"},
		{"source-inventory", "inventory-projection"},
	}
	stage, boundary := "unknown-source-boundary", "unknown-detail"
	if int(detail) < len(labels) {
		stage, boundary = labels[detail].stage, labels[detail].boundary
	}
	log.Printf("[system-backup-source] stage=%s boundary=%s status=rejected", stage, boundary)
	return d.ErrNotReady
}
