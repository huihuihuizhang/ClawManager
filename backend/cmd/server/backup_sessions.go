package main

import (
	"clawreef/internal/systembackupsecurity"
	"database/sql"
)

// No defaults can silently enroll a deployment into backup session issuance.
func backupSessionRecorder(db *sql.DB, database, secret string, getenv func(string) string) (*systembackupsecurity.SQLLoginSessions, error) {
	switch getenv("SYSTEM_BACKUP_READ_SESSIONS_ENABLED") {
	case "", "false":
		return nil, nil
	case "true":
	default:
		return nil, systembackupsecurity.ErrLoginSessionUnavailable
	}
	return systembackupsecurity.NewSQLLoginSessions(db, systembackupsecurity.DatabaseIdentity{Database: database, ServerUUID: getenv("SYSTEM_BACKUP_READ_SESSIONS_SERVER_UUID")}, getenv("SYSTEM_BACKUP_REGISTRATION_INSTALLATION_ID"), []byte(secret))
}
