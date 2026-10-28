package main

import (
	"database/sql"
	"os"
	"time"

	"clawreef/internal/middleware"
	"clawreef/internal/systembackupapi"
	"clawreef/internal/systembackupread"
	"clawreef/internal/systembackupsecurity"
	"github.com/gin-gonic/gin"
)

// This is the only production task application composition point. The existing
// read authorizer is intentionally not reused as system_backup.operate authority.
// Supply the reviewed request decoder + A mutation admission + atomic SQL
// create/enqueue + B runner/C provider adapters here when those contracts land.
// No production implementation is currently available, so both POSTs and the
// dependent details stay not_ready rather than falling through to the proxy.
func linkedSystemBackupTaskApplication(db *sql.DB, sessions *systembackupsecurity.SQLLoginSessions) systembackupapi.TaskApplication {
	// The missing reviewed request writer and complete B/C detail adapters
	// have one explicit link location. Never substitute test models here.
	var writer systembackupapi.TaskWriter
	var details systembackupapi.TaskDetails
	application, err := composeSystemBackupTaskApplication(db, sessions, writer, details, os.Getenv)
	if err != nil {
		return nil
	}
	return application
}

func composeSystemBackupTaskApplication(db *sql.DB, sessions *systembackupsecurity.SQLLoginSessions,
	writer systembackupapi.TaskWriter, details systembackupapi.TaskDetails, getenv func(string) string) (systembackupapi.TaskApplication, error) {
	if writer == nil || details == nil || getenv == nil {
		return nil, &systembackupapi.Error{Code: "not_ready"}
	}
	// A's action and read scopes share the real login/refresh recorder and
	// existing pins; operate authority is never inferred from read authority.
	actions, err := systembackupsecurity.LoadSystemBackupActionAuthorizer(sessions, getenv("SYSTEM_BACKUP_READ_PINS_PATH"), getenv("SYSTEM_BACKUP_READ_PINS_SHA256"))
	if err != nil {
		return nil, err
	}
	reads, err := systembackupsecurity.LoadSystemBackupReadAuthorizer(sessions, getenv("SYSTEM_BACKUP_READ_PINS_PATH"), getenv("SYSTEM_BACKUP_READ_PINS_SHA256"))
	if err != nil {
		return nil, err
	}
	return systembackupapi.NewSQLApplication(db, actions, reads, writer, details, 30*time.Second)
}

func registerBackupTaskMutations(admin *gin.RouterGroup, handler *systembackupapi.Handler) {
	admin.POST("/system-backups", func(c *gin.Context) {
		handler.Create(c.Writer, c.Request, systembackupread.BackupTask, middleware.SystemBackupRequestID(c))
	})
	admin.POST("/system-backup-preflights", func(c *gin.Context) {
		handler.Create(c.Writer, c.Request, systembackupread.PreflightTask, middleware.SystemBackupRequestID(c))
	})
}
