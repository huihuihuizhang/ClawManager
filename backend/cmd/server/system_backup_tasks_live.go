package main

import (
	"database/sql"
	"log"
	"os"
	"time"

	"clawreef/internal/middleware"
	"clawreef/internal/systembackupapi"
	"clawreef/internal/systembackupread"
	"clawreef/internal/systembackupsecurity"
	"github.com/gin-gonic/gin"
)

// Read and operate authorities remain separate. Task admission additionally
// requires a matching, fresh execution-adapter receipt inside its SQL transaction.
func linkedSystemBackupTaskApplication(db *sql.DB, sessions *systembackupsecurity.SQLLoginSessions) systembackupapi.TaskApplication {
	var writer systembackupapi.TaskWriter = systembackupapi.DisabledTaskWriter{}
	if path := os.Getenv("SYSTEM_BACKUP_EXECUTION_PROFILE_FILE"); path != "" {
		profile, err := systembackupapi.LoadExecutionProfile(path)
		if err == nil {
			if os.Getenv("SYSTEM_BACKUP_EXECUTION_PROTOCOL") == "public-v1" {
				writer, err = systembackupapi.NewAdmittedTaskWriter(profile, os.Getenv("SYSTEM_BACKUP_CAPACITY_REPORT_FILE"), os.Getenv("SYSTEM_BACKUP_V2_EXECUTION_ENABLED") == "true")
			} else {
				var configured *systembackupapi.SQLTaskWriter
				configured, err = systembackupapi.NewSQLTaskWriter(profile)
				if err == nil {
					writer = configured.WithCapacityReport(os.Getenv("SYSTEM_BACKUP_CAPACITY_REPORT_FILE"))
				}
			}
		}
		if err != nil {
			writer = systembackupapi.DisabledTaskWriter{}
			log.Print("backup execution profile unavailable; task submission disabled, authorized history and unstarted cancellation retained")
		}
	}
	details := systembackupapi.SQLTaskDetails{DB: db}
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
	app, err := systembackupapi.NewSQLApplication(db, actions, reads, writer, details, 30*time.Second)
	if err != nil {
		return nil, err
	}
	return app.WithCancellationCapacityReport(getenv("SYSTEM_BACKUP_CAPACITY_REPORT_FILE")), nil
}

func registerBackupTaskMutations(admin *gin.RouterGroup, handler *systembackupapi.Handler) {
	admin.POST("/system-backups", func(c *gin.Context) {
		handler.Create(c.Writer, c.Request, systembackupread.BackupTask, middleware.SystemBackupRequestID(c))
	})
	admin.POST("/system-backup-preflights", func(c *gin.Context) {
		handler.Create(c.Writer, c.Request, systembackupread.PreflightTask, middleware.SystemBackupRequestID(c))
	})
	admin.POST("/system-backups/:id/cancel", func(c *gin.Context) {
		handler.Cancel(c.Writer, c.Request, systembackupread.BackupTask, c.Param("id"), middleware.SystemBackupRequestID(c))
	})
	admin.POST("/system-backup-preflights/:id/cancel", func(c *gin.Context) {
		handler.Cancel(c.Writer, c.Request, systembackupread.PreflightTask, c.Param("id"), middleware.SystemBackupRequestID(c))
	})
}
