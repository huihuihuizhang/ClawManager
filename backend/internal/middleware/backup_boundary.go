package middleware

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"clawreef/internal/backupgate"
	"github.com/gin-gonic/gin"
)

// BackupRequestBoundary includes GET because some existing read endpoints
// create workspace directories or audit records. Only registered backup control
// routes and the pure version route are exempt; a matching unknown URL is not.
func BackupRequestBoundary(pool *sql.DB, scope string) gin.HandlerFunc {
	return backupRequestBoundary(scope, func(ctx context.Context) (func(), error) { return backupgate.HoldRequest(ctx, pool, scope) })
}
func backupRequestBoundary(scope string, acquire func(context.Context) (func(), error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.FullPath()
		if scope == "" || strings.HasPrefix(path, "/api/v1/admin/system-backup/") || backupRecordControlRoute(c.Request.Method, path) || (c.Request.Method == http.MethodGet && path == "/api/v1/version") {
			c.Next()
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
		release, e := acquire(ctx)
		cancel()
		if e != nil {
			code := "backup_coordination_unavailable"
			if errors.Is(e, backupgate.ErrMaintenance) {
				code = "backup_maintenance"
			}
			c.Header("Retry-After", "15")
			c.Header("Cache-Control", "no-store")
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"success": false, "code": code, "error": code})
			return
		}
		defer release()
		c.Next()
	}
}

// FullPath is Gin's registered route, never the user-supplied URL. Keep this
// closed: an unknown suffix must not bypass admission during maintenance.
func backupRecordControlRoute(method, path string) bool {
	if method == http.MethodPost {
		return path == "/api/v1/admin/system-backups" || path == "/api/v1/admin/system-backup-preflights" ||
			path == "/api/v1/admin/system-backups/:id/cancel" || path == "/api/v1/admin/system-backup-preflights/:id/cancel"
	}
	if method != http.MethodGet {
		return false
	}
	switch path {
	case "/api/v1/admin/system-backup-overview", "/api/v1/admin/system-backup-config", "/api/v1/admin/system-backup-config/versions", "/api/v1/admin/system-backup-config/versions/:version", "/api/v1/admin/system-backup-operations", "/api/v1/admin/system-backup-operations/:id", "/api/v1/admin/system-backup-catalog-scans", "/api/v1/admin/system-backup-catalog-records", "/api/v1/admin/system-backup-catalog-imports", "/api/v1/admin/system-backup-prune-runs", "/api/v1/admin/system-backup-promotions", "/api/v1/admin/system-backups/:id/manifest":
		return true
	}
	for _, base := range []string{"/api/v1/admin/system-backups", "/api/v1/admin/system-restore-drills", "/api/v1/admin/system-backup-preflights", "/api/v1/admin/system-backup-artifact-verifications"} {
		if path == base || path == base+"/:id" || path == base+"/:id/events" || path == base+"/:id/logs" {
			return true
		}
	}
	return false
}
