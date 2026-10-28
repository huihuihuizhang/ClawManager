package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"clawreef/internal/middleware"
	"clawreef/internal/systembackupapi"
	"clawreef/internal/systembackupread"
	"clawreef/internal/systembackupsecurity"
	"github.com/gin-gonic/gin"
)

// Live reads use A's deployment-pinned authorizer and a separate cursor key.
// A nil authorizer represents an enabled but unavailable deployment, not a
// permission to fall back to fixture data.
type liveBackupRead struct {
	db         *sql.DB
	authorizer *systembackupsecurity.SystemBackupReadAuthorizer
	cursorKey  []byte
	tasks      *systembackupapi.Handler
}

func loadLiveBackupRead(db *sql.DB, sessions *systembackupsecurity.SQLLoginSessions, getenv func(string) string) (*liveBackupRead, error) {
	if getenv == nil {
		return nil, errors.New("environment reader missing")
	}
	switch getenv("SYSTEM_BACKUP_READ_LIVE_ENABLED") {
	case "", "false":
		return nil, nil
	case "true":
	default:
		return nil, errors.New("invalid live read switch")
	}
	live := &liveBackupRead{db: db}
	key, err := loadBackupReadCursorKey(getenv)
	if db == nil || err != nil || len(key) < 32 {
		return live, errors.New("live read cursor key or SQL session unavailable")
	}
	live.cursorKey = append([]byte(nil), key...)
	live.authorizer, err = systembackupsecurity.LoadSystemBackupReadAuthorizer(sessions,
		getenv("SYSTEM_BACKUP_READ_PINS_PATH"), getenv("SYSTEM_BACKUP_READ_PINS_SHA256"))
	if err != nil {
		return live, errors.New("live read authority pin unavailable")
	}
	return live, nil
}

func registerBackupReadLive(admin *gin.RouterGroup, live *liveBackupRead) {
	unavailable := func(c *gin.Context) { liveReadError(c, systembackupread.ErrUnavailable) }
	for _, path := range []string{
		"/system-backup-overview", "/system-backup-catalog-scans", "/system-backup-catalog-records",
		"/system-backup-catalog-imports", "/system-backup-prune-runs", "/system-backup-promotions",
	} {
		admin.GET(path, unavailable)
	}
	admin.GET("/system-backup-config", live.getActiveConfig)
	admin.GET("/system-backup-config/versions", live.listConfigVersions)
	admin.GET("/system-backup-config/versions/:version", live.getConfigVersion)
	for _, route := range []struct {
		path string
		kind systembackupread.TaskKind
	}{
		{"/system-backups", systembackupread.BackupTask},
		{"/system-restore-drills", systembackupread.DrillTask},
		{"/system-backup-preflights", systembackupread.PreflightTask},
		{"/system-backup-artifact-verifications", systembackupread.VerificationTask},
	} {
		kind := route.kind
		admin.GET(route.path, func(c *gin.Context) { live.listTasks(c, kind) })
		if kind == systembackupread.VerificationTask {
			admin.GET(route.path+"/:id", live.getVerificationDetail)
		} else if kind == systembackupread.DrillTask {
			admin.GET(route.path+"/:id", live.getDrillDetail)
		} else {
			admin.GET(route.path+"/:id", func(c *gin.Context) {
				var handler *systembackupapi.Handler
				if live != nil {
					handler = live.tasks
				}
				handler.Detail(c.Writer, c.Request, kind, c.Param("id"), middleware.SystemBackupRequestID(c))
			})
		}
		admin.GET(route.path+"/:id/events", func(c *gin.Context) { live.listTaskEvents(c, kind) })
		admin.GET(route.path+"/:id/logs", unavailable)
	}
	admin.GET("/system-backups/:id/manifest", unavailable)
	admin.GET("/system-backup-operations", live.listOperations)
	admin.GET("/system-backup-operations/:id", live.getOperation)
}

func (l *liveBackupRead) getActiveConfig(c *gin.Context) {
	if c.Request.URL.RawQuery != "" {
		liveReadError(c, systembackupread.ErrInvalid)
		return
	}
	service, ctx, ok := l.service(c)
	if !ok {
		return
	}
	result, err := service.ReadActiveConfigDTO(ctx)
	if err != nil {
		liveReadError(c, err)
		return
	}
	c.Header("X-System-Backup-Data-Source", "live")
	c.JSON(http.StatusOK, result)
}

func (l *liveBackupRead) listConfigVersions(c *gin.Context) {
	limit, cursor, _, err := liveReadListQuery(c, false)
	if err != nil {
		liveReadError(c, err)
		return
	}
	service, ctx, ok := l.service(c)
	if !ok {
		return
	}
	result, err := service.ListConfigDTO(ctx, limit, cursor)
	if err != nil {
		liveReadError(c, err)
		return
	}
	c.Header("X-System-Backup-Data-Source", "live")
	c.JSON(http.StatusOK, result)
}

func (l *liveBackupRead) getConfigVersion(c *gin.Context) {
	if c.Request.URL.RawQuery != "" {
		liveReadError(c, systembackupread.ErrInvalid)
		return
	}
	raw := c.Param("version")
	version, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || version == 0 || version > 9007199254740991 || strconv.FormatUint(version, 10) != raw {
		liveReadError(c, systembackupread.ErrInvalid)
		return
	}
	service, ctx, ok := l.service(c)
	if !ok {
		return
	}
	result, err := service.ReadConfigVersionDTO(ctx, version)
	if err != nil {
		liveReadError(c, err)
		return
	}
	c.Header("X-System-Backup-Data-Source", "live")
	c.JSON(http.StatusOK, result)
}

func liveReadError(c *gin.Context, err error) {
	c.Header("Cache-Control", "no-store")
	status, code := http.StatusServiceUnavailable, "not_ready"
	switch {
	case errors.Is(err, systembackupread.ErrInvalid):
		status, code = http.StatusBadRequest, "validation_failed"
	case errors.Is(err, systembackupread.ErrNotFound):
		status, code = http.StatusNotFound, "not_found"
	case errors.Is(err, systembackupsecurity.ErrSystemBackupReadAuthentication):
		status, code = http.StatusUnauthorized, "authentication_required"
	case errors.Is(err, systembackupsecurity.ErrRegistrationUnavailable),
		errors.Is(err, systembackupsecurity.ErrProviderEvidenceStorage):
		status, code = http.StatusServiceUnavailable, "not_ready"
	case errors.Is(err, systembackupsecurity.ErrRegistrationPermission):
		status, code = http.StatusForbidden, "permission_denied"
	case errors.Is(err, systembackupread.ErrDenied):
		status, code = http.StatusForbidden, "permission_denied"
	}
	c.JSON(status, gin.H{"code": code, "message": code, "details": gin.H{}, "request_id": middleware.SystemBackupRequestID(c)})
}

func (l *liveBackupRead) service(c *gin.Context) (*systembackupread.Service, context.Context, bool) {
	if l == nil || l.db == nil || l.authorizer == nil || c == nil {
		if c != nil {
			liveReadError(c, systembackupread.ErrUnavailable)
		}
		return nil, nil, false
	}
	c.Header("Cache-Control", "no-store")
	scope, err := l.authorizer.Scope(c.Request)
	if err != nil {
		liveReadError(c, err)
		return nil, nil, false
	}
	service, err := systembackupread.NewService(l.db, scope, l.cursorKey)
	if err != nil {
		liveReadError(c, systembackupread.ErrUnavailable)
		return nil, nil, false
	}
	return service, scope.Context(), true
}

func liveReadListQuery(c *gin.Context, allowStatus bool) (int, string, string, error) {
	if c == nil || len(c.Request.URL.RawQuery) > 8192 {
		return 0, "", "", systembackupread.ErrInvalid
	}
	limit, cursor, status := 50, "", ""
	query, err := url.ParseQuery(c.Request.URL.RawQuery)
	if err != nil {
		return 0, "", "", systembackupread.ErrInvalid
	}
	for name, values := range query {
		if len(values) != 1 || values[0] == "" {
			return 0, "", "", systembackupread.ErrInvalid
		}
		switch name {
		case "limit":
			parsed, err := strconv.Atoi(values[0])
			if err != nil || parsed < 1 || parsed > 500 || strconv.Itoa(parsed) != values[0] {
				return 0, "", "", systembackupread.ErrInvalid
			}
			limit = parsed
		case "cursor":
			if len(values[0]) > 4096 {
				return 0, "", "", systembackupread.ErrInvalid
			}
			cursor = values[0]
		case "status":
			if !allowStatus {
				return 0, "", "", systembackupread.ErrInvalid
			}
			status = values[0]
		default:
			return 0, "", "", systembackupread.ErrInvalid
		}
	}
	return limit, cursor, status, nil
}

func (l *liveBackupRead) listTasks(c *gin.Context, kind systembackupread.TaskKind) {
	limit, cursor, status, err := liveReadListQuery(c, true)
	if err != nil {
		liveReadError(c, err)
		return
	}
	service, ctx, ok := l.service(c)
	if !ok {
		return
	}
	result, err := service.ListTaskDTO(ctx, kind, status, limit, cursor)
	if err != nil {
		liveReadError(c, err)
		return
	}
	c.Header("X-System-Backup-Data-Source", "live")
	c.JSON(http.StatusOK, result)
}

func (l *liveBackupRead) listOperations(c *gin.Context) {
	limit, cursor, _, err := liveReadListQuery(c, false)
	if err != nil {
		liveReadError(c, err)
		return
	}
	service, ctx, ok := l.service(c)
	if !ok {
		return
	}
	result, err := service.ListOperationDTO(ctx, limit, cursor)
	if err != nil {
		liveReadError(c, err)
		return
	}
	c.Header("X-System-Backup-Data-Source", "live")
	c.JSON(http.StatusOK, result)
}

func (l *liveBackupRead) getOperation(c *gin.Context) {
	if c.Request.URL.RawQuery != "" {
		liveReadError(c, systembackupread.ErrInvalid)
		return
	}
	service, ctx, ok := l.service(c)
	if !ok {
		return
	}
	result, err := service.GetOperationDTO(ctx, c.Param("id"))
	if err != nil {
		liveReadError(c, err)
		return
	}
	c.Header("X-System-Backup-Data-Source", "live")
	c.JSON(http.StatusOK, result)
}

func (l *liveBackupRead) getDrillDetail(c *gin.Context) {
	if c.Request.URL.RawQuery != "" {
		liveReadError(c, systembackupread.ErrInvalid)
		return
	}
	service, ctx, ok := l.service(c)
	if !ok {
		return
	}
	result, err := service.ReadDrillDetailDTO(ctx, c.Param("id"))
	if err != nil {
		liveReadError(c, err)
		return
	}
	c.Header("X-System-Backup-Data-Source", "live")
	c.Writer.Header().Add("Access-Control-Expose-Headers", "X-System-Backup-Data-Source, X-System-Backup-Origin-Installation-ID, X-System-Backup-Task-Row-Version")
	c.Header(systembackupread.TaskEventInstallationHeader, result.Task.OriginInstallationID)
	c.Header(systembackupread.TaskEventRowVersionHeader, strconv.FormatInt(result.Task.RowVersion, 10))
	c.JSON(http.StatusOK, result)
}

func (l *liveBackupRead) getVerificationDetail(c *gin.Context) {
	if c.Request.URL.RawQuery != "" {
		liveReadError(c, systembackupread.ErrInvalid)
		return
	}
	service, ctx, ok := l.service(c)
	if !ok {
		return
	}
	result, err := service.ReadVerificationDetailDTO(ctx, c.Param("id"))
	if err != nil {
		liveReadError(c, err)
		return
	}
	c.Header("X-System-Backup-Data-Source", "live")
	c.Writer.Header().Add("Access-Control-Expose-Headers", "X-System-Backup-Data-Source, X-System-Backup-Origin-Installation-ID, X-System-Backup-Task-Row-Version")
	c.Header(systembackupread.TaskEventInstallationHeader, result.Task.OriginInstallationID)
	c.Header(systembackupread.TaskEventRowVersionHeader, strconv.FormatInt(result.Task.RowVersion, 10))
	c.JSON(http.StatusOK, result)
}

func (l *liveBackupRead) listTaskEvents(c *gin.Context, kind systembackupread.TaskKind) {
	limit, cursor, _, err := liveReadListQuery(c, false)
	if err != nil {
		liveReadError(c, err)
		return
	}
	service, ctx, ok := l.service(c)
	if !ok {
		return
	}
	result, err := service.ListTaskEventsDTO(ctx, kind, c.Param("id"), limit, cursor)
	if err != nil {
		liveReadError(c, err)
		return
	}
	c.Header("X-System-Backup-Data-Source", "live")
	c.Writer.Header().Add("Access-Control-Expose-Headers", "X-System-Backup-Data-Source, X-System-Backup-Origin-Installation-ID, X-System-Backup-Task-Row-Version")
	c.Header(systembackupread.TaskEventInstallationHeader, result.InstallationID)
	c.Header(systembackupread.TaskEventRowVersionHeader, strconv.FormatUint(result.TaskRowVersion, 10))
	c.JSON(http.StatusOK, result.Resource)
}
