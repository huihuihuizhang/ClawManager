package systembackuptrial

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"time"

	"clawreef/internal/middleware"
	"clawreef/internal/repository"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/staging"

	"github.com/gin-gonic/gin"
)

func (s *Service) Register(api *gin.RouterGroup, users repository.UserRepository) {
	admin := api.Group("/admin/system-backup/trial")
	admin.Use(middleware.Auth(), middleware.SetUserInfo(users), middleware.NewAdminAuth(users), func(c *gin.Context) {
		user := middleware.GetCurrentUser(c)
		if user == nil || !user.IsActive {
			c.AbortWithStatus(http.StatusForbidden)
		}
	})
	admin.GET("/readiness", func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, s.readiness(c.Request.Context()))
	})
	admin.GET("/task", func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		s.mu.Lock()
		task := s.task
		s.mu.Unlock()
		c.JSON(http.StatusOK, gin.H{"task": task})
	})
	admin.POST("/backups", func(c *gin.Context) {
		if ready := s.readiness(c.Request.Context()); len(ready.Missing) != 0 {
			c.JSON(http.StatusServiceUnavailable, ready)
			return
		}
		s.start(c, "", s.backup)
	})
	admin.POST("/backups/:id/restore", func(c *gin.Context) {
		id := c.Param("id")
		if !taskID.MatchString(id) {
			c.JSON(http.StatusBadRequest, gin.H{"code": "invalid_backup_id"})
			return
		}
		if missing := s.restoreSettings(); len(missing) != 0 {
			c.JSON(http.StatusServiceUnavailable, Readiness{RestoreMissing: missing})
			return
		}
		s.start(c, id, s.restore)
	})
}

func (s *Service) start(c *gin.Context, backupID string, run func(context.Context, *Task) error) {
	s.mu.Lock()
	if s.task != nil && s.task.Status == "running" {
		s.mu.Unlock()
		c.JSON(http.StatusConflict, gin.H{"code": "trial_task_running"})
		return
	}
	task := Task{ID: newID(), BackupID: backupID, Status: "running", Stage: "prepare"}
	s.publishLocked(task)
	s.mu.Unlock()
	go func(task Task) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := run(ctx, &task); err != nil {
			task.Status, task.Error = "failed", category(err)
		} else {
			task.Status, task.Stage = "succeeded", "done"
		}
		s.publish(task)
	}(task)
	c.JSON(http.StatusAccepted, task)
}

func (s *Service) publish(task Task) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.publishLocked(task)
}

func (s *Service) publishLocked(task Task) {
	task.Counts = maps.Clone(task.Counts)
	s.task = &task
}

func counts(snapshot domain.Snapshot) map[string]int {
	out := make(map[string]int, len(snapshot.Tables))
	for _, t := range snapshot.Tables {
		out[t.Name] = len(t.Rows)
	}
	return out
}

func (s *Service) backup(ctx context.Context, task *Task) error {
	source, database, err := s.database("SOURCE")
	if err != nil {
		return err
	}
	defer source.Close()
	key, err := s.key()
	if err != nil {
		return err
	}
	defer clear(key)
	store, err := s.storage()
	if err != nil {
		return err
	}
	defer store.close()

	task.Stage = "capture"
	s.publish(*task)
	uuid := s.value("SOURCE_UUID")
	snapshot, err := domain.CaptureTrial(ctx, source, limits, database, uuid)
	if err != nil {
		return err
	}
	digest, err := domain.Digest(snapshot)
	if err != nil {
		return err
	}
	m := manifest{SourceUUID: uuid, SHA256: digest, Counts: counts(snapshot)}
	task.Stage = "encrypt"
	s.publish(*task)
	b := binding(task.ID)
	derived := taskKey(key, task.ID)
	defer clear(derived)
	receipt, err := staging.SealFile(ctx, store.writer, b.Path, derived, b, func(w io.Writer) error {
		if err := json.NewEncoder(w).Encode(m); err != nil {
			return err
		}
		return domain.Encode(w, snapshot)
	})
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = removeOwned(store.writer, receipt.Name)
		}
	}()
	task.Stage = "readback"
	s.publish(*task)
	a := artifact{Receipt: receipt}
	_, verified, err := store.snapshot(ctx, task.ID, a, key)
	if err != nil {
		return err
	}
	if verified.SHA256 != m.SHA256 || verified.SourceUUID != uuid {
		return errReadback
	}
	if _, err := staging.WriteUnpublishedFile(ctx, store.writer, task.ID+".receipt", func(w io.Writer) error {
		return json.NewEncoder(w).Encode(a)
	}); err != nil {
		return err
	}
	complete = true
	task.BackupID, task.Counts, task.Readback = task.ID, m.Counts, true
	return nil
}

func (s *Service) restore(ctx context.Context, task *Task) error {
	key, err := s.key()
	if err != nil {
		return err
	}
	defer clear(key)
	store, err := s.storage()
	if err != nil {
		return err
	}
	defer store.close()
	task.Stage = "readback"
	s.publish(*task)
	a, err := store.metadata(task.BackupID)
	if err != nil {
		return err
	}
	source, m, err := store.snapshot(ctx, task.BackupID, a, key)
	if err != nil {
		return err
	}
	task.Counts, task.Readback = m.Counts, true
	task.Stage = "restore"
	s.publish(*task)
	if len(s.restoreSettings()) != 0 || s.value("RESTORE_UUID") == m.SourceUUID {
		return domain.ErrIsolation
	}
	db, database, err := s.database("RESTORE")
	if err != nil {
		return err
	}
	defer db.Close()
	reader, readDatabase, err := s.database("RESTORE_READ")
	if err != nil {
		return err
	}
	defer reader.Close()
	if database != readDatabase {
		return domain.ErrIsolation
	}
	target := domain.DrillTarget{Database: database, ServerUUID: s.value("RESTORE_UUID"), CheckIsolation: func(ctx context.Context) error {
		if ctx.Err() != nil || s.value("RESTORE_ISOLATED") != "true" {
			return domain.ErrIsolation
		}
		return nil
	}}
	if err := domain.CheckTrialTargetReader(ctx, reader, target); err != nil {
		return err
	}
	plan, err := domain.RestoreTrial(ctx, db, target, source, domain.Placement{
		Namespace:    s.value("RESTORE_NAMESPACE"),
		StorageClass: s.value("RESTORE_STORAGE_CLASS"),
	})
	if err != nil {
		return err
	}
	db.Close()
	task.Stage = "verify"
	s.publish(*task)
	return domain.VerifyDrill(ctx, reader, target, plan)
}
