package main

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"regexp"
	"sync"

	"clawreef/internal/systembackupinstallationowner/install"
	sec "clawreef/internal/systembackupsecurity"
	"github.com/gin-gonic/gin"
)

// One first initialization from the original owner-controlled, read-only input
// mount. There is no reload, request-supplied locator, new route or authority.
const backupMutationLatePin = "SYSTEM_BACKUP_CONFIG_MUTATION_COMPOSITION_SHA256_FILE"

func loadBackupConfigMutationStartup(db *sql.DB, database, secret string, getenv func(string) string) (*sec.ConfigMutationProduction, error) {
	if getenv != nil && getenv(backupMutationLatePin) != "" {
		if !validBackupMutationLateConfiguration(db, secret, getenv) {
			return nil, sec.ErrRegistrationUnavailable
		}
		return nil, nil // Existing login-session recorder starts before materials arrive.
	}
	return loadBackupConfigMutationProduction(db, database, secret, getenv)
}

func validBackupMutationLateConfiguration(db *sql.DB, secret string, getenv func(string) string) bool {
	if db == nil || getenv == nil || len(secret) < 32 || getenv("SYSTEM_BACKUP_CONFIG_MUTATION_ENABLED") != "true" || getenv("SYSTEM_BACKUP_READ_LIVE_ENABLED") != "true" || getenv("SYSTEM_BACKUP_READ_SESSIONS_ENABLED") != "true" || getenv("SYSTEM_BACKUP_CONFIG_MUTATION_COMPOSITION_SHA256") != "" {
		return false
	}
	document, pin := getenv("SYSTEM_BACKUP_CONFIG_MUTATION_COMPOSITION_FILE"), getenv(backupMutationLatePin)
	// Restrict this first-install mode to the existing original runtime directory.
	for _, path := range []string{document, pin} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) != "/run/system-backup/runtime" {
			return false
		}
	}
	return document != pin
}

type backupMutationFirstLoad struct {
	mu                              sync.Mutex
	production                      *sec.ConfigMutationProduction
	db                              *sql.DB
	database, secret, document, pin string
	getenv                          func(string) string
	closed                          bool
	load                            func(*sql.DB, string, string, func(string) string) (*sec.ConfigMutationProduction, error)
}

func newBackupMutationFirstLoad(db *sql.DB, database, secret string, getenv func(string) string) (*backupMutationFirstLoad, error) {
	if getenv == nil || getenv(backupMutationLatePin) == "" {
		return nil, nil
	}
	if !validBackupMutationLateConfiguration(db, secret, getenv) {
		return nil, sec.ErrRegistrationUnavailable
	}
	return &backupMutationFirstLoad{db: db, database: database, secret: secret, document: getenv("SYSTEM_BACKUP_CONFIG_MUTATION_COMPOSITION_FILE"), pin: getenv(backupMutationLatePin), getenv: getenv, load: loadBackupConfigMutationProduction}, nil
}

func (s *backupMutationFirstLoad) get() (*sec.ConfigMutationProduction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, sec.ErrRegistrationUnavailable
	}
	if s.production != nil {
		return s.production, nil
	}
	// Pin is published LAST by the existing installation-owner writer. A request
	// cannot choose it. ReadPrivateFile enforces the original private-file rules.
	raw, err := install.ReadPrivateFile(s.pin, 64)
	if err != nil || !regexp.MustCompile(`^[0-9a-f]{64}$`).Match(raw) {
		return nil, sec.ErrRegistrationUnavailable
	}
	expected := string(raw)
	environment := func(name string) string {
		switch name {
		case "SYSTEM_BACKUP_CONFIG_MUTATION_COMPOSITION_FILE":
			return s.document
		case "SYSTEM_BACKUP_CONFIG_MUTATION_COMPOSITION_SHA256":
			return expected
		default:
			return s.getenv(name)
		}
	}
	loader := s.load
	if loader == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	production, err := loader(s.db, s.database, s.secret, environment)
	if err != nil || production == nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	after, err := install.ReadPrivateFile(s.pin, 64)
	if err != nil || string(after) != expected {
		production.Close()
		return nil, sec.ErrRegistrationUnavailable
	}
	s.production = production
	return production, nil
}

func (s *backupMutationFirstLoad) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.production != nil {
		s.production.Close()
	}
	s.secret = ""
}

func registerBackupConfigMutationFirstLoad(admin *gin.RouterGroup, s *backupMutationFirstLoad) {
	if admin == nil || s == nil {
		return
	}
	handler := func(c *gin.Context) {
		production, err := s.get()
		if err != nil {
			c.Header("Cache-Control", "no-store")
			c.JSON(http.StatusServiceUnavailable, gin.H{"code": "not_ready"})
			return
		}
		// Reuse the original bounded handler and all original mutation checks.
		serveBackupConfigMutationLive(c, production)
	}
	admin.PUT("/system-backup-config", handler)
	admin.POST("/system-backup-config/rollback", handler)
}
