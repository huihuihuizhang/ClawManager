package db

import (
	"fmt"
	"log"

	"clawreef/internal/config"
	"github.com/upper/db/v4"
	"github.com/upper/db/v4/adapter/mysql"
)

// Session holds the database session
var Session db.Session

// Initialize initializes the database connection
func Initialize(cfg config.DatabaseConfig) (db.Session, error) {
	session, err := connect(cfg)
	if err != nil {
		return nil, err
	}
	if err := applyEmbeddedMigrations(session); err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("failed to apply database migrations: %w", err)
	}

	Session = session
	log.Println("Database connected successfully")
	return session, nil
}

// Connect opens an application database session without applying migrations.
// It is used by the separately deployed northbound gateway so that the edge
// service can run with a least-privilege database account. Core must apply
// migrations before the gateway is started.
func Connect(cfg config.DatabaseConfig) (db.Session, error) {
	session, err := connect(cfg)
	if err != nil {
		return nil, err
	}
	Session = session
	log.Println("Database connected successfully (migrations disabled)")
	return session, nil
}

// ConnectSystemBackupController opens only the D-owned controller session.
// The MySQL driver applies time_zone on every newly opened pooled connection;
// a one-time SET after Open would configure only one connection.
func ConnectSystemBackupController(cfg config.DatabaseConfig) (db.Session, error) {
	session, err := connectWithOptions(cfg, systemBackupControllerOptions())
	if err != nil {
		return nil, err
	}
	Session = session
	log.Println("System backup controller database connected successfully (migrations disabled, UTC sessions)")
	return session, nil
}

func systemBackupControllerOptions() map[string]string {
	return map[string]string{
		"loc":       "UTC",
		"time_zone": "'+00:00'",
	}
}

func connect(cfg config.DatabaseConfig) (db.Session, error) {
	return connectWithOptions(cfg, nil)
}

func connectWithOptions(cfg config.DatabaseConfig, additionalOptions map[string]string) (db.Session, error) {
	hostPort := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	options := map[string]string{
		"charset":   "utf8mb4",
		"collation": "utf8mb4_unicode_ci",
		"parseTime": "true",
	}
	for key, value := range additionalOptions {
		options[key] = value
	}
	settings := mysql.ConnectionURL{
		Host:     hostPort,
		User:     cfg.User,
		Password: cfg.Password,
		Database: cfg.Database,
		Options:  options,
	}

	session, err := mysql.Open(settings)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	maxOpenConns := cfg.MaxOpenConns
	if maxOpenConns < 0 {
		maxOpenConns = 0
	}
	maxIdleConns := cfg.MaxIdleConns
	if maxIdleConns < 0 {
		maxIdleConns = 0
	}
	if maxOpenConns > 0 && maxIdleConns > maxOpenConns {
		maxIdleConns = maxOpenConns
	}
	session.SetMaxOpenConns(maxOpenConns)
	session.SetMaxIdleConns(maxIdleConns)
	session.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	session.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)
	if _, err := session.SQL().Exec("SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"); err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("failed to configure database connection charset: %w", err)
	}
	return session, nil
}

// Close closes the database connection
func Close() error {
	if Session != nil {
		return Session.Close()
	}
	return nil
}

// GetSession returns the current database session
func GetSession() db.Session {
	return Session
}
