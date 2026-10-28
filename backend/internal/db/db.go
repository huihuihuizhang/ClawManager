package db

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"clawreef/internal/backupgate"
	"clawreef/internal/config"
	mysqldriver "github.com/go-sql-driver/mysql"
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
	var migrationErr error
	if SQLGateScope() != "" {
		migrationErr = verifyEmbeddedMigrationsApplied(session)
	} else {
		migrationErr = applyEmbeddedMigrations(session)
	}
	if err := migrationErr; err != nil {
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

// OpenSystemBackupRead owns an independent UTC pool; business startup and SQL
// fencing are identical to the normal connection path. No migrations or globals.
func OpenSystemBackupRead(cfg config.DatabaseConfig) (db.Session, error) {
	return connectWithOptions(cfg, systemBackupReadOptions())
}
func systemBackupReadOptions() map[string]string {
	return map[string]string{"loc": "UTC", "time_zone": "'+00:00'"}
}

func connect(cfg config.DatabaseConfig) (db.Session, error) { return connectWithOptions(cfg, nil) }

func connectWithOptions(cfg config.DatabaseConfig, extra map[string]string) (db.Session, error) {
	return connectWithGateOptions(cfg, extra, SQLGateScope())
}

// An explicit metadata-only controller connection is admitted separately below.
// Every ordinary business/read/operate entry retains SQLGateScope fencing.
func connectWithGateOptions(cfg config.DatabaseConfig, extra map[string]string, gateScope string) (db.Session, error) {

	// P0 restored databases are data-only drill targets. Every official business
	// process uses this connection path; none may start consumers, retry Owner
	// operations, reconcile upgrades, seed data or migrate a restored copy.
	if regexp.MustCompile(`^cm_(restore|import)_[a-f0-9]{32}$`).MatchString(cfg.Database) {
		return nil, fmt.Errorf("isolated restore databases cannot run business services")
	}
	options := map[string]string{"charset": "utf8mb4", "collation": "utf8mb4_unicode_ci", "parseTime": "true"}
	for key, value := range extra {
		options[key] = value
	}
	hostPort := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	settings := mysql.ConnectionURL{
		Host:     hostPort,
		User:     cfg.User,
		Password: cfg.Password,
		Database: cfg.Database,
		Options:  options,
	}

	var session db.Session
	var err error
	if scope := gateScope; scope != "" {
		driverConfig, e := mysqldriver.ParseDSN(settings.String())
		if e != nil {
			return nil, fmt.Errorf("invalid gated database configuration")
		}
		driverConfig.MultiStatements = false
		connector, e := mysqldriver.NewConnector(driverConfig)
		if e != nil {
			return nil, e
		}
		pool, e := backupgate.Open(connector, scope)
		if e != nil {
			return nil, e
		}
		session, err = mysql.New(pool)
		if err != nil {
			pool.Close()
		}
	} else {
		session, err = mysql.Open(settings)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	if pool, ok := session.Driver().(*sql.DB); ok {
		checkCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := checkBackupControlSchema(checkCtx, pool)
		cancel()
		if err != nil {
			session.Close()
			return nil, err
		}
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

// SQLGateScope is opt-in until the full writer registry and Runtime protocols
// are deployed. Enabling it never certifies non-SQL writers as drained.
func SQLGateScope() string { return strings.TrimSpace(os.Getenv("SYSTEM_BACKUP_SQL_GATE_SCOPE")) }

func verifyEmbeddedMigrationsApplied(session db.Session) error {
	pool, ok := session.Driver().(*sql.DB)
	if !ok {
		return fmt.Errorf("SQL schema verifier unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rows, e := pool.QueryContext(ctx, "SELECT filename FROM schema_migrations")
	if e != nil {
		return e
	}
	applied := map[string]bool{}
	for rows.Next() {
		var name string
		if e = rows.Scan(&name); e != nil {
			rows.Close()
			return e
		}
		applied[name] = true
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	entries, e := embeddedMigrations.ReadDir("migrations")
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") && !applied[entry.Name()] {
			return fmt.Errorf("gated application requires offline migration: %s", entry.Name())
		}
	}
	return nil
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
