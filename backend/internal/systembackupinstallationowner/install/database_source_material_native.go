package install

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/worker"
	"github.com/go-sql-driver/mysql"
)

type silentDatabaseSourceLogger struct{}

func (silentDatabaseSourceLogger) Print(...any) {}

func databaseSourceConnector(r worker.Request, credential worker.DatabaseCredential, verified *atomic.Bool) (*mysql.Config, error) {
	if r.Database == nil || r.Database.SourceScope != domain.BusinessTableSourceScope || r.Database.SchemaCensus == nil || r.Database.SchemaCensus.Validate() != nil || credential.Username == "" || credential.Username == "root" || len(credential.Password) == 0 || verified == nil {
		return nil, ErrInstall
	}
	pool := x509.NewCertPool()
	if len(r.Database.RootCA) == 0 || len(r.Database.RootCA) > 65536 || !pool.AppendCertsFromPEM(r.Database.RootCA) || r.Database.TLSServerName == "" {
		return nil, ErrInstall
	}
	cfg := mysql.NewConfig()
	cfg.Net, cfg.Addr, cfg.DBName, cfg.User, cfg.Passwd = "tcp", r.Database.Address, r.Database.Name, credential.Username, string(credential.Password)
	cfg.TLS = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: r.Database.TLSServerName, VerifyConnection: func(state tls.ConnectionState) error {
		if state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return ErrInstall
		}
		verified.Store(true)
		return nil
	}}
	cfg.ParseTime, cfg.Loc = true, time.UTC
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 10*time.Second, 10*time.Second
	cfg.Logger = silentDatabaseSourceLogger{}
	return cfg, nil
}

// This function always opens the actual driver/native source itself. A test
// adapter, sampled receipt, input boolean or caller database cannot authorize
// signing. It runs before signing and before owner-prefix locks are reacquired.
func observeDatabaseSource(ctx context.Context, d DatabaseSourceIssueDefinition, r worker.Request, credential worker.DatabaseCredential, notBefore, until time.Time) (time.Time, error) {
	var verified atomic.Bool
	cfg, err := databaseSourceConnector(r, credential, &verified)
	if err != nil {
		return time.Time{}, ErrInstall
	}
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return time.Time{}, ErrInstall
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	conn, err := db.Conn(ctx)
	if err != nil {
		return time.Time{}, ErrInstall
	}
	defer conn.Close()
	previous := time.Time{}
	identity := func() error {
		var account, role, database, uuid string
		var now time.Time
		if conn.QueryRowContext(ctx, "SELECT CURRENT_USER(),CURRENT_ROLE(),DATABASE(),@@server_uuid,UTC_TIMESTAMP(6)").Scan(&account, &role, &database, &uuid, &now) != nil || !verified.Load() || account != d.Account || role != "NONE" || database != r.Database.Name || uuid != r.Database.ServerUUID || now.IsZero() || now.Before(previous) || now.Before(notBefore) || !now.Before(until) {
			return ErrInstall
		}
		previous = now
		return nil
	}
	grants := func() error {
		rows, err := conn.QueryContext(ctx, "SHOW GRANTS FOR CURRENT_USER")
		if err != nil {
			return ErrInstall
		}
		var actual []string
		for rows.Next() {
			var grant string
			if rows.Scan(&grant) != nil || len(actual) >= 1000 || len(grant) > 16384 {
				rows.Close()
				return ErrInstall
			}
			actual = append(actual, grant)
		}
		if rows.Err() != nil {
			rows.Close()
			return ErrInstall
		}
		if rows.Close() != nil || domain.ValidateBusinessSourceGrants(r.Database.Name, actual) != nil {
			return ErrInstall
		}
		return nil
	}
	if identity() != nil || grants() != nil || domain.CheckBusinessSchemaCensus(ctx, conn, *r.Database.SchemaCensus) != nil || grants() != nil || identity() != nil || ctx.Err() != nil {
		return time.Time{}, ErrInstall
	}
	// This short tail bound is independent from the immutable delegation window.
	// It cannot extend source credentials, original enrollment or owner authority.
	return time.Now().Add(15 * time.Second), nil
}

func writeDatabaseSourceGrant(file string, raw []byte) error {
	if !filepath.IsAbs(file) || filepath.Clean(file) != file {
		return ErrInstall
	}
	directory, err := os.Lstat(filepath.Dir(file))
	if err != nil || !directory.IsDir() || directory.Mode()&os.ModeSymlink != 0 || directory.Mode().Perm()&0077 != 0 {
		return ErrInstall
	}
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		actual, e := ReadSourceMaterialFile(file)
		if e == nil && string(actual) == string(raw) {
			return nil
		}
		return ErrInstall
	}
	if err != nil {
		return ErrInstall
	}
	n, writeErr := f.Write(raw)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil || n != len(raw) {
		return ErrInstall
	}
	return nil
}
