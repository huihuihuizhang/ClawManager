package systembackup

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"clawreef/internal/mysqltls"
	"github.com/go-sql-driver/mysql"
)

// OpenControlDatabase resolves an offline-mounted credential. This pool must
// be separate from the gated application pool so cancellation and gate release
// remain possible during maintenance. It never applies schema migrations.
func OpenControlDatabase(ctx context.Context, path string) (*sql.DB, error) {
	return OpenControlDatabaseWithTLS(ctx, path, mysqltls.Material{})
}

// OpenControlDatabaseWithTLS preserves the independent control credential and
// pool while binding transport to administrator-selected CA and server identity.
func OpenControlDatabaseWithTLS(ctx context.Context, path string, material mysqltls.Material) (*sql.DB, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, errors.New("control credential unavailable")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > 16384 {
		return nil, errors.New("control credential invalid")
	}
	raw, e := io.ReadAll(io.LimitReader(f, 16385))
	if e != nil || len(raw) > 16384 {
		return nil, errors.New("control credential invalid")
	}
	defer clear(raw)
	c, e := mysql.ParseDSN(strings.TrimSpace(string(raw)))
	if e != nil || c.DBName == "" || c.MultiStatements || c.AllowAllFiles {
		return nil, errors.New("control database configuration invalid")
	}
	c.ParseTime = true
	c.Timeout = 5 * time.Second
	c.ReadTimeout = 10 * time.Second
	c.WriteTimeout = 10 * time.Second
	if e = material.Apply(c); e != nil {
		return nil, errors.New("control database TLS configuration invalid")
	}
	connector, e := mysql.NewConnector(c)
	if e != nil {
		return nil, errors.New("control database unavailable")
	}
	pool := sql.OpenDB(connector)
	pool.SetMaxOpenConns(4)
	pool.SetMaxIdleConns(2)
	if e = pool.PingContext(ctx); e != nil {
		pool.Close()
		return nil, errors.New("control database unavailable")
	}
	return pool, nil
}
