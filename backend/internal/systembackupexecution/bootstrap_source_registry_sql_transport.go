package systembackupexecution

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"io"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
	"github.com/go-sql-driver/mysql"
)

type bootstrapSourceSQLLogger struct{}

func (bootstrapSourceSQLLogger) Print(...any) {}

// Only the actual native driver is constructed here. Neither DB/connector nor
// SQL callbacks can be injected by deployment data or a source observation DTO.
func openBootstrapSourceSQL(ctx context.Context, access bootstrapSourceReadAccess, binding install.BootstrapSourceConnection) (*sql.DB, *atomic.Bool, error) {
	if binding.Purpose != "source_sql" {
		return nil, nil, install.ErrInstall
	}
	return openBootstrapSelectedSQL(ctx, access, binding, "")
}

func openBootstrapControlSQL(ctx context.Context, access bootstrapSourceReadAccess, binding install.BootstrapSourceConnection, applicationScope string) (*sql.DB, *atomic.Bool, error) {
	if binding.Purpose != "control_sql" || applicationScope == "" {
		return nil, nil, install.ErrInstall
	}
	return openBootstrapSelectedSQL(ctx, access, binding, applicationScope)
}

func openBootstrapSelectedSQL(ctx context.Context, access bootstrapSourceReadAccess, binding install.BootstrapSourceConnection, applicationScope string) (*sql.DB, *atomic.Bool, error) {
	if access == nil || access.Check(ctx) != nil {
		return nil, nil, install.ErrInstall
	}
	u, err := url.Parse(binding.Endpoint)
	if err != nil || u.Scheme != "mysql+tls" || u.Hostname() == "" {
		return nil, nil, install.ErrInstall
	}
	raw, err := access.Read(ctx, binding.Credential)
	if err != nil {
		return nil, nil, install.ErrInstall
	}
	parsed, err := mysql.ParseDSN(strings.TrimSpace(string(raw)))
	clear(raw)
	if err != nil || parsed.Net != "tcp" || parsed.Addr != u.Host || parsed.DBName != binding.Database || parsed.User == "" || strings.EqualFold(parsed.User, "root") || !strings.HasPrefix(binding.Account, parsed.User+"@") || parsed.MultiStatements || parsed.AllowAllFiles || parsed.AllowCleartextPasswords || parsed.AllowFallbackToPlaintext {
		return nil, nil, install.ErrInstall
	}
	ca, err := access.Read(ctx, binding.CA)
	if err != nil {
		return nil, nil, install.ErrInstall
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, nil, install.ErrInstall
	}
	verified := &atomic.Bool{}
	// Copy ONLY the selected username/password. DSN flags, arbitrary params,
	// plugins and TLS profiles never replace this fixed read-only native client.
	cfg := mysql.NewConfig()
	cfg.Net, cfg.Addr, cfg.DBName, cfg.User, cfg.Passwd = "tcp", u.Host, binding.Database, parsed.User, parsed.Passwd
	cfg.ParseTime, cfg.Loc = true, time.UTC
	// Use the driver's fixed default utf8mb4 escaping for bound parameters.
	// Otherwise mysql returns ErrSkip for parameterized QueryContext and would
	// fall back to the deliberately unavailable arbitrary Prepare interface.
	// No DSN charset/collation/params or interpolation option is inherited.
	cfg.InterpolateParams = true
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 10*time.Second, 10*time.Second
	cfg.Logger = bootstrapSourceSQLLogger{}
	cfg.TLS = &tls.Config{RootCAs: roots, ServerName: u.Hostname(), MinVersion: tls.VersionTLS13, VerifyConnection: func(state tls.ConnectionState) error {
		if state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return install.ErrInstall
		}
		verified.Store(true)
		return nil
	}}
	native, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, nil, install.ErrInstall
	}
	db := sql.OpenDB(bootstrapSourceSQLConnector{native: native, access: access, ctx: ctx, purpose: binding.Purpose, scope: applicationScope, verified: verified})
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	return db, verified, nil
}

// Guard every real query boundary, including the queries inside unchanged
// domain helpers taking *sql.Tx. Rows retain the same physical deadline and
// require a successful complete EOF/Close; this is not a synthetic SQL model.
type bootstrapSourceSQLConnector struct {
	native         driver.Connector
	access         bootstrapSourceReadAccess
	ctx            context.Context
	purpose, scope string
	verified       *atomic.Bool
}
type bootstrapSourceSQLDriver struct{}

func (bootstrapSourceSQLDriver) Open(string) (driver.Conn, error) { return nil, install.ErrInstall }
func (c bootstrapSourceSQLConnector) Driver() driver.Driver       { return bootstrapSourceSQLDriver{} }
func (c bootstrapSourceSQLConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if c.access.Check(c.ctx) != nil {
		return nil, install.ErrInstall
	}
	c.verified.Store(false)
	conn, err := c.native.Connect(ctx)
	if err != nil {
		return nil, install.ErrInstall
	}
	if c.access.Check(c.ctx) != nil {
		conn.Close()
		return nil, install.ErrInstall
	}
	return &bootstrapSourceSQLConn{Conn: conn, access: c.access, ctx: c.ctx, purpose: c.purpose, scope: c.scope}, nil
}

type bootstrapSourceSQLConn struct {
	driver.Conn
	access         bootstrapSourceReadAccess
	ctx            context.Context
	purpose, scope string
}

func (*bootstrapSourceSQLConn) Prepare(string) (driver.Stmt, error) { return nil, install.ErrInstall }
func (*bootstrapSourceSQLConn) Begin() (driver.Tx, error)           { return nil, install.ErrInstall }
func (*bootstrapSourceSQLConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return nil, install.ErrInstall
}
func (c *bootstrapSourceSQLConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	if !options.ReadOnly || options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || c.access.Check(c.ctx) != nil {
		return nil, install.ErrInstall
	}
	native, ok := c.Conn.(driver.ConnBeginTx)
	if !ok {
		return nil, install.ErrInstall
	}
	tx, err := native.BeginTx(ctx, options)
	if err != nil {
		return nil, install.ErrInstall
	}
	if c.access.Check(c.ctx) != nil {
		tx.Rollback()
		return nil, install.ErrInstall
	}
	return tx, nil
}
func (c *bootstrapSourceSQLConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if (!strings.HasPrefix(query, "SELECT ") && !strings.HasPrefix(query, "SHOW GRANTS") && !strings.HasPrefix(query, "CALL ")) || c.access.Check(c.ctx) != nil {
		return nil, install.ErrInstall
	}
	if c.purpose == "control_sql" {
		switch query {
		case "SELECT CURRENT_USER(),CURRENT_ROLE(),DATABASE(),@@server_uuid,UTC_TIMESTAMP(6)", "SHOW GRANTS FOR CURRENT_USER":
			if len(args) != 0 {
				return nil, install.ErrInstall
			}
		case "SELECT participant_id FROM system_backup_participants WHERE scope=? ORDER BY participant_id":
			if len(args) != 1 || args[0].Value != c.scope {
				return nil, install.ErrInstall
			}
		default:
			return nil, install.ErrInstall
		}
	}
	native, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, install.ErrInstall
	}
	rows, err := native.QueryContext(ctx, query, args)
	if err != nil {
		return nil, install.ErrInstall
	}
	if c.access.Check(c.ctx) != nil {
		rows.Close()
		return nil, install.ErrInstall
	}
	return &bootstrapSourceSQLRows{Rows: rows, access: c.access, ctx: c.ctx}, nil
}

type bootstrapSourceSQLRows struct {
	driver.Rows
	access bootstrapSourceReadAccess
	ctx    context.Context
}

func (r *bootstrapSourceSQLRows) Next(dest []driver.Value) error {
	err := r.Rows.Next(dest)
	if err == io.EOF && r.access.Check(r.ctx) != nil {
		return install.ErrInstall
	}
	return err
}
func (r *bootstrapSourceSQLRows) Close() error {
	err := r.Rows.Close()
	if err != nil || r.access.Check(r.ctx) != nil {
		return install.ErrInstall
	}
	return nil
}
func (r *bootstrapSourceSQLRows) HasNextResultSet() bool {
	native, ok := r.Rows.(driver.RowsNextResultSet)
	return ok && native.HasNextResultSet()
}
func (r *bootstrapSourceSQLRows) NextResultSet() error {
	if r.access.Check(r.ctx) != nil {
		return install.ErrInstall
	}
	native, ok := r.Rows.(driver.RowsNextResultSet)
	if !ok {
		return io.EOF
	}
	return native.NextResultSet()
}
