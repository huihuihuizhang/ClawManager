package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"clawreef/internal/systembackup/domain"
	k "clawreef/internal/systembackupkms"
	mysql "github.com/go-sql-driver/mysql"
)

// Real MySQL SELECT-only session/RR snapshot and real signed source-material
// revocation after the first table's EOF. The driver decorator only records
// actual reads and changes the local fixture file; it supplies no SQL results.
// This injects a local TCP DB into the collector, not a SQL TLS admission test.
func TestFormalSQLSourceRevocationStopsBeforeNextTableMySQL(t *testing.T) {
	file := os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS")
	if file == "" {
		t.Skip("requires disposable local MySQL")
	}
	var credentials struct {
		Host, User, Password string
		Port                 int
	}
	raw, err := os.ReadFile(file)
	if err != nil || json.Unmarshal(raw, &credentials) != nil || credentials.Host != "127.0.0.1" {
		t.Fatal("local MySQL fixture unavailable")
	}
	clear(raw)
	ctx := context.Background()
	config := mysql.NewConfig()
	config.Net = "tcp"
	config.Addr = credentials.Host + ":" + strconv.Itoa(credentials.Port)
	config.User = credentials.User
	config.Passwd = credentials.Password
	config.Timeout = 5 * time.Second
	root, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var entropy [8]byte
	rand.Read(entropy[:])
	id := hex.EncodeToString(entropy[:])
	database, user := "ad_d_source_"+id, "ad_d_src_"+id
	if _, err = root.Exec("CREATE DATABASE `" + database + "`"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := root.Exec("DROP DATABASE `" + database + "`"); err != nil {
			t.Error("owned source fixture cleanup failed")
		}
	}()
	config.DBName = database
	admin, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	for _, table := range []string{"users", "user_quotas", "instances"} {
		if _, err = admin.Exec("CREATE TABLE `" + table + "`(id INT PRIMARY KEY,payload TEXT) ENGINE=InnoDB"); err != nil {
			t.Fatal(err)
		}
		if _, err = admin.Exec("INSERT INTO `" + table + "` VALUES(1,'original private SQL value')"); err != nil {
			t.Fatal(err)
		}
	}
	var pass [24]byte
	rand.Read(pass[:])
	password := hex.EncodeToString(pass[:])
	clear(pass[:])
	if _, err = root.Exec("CREATE USER '" + user + "'@'127.0.0.1' IDENTIFIED BY '" + password + "'"); err != nil {
		t.Fatal("source user creation failed")
	}
	defer func() {
		if _, err := root.Exec("DROP USER '" + user + "'@'127.0.0.1'"); err != nil {
			t.Error("owned source account cleanup failed")
		}
	}()
	conn, err := root.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	grantDB, err := domain.QuotedGrantDatabase(ctx, conn, database)
	conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = root.Exec("GRANT SELECT ON " + grantDB + ".* TO '" + user + "'@'127.0.0.1'"); err != nil {
		t.Fatal(err)
	}
	var uuid string
	if admin.QueryRow("SELECT @@server_uuid").Scan(&uuid) != nil {
		t.Fatal("local source UUID unavailable")
	}
	i, env, keyUse := formalInvocationFixture(t)
	i.WorkspacePath = ""
	env.Workspace = nil
	i.Request.Operation = "capture-database"
	i.Request.MaxFiles, i.Request.MaxFileBytes = 0, 0
	i.Request.Files = nil
	i.Request.RuntimePolicy = nil
	databaseInvocation := databaseRequestFixture(t)
	i.Request.Database = databaseInvocation.Request.Database
	i.Request.Database.Name = database
	i.Request.Database.ServerUUID = uuid
	i.FormalCapture.SourceConfigSHA256 = strings.Repeat("c", 64)
	i.FormalCapture.PermitDelivery = &k.PermitDeliveryPin{Version: k.PermitDeliveryVersion, Issuer: bytes.Repeat([]byte{4}, 32), IssuerGrantSHA256: strings.Repeat("d", 64)}
	job := sourceControlJobFixture(t, i)
	dir := t.TempDir()
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(private)
	credentialRaw, _ := json.Marshal(formalSourceCredential{Username: user, Password: []byte(password)})
	mount := FormalSourceMount{GrantFile: filepath.Join(dir, "source.json"), CredentialFile: filepath.Join(dir, "credential.json"), CredentialSHA256: sourceDigest(credentialRaw), Issuer: pub}
	if os.WriteFile(mount.CredentialFile, credentialRaw, 0600) != nil {
		t.Fatal("source credential fixture failed")
	}
	clear(credentialRaw)
	scope, err := FormalSourceScopeSHA256(i, mount)
	if err != nil {
		t.Fatal(err)
	}
	grant := FormalSourceGrant{Version: FormalSourceGrantVersion, InstallationID: i.ProviderKey.Request.Context.InstallationID, ConfigSHA256: i.FormalCapture.SourceConfigSHA256, WorkerNamespace: "ns", WorkerServiceAccountUID: "sa", Operation: i.Request.Operation, ScopeSHA256: scope, CredentialSHA256: mount.CredentialSHA256, NotBefore: time.Now().Add(-time.Minute), Until: time.Now().Add(time.Minute)}
	grantRaw, _ := json.Marshal(grant)
	signedRaw, _ := json.Marshal(SignedFormalSourceGrant{Record: grantRaw, Signature: ed25519.Sign(private, append([]byte(FormalSourceGrantDomain), grantRaw...))})
	mount.GrantSHA256 = sourceDigest(signedRaw)
	if os.WriteFile(mount.GrantFile, signedRaw, 0600) != nil {
		t.Fatal("source grant fixture failed")
	}
	sourceUse := &FormalCaptureSources{invocation: i, invocationSHA: mustSourceInvocationHash(t, i), mount: mount, job: job, identity: job.original.Identity(), until: job.until}
	sourceUse.grant, err = sourceUse.readGrant(ctx)
	if err != nil {
		t.Fatal("actual original source signature rejected", err)
	}
	config.User, config.Passwd = user, password
	password = ""
	connector, err := mysql.NewConnector(config)
	if err != nil {
		t.Fatal(err)
	}
	trace := &sourceSQLTrace{afterFirstEOF: func() {
		if err := os.WriteFile(mount.GrantFile, append(signedRaw, ' '), 0600); err != nil {
			t.Error("source revocation fixture failed")
		}
	}}
	sourceDB := sql.OpenDB(sourceTraceConnector{Connector: connector, trace: trace})
	defer sourceDB.Close()
	sourceDB.SetMaxOpenConns(1)
	env.Database, env.SourceAuthorize, env.SourceValidUntil = sourceDB, sourceUse.Authorize, sourceUse.ValidUntil()
	result, err := runFormalCapture(ctx, i, keyUse, env)
	if err == nil || result.Ciphertext.Name != "" || result.Envelope.Name != "" {
		t.Fatal("revoked SQL source yielded candidate", err)
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	if len(trace.tables) != 1 || !trace.revoked {
		t.Fatal("subsequent table received SQL after source revocation", trace.tables, trace.revoked)
	}
	for _, name := range []string{i.Request.ArtifactName, i.FormalCapture.EnvelopeName, "." + i.Request.ArtifactName + ".partial", "." + i.FormalCapture.EnvelopeName + ".partial"} {
		if _, err := env.Staging.Lstat(name); !os.IsNotExist(err) {
			t.Fatal("revoked source retained candidate bytes", name, err)
		}
	}
}

func mustSourceInvocationHash(t *testing.T, i Invocation) string {
	t.Helper()
	hash, err := i.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

type sourceSQLTrace struct {
	mu            sync.Mutex
	tables        []string
	revoked       bool
	afterFirstEOF func()
}
type sourceTraceConnector struct {
	driver.Connector
	trace *sourceSQLTrace
}

func (c sourceTraceConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return sourceTraceConn{Conn: conn, trace: c.trace}, nil
}

type sourceTraceConn struct {
	driver.Conn
	trace *sourceSQLTrace
}

func (c sourceTraceConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, options)
}
func (c sourceTraceConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	rows, err := c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(query, "SELECT `") && strings.Contains(query, " FROM `") {
		c.trace.mu.Lock()
		c.trace.tables = append(c.trace.tables, strings.Split(strings.Split(query, " FROM `")[1], "`")[0])
		first := len(c.trace.tables) == 1
		c.trace.mu.Unlock()
		if first {
			return sourceTraceRows{Rows: rows, trace: c.trace}, nil
		}
	}
	return rows, nil
}

type sourceTraceRows struct {
	driver.Rows
	trace *sourceSQLTrace
}

func (r sourceTraceRows) Next(values []driver.Value) error {
	err := r.Rows.Next(values)
	if errors.Is(err, io.EOF) {
		r.trace.mu.Lock()
		if !r.trace.revoked {
			r.trace.revoked = true
			r.trace.afterFirstEOF()
		}
		r.trace.mu.Unlock()
	}
	return err
}
