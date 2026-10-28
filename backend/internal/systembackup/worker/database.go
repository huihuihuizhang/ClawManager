package worker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/staging"
	"github.com/go-sql-driver/mysql"
)

// DatabaseSpec is public task configuration, not a DSN. RootCA is public PEM.
// Credentials only arrive in an acquire grant; source and drill identities,
// placement and policy are bound to the complete invocation hash.
type DatabaseSpec struct {
	Address         string                         `json:"address"`
	Name            string                         `json:"name"`
	ServerUUID      string                         `json:"server_uuid"`
	TLSServerName   string                         `json:"tls_server_name"`
	RootCA          []byte                         `json:"root_ca"`
	MaxRows         int64                          `json:"max_rows"`
	MaxMemoryBytes  int64                          `json:"max_memory_bytes"`
	Placements      map[string]domain.Placement    `json:"placements,omitempty"`
	Configs         domain.JSONRegistry            `json:"configs,omitempty"`
	WorkBuddy       *domain.WorkBuddySchema        `json:"workbuddy,omitempty"`
	Dependencies    map[string]domain.TableAdapter `json:"dependencies,omitempty"`
	TeamPlacements  map[string]domain.Placement    `json:"team_placements,omitempty"`
	EvidenceName    string                         `json:"evidence_name,omitempty"`
	EvidenceBinding staging.Binding                `json:"evidence_binding"`
}
type DatabaseCredential struct {
	Username string `json:"username"`
	Password []byte `json:"password"`
}
type DatabaseEnvironment struct {
	Database *sql.DB
	Staging  *os.Root
	Evidence *os.Root // separate writable encrypted output; input staging stays readonly
	Key      []byte
	Check    func(context.Context, string, Request) error
}

var databaseName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func databaseOperation(op string) bool {
	return op == "capture-database" || op == "restore-database" || op == "verify-database"
}
func validDatabaseSpec(d *DatabaseSpec) bool {
	if d == nil || !databaseName.MatchString(d.Name) || d.ServerUUID == "" || len(d.ServerUUID) > 128 || len(d.RootCA) == 0 || len(d.RootCA) > 32<<10 || d.TLSServerName == "" || strings.ContainsAny(d.Address+d.TLSServerName, "\x00\r\n/\\@? ") {
		return false
	}
	host, port, err := net.SplitHostPort(d.Address)
	n, portErr := strconv.Atoi(port)
	return err == nil && host != "" && portErr == nil && n > 0 && n <= 65535
}
func validDatabaseRequest(r Request) bool {
	if r.RuntimePolicy != nil || r.WorkBuddyIdentity != nil {
		return false
	}
	d := r.Database
	if r.Version != Version || !databaseOperation(r.Operation) || !time.Now().Before(r.Deadline) || !validDatabaseSpec(d) || d.MaxRows <= 0 || d.MaxRows > 100_000 || d.MaxMemoryBytes <= 0 || d.MaxMemoryBytes > 32<<20 || r.MaxArchiveBytes <= 0 || r.MaxArchiveBytes > 32<<20 || r.MaxCompressedBytes <= 0 || r.MaxCompressedBytes > 32<<20 || r.MaxFiles != 0 || r.MaxFileBytes != 0 || len(r.Files) != 0 {
		return false
	}
	if r.Operation == "capture-database" {
		return r.ArtifactName != "" && r.PolicyVersion == "" && len(d.Placements) == 0 && len(d.TeamPlacements) == 0 && len(d.Configs) == 0 && d.EvidenceName == ""
	}
	if !strings.HasPrefix(d.Name, "cm_drill_") {
		return false
	}
	if r.Operation == "restore-database" {
		return r.PolicyVersion != "" && d.EvidenceName != "" && d.EvidenceBinding != r.Binding
	}
	return r.PolicyVersion != "" && len(d.Placements) == 0 && len(d.TeamPlacements) == 0 && len(d.Configs) == 0 && d.EvidenceName == ""
}

// OpenDatabase never parses an arbitrary DSN, runs schema migrations, enables
// multi-statements/LOCAL INFILE or falls back to plaintext. sql.OpenDB is lazy;
// RunDatabase authenticates restore input before the first target query.
func OpenDatabase(d *DatabaseSpec, credential *DatabaseCredential) (*sql.DB, error) {
	cfg, err := databaseConfig(d, credential)
	if err != nil {
		return nil, err
	}
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, ErrRequest
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Minute)
	return db, nil
}

type silentDatabaseLogger struct{}

func (silentDatabaseLogger) Print(...any) {} // driver failures must not log server/credential payloads
func databaseConfig(d *DatabaseSpec, c *DatabaseCredential) (*mysql.Config, error) {
	if !validDatabaseSpec(d) || c == nil || c.Username == "" || len(c.Username) > 128 || len(c.Password) == 0 || len(c.Password) > 4096 || strings.ContainsAny(c.Username, "\x00\r\n") {
		return nil, ErrRequest
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(d.RootCA) {
		return nil, ErrRequest
	}
	cfg := mysql.NewConfig()
	cfg.Net = "tcp"
	cfg.Addr = d.Address
	cfg.DBName = d.Name
	cfg.User = c.Username
	cfg.Passwd = string(c.Password)
	cfg.TLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: d.TLSServerName}
	cfg.ParseTime = false
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 30 * time.Second
	cfg.WriteTimeout = 30 * time.Second
	cfg.MaxAllowedPacket = 8 << 20
	cfg.Logger = silentDatabaseLogger{}
	return cfg, nil
}

// RunDatabase emits only encrypted receipts/counts. It neither publishes drill
// data nor starts agents. Verification uses a separately authorized SELECT-only
// session and the EXACT encrypted plan sealed by the restore before commit.
func RunDatabase(ctx context.Context, r Request, env DatabaseEnvironment) (Result, error) {
	if !validDatabaseRequest(r) || env.Database == nil || env.Staging == nil || len(env.Key) != 32 {
		return Result{}, ErrRequest
	}
	if env.Check == nil {
		return Result{}, ErrNotReady
	}
	if r.Operation == "restore-database" && (env.Evidence == nil || !separateRoots(env.Staging, env.Evidence)) {
		return Result{}, ErrRequest
	}
	ctx, cancel := context.WithDeadline(ctx, r.Deadline)
	defer cancel()
	check := func(point string) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if env.Check(ctx, point, r) != nil {
			return ErrNotReady
		}
		return ctx.Err()
	}
	if err := check("prepare"); err != nil {
		return Result{}, err
	}
	key := append([]byte(nil), env.Key...)
	defer clear(key)
	d := r.Database
	seal := func(root *os.Root, name string, binding staging.Binding, s domain.Snapshot) (staging.Receipt, error) {
		return staging.SealFile(ctx, root, name, key, binding, func(dst io.Writer) error {
			compressed := &budgetWriter{w: dst, left: r.MaxCompressedBytes}
			return staging.Compress(compressed, func(plain io.Writer) error { return domain.Encode(&budgetWriter{w: plain, left: r.MaxArchiveBytes}, s) })
		})
	}
	if r.Operation == "capture-database" {
		if err := check("before-capture"); err != nil {
			return Result{}, err
		}
		s, err := domain.CaptureSource(ctx, env.Database, domain.Limits{MaxRows: d.MaxRows, MaxBytes: d.MaxMemoryBytes}, d.Name, d.ServerUUID)
		if err != nil {
			return Result{}, ErrExecution
		}
		defer clearSnapshot(s)
		if err = check("before-seal"); err != nil {
			return Result{}, err
		}
		receipt, err := seal(env.Staging, r.ArtifactName, r.Binding, s)
		if err != nil {
			return Result{}, ErrExecution
		}
		if err = check("sealed"); err != nil {
			return Result{}, err
		}
		result := snapshotCounts(s)
		result.Receipt = receipt
		return result, nil
	}
	file, err := staging.OpenFile(ctx, env.Staging, r.Receipt)
	if err != nil {
		return Result{}, ErrExecution
	}
	defer file.Close()
	var source domain.Snapshot
	// Decode is inert in memory. No target queries or writes until the terminal
	// GCM frame, gzip checksum and all payload limits have been verified.
	err = staging.ConsumeCompressed(ctx, file, key, r.Binding, r.MaxCompressedBytes, r.MaxArchiveBytes, func(src io.Reader) error {
		var e error
		source, e = domain.Decode(src, domain.Limits{MaxRows: d.MaxRows, MaxBytes: r.MaxArchiveBytes})
		return e
	})
	defer clearSnapshot(source)
	if err != nil || !snapshotFitsMemory(source, d.MaxMemoryBytes) {
		return Result{}, ErrExecution
	}
	target := domain.DrillTarget{Database: d.Name, ServerUUID: d.ServerUUID, CheckIsolation: func(context.Context) error { return check("database-isolation") }}
	if r.Operation == "verify-database" {
		if err = check("before-verify"); err != nil {
			return Result{}, err
		}
		if err = domain.VerifyDrill(ctx, env.Database, target, domain.RestorePlan{Data: source}); err != nil {
			return Result{}, ErrExecution
		}
		if err = check("verified-quarantine"); err != nil {
			return Result{}, err
		}
		result := snapshotCounts(source)
		result.Receipt = r.Receipt
		result.Quarantined = true
		result.Verified = true
		return result, nil
	}
	if err = check("before-restore"); err != nil {
		return Result{}, err
	}
	var evidence staging.Receipt
	var normalized domain.Snapshot
	defer func() { clearSnapshot(normalized) }()
	plan, err := domain.RestoreDrillWithEvidence(ctx, env.Database, target, source, domain.Policy{Placements: d.Placements, Configs: d.Configs, WorkBuddy: d.WorkBuddy, Dependencies: d.Dependencies, TeamPlacements: d.TeamPlacements}, func(ctx context.Context, p domain.RestorePlan) error {
		normalized = p.Data
		if e := check("before-evidence"); e != nil {
			return e
		}
		var e error
		evidence, e = seal(env.Evidence, d.EvidenceName, d.EvidenceBinding, p.Data)
		if e != nil {
			return ErrExecution
		}
		return check("before-database-commit")
	})
	if err != nil {
		return Result{}, ErrExecution
	}
	if err = check("restored-quarantine"); err != nil {
		return Result{}, err
	}
	result := snapshotCounts(plan.Data)
	result.Receipt = r.Receipt
	result.Evidence = evidence
	result.Quarantined = true
	return result, nil
}
func snapshotCounts(s domain.Snapshot) Result {
	r := Result{Tables: len(s.Tables)}
	for _, t := range s.Tables {
		r.Rows += int64(len(t.Rows))
	}
	return r
}
func snapshotFitsMemory(s domain.Snapshot, limit int64) bool {
	var size int64
	for _, t := range s.Tables {
		for _, row := range t.Rows {
			for name, cell := range row {
				size += int64(len(name) + len(cell.Bytes) + 128)
				if size > limit {
					return false
				}
			}
		}
	}
	return true
}
func clearSnapshot(s domain.Snapshot) {
	for _, t := range s.Tables {
		for _, row := range t.Rows {
			for _, cell := range row {
				clear(cell.Bytes)
			}
		}
	}
}
