package systembackupsecurity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
)

// Fault-injection tests are not evidence of real InnoDB concurrency or DDL.
type bootstrapTestState struct {
	grant                                                        OfflineBootstrapGrant
	pending, committed                                           []string
	stagedOp, op, stagedHash, hash                               string
	failWrite                                                    int
	wrongDB, inactive, denied, unresolved, exists, commitUnknown bool
	authorized, validated                                        int
	tx                                                           *sql.Tx
	canonical                                                    []byte
	config, savedConfig                                          map[string]driver.Value
	matrix, savedMatrix                                          string
	queries                                                      []string
	coreTables                                                   bool
	probeError                                                   error
	sqlNow                                                       time.Time
	afterInstallation                                            func()
}
type bootstrapConnector struct{ s *bootstrapTestState }

func (c bootstrapConnector) Driver() driver.Driver { return registrationTestDriver{} }
func (c bootstrapConnector) Connect(context.Context) (driver.Conn, error) {
	return &bootstrapConn{c.s}, nil
}

type bootstrapConn struct{ s *bootstrapTestState }

func (*bootstrapConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (*bootstrapConn) Close() error                        { return nil }
func (c *bootstrapConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{Isolation: driver.IsolationLevel(sql.LevelRepeatableRead)})
}
func (c *bootstrapConn) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	if o.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		return nil, errors.New("wrong isolation")
	}
	c.s.pending = nil
	c.s.stagedOp = ""
	c.s.stagedHash = ""
	c.s.savedMatrix = c.s.matrix
	c.s.savedConfig = make(map[string]driver.Value, len(c.s.config))
	for key, value := range c.s.config {
		c.s.savedConfig[key] = value
	}
	return &bootstrapTx{c.s}, nil
}
func (c *bootstrapConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	s := c.s
	s.queries = append(s.queries, q)
	switch {
	case strings.HasPrefix(q, "SELECT TABLE_NAME,TABLE_TYPE,ENGINE FROM information_schema.tables"):
		if s.coreTables {
			if len(args) != 9 || args[0].Value != s.grant.Database {
				return nil, errors.New("wrong closed schema scope")
			}
			var rows [][]driver.Value
			for _, arg := range args[1:] {
				rows = append(rows, []driver.Value{arg.Value, "BASE TABLE", "InnoDB"})
			}
			return &registrationTestRows{data: rows, width: 3}, nil
		}
		return &registrationTestRows{width: 3}, nil // Original non-C1 fixture.
	case strings.HasPrefix(q, "SELECT 1 FROM ") && strings.HasSuffix(q, " LIMIT 0"):
		if s.probeError != nil {
			return nil, s.probeError
		}
		return nil, &mysqldriver.MySQLError{Number: 1146}
	case strings.Contains(q, " WHERE scope_key = ? FOR UPDATE"):
		return &registrationTestRows{width: 1}, nil // Complete C1, no scoped domain.
	case strings.Contains(q, "SELECT @@server_uuid"):
		server := s.grant.ServerUUID
		if s.wrongDB {
			server = "other-server"
		}
		if q == "SELECT @@server_uuid,DATABASE()" {
			return registrationRow(server, s.grant.Database), nil
		}
		now := s.sqlNow
		if now.IsZero() {
			now = time.Now().UTC().Truncate(time.Microsecond)
		}
		return registrationRow(server, s.grant.Database, now, int64(0)), nil
	case q == bootstrapCandidateGlobalConfigSQL:
		if len(s.config) == 0 {
			return &registrationTestRows{width: 7}, nil
		}
		return registrationRow(int64(1), s.grant.InstallationID, s.config["version"], s.config["config_sha256"], s.config["enabled"], s.config["nonce_hmac_ref_version"], s.config["nonce_hmac_identity_hash"]), nil
	case strings.HasPrefix(q, "SELECT origin_installation_id,version,config_sha256,"):
		columns := strings.Split(strings.Split(strings.TrimPrefix(q, "SELECT "), " FROM ")[0], ",")
		values := make([]driver.Value, len(columns))
		for i, column := range columns {
			values[i] = s.config[column]
		}
		return registrationRow(values...), nil
	case strings.Contains(q, "SELECT origin_installation_id"):
		if s.afterInstallation != nil {
			s.afterInstallation()
		}
		return &registrationTestRows{width: 1}, nil
	case strings.Contains(q, "SELECT username,role"):
		return registrationRow(s.grant.Username, "admin", !s.inactive, "local"), nil
	case strings.Contains(q, "SELECT public_id,result_config_version"):
		if s.stagedOp != "" {
			return registrationRow(s.stagedOp, int64(1), s.stagedHash, "succeeded", int64(201)), nil
		}
		if s.op == "" {
			return &registrationTestRows{width: 5}, nil
		}
		return registrationRow(s.op, int64(1), s.hash, "succeeded", int64(201)), nil
	case strings.Contains(q, "SELECT c.config_sha256"):
		return registrationRow(s.grant.ConfigSHA256, int64(1), false, s.matrix), nil
	case strings.Contains(q, "SELECT active_config_version"), strings.Contains(q, "SELECT version FROM"):
		if s.exists || s.op != "" {
			return registrationRow(int64(1)), nil
		}
		return &registrationTestRows{width: 1}, nil
	}
	return nil, errors.New("unexpected query")
}
func (c *bootstrapConn) ExecContext(_ context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	s := c.s
	if s.failWrite == len(s.pending)+1 {
		return nil, errors.New("PRIVATE SQL error")
	}
	kind := ""
	switch {
	case q == "synthetic reserve":
		kind = "reservation"
	case strings.Contains(q, "INSERT INTO audit_logs"):
		kind = "audit"
	case strings.Contains(q, "INSERT INTO system_backup_v2_configs"):
		kind = "config"
		columns := strings.Split(strings.Split(strings.TrimPrefix(q, "INSERT INTO system_backup_v2_configs ("), ")")[0], ",")
		s.config = make(map[string]driver.Value, len(columns))
		for i, column := range columns {
			s.config[column] = a[i].Value
		}
		wantArgs := 132
		if s.canonical != nil {
			wantArgs++
			stored, ok := a[len(a)-1].Value.([]byte)
			if !ok || !bytes.Equal(stored, s.canonical) {
				return nil, errors.New("canonical snapshot mismatch")
			}
			storedHash := sha256.Sum256(stored)
			if a[2].Value != hex.EncodeToString(storedHash[:]) || a[3].Value != int64(len(stored)) {
				return nil, errors.New("canonical hash or size mismatch")
			}
		}
		if len(a) != wantArgs || a[1].Value != int64(1) || a[4].Value != false {
			return nil, errors.New("bad snapshot")
		}
	case strings.Contains(q, "INSERT INTO system_backup_v2_installation_state"):
		kind = "state"
		s.matrix = a[2].Value.(string)
	case strings.Contains(q, "INSERT INTO system_backup_v2_operations"):
		kind = "operation"
		s.stagedOp = a[0].Value.(string)
		s.stagedHash = a[6].Value.(string)
	default:
		return nil, errors.New("unexpected write")
	}
	s.pending = append(s.pending, kind)
	return registrationTestResult(len(s.pending)), nil
}

type bootstrapTx struct{ s *bootstrapTestState }

func (t *bootstrapTx) Commit() error {
	t.s.committed = append(t.s.committed, t.s.pending...)
	t.s.pending = nil
	if t.s.stagedOp != "" {
		t.s.op = t.s.stagedOp
		t.s.hash = t.s.stagedHash
	}
	if t.s.commitUnknown {
		return errors.New("PRIVATE commit error")
	}
	return nil
}
func (t *bootstrapTx) Rollback() error {
	t.s.pending = nil
	t.s.stagedOp = ""
	t.s.stagedHash = ""
	t.s.config = t.s.savedConfig
	t.s.matrix = t.s.savedMatrix
	return nil
}

type syntheticBootstrapAdmission struct{ s *bootstrapTestState }

func (a syntheticBootstrapAdmission) Authorize(_ context.Context, tx *sql.Tx, _ OfflineBootstrapGrant, _ BootstrapConfig, _ time.Time) error {
	a.s.authorized++
	a.s.tx = tx
	if a.s.denied {
		return ErrRegistrationPermission
	}
	return nil
}
func (a syntheticBootstrapAdmission) ValidateAndReserve(ctx context.Context, tx *sql.Tx, _ OfflineBootstrapGrant, _ BootstrapConfig, _ time.Time) error {
	a.s.validated++
	if a.s.tx != tx || a.s.unresolved {
		return ErrRegistrationUnavailable
	}
	_, err := tx.ExecContext(ctx, "synthetic reserve")
	return err
}
func bootstrapServiceFixture(t *testing.T) (ConfigBootstrapService, OfflineBootstrapGrant, []byte, *bootstrapTestState) {
	t.Helper()
	raw := bootstrapFixture(t)
	c, err := DecodeBootstrapConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	g := OfflineBootstrapGrant{InstallationID: "installation_synthetic", ServerUUID: "11111111-2222-3333-4444-555555555555", Database: "synthetic", Username: "admin", UserID: 42, MatrixKey: "k8s-cluster", ConfigSHA256: c.SHA256(), IdempotencyKey: "synthetic-bootstrap-0001", ChangeReason: "synthetic unit test"}
	s := &bootstrapTestState{grant: g}
	db := sql.OpenDB(bootstrapConnector{s})
	t.Cleanup(func() { db.Close() })
	return ConfigBootstrapService{DB: db, Admission: syntheticBootstrapAdmission{s}}, g, raw, s
}
func TestBootstrapAtomicIdempotencyAndReauthorization(t *testing.T) {
	svc, g, raw, s := bootstrapServiceFixture(t)
	first, err := svc.Bootstrap(context.Background(), g, raw)
	if err != nil || first.Version != 1 || first.Replayed || strings.Join(s.committed, ",") != "reservation,audit,config,state,operation,audit" {
		t.Fatal(first, err, s.committed)
	}
	retry, err := svc.Bootstrap(context.Background(), g, raw)
	if err != nil || !retry.Replayed || retry.OperationPublicID != first.OperationPublicID || len(s.committed) != 6 || s.authorized != 4 || s.validated != 1 {
		t.Fatal("retry", retry, err)
	}
	g.ChangeReason = "different reason"
	if _, err = svc.Bootstrap(context.Background(), g, raw); err != ErrRegistrationConflict {
		t.Fatal("body conflict", err)
	}
	g = s.grant
	s.denied = true
	if _, err = svc.Bootstrap(context.Background(), g, raw); err != ErrRegistrationPermission {
		t.Fatal("revoked grant replayed", err)
	}
	s.denied = false
	s.inactive = true
	if _, err = svc.Bootstrap(context.Background(), g, raw); err != ErrRegistrationPermission {
		t.Fatal("inactive user replayed", err)
	}
}

func TestBootstrapCanonicalCandidateWritesExactSnapshotAtomically(t *testing.T) {
	svc, grant, raw, state := bootstrapServiceFixture(t)
	config, err := DecodeBootstrapConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	state.canonical = config.CanonicalJSON()
	svc.CanonicalSnapshot = true
	result, err := svc.Bootstrap(context.Background(), grant, raw)
	if err != nil || result.Replayed || result.ConfigSHA256 != config.SHA256() ||
		strings.Join(state.committed, ",") != "reservation,audit,config,state,operation,audit" {
		t.Fatal("candidate canonical insert failed", result, err, state.committed)
	}
	svc, grant, raw, state = bootstrapServiceFixture(t)
	config, err = DecodeBootstrapConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	state.canonical = config.CanonicalJSON()
	state.failWrite = 5 // Operation receipt fails after config and state writes.
	svc.CanonicalSnapshot = true
	if result, err = svc.Bootstrap(context.Background(), grant, raw); err == nil ||
		result.OperationPublicID != "" || len(state.committed) != 0 || len(state.pending) != 0 {
		t.Fatal("candidate insert survived failed receipt", result, err, state)
	}
}
func TestBootstrapRollsBackEveryWriteAndUnknownCommitRetries(t *testing.T) {
	for fail := 1; fail <= 6; fail++ {
		t.Run(string(rune('0'+fail)), func(t *testing.T) {
			svc, g, raw, s := bootstrapServiceFixture(t)
			s.failWrite = fail
			result, err := svc.Bootstrap(context.Background(), g, raw)
			if err == nil || result.OperationPublicID != "" || len(s.committed) != 0 || len(s.pending) != 0 || s.op != "" || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("partial result", result, err, s)
			}
		})
	}
	svc, g, raw, s := bootstrapServiceFixture(t)
	s.commitUnknown = true
	result, err := svc.Bootstrap(context.Background(), g, raw)
	if err != ErrRegistrationCommitUnknown || result.OperationPublicID != "" || len(s.committed) != 6 {
		t.Fatal("unknown commit", err)
	}
	s.commitUnknown = false
	retry, err := svc.Bootstrap(context.Background(), g, raw)
	if err != nil || !retry.Replayed || len(s.committed) != 6 {
		t.Fatal("unknown retry", err)
	}
}
func TestBootstrapFailsClosedBeforeWrites(t *testing.T) {
	for _, name := range []string{"wrong-database", "inactive", "denied", "missing-admission", "unresolved", "existing", "wrong-digest", "short-idempotency"} {
		t.Run(name, func(t *testing.T) {
			svc, g, raw, s := bootstrapServiceFixture(t)
			switch name {
			case "wrong-database":
				s.wrongDB = true
			case "inactive":
				s.inactive = true
			case "denied":
				s.denied = true
			case "missing-admission":
				svc.Admission = nil
			case "unresolved":
				s.unresolved = true
			case "existing":
				s.exists = true
			case "wrong-digest":
				g.ConfigSHA256 = strings.Repeat("0", 64)
			case "short-idempotency":
				g.IdempotencyKey = "too-short"
			}
			if _, err := svc.Bootstrap(context.Background(), g, raw); err == nil || len(s.committed) != 0 || len(s.pending) != 0 {
				t.Fatal("guard bypassed", err)
			}
		})
	}
}
