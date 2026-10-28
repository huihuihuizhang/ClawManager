package systembackupconfig

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	ev "clawreef/internal/systembackupevidence"
	sec "clawreef/internal/systembackupsecurity"
)

// SQL/authority models verify exact binding and caller transaction ownership;
// they do not prove InnoDB atomicity or a real C publication grant.
type responseSQLState struct {
	c                              ConfigMutationResponseContent
	m                              ev.Manifest
	ref                            ev.Ref
	corrupt                        string
	active, inline, zeroRows, fail bool
	writes, commits                int
}
type responseSQLConnector struct{ s *responseSQLState }

func (c responseSQLConnector) Driver() driver.Driver { return responseSQLDriver{} }
func (c responseSQLConnector) Connect(context.Context) (driver.Conn, error) {
	return &responseSQLConn{c.s}, nil
}

type responseSQLDriver struct{}

func (responseSQLDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

type responseSQLConn struct{ s *responseSQLState }

func (*responseSQLConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (*responseSQLConn) Close() error                        { return nil }
func (c *responseSQLConn) Begin() (driver.Tx, error) {
	if c.s.active {
		return nil, errors.New("nested transaction")
	}
	c.s.active = true
	return &responseSQLTx{c.s}, nil
}
func (c *responseSQLConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return c.Begin()
}

type responseSQLTx struct{ s *responseSQLState }

func (t *responseSQLTx) Commit() error   { t.s.commits++; t.s.active = false; return nil }
func (t *responseSQLTx) Rollback() error { t.s.active = false; t.s.inline = false; return nil }

type responseSQLRows struct {
	values []driver.Value
	extra  [][]driver.Value
	done   bool
}

func (r *responseSQLRows) Columns() []string {
	out := make([]string, len(r.values))
	for i := range out {
		out[i] = "column"
	}
	return out
}
func (*responseSQLRows) Close() error { return nil }
func (r *responseSQLRows) Next(dst []driver.Value) error {
	if r.done {
		if len(r.extra) == 0 {
			return io.EOF
		}
		copy(dst, r.extra[0])
		r.extra = r.extra[1:]
		return nil
	}
	copy(dst, r.values)
	r.done = true
	return nil
}
func responseRow(values ...driver.Value) driver.Rows { return &responseSQLRows{values: values} }

type responseSQLResult struct{ id, rows int64 }

func (r responseSQLResult) LastInsertId() (int64, error) { return r.id, nil }
func (r responseSQLResult) RowsAffected() (int64, error) { return r.rows, nil }
func (c *responseSQLConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	s := c.s
	if !s.active || s.fail {
		return nil, errors.New("PRIVATE response SQL failure")
	}
	if q == "SELECT @@server_uuid,DATABASE()" {
		db := s.c.database.Database
		if s.corrupt == "database" {
			db = "foreign"
		}
		return responseRow(s.c.database.ServerUUID, db), nil
	}
	if strings.HasPrefix(q, "SELECT chunk_index,") {
		if len(args) != 1 || args[0].Value != int64(67) || strings.Contains(q, "AND chunk_index=0") || !strings.Contains(q, "ORDER BY chunk_index FOR UPDATE") {
			return nil, errors.New("wrong chunk FK")
		}
		chunk := s.m.Chunks[0]
		nonce, _ := base64.RawURLEncoding.DecodeString(chunk.Nonce)
		tag, _ := base64.RawURLEncoding.DecodeString(chunk.Tag)
		if s.corrupt == "chunk-tag" {
			tag[0] ^= 1
		}
		values := []driver.Value{chunk.Index, chunk.PlainOffset, chunk.PlainLength, chunk.PlainHash, chunk.FrameOffset, chunk.FrameLength, chunk.CipherHash, nonce, tag}
		rows := &responseSQLRows{values: values}
		if s.corrupt == "extra-chunk" {
			extra := append([]driver.Value(nil), values...)
			extra[0] = int64(1)
			rows.extra = [][]driver.Value{extra}
		}
		return rows, nil
	}
	if len(args) != 1 || args[0].Value != s.c.identity.ID || !strings.Contains(q, "FOR UPDATE") {
		return nil, errors.New("wrong response identity/lock")
	}
	if strings.HasPrefix(q, "SELECT id,schema_version,public_id,") {
		state, health, role, owner, hash, expiry := "ready", "healthy", "evidence", s.c.identity.Installation, s.c.identity.ContentHash, s.c.retain
		switch s.corrupt {
		case "pending":
			state = "pending"
		case "write-unknown":
			state = "write_unknown"
		case "health":
			health = "unknown"
		case "artifact-role":
			role = "artifact"
		case "owner":
			owner = "installation_foreign"
		case "content-hash":
			hash = strings.Repeat("f", 64)
		case "retention":
			expiry = expiry.Add(-time.Second)
		}
		return responseRow(int64(67), "system-backup-evidence.v1", s.c.identity.ID, "system", owner, "diagnostic", state, "none", health, role, s.ref.Identity, s.ref.Version, s.ref.RelativeKey, registrationHash(s.ref.RelativeKey), s.ref.ImmutableVersion, hash, s.c.identity.ContentSize, s.m.ObjectHash, s.m.ObjectSize, ev.ChunkSize, int64(1), s.m.ChunkRoot, "application/json", "envelope_v1", ev.Framing, s.m.Key.Identity, s.m.Key.Version, s.m.EnvelopeHash, "internal", expiry, s.c.created), nil
	}
	if strings.HasPrefix(q, "SELECT id,schema_version,owner_target_type,") && s.inline {
		raw := s.c.Bytes()
		if s.corrupt == "inline-body" {
			raw[0] = '!'
		}
		return responseRow(int64(67), "system-backup-evidence.v1", "system", s.c.identity.Installation, "diagnostic", "inline", "none", "healthy", raw, s.c.identity.ContentHash, int64(len(raw)), "application/json", "none", "internal", s.c.retain, s.c.created), nil
	}
	return nil, errors.New("unexpected SQL read")
}
func (c *responseSQLConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	s := c.s
	if !s.active || s.fail {
		return nil, errors.New("PRIVATE response insert failure")
	}
	if !strings.HasPrefix(q, "INSERT INTO system_backup_v2_evidence") || len(args) != 9 || args[0].Value != s.c.identity.ID || args[1].Value != s.c.identity.Installation || registrationHash(string(args[2].Value.([]byte))) != s.c.identity.ContentHash || args[3].Value != s.c.identity.ContentHash || args[4].Value != int64(len(s.c.payload)) {
		return nil, errors.New("wrong full inline payload or bind values")
	}
	s.writes++
	if s.zeroRows {
		return responseSQLResult{0, 0}, nil
	}
	s.inline = true
	return responseSQLResult{67, 1}, nil
}
func responseSQLFixture(t *testing.T, c ConfigMutationResponseContent, m ev.Manifest, ref ev.Ref) (*responseSQLState, *sql.Tx) {
	t.Helper()
	s := &responseSQLState{c: c, m: m, ref: ref}
	db := sql.OpenDB(responseSQLConnector{s})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	return s, tx
}

type responsePublicationGuardFixture struct {
	until time.Time
	fail  bool
}

func (g *responsePublicationGuardFixture) ValidUntil() time.Time { return g.until }
func (g *responsePublicationGuardFixture) Recheck(context.Context, *sql.Tx, time.Time) error {
	if g.fail {
		return errors.New("PRIVATE publication authority revoked")
	}
	return nil
}

func TestResponseInlineStagesExactlyOnceWithoutCommitting(t *testing.T) {
	c := responseContent(t, false)
	s, tx := responseSQLFixture(t, c, ev.Manifest{}, ev.Ref{})
	p, err := PrepareInlineConfigMutationResponse(c)
	if err != nil {
		t.Fatal(err)
	}
	id, err := p.Stage(context.Background(), tx, c.created)
	if err != nil || id != 67 || s.writes != 1 || s.commits != 0 {
		t.Fatal("inline stage failed or committed caller tx", err)
	}
	if err = p.Recheck(context.Background(), tx, c.created); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Stage(context.Background(), tx, c.created); err != sec.ErrRegistrationUnavailable {
		t.Fatal("staged twice", err)
	}
	s.corrupt = "inline-body"
	if err = p.Recheck(context.Background(), tx, c.created); err != sec.ErrRegistrationUnavailable {
		t.Fatal("inline body mutation accepted", err)
	}
}
func TestResponsePublishedBindingRequiresExactReadyRecord(t *testing.T) {
	for _, name := range []string{"valid", "pending", "write-unknown", "health", "artifact-role", "owner", "content-hash", "retention", "chunk-tag", "extra-chunk", "database", "expired", "publication-revoked", "publication-extended"} {
		t.Run(name, func(t *testing.T) {
			c := responseContent(t, true)
			prepared, store, _, _ := encryptResponseFixture(t, c)
			s, tx := responseSQLFixture(t, c, prepared.Manifest(), store.ref)
			guard := &responsePublicationGuardFixture{until: c.until}
			p, err := PreparePublishedConfigMutationResponse(c, prepared, store.ref, guard)
			if err != nil {
				t.Fatal(err)
			}
			now := c.created
			switch name {
			case "expired":
				now = p.ValidUntil()
			case "publication-revoked":
				guard.fail = true
			case "publication-extended":
				guard.until = guard.until.Add(time.Second)
			default:
				s.corrupt = name
			}
			id, err := p.Stage(context.Background(), tx, now)
			if name == "valid" {
				if err != nil || id != 67 || p.Recheck(context.Background(), tx, now) != nil {
					t.Fatal("ready immutable response not bound", err)
				}
			} else if err != sec.ErrRegistrationUnavailable || id != 0 {
				t.Fatal("invalid publication admitted", err)
			}
			if s.writes != 0 || s.commits != 0 {
				t.Fatal("binding changed publication or committed")
			}
		})
	}
}
func TestResponseInlineRejectsZeroRowAndPrivateDatabaseFailures(t *testing.T) {
	for _, name := range []string{"zero-row", "storage-failure", "foreign-database"} {
		t.Run(name, func(t *testing.T) {
			c := responseContent(t, false)
			s, tx := responseSQLFixture(t, c, ev.Manifest{}, ev.Ref{})
			switch name {
			case "zero-row":
				s.zeroRows = true
			case "storage-failure":
				s.fail = true
			case "foreign-database":
				s.corrupt = "database"
			}
			id, err := c.StageInline(context.Background(), tx, c.created)
			if err == nil || id != 0 || s.commits != 0 {
				t.Fatal("failed stage returned success", err)
			}
			if strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("database diagnostics leaked")
			}
		})
	}
}
