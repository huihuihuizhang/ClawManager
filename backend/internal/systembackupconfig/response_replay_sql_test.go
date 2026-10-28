package systembackupconfig

import (
	"bytes"
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

// SQL/live policy are explicit protocol models; ciphertext and KEK wrapping use
// the real SBEV/AES-GCM fixtures. No InnoDB/concurrency/deployment claim follows.
type replaySQLState struct {
	facts                      sec.ConfigMutationResponseReplayFacts
	snapshot                   responseReplaySnapshot
	now                        time.Time
	mode                       string
	active                     bool
	commits, writes, rollbacks int
}
type replaySQLConnector struct{ s *replaySQLState }

func (c replaySQLConnector) Driver() driver.Driver { return responseSQLDriver{} }
func (c replaySQLConnector) Connect(context.Context) (driver.Conn, error) {
	return &replaySQLConn{c.s}, nil
}

type replaySQLConn struct{ s *replaySQLState }

func (*replaySQLConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (*replaySQLConn) Close() error                        { return nil }
func (c *replaySQLConn) Begin() (driver.Tx, error) {
	if c.s.active {
		return nil, errors.New("nested replay transaction")
	}
	c.s.active = true
	return &replaySQLTx{c.s}, nil
}
func (c *replaySQLConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return c.Begin()
}

type replaySQLTx struct{ s *replaySQLState }

func (t *replaySQLTx) Commit() error   { t.s.commits++; t.s.active = false; return nil }
func (t *replaySQLTx) Rollback() error { t.s.rollbacks++; t.s.active = false; return nil }
func (c *replaySQLConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.s.writes++
	return nil, errors.New("replay must never write")
}
func replayNullString(s sql.NullString) driver.Value {
	if s.Valid {
		return s.String
	}
	return nil
}
func replayNullInt(n sql.NullInt64) driver.Value {
	if n.Valid {
		return n.Int64
	}
	return nil
}
func (c *replaySQLConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	s := c.s
	if !s.active {
		return nil, errors.New("query outside transaction")
	}
	if q == "SELECT @@server_uuid,DATABASE()" {
		name := s.facts.Database.Database
		if s.mode == "database" {
			name = "foreign"
		}
		return responseRow(s.facts.Database.ServerUUID, name), nil
	}
	if strings.HasPrefix(q, "SELECT UTC_TIMESTAMP(6),") {
		return responseRow(s.now, int64(0)), nil
	}
	if !strings.Contains(q, "FOR UPDATE") {
		return nil, errors.New("unlocked snapshot")
	}
	if strings.Contains(q, "FROM system_backup_v2_operations") {
		f := s.facts
		want := []driver.Value{f.Installation, "42", f.Endpoint, f.IdempotencyKey, f.Operation}
		if f.Actor.UserID == 7 {
			want[1] = "7"
		}
		if len(args) != len(want) {
			return nil, errors.New("wrong receipt scope")
		}
		for i, v := range want {
			if args[i].Value != v {
				return nil, errors.New("wrong receipt scope")
			}
		}
		hash, version := f.RequestHash, f.Version
		if s.mode == "receipt-hash" {
			hash = strings.Repeat("f", 64)
		}
		if s.mode == "receipt-version" {
			version++
		}
		started, rowVersion := s.snapshot.Created, int64(1)
		if s.mode == "operation-started" {
			started = started.Add(-time.Second)
		}
		if s.mode == "operation-row-version" {
			rowVersion++
		}
		return responseRow(f.Operation, hash, "succeeded", int64(200), version, f.EvidenceID, f.ResponseHash, "system", f.Installation, "config_update", started, started, s.snapshot.Created, rowVersion), nil
	}
	if len(args) != 1 || args[0].Value != s.facts.EvidenceID {
		return nil, errors.New("wrong evidence FK")
	}
	if strings.Contains(q, "FROM system_backup_v2_evidence_chunks") {
		if !strings.Contains(q, "ORDER BY chunk_index FOR UPDATE") {
			return nil, errors.New("partial chunk query")
		}
		if len(s.snapshot.Manifest.Chunks) == 0 {
			return &responseSQLRows{done: true}, nil
		}
		ch := s.snapshot.Manifest.Chunks[0]
		nonce, _ := base64.RawURLEncoding.DecodeString(ch.Nonce)
		tag, _ := base64.RawURLEncoding.DecodeString(ch.Tag)
		if s.mode == "chunk-tag" {
			tag[0] ^= 1
		}
		values := []driver.Value{ch.Index, ch.PlainOffset, ch.PlainLength, ch.PlainHash, ch.FrameOffset, ch.FrameLength, ch.CipherHash, nonce, tag}
		rows := &responseSQLRows{values: values}
		if s.mode == "extra-chunk" {
			rows.extra = [][]driver.Value{values}
		}
		return rows, nil
	}
	if !strings.Contains(q, "FROM system_backup_v2_evidence WHERE id=?") {
		return nil, errors.New("unexpected replay query")
	}
	e := s.snapshot
	if s.mode == "row-version" {
		e.RowVersion++
	}
	if s.mode == "pending" {
		e.State = "pending"
	}
	if s.mode == "owner" {
		e.Owner = "installation_foreign"
	}
	if s.mode == "health" {
		e.Health = "unknown"
	}
	if s.mode == "expired" {
		e.Expires = s.now
	}
	if s.mode == "inline-external-metadata" {
		e.Role = sql.NullString{String: "evidence", Valid: true}
	}
	return responseRow(e.ID, e.Schema, e.PublicID, e.OwnerType, e.Owner, e.Kind, e.State, e.Failure, e.Health, e.Inline, e.Checksum, e.Size, e.Media, e.Classification, e.Encryption, e.Expires, e.Created, e.RowVersion,
		replayNullString(e.Role), replayNullString(e.StoreIdentity), replayNullString(e.StoreVersion), replayNullString(e.RelativeKey), replayNullString(e.RelativeKeyHash), replayNullString(e.Immutable), replayNullString(e.ObjectHash), replayNullInt(e.ObjectSize), replayNullInt(e.ChunkSize), e.Count, replayNullString(e.Root), replayNullString(e.Framing), replayNullString(e.KEKIdentity), replayNullString(e.KEKVersion), replayNullString(e.Envelope)), nil
}

type replayAccessFixture struct {
	s         *replaySQLState
	resources ConfigMutationResponseReadResources
	until     time.Time
	revoked   bool
	checks    int
}

func (a *replayAccessFixture) Resources() ConfigMutationResponseReadResources { return a.resources }
func (a *replayAccessFixture) ValidUntil() time.Time                          { return a.until }
func (a *replayAccessFixture) Recheck(_ context.Context, tx *sql.Tx, _ time.Time) error {
	a.checks++
	if tx == nil || !a.s.active || a.revoked {
		return errors.New("PRIVATE read access revoked")
	}
	return nil
}

type replayAuthorityFixture struct{ a *replayAccessFixture }

func (a replayAuthorityFixture) Prepare(_ context.Context, in sec.ConfigMutationResponseReplayPreparation, l ConfigMutationResponseLocation) (ConfigMutationResponseReadAccess, error) {
	if a.a.s.active || in.Facts() != a.a.s.facts || l.Reference() != a.a.s.snapshot.Ref {
		return nil, errors.New("authority work under locks or wrong receipt")
	}
	// Neither public accessor may alias the private locked chunk index.
	m := l.Manifest()
	if len(m.Chunks) > 0 {
		m.Chunks[0].CipherHash = "mutated caller copy"
	}
	return a.a, nil
}

type replayUnlockedObject struct {
	*responseTestObject
	s     *replaySQLState
	after func()
}

func (s *replayUnlockedObject) Range(ctx context.Context, r ev.Ref, offset, length int64) (io.ReadCloser, error) {
	if s.s.active {
		return nil, errors.New("provider Range under SQL locks")
	}
	out, err := s.responseTestObject.Range(ctx, r, offset, length)
	if s.after != nil {
		s.after()
	}
	return out, err
}
func (s *replayUnlockedObject) Stat(ctx context.Context, r ev.Ref) (ev.ObjectInfo, error) {
	if s.s.active {
		return ev.ObjectInfo{}, errors.New("provider Stat under SQL locks")
	}
	return s.responseTestObject.Stat(ctx, r)
}
func replayReaderFixture(t *testing.T, large bool) (*SQLConfigMutationResponseReader, sec.ConfigMutationResponseReplayPreparation, *replaySQLState, *replayAccessFixture, []byte) {
	t.Helper()
	c := responseContent(t, large)
	f := sec.ConfigMutationResponseReplayFacts{Database: c.database, Installation: c.identity.Installation, Actor: c.input.Actor(), Operation: "sop_12345678-1234-1234-1234-123456789abc", Endpoint: sec.ConfigUpdateEndpoint, IdempotencyKey: "mutation_key_0123456789", RequestHash: strings.Repeat("d", 64), EvidenceID: 67, ResponseHash: c.identity.ContentHash, Version: 2, AuthorizedAt: c.created, ValidUntil: c.until}
	snap := responseReplaySnapshot{ID: 67, Schema: "system-backup-evidence.v1", PublicID: c.identity.ID, OwnerType: "system", Owner: f.Installation, Kind: "diagnostic", State: "inline", Failure: "none", Health: "healthy", Inline: c.Bytes(), Checksum: c.identity.ContentHash, Size: c.identity.ContentSize, Media: "application/json", Classification: "internal", Encryption: "none", Expires: c.retain, Created: c.created, RowVersion: 1, Manifest: ev.Manifest{Identity: c.identity}}
	s := &replaySQLState{facts: f, snapshot: snap, now: time.Now().UTC().Truncate(time.Microsecond)}
	a := &replayAccessFixture{s: s, until: c.until}
	if large {
		p, store, keys, _ := encryptResponseFixture(t, c)
		m := p.Manifest()
		s.snapshot.State = "ready"
		s.snapshot.Inline = nil
		s.snapshot.Encryption = "envelope_v1"
		s.snapshot.Manifest = m
		s.snapshot.Ref = store.ref
		s.snapshot.Count = 1
		str := func(v string) sql.NullString { return sql.NullString{String: v, Valid: true} }
		s.snapshot.Role = str("evidence")
		s.snapshot.StoreIdentity = str(store.ref.Identity)
		s.snapshot.StoreVersion = str(store.ref.Version)
		s.snapshot.RelativeKey = str(store.ref.RelativeKey)
		s.snapshot.RelativeKeyHash = str(registrationHash(store.ref.RelativeKey))
		s.snapshot.Immutable = str(store.ref.ImmutableVersion)
		s.snapshot.ObjectHash = str(m.ObjectHash)
		s.snapshot.ObjectSize = sql.NullInt64{Int64: m.ObjectSize, Valid: true}
		s.snapshot.ChunkSize = sql.NullInt64{Int64: ev.ChunkSize, Valid: true}
		s.snapshot.Root = str(m.ChunkRoot)
		s.snapshot.Framing = str(ev.Framing)
		s.snapshot.KEKIdentity = str(m.Key.Identity)
		s.snapshot.KEKVersion = str(m.Key.Version)
		s.snapshot.Envelope = str(m.EnvelopeHash)
		a.resources = ConfigMutationResponseReadResources{Root: "responses", Store: ev.KeyRef{Identity: store.ref.Identity, Version: store.ref.Version}, KEK: m.Key, Reader: &replayUnlockedObject{responseTestObject: store, s: s}, Keys: keys}
	}
	db := sql.OpenDB(replaySQLConnector{s})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	r, err := NewSQLConfigMutationResponseReader(db, f.Database, f.Installation, replayAuthorityFixture{a})
	if err != nil {
		t.Fatal(err)
	}
	in, err := sec.NewConfigMutationResponseReplayPreparation(f)
	if err != nil {
		t.Fatal(err)
	}
	return r, in, s, a, c.Bytes()
}
func TestResponseReplaySQLReadsOriginalAndRechecksCallerTransaction(t *testing.T) {
	for _, large := range []bool{false, true} {
		name := "inline"
		if large {
			name = "external"
		}
		t.Run(name, func(t *testing.T) {
			r, in, s, a, want := replayReaderFixture(t, large)
			read, err := r.Read(context.Background(), in)
			if err != nil || !bytes.Equal(read.Bytes(), want) {
				t.Fatal("original canonical read", err)
			}
			got := read.Bytes()
			got[0] = '!'
			if !bytes.Equal(read.Bytes(), want) {
				t.Fatal("caller modified immutable body")
			}
			tx, err := r.db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if err = read.Recheck(context.Background(), tx, s.now); err != nil || a.checks < 4 {
				t.Fatal("final replay snapshot", err)
			}
			if s.writes != 0 || s.commits != 0 || s.rollbacks != 2 {
				t.Fatal("read committed or wrote")
			}
		})
	}
}
func TestResponseReplaySQLRejectsUnboundOrMalformedOriginal(t *testing.T) {
	for _, name := range []string{"database", "receipt-hash", "receipt-version", "pending", "owner", "health", "expired", "inline-external-metadata", "body-version", "body-actor", "operation-started", "extra-chunk", "chunk-tag", "store-map", "kek-map", "root-map", "revoked"} {
		t.Run(name, func(t *testing.T) {
			large := name == "extra-chunk" || name == "chunk-tag" || name == "store-map" || name == "kek-map" || name == "root-map"
			r, in, s, a, _ := replayReaderFixture(t, large)
			s.mode = name
			switch name {
			case "body-version":
				s.facts.Version = 3
				in, _ = sec.NewConfigMutationResponseReplayPreparation(s.facts)
			case "body-actor":
				s.facts.Actor.UserID = 7
				s.facts.Actor.Subject = "user:7"
				in, _ = sec.NewConfigMutationResponseReplayPreparation(s.facts)
			case "store-map":
				a.resources.Store.Version = "unrelated-version"
			case "kek-map":
				a.resources.KEK.Version = "unrelated-version"
			case "root-map":
				a.resources.Root = "unrelated-root"
			case "revoked":
				a.revoked = true
			}
			read, err := r.Read(context.Background(), in)
			if err != sec.ErrRegistrationUnavailable || read != nil {
				t.Fatal("invalid replay returned body or diagnostics", err)
			}
			if s.active || s.writes != 0 || s.commits != 0 {
				t.Fatal("failed read leaked transaction or wrote")
			}
		})
	}
}
func TestResponseReplayFinalSnapshotRejectsProviderTimeChanges(t *testing.T) {
	for _, name := range []string{"receipt-hash", "receipt-version", "operation-row-version", "operation-started", "row-version", "chunk-tag", "revoked", "deadline-extended", "expired"} {
		t.Run(name, func(t *testing.T) {
			r, in, s, a, _ := replayReaderFixture(t, true)
			a.resources.Reader.(*replayUnlockedObject).after = func() {
				s.mode = name
				if name == "revoked" {
					a.revoked = true
				}
				if name == "deadline-extended" {
					a.until = in.Facts().ValidUntil.Add(time.Second)
				}
				if name == "expired" {
					s.now = in.Facts().ValidUntil
				}
			}
			read, err := r.Read(context.Background(), in)
			if name == "deadline-extended" {
				if err != sec.ErrRegistrationUnavailable || read != nil || s.active || s.writes != 0 || s.commits != 0 {
					t.Fatal("provider extended read grant", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tx, err := r.db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if err = read.Recheck(context.Background(), tx, s.now); err != sec.ErrRegistrationUnavailable {
				t.Fatal("changed replay admitted", err)
			}
			if s.writes != 0 || s.commits != 0 {
				t.Fatal("final recheck changed state")
			}
		})
	}
}
