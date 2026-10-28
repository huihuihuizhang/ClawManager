package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// This driver executes A's real parameterized SQL through D's real transaction
// owner, with rollback snapshots shared by the A rows and a synthetic D/audit
// participant. It does not simulate MySQL FK/gap locks or production authority.
type systemPendingTestDB struct {
	t                                  *testing.T
	scope                              pd.Scope
	now                                time.Time
	row                                map[string]driver.Value
	chunks                             []map[string]driver.Value
	marker                             int
	savedRow                           map[string]driver.Value
	savedChunks                        []map[string]driver.Value
	savedMarker                        int
	begins, commits, rollbacks, writes int
	events                             []string
	fail                               string
	queryMode                          string
	onAudit                            func()
}

func cloneSystemPendingRow(r map[string]driver.Value) map[string]driver.Value {
	if r == nil {
		return nil
	}
	c := make(map[string]driver.Value, len(r))
	for k, v := range r {
		if b, ok := v.([]byte); ok {
			v = append([]byte(nil), b...)
		}
		c[k] = v
	}
	return c
}
func cloneSystemPendingChunks(rows []map[string]driver.Value) []map[string]driver.Value {
	var c []map[string]driver.Value
	for _, r := range rows {
		c = append(c, cloneSystemPendingRow(r))
	}
	return c
}
func (d *systemPendingTestDB) Driver() driver.Driver                        { return authorityDriver{} }
func (d *systemPendingTestDB) Connect(context.Context) (driver.Conn, error) { return d, nil }
func (d *systemPendingTestDB) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (d *systemPendingTestDB) Close() error { return nil }
func (d *systemPendingTestDB) Begin() (driver.Tx, error) {
	return nil, errors.New("explicit transaction required")
}
func (d *systemPendingTestDB) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	if o.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || o.ReadOnly {
		d.t.Fatal("wrong transaction isolation")
	}
	d.begins++
	d.savedRow = cloneSystemPendingRow(d.row)
	d.savedChunks = cloneSystemPendingChunks(d.chunks)
	d.savedMarker = d.marker
	d.events = append(d.events, "begin")
	return d, nil
}
func (d *systemPendingTestDB) Commit() error {
	d.events = append(d.events, "commit")
	if d.fail == "commit_unknown" {
		return errors.New("synthetic private commit failure")
	}
	d.commits++
	return nil
}
func (d *systemPendingTestDB) Rollback() error {
	d.row = d.savedRow
	d.chunks = d.savedChunks
	d.marker = d.savedMarker
	d.rollbacks++
	d.events = append(d.events, "rollback")
	return nil
}

type systemPendingTestResult struct {
	n   int64
	bad bool
}

func (r systemPendingTestResult) LastInsertId() (int64, error) {
	return 0, errors.New("do not rely on pooled last insert id")
}
func (r systemPendingTestResult) RowsAffected() (int64, error) {
	if r.bad {
		return 0, errors.New("synthetic affected failure")
	}
	return r.n, nil
}
func (d *systemPendingTestDB) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	d.writes++
	if q == "INSERT INTO synthetic_guard_marker (n) VALUES (?)" {
		d.marker++
		d.events = append(d.events, "marker")
		if d.onAudit != nil {
			d.onAudit()
		}
		if d.fail == "audit" {
			return nil, errors.New("synthetic private audit failure")
		}
		return systemPendingTestResult{n: 1}, nil
	}
	stage := "evidence"
	if strings.HasPrefix(q, "INSERT INTO system_backup_v2_evidence_chunks ") {
		stage = "chunk"
	} else if !strings.HasPrefix(q, "INSERT INTO system_backup_v2_evidence ") {
		d.t.Fatalf("unexpected SQL %s", q)
	}
	d.events = append(d.events, "insert:"+stage)
	if d.fail == stage {
		return nil, errors.New("synthetic private insert failure")
	}
	n := int64(1)
	if d.fail == stage+"_zero" {
		n = 0
	}
	if d.fail == stage+"_many" {
		n = 2
	}
	start, end := strings.Index(q, "("), strings.Index(q, ")")
	columns := strings.Split(q[start+1:end], ",")
	if len(columns) != len(args) || strings.Count(q, "?") != len(args) {
		d.t.Fatal("SQL placeholder mismatch")
	}
	row := make(map[string]driver.Value, len(columns))
	for i, col := range columns {
		row[strings.TrimSpace(col)] = args[i].Value
	}
	if stage == "evidence" {
		if d.row != nil {
			return nil, errors.New("duplicate public id")
		}
		row["id"] = int64(41)
		d.row = row
	} else {
		if d.row == nil || row["evidence_id"] != d.row["id"] {
			d.t.Fatal("wrong parent key")
		}
		d.chunks = append(d.chunks, row)
	}
	return systemPendingTestResult{n: n, bad: d.fail == stage+"_affected"}, nil
}

type systemPendingTestRows struct {
	cols  []string
	rows  [][]driver.Value
	index int
	mode  string
}

func (r *systemPendingTestRows) Columns() []string { return r.cols }
func (r *systemPendingTestRows) Close() error {
	if r.mode == "close" {
		return errors.New("synthetic close failure")
	}
	return nil
}
func (r *systemPendingTestRows) Next(dst []driver.Value) error {
	if r.index >= len(r.rows) {
		if r.mode == "iterate" {
			return errors.New("synthetic iteration failure")
		}
		return io.EOF
	}
	copy(dst, r.rows[r.index])
	r.index++
	return nil
}
func (d *systemPendingTestDB) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.HasPrefix(q, "SELECT @@server_uuid,") {
		return &systemPendingTestRows{cols: []string{"uuid", "db", "now", "offset"}, rows: [][]driver.Value{{string(d.scope.ServerUUID), string(d.scope.Database), d.now, int64(0)}}}, nil
	}
	if q == "SELECT UTC_TIMESTAMP(6)" {
		return &systemPendingTestRows{cols: []string{"now"}, rows: [][]driver.Value{{d.now}}}, nil
	}
	if !strings.HasSuffix(q, "FOR UPDATE") {
		d.t.Fatal("row read did not use current locking read")
	}
	end := strings.Index(q, " FROM ")
	if end < 0 {
		d.t.Fatal("bad SELECT")
	}
	cols := strings.Split(strings.TrimPrefix(q[:end], "SELECT "), ",")
	var source []map[string]driver.Value
	stage := "evidence"
	if strings.Contains(q, " FROM system_backup_v2_evidence_chunks ") {
		stage = "chunks"
		if len(args) != 1 || d.row == nil || args[0].Value != d.row["id"] {
			d.t.Fatal("wrong chunk lookup")
		}
		source = d.chunks
	} else if strings.Contains(q, " FROM system_backup_v2_evidence ") {
		if len(args) != 1 {
			d.t.Fatal("wrong evidence key")
		}
		if d.row != nil && args[0].Value == d.row["public_id"] {
			source = []map[string]driver.Value{d.row}
		}
	} else {
		d.t.Fatalf("unexpected SELECT %s", q)
	}
	d.events = append(d.events, "read:"+stage)
	if d.fail == "read_"+stage {
		return nil, errors.New("synthetic read failure")
	}
	r := &systemPendingTestRows{cols: cols}
	for _, row := range source {
		values := make([]driver.Value, len(cols))
		for i, c := range cols {
			v, ok := row[c]
			if !ok {
				d.t.Fatalf("unrecognized column %s", c)
			}
			values[i] = v
		}
		r.rows = append(r.rows, values)
	}
	if d.queryMode == stage+"_extra" && len(r.rows) > 0 {
		r.rows = append(r.rows, r.rows[0])
	}
	if d.queryMode == stage+"_missing" {
		r.rows = nil
	}
	if d.queryMode == stage+"_columns" {
		r.cols = append(r.cols, "unexpected")
	}
	if strings.HasPrefix(d.queryMode, stage+"_") {
		r.mode = strings.TrimPrefix(d.queryMode, stage+"_")
	}
	return r, nil
}

type systemPendingTestAuthority struct {
	fail          string
	sample        time.Time
	prepareRecord Record
	mutateRecord  bool
	checks        int
}

func (a *systemPendingTestAuthority) PreparePendingAuthority(_ context.Context, _ pd.PendingBinding, r Record) (SystemPendingAuthoritySession, *time.Time, error) {
	a.prepareRecord = r
	if a.mutateRecord {
		r.Manifest.Chunks[0].CipherHash = strings.Repeat("f", 64)
	}
	if a.fail == "prepare" {
		return nil, nil, ErrDenied
	}
	if a.fail == "nil_session" {
		return nil, &a.sample, nil
	}
	return a, &a.sample, nil
}
func (a *systemPendingTestAuthority) LockInstallation(context.Context, pd.SQL, pd.PendingBinding) error {
	return nil
}
func (a *systemPendingTestAuthority) Authenticate(context.Context, pd.SQL, pd.PendingBinding, pd.DomainRecord) (pd.PendingAdmission, error) {
	return pd.PendingAdmission{}, ErrDenied
}
func (a *systemPendingTestAuthority) LockHost(context.Context, pd.SQL, pd.PendingBinding, pd.GrantRecord) error {
	return nil
}
func (a *systemPendingTestAuthority) LockReferences(context.Context, pd.SQL, pd.PendingBinding, pd.PendingFacts) error {
	return nil
}
func (a *systemPendingTestAuthority) Reserve(context.Context, pd.SQL, pd.PendingBinding, uint64) error {
	return nil
}
func (a *systemPendingTestAuthority) Audit(context.Context, pd.SQL, pd.PendingBinding, string) error {
	return nil
}
func (a *systemPendingTestAuthority) Recheck(context.Context, pd.ReadSQL, pd.PendingBinding, pd.PendingFacts, time.Time) error {
	a.checks++
	if a.fail == "guard" {
		return ErrDenied
	}
	return nil
}

type systemPendingTestFixture struct {
	prepared Prepared
	channel  ProducerEvidenceChannel
	env      *SystemPendingEnvironment
	a        *systemPendingTestAuthority
	d        *systemPendingTestDB
	db       *sql.DB
	b        pd.PendingBinding
	s        *systemPendingSession
	facts    pd.PendingFacts
	capacity *time.Time
}

func newSystemPendingTestFixture(t *testing.T) *systemPendingTestFixture {
	t.Helper()
	prepared, channel, r, binding := producerBindingFixture(t)
	var h pd.HistoricalBindingRecord
	if e := pd.DecodeRecord(producerHistoricalVector(t), &h); e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	h.Scope.Installation = pd.Installation(r.Manifest.Identity.Installation)
	h.Evidence = binding
	h.RelativeKey = pd.RelativeKey(r.Ref.RelativeKey)
	h.CreatedAt = systemExecutionStamp(now)
	h.ObservedAt = systemExecutionStamp(now.Add(-time.Minute))
	h.ObservationExpiresAt = systemExecutionStamp(now.Add(time.Minute))
	h.OwnerWriteExpiresAt = systemExecutionStamp(now.Add(2 * time.Minute))
	h.RetentionExpiresAt = systemExecutionStamp(now.Add(24 * time.Hour))
	a := &systemPendingTestAuthority{sample: now}
	env, e := NewSystemPendingEnvironment(a, prepared, channel, h)
	if e != nil {
		t.Fatal(e)
	}
	b := pd.PendingBinding{Scope: h.Scope, Subject: pd.Hash(strings.Repeat("a", 64)), GrantID: h.GrantID, GrantGeneration: h.GrantGeneration, GrantVersion: "1", RunID: h.RunID, Request: pd.PendingRequest{History: h, ExpectedRunVersion: "1", PolicyHash: pd.Hash(strings.Repeat("b", 64)), BudgetUntil: systemExecutionStamp(now.Add(time.Minute))}}
	d := &systemPendingTestDB{t: t, scope: h.Scope, now: now}
	db := sql.OpenDB(d)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return &systemPendingTestFixture{prepared: prepared, channel: channel, env: env, a: a, d: d, db: db, b: b}
}
func (f *systemPendingTestFixture) LockAndAuthorize(ctx context.Context, _ pd.SQL, _ pd.Scope) (pd.GuardPlan, error) {
	h, _ := pd.PendingBindingHash(f.b)
	until, _ := f.b.Request.BudgetUntil.Time()
	return pd.GuardPlan{BindingHash: h, Deadlines: []time.Time{until}, CapacityObservedAt: f.capacity}, nil
}
func (f *systemPendingTestFixture) Recheck(ctx context.Context, tx pd.ReadSQL, _ pd.Scope, _ pd.GuardPlan, now time.Time) error {
	return f.s.Recheck(ctx, tx, f.b, f.facts, now)
}
func (f *systemPendingTestFixture) run(t *testing.T, replay bool, after func(*pd.Transaction) error) (pd.CommitReceipt, error) {
	t.Helper()
	p, e := f.env.PreparePending(context.Background(), f.b)
	if e != nil {
		return pd.CommitReceipt{}, e
	}
	f.s = p.Session.(*systemPendingSession)
	f.capacity = p.CapacityObservedAt
	f.facts = pd.PendingFacts{Replayed: replay}
	r, e := pd.NewTransactions(f.db, f.b.Scope, f)
	if e != nil {
		t.Fatal(e)
	}
	return r.Run(context.Background(), func(ctx context.Context, tx *pd.Transaction) error {
		v, e := f.s.LockEvidence(ctx, tx, f.b, f.facts)
		if e != nil {
			return e
		}
		f.facts.Evidence = v
		if !replay {
			if e = f.s.InsertEvidence(ctx, tx, f.b, f.facts); e != nil {
				return e
			}
			f.facts.Evidence = pd.PendingEvidence{Existing: true, EvidenceID: v.EvidenceID, HistoryHash: v.HistoryHash, RowVersion: "1", State: "pending"}
			if _, e = tx.ExecContext(ctx, "INSERT INTO synthetic_guard_marker (n) VALUES (?)", 1); e != nil {
				// This is the synthetic audit participant's error boundary, not
				// A's loader. A production audit adapter must also redact SQL errors.
				return ErrUnavailable
			}
		}
		if after != nil {
			return after(tx)
		}
		return nil
	})
}

func TestSystemPendingAtomicSQLAndReplay(t *testing.T) {
	f := newSystemPendingTestFixture(t)
	receipt, e := f.run(t, false, nil)
	if e != nil || !receipt.Committed() || f.d.commits != 1 || f.d.begins != 1 || f.d.rollbacks != 0 || f.d.marker != 1 || len(f.d.chunks) != 1 || f.a.checks != 1 {
		t.Fatal("atomic insert failed", e)
	}
	i, m := f.env.record.Manifest.Identity, f.env.record.Manifest
	for col, want := range map[string]any{"public_id": i.ID, "owner_target_type": "system", "owner_target_public_id": i.Installation, "content_checksum": i.ContentHash, "content_size_bytes": i.ContentSize, "object_checksum": m.ObjectHash, "storage_state": "pending", "storage_immutable_version": nil, "claim_owner": nil, "claim_expires_at": nil, "inline_payload": nil, "row_version": int64(1), "observed_health": "unknown", "protected_until": f.env.record.ExpiresAt} {
		if !reflect.DeepEqual(f.d.row[col], want) {
			t.Fatalf("wrong persisted %s", col)
		}
	}
	if f.d.chunks[0]["evidence_id"] != int64(41) || f.d.chunks[0]["plaintext_sha256"] != m.Chunks[0].PlainHash || f.d.chunks[0]["ciphertext_sha256"] != m.Chunks[0].CipherHash {
		t.Fatal("wrong chunk bytes")
	}
	writes := f.d.writes
	original := cloneSystemPendingRow(f.d.row)
	receipt, e = f.run(t, true, nil)
	if e != nil || !receipt.Committed() || f.d.writes != writes || !reflect.DeepEqual(f.d.row, original) {
		t.Fatal("replay changed original", e)
	}
	if e := f.s.InsertEvidence(context.Background(), f.s.tx, f.b, f.facts); e == nil {
		t.Fatal("retained session can write after commit")
	}
}

func TestSystemPendingRollbackAndFinalGuard(t *testing.T) {
	for _, mode := range []string{"evidence", "chunk", "evidence_zero", "evidence_many", "evidence_affected", "chunk_zero", "chunk_many", "chunk_affected", "audit", "guard", "guard_row_drift", "guard_chunk_drift", "guard_state_drift", "wait_past_budget", "wait_past_capacity", "read_evidence", "read_chunks"} {
		t.Run(mode, func(t *testing.T) {
			f := newSystemPendingTestFixture(t)
			switch mode {
			case "guard":
				f.a.fail = "guard"
			case "guard_row_drift":
				f.d.onAudit = func() { f.d.row["content_checksum"] = strings.Repeat("f", 64) }
			case "guard_chunk_drift":
				f.d.onAudit = func() { f.d.chunks[0]["gcm_nonce"] = []byte("changed") }
			case "guard_state_drift":
				f.d.onAudit = func() { f.d.row["row_version"] = int64(2) }
			case "wait_past_budget":
				f.d.onAudit = func() { f.d.now = f.d.now.Add(2 * time.Minute) }
			case "wait_past_capacity":
				f.d.onAudit = func() { f.d.now = f.d.now.Add(6 * time.Second) }
			default:
				f.d.fail = mode
			}
			r, e := f.run(t, false, nil)
			if e == nil || r.Committed() || f.d.commits != 0 || f.d.rollbacks != 1 || f.d.row != nil || len(f.d.chunks) != 0 || f.d.marker != 0 {
				t.Fatal("failure did not roll back every participant", e)
			}
			if strings.Contains(e.Error(), "private") {
				t.Fatal("DB diagnostic leaked")
			}
			if (mode == "read_evidence" || mode == "read_chunks") && e != ErrUnavailable {
				t.Fatal("transient read failure mislabeled as corrupted evidence", e)
			}
		})
	}
}

func TestSystemPendingReplayRejectsChangedSQL(t *testing.T) {
	for _, mode := range []string{"owner", "manifest", "retention", "relative_key", "ready", "missing", "missing_chunk", "extra_chunk", "nonce", "chunk_order", "inline", "claim_pair", "bad_version", "bad_failure", "extra_evidence", "columns", "iteration", "close"} {
		t.Run(mode, func(t *testing.T) {
			f := newSystemPendingTestFixture(t)
			if _, e := f.run(t, false, nil); e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "owner":
				f.d.row["owner_target_public_id"] = "installation_other"
			case "manifest":
				f.d.row["envelope_hash"] = strings.Repeat("f", 64)
			case "retention":
				f.d.row["protected_until"] = nil
			case "relative_key":
				f.d.row["storage_relative_key"] = "other/key"
			case "ready":
				f.d.row["storage_state"] = "ready"
			case "missing":
				f.d.row = nil
			case "missing_chunk":
				f.d.chunks = nil
			case "extra_chunk":
				f.d.chunks = append(f.d.chunks, cloneSystemPendingRow(f.d.chunks[0]))
			case "nonce":
				f.d.chunks[0]["gcm_nonce"] = []byte("other")
			case "chunk_order":
				f.d.chunks[0]["chunk_index"] = int64(1)
			case "inline":
				f.d.row["inline_payload"] = []byte("secret")
			case "claim_pair":
				f.d.row["claim_owner"] = "aev_test"
			case "bad_version":
				f.d.row["row_version"] = int64(0)
			case "bad_failure":
				f.d.row["evidence_failure_code"] = "provider_unavailable"
			case "extra_evidence":
				f.d.queryMode = "evidence_extra"
			case "columns":
				f.d.queryMode = "chunks_columns"
			case "iteration":
				f.d.queryMode = "chunks_iterate"
			case "close":
				f.d.queryMode = "chunks_close"
			}
			writes := f.d.writes
			if r, e := f.run(t, true, nil); e == nil || r.Committed() || f.d.commits != 1 || f.d.writes != writes {
				t.Fatal("changed replay accepted", e)
			}
		})
	}
}

func TestSystemPendingUnknownReplayAndCommitUncertainty(t *testing.T) {
	f := newSystemPendingTestFixture(t)
	if _, e := f.run(t, false, nil); e != nil {
		t.Fatal(e)
	}
	f.d.row["storage_state"] = "write_unknown"
	f.d.row["evidence_failure_code"] = "deadline_exceeded"
	f.d.row["row_version"] = int64(3)
	f.d.row["claim_owner"] = "aev_prior"
	f.d.row["claim_expires_at"] = f.d.now.Add(time.Minute)
	writes := f.d.writes
	if r, e := f.run(t, true, nil); e != nil || !r.Committed() || f.d.writes != writes {
		t.Fatal("exact unknown replay failed", e)
	}
	other := newSystemPendingTestFixture(t)
	other.d.fail = "commit_unknown"
	if r, e := other.run(t, false, nil); e != pd.ErrCommitUnknown || r.Committed() {
		t.Fatal("uncertain commit reported success", e)
	}
}

func TestSystemPendingImmutablePreparationAndBoundaries(t *testing.T) {
	f := newSystemPendingTestFixture(t)
	if env, e := NewSystemPendingEnvironment(nil, Prepared{}, ProducerEvidenceChannel{}, f.b.Request.History); e == nil || env != nil {
		t.Fatal("nil authority accepted")
	}
	if env, e := NewSystemPendingEnvironment(f.a, Prepared{}, ProducerEvidenceChannel{}, f.b.Request.History); e == nil || env != nil {
		t.Fatal("request manufactured preparation")
	}
	f.a.mutateRecord = true
	p, e := f.env.PreparePending(context.Background(), f.b)
	if e != nil {
		t.Fatal(e)
	}
	if f.env.record.Manifest.Chunks[0].CipherHash == strings.Repeat("f", 64) {
		t.Fatal("authority mutated original preparation")
	}
	sample := *p.CapacityObservedAt
	f.a.sample = f.a.sample.Add(time.Hour)
	if *p.CapacityObservedAt != sample {
		t.Fatal("capacity sample refreshed")
	}
	b := f.b
	b.Request.History.InputHash = pd.Hash(strings.Repeat("f", 64))
	if _, e := f.env.PreparePending(context.Background(), b); e == nil {
		t.Fatal("different history admitted")
	}
	for _, mode := range []string{"prepare", "nil_session"} {
		f.a.fail = mode
		if _, e := f.env.PreparePending(context.Background(), f.b); e == nil {
			t.Fatal("missing authority accepted")
		}
	}
	f.a.fail = ""
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := f.env.PreparePending(ctx, f.b); e == nil {
		t.Fatal("canceled preparation admitted")
	}
	if _, e := f.env.PreparePending(nil, f.b); e == nil {
		t.Fatal("nil context admitted")
	}
}

func TestSystemPendingSessionFailureCannotBeIgnored(t *testing.T) {
	for _, mode := range []string{"second_lock", "second_insert", "wrong_binding", "missing_insert", "missing_existing_fact"} {
		t.Run(mode, func(t *testing.T) {
			f := newSystemPendingTestFixture(t)
			r, e := f.run(t, false, func(tx *pd.Transaction) error {
				switch mode {
				case "second_lock":
					_, _ = f.s.LockEvidence(context.Background(), tx, f.b, f.facts)
				case "second_insert":
					_ = f.s.InsertEvidence(context.Background(), tx, f.b, f.facts)
				case "wrong_binding":
					b := f.b
					b.GrantVersion = "9"
					_ = f.s.InsertEvidence(context.Background(), tx, b, f.facts)
				case "missing_insert":
					f.s.inserted = false
				case "missing_existing_fact":
					f.facts.Evidence.Existing = false
				}
				return nil
			})
			if e == nil || r.Committed() || f.d.row != nil || f.d.marker != 0 {
				t.Fatal("ignored adapter failure committed", e)
			}
		})
	}
}
