package systembackupevidence

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// Real C1 codecs/projections and prepared encrypted capability, scripted SQL.
// No actual MySQL lock, complete GC policy, grants or physical-capacity proof.
type gcProducerModel struct {
	data                *producerDownloadModel
	tables, savedTables [][]driver.Value
	saved               map[string][]pd.StoredRecord
	locked              map[string]bool
	queries             []string
	lastStage           int
	rechecking          bool
	failQuery           string
	afterHint           func()
}

func cloneGCProducerRows(in map[string][]pd.StoredRecord) map[string][]pd.StoredRecord {
	out := map[string][]pd.StoredRecord{}
	for table, rows := range in {
		for _, r := range rows {
			next := pd.StoredRecord{Table: r.Table, Columns: map[string]any{}}
			for k, v := range r.Columns {
				if b, ok := v.([]byte); ok {
					v = append([]byte(nil), b...)
				}
				next.Columns[k] = v
			}
			out[table] = append(out[table], next)
		}
	}
	return out
}
func (m *gcProducerModel) Connect(context.Context) (driver.Conn, error) { return m, nil }
func (m *gcProducerModel) Driver() driver.Driver                        { return gcTaskDriver{} }
func (*gcProducerModel) Prepare(string) (driver.Stmt, error)            { return nil, ErrDenied }
func (*gcProducerModel) Close() error                                   { return nil }
func (*gcProducerModel) Begin() (driver.Tx, error)                      { return nil, ErrDenied }
func (m *gcProducerModel) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	if o.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || o.ReadOnly {
		return nil, ErrDenied
	}
	m.saved = cloneGCProducerRows(m.data.rows)
	m.savedTables = cloneGCEarlyRows(m.tables)
	m.locked = map[string]bool{}
	m.lastStage = 0
	m.rechecking = false
	return m, nil
}
func (*gcProducerModel) Commit() error { return errors.New("component must not commit") }
func (m *gcProducerModel) Rollback() error {
	m.data.rows = m.saved
	m.tables = m.savedTables
	return nil
}
func (*gcProducerModel) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return nil, errors.New("component must not write")
}
func (m *gcProducerModel) QueryContext(_ context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	m.queries = append(m.queries, q)
	if q == m.failQuery {
		return nil, errors.New("PRIVATE producer GC transport")
	}
	switch q {
	case downloadGCTaskDatabaseSQL:
		return admissionTxRow(m.data.base.f.db.identity.ServerUUID, m.data.base.f.db.identity.Database), nil
	case downloadGCProducerTablesSQL:
		return &admissionTxRows{width: 3, data: cloneGCEarlyRows(m.tables)}, nil
	}
	for _, d := range producerDownloadDefinitions() {
		locking := strings.HasSuffix(q, " FOR UPDATE")
		if q != producerDownloadSQL(d, locking) {
			continue
		}
		if len(a) != 1 || a[0].Value != m.data.base.f.initial.Manifest.Identity.ID {
			return nil, ErrDenied
		}
		if locking {
			key := gcTaskRangeKey(q, a[0].Value)
			if !m.locked[key] {
				if m.rechecking || d.stage < m.lastStage {
					return nil, errors.New("new prefix key after later phase")
				}
				m.locked[key] = true
				m.lastStage = d.stage
			}
		}
		fields := strings.Fields(d.fields)
		out := &admissionTxRows{width: len(fields)}
		for _, r := range m.data.rows[d.table] {
			row := make([]driver.Value, len(fields))
			for n, k := range fields {
				v := r.Columns[k]
				if k == "record_bytes" {
					if b, ok := v.([]byte); ok && len(b) > d.limit {
						v = nil
					}
				}
				if u, ok := v.(uint64); ok {
					v = strconv.FormatUint(u, 10)
				}
				row[n] = v
			}
			out.data = append(out.data, row)
		}
		if !locking && d.table == "system_backup_producer_evidence_bindings" && m.afterHint != nil {
			f := m.afterHint
			m.afterHint = nil
			f()
		}
		return out, nil
	}
	return nil, ErrDenied
}

type gcProducerFixture struct {
	m       *gcProducerModel
	service *SQLDownloadGCProducerEligibility
	tx      *sql.Tx
	scope   DownloadRetentionGCScope
	now     time.Time
	receipt pd.ReceiptRecord
}

func newGCProducerFixture(t *testing.T) *gcProducerFixture {
	t.Helper()
	f, _, _, p := producerDownloadFixture(t)
	receipt := seedGCProducerRows(t, p)
	m := &gcProducerModel{data: p}
	for _, table := range taskDownloadSystemProducerTables {
		m.tables = append(m.tables, []driver.Value{table, "BASE TABLE", "InnoDB"})
	}
	db := sql.OpenDB(m)
	t.Cleanup(func() { db.Close() })
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	s, err := NewSQLDownloadGCProducerEligibility(DownloadGCProducerEligibilityConfig{Database: f.db.identity, Installation: f.initial.Manifest.Identity.Installation, Root: "evidence"})
	if err != nil {
		t.Fatal(err)
	}
	until, _ := p.history.RetentionExpiresAt.Time()
	now := until.Add(24 * time.Hour)
	scope := DownloadRetentionGCScope{Database: f.db.identity, Installation: f.initial.Manifest.Identity.Installation, WorkerOperation: "sop_99999999-9999-4999-8999-999999999999", Operation: "sop_88888888-8888-4888-8888-888888888888", PrincipalSHA256: strings.Repeat("a", 64), RequestHash: strings.Repeat("b", 64), ManifestSHA256: string(p.history.Evidence.ManifestHash), Evidence: f.initial.Manifest.Identity, EvidenceCreatedAt: f.initial.CreatedAt, OperationID: 73, EvidenceID: 61, EvidenceRowVersion: 1000, ActorID: 42, IntentAuditID: 91, ResultAuditID: 92, AdmittedAt: f.initial.CreatedAt.Add(time.Minute), RetainUntil: now.Add(-time.Hour), MinimumRetainUntil: now.Add(-time.Hour)}
	return &gcProducerFixture{m, s, tx, scope, now, receipt}
}

func seedGCProducerRows(t *testing.T, p *producerDownloadModel) pd.ReceiptRecord {
	t.Helper()
	receipt := producerDownloadReceipt(t, p)
	p.store(t, &receipt)
	for _, kind := range []string{"producer_result", "producer_receipt", "bootstrap_candidate", "hold"} {
		r := pd.ReferenceRecord{Scope: p.history.Scope, EvidenceID: p.history.Evidence.EvidenceID, ReferenceKind: kind, ReferenceKeyHash: pd.Hash(strings.Repeat("a", 64)), CreatedAt: p.history.CreatedAt, ProtectedUntil: p.history.RetentionExpiresAt}
		stored, err := pd.EncodeStoredRecord(&r)
		if err != nil {
			t.Fatal(err)
		}
		p.rows[stored.Table] = append(p.rows[stored.Table], stored)
	}
	return receipt
}
func (f *gcProducerFixture) storeReceipt(t *testing.T, r pd.ReceiptRecord) {
	t.Helper()
	d, err := pd.ResultHashes(r.Request)
	if err != nil {
		t.Fatal(err)
	}
	r.ReceiptKeyHash, r.RequestHash = d.Key, d.Request
	f.m.data.store(t, &r)
}

func TestDownloadRetentionGCProducerOriginalBinding(t *testing.T) {
	for _, mode := range []string{"valid", "superseded", "acquired", "pending", "published", "missing_history", "missing_run", "missing_receipt", "wrong_root", "manifest", "content", "creation", "future_write", "future_retention", "hint_drift", "foreign_scope", "view", "missing_table"} {
		t.Run(mode, func(t *testing.T) {
			f := newGCProducerFixture(t)
			p := f.m.data
			switch mode {
			case "superseded", "acquired", "pending", "published":
				p.run.State = mode
				p.store(t, &p.run)
			case "missing_history":
				delete(p.rows, "system_backup_producer_evidence_bindings")
			case "missing_run":
				delete(p.rows, "system_backup_producer_runs")
			case "missing_receipt":
				delete(p.rows, "system_backup_producer_result_receipts")
			case "wrong_root":
				f.service.c.Root = "other-evidence"
			case "manifest":
				f.scope.ManifestSHA256 = strings.Repeat("f", 64)
			case "content":
				f.scope.Evidence.ContentHash = strings.Repeat("e", 64)
			case "creation":
				f.scope.EvidenceCreatedAt = f.scope.EvidenceCreatedAt.Add(-time.Microsecond)
			case "future_write":
				p.history.OwnerWriteExpiresAt = systemExecutionStamp(f.now.Add(time.Second))
				p.history.RetentionExpiresAt = systemExecutionStamp(f.now.Add(time.Hour))
				p.run.OwnerWriteExpiresAt = p.history.OwnerWriteExpiresAt
				p.store(t, &p.history)
				p.store(t, &p.run)
			case "future_retention":
				p.history.RetentionExpiresAt = systemExecutionStamp(f.now.Add(time.Second))
				p.store(t, &p.history)
			case "hint_drift":
				f.m.afterHint = func() {
					h := p.history
					at, _ := h.RetentionExpiresAt.Time()
					h.RetentionExpiresAt = systemExecutionStamp(at.Add(time.Microsecond))
					p.store(t, &h)
				}
			case "foreign_scope":
				h := p.history
				h.Scope.Database = "foreign_database"
				p.store(t, &h)
			case "view":
				f.m.tables[0][1] = "VIEW"
			case "missing_table":
				f.m.tables = f.m.tables[1:]
			}
			g, err := f.service.Lock(context.Background(), f.tx, f.scope, f.now)
			allowed := mode == "valid" || mode == "superseded"
			if (err == nil) != allowed {
				t.Fatal("wrong original binding eligibility", mode, err)
			}
			if allowed {
				locks := len(f.m.locked)
				f.m.rechecking = true
				if err = g.Recheck(context.Background(), f.tx, f.scope, f.now.Add(time.Microsecond)); err != nil || len(f.m.locked) != locks {
					t.Fatal("unchanged binding recheck or lock prefix", err)
				}
			}
		})
	}
}

func TestDownloadRetentionGCProducerReceiptFacts(t *testing.T) {
	for _, mode := range []string{"valid", "grant", "input", "manifest", "expected_version", "null_version", "no_version", "future_retention", "future_commit", "other_target_generation"} {
		t.Run(mode, func(t *testing.T) {
			f := newGCProducerFixture(t)
			r := f.receipt
			switch mode {
			case "grant":
				r.Request.GrantGeneration = "99"
			case "input":
				r.Request.InputHash = pd.Hash(strings.Repeat("c", 64))
			case "manifest":
				r.Request.Evidence.ManifestHash = pd.Hash(strings.Repeat("f", 64))
			case "expected_version":
				r.Request.ExpectedEvidenceVersion = "1001"
			case "null_version":
				v := pd.Text("null")
				r.Request.Evidence.ImmutableVersion = &v
			case "no_version":
				r.Request.Evidence.ImmutableVersion = nil
			case "future_retention":
				r.RetentionExpiresAt = systemExecutionStamp(f.now.Add(time.Second))
			case "future_commit":
				r.CommittedAt = systemExecutionStamp(f.now.Add(time.Second))
				r.RetentionExpiresAt = systemExecutionStamp(f.now.Add(time.Hour))
			case "other_target_generation":
				r.Request.TargetGeneration = "99"
			}
			if mode == "null_version" || mode == "no_version" {
				// The public C1 encoder correctly refuses these invalid requests.
				// Inject C1 typed-frame corruption with a matching outer digest
				// so the component must reject it through its real record decoder.
				stored := &f.m.data.rows["system_backup_producer_result_receipts"][0]
				raw, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				raw, err = pd.CanonicalJSON(raw)
				if err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(raw)
				stored.Columns["record_bytes"], stored.Columns["record_sha256"] = raw, digest[:]
			} else {
				f.storeReceipt(t, r)
			}
			_, err := f.service.Lock(context.Background(), f.tx, f.scope, f.now)
			if (err == nil) != (mode == "valid") {
				t.Fatal("rehashed receipt escaped original facts", mode, err)
			}
		})
	}
}

func TestDownloadRetentionGCProducerReferenceRetention(t *testing.T) {
	for _, kind := range []string{"producer_result", "producer_receipt", "bootstrap_candidate", "hold"} {
		for _, mode := range []string{"expired", "active", "foreign", "duplicate"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				f := newGCProducerFixture(t)
				table := "system_backup_producer_evidence_refs"
				for n, stored := range f.m.data.rows[table] {
					if stored.Columns["reference_kind"] != kind {
						continue
					}
					var r pd.ReferenceRecord
					if pd.DecodeStoredRecord(stored, f.m.data.history.Scope, &r) != nil {
						t.Fatal("decode reference")
					}
					switch mode {
					case "active":
						r.ProtectedUntil = systemExecutionStamp(f.now.Add(time.Microsecond))
					case "foreign":
						r.Scope.Database = "foreign_database"
					}
					next, err := pd.EncodeStoredRecord(&r)
					if err != nil {
						t.Fatal(err)
					}
					f.m.data.rows[table][n] = next
					if mode == "duplicate" {
						f.m.data.rows[table] = append(f.m.data.rows[table], next)
					}
					break
				}
				_, err := f.service.Lock(context.Background(), f.tx, f.scope, f.now)
				if (err == nil) != (mode == "expired") {
					t.Fatal("wrong retained reference", kind, mode, err)
				}
			})
		}
	}
	t.Run("empty_range", func(t *testing.T) {
		f := newGCProducerFixture(t)
		delete(f.m.data.rows, "system_backup_producer_evidence_refs")
		g, err := f.service.Lock(context.Background(), f.tx, f.scope, f.now)
		if err != nil {
			t.Fatal(err)
		}
		f.m.rechecking = true
		if err = g.Recheck(context.Background(), f.tx, f.scope, f.now); err != nil {
			t.Fatal(err)
		}
		if !f.m.locked[gcTaskRangeKey(producerDownloadSQL(producerDownloadDefinitions()[3], true), f.scope.Evidence.ID)] {
			t.Fatal("empty reference range not locked")
		}
	})
}

func TestDownloadRetentionGCProducerRecheckLatchAndRollback(t *testing.T) {
	for _, mode := range []string{"run_version", "late_reference", "late_expired_reference", "metadata", "query_failure", "scope", "backward_clock"} {
		t.Run(mode, func(t *testing.T) {
			f := newGCProducerFixture(t)
			before := cloneGCProducerRows(f.m.data.rows)
			g, err := f.service.Lock(context.Background(), f.tx, f.scope, f.now)
			if err != nil {
				t.Fatal(err)
			}
			copyGuard := *g
			scope := f.scope
			now := f.now.Add(time.Microsecond)
			switch mode {
			case "run_version":
				r := f.m.data.run
				r.RowVersion = "6"
				f.m.data.store(t, &r)
			case "late_reference", "late_expired_reference":
				r := pd.ReferenceRecord{Scope: f.m.data.history.Scope, EvidenceID: f.m.data.history.Evidence.EvidenceID, ReferenceKind: "hold", ReferenceKeyHash: pd.Hash(strings.Repeat("f", 64)), CreatedAt: f.m.data.history.CreatedAt, ProtectedUntil: f.m.data.history.RetentionExpiresAt}
				if mode == "late_reference" {
					r.ProtectedUntil = systemExecutionStamp(f.now.Add(time.Hour))
				}
				s, err := pd.EncodeStoredRecord(&r)
				if err != nil {
					t.Fatal(err)
				}
				table := s.Table
				f.m.data.rows[table] = append(f.m.data.rows[table], s)
			case "metadata":
				f.m.tables[0][2] = "MyISAM"
			case "query_failure":
				f.m.failQuery = producerDownloadSQL(producerDownloadDefinitions()[0], true)
			case "scope":
				scope.RequestHash = strings.Repeat("e", 64)
			case "backward_clock":
				now = f.now.Add(-time.Microsecond)
			}
			f.m.rechecking = true
			if err = g.Recheck(context.Background(), f.tx, scope, now); err != ErrDenied || strings.Contains(fmt.Sprint(err), "PRIVATE") {
				t.Fatal("late fact accepted", mode, err)
			}
			f.m.data.rows = cloneGCProducerRows(before)
			f.m.tables = cloneGCEarlyRows(f.m.savedTables)
			f.m.failQuery = ""
			if copyGuard.Recheck(context.Background(), f.tx, f.scope, f.now.Add(2*time.Microsecond)) != ErrDenied {
				t.Fatal("failed copied guard revived")
			}
			if err = f.tx.Rollback(); err != nil || !reflect.DeepEqual(f.m.data.rows, before) {
				t.Fatal("original C1 rows not restored", err)
			}
		})
	}
}

func TestDownloadRetentionGCOriginalManifestAndCreation(t *testing.T) {
	for _, mode := range []string{"valid", "creation_after_admission", "hint_creation_drift", "late_creation"} {
		t.Run(mode, func(t *testing.T) {
			f := newRetentionGCFixture(t)
			r, err := DecodeCanonicalDownloadAdmissionReceipt(f.d.m.receipt[6].([]byte))
			if err != nil {
				t.Fatal(err)
			}
			created := f.d.record.CreatedAt
			switch mode {
			case "creation_after_admission":
				f.d.record.CreatedAt = r.AdmittedAt.Add(time.Microsecond)
			case "hint_creation_drift":
				f.d.mutateRead = func(q string, v []driver.Value) []driver.Value {
					if q == downloadGCEvidenceHintSQL {
						v[8] = created.Add(-time.Microsecond)
					}
					return v
				}
			case "late_creation":
				f.policy.onCheck = func(n int) {
					if n == 1 {
						f.d.record.CreatedAt = created.Add(time.Microsecond)
					}
				}
			}
			err = f.s.Collect(f.ctx, f.operation)
			if mode == "valid" {
				if err != nil || f.policy.scope.ManifestSHA256 != r.ManifestSHA256 || !f.policy.scope.EvidenceCreatedAt.Equal(created) {
					t.Fatal("original receipt/envelope facts not passed", err)
				}
			} else if err == nil || f.d.commits != f.commits || len(f.d.m.op) == 0 {
				t.Fatal("changed creation committed or lost original group", mode, err)
			}
		})
	}
}

// Exercise the new C1 guard inside the original collector after the actual
// admission/result services. Only SQL transport/capacity/outer policy are
// scripted. Age every original timestamp by the SAME delta; never refresh an
// original deadline or weaken the production five-second clock constraint.
func newGCProducerCollectorFixture(t *testing.T) (*retentionGCFixture, *producerDownloadModel) {
	t.Helper()
	gc, producer, err := newGCProducerCollectorFixtureWithResultReport(t, false)
	if err != nil {
		t.Fatal("paired independent producer result", err)
	}
	return gc, producer
}

func newGCProducerCollectorFixtureWithResultReport(t *testing.T, staleReport bool) (*retentionGCFixture, *producerDownloadModel, error) {
	t.Helper()
	f, authority, owners, producer := producerDownloadFixture(t)
	receipt := seedGCProducerRows(t, producer)
	receipt.Request.ExpectedEvidenceVersion = pd.Counter(strconv.FormatInt(f.initial.RowVersion, 10))
	digests, err := pd.ResultHashes(receipt.Request)
	if err != nil {
		t.Fatal(err)
	}
	receipt.ReceiptKeyHash, receipt.RequestHash = digests.Key, digests.Request
	producer.store(t, &receipt)
	f.service, err = NewDownloadAdmissionService(owners.Registry(), f.secret, &producerOwnerTestEnvironment{f.env, owners})
	if err != nil {
		t.Fatal(err)
	}
	writeCommittedProviderToken(t, authority)
	if err = sampleAAdmissionProofTime(f, time.Now().UTC().Truncate(time.Microsecond)); err != nil {
		t.Fatal(err)
	}
	committed, err := f.service.Admit(f.request)
	if err != nil {
		t.Fatal("paired producer admission", err)
	}
	var sampleResultCapacity func(time.Time) error
	baseQuery := f.db.ownerQuery
	f.db.ownerQuery = func(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, bool, error) {
		if strings.HasPrefix(q, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)") || strings.HasPrefix(q, "SELECT UTC_TIMESTAMP(6)") || strings.HasPrefix(q, "SELECT user_id,subject,credential_hash,expires_at,revoked,UTC_TIMESTAMP(6)") {
			at := time.Now().UTC().Truncate(time.Microsecond)
			if at.Before(f.db.now) {
				t.Fatal("paired SQL clock moved backwards")
			}
			f.db.now = at
			if !staleReport && sampleResultCapacity != nil {
				if err := sampleResultCapacity(at); err != nil {
					t.Fatal(err)
				}
			}
		}
		return baseQuery(ctx, q, args)
	}
	results, sampleResultCapacity := resultFixtureWithReportSampler(t, f)
	// Deterministic stale control: only the independent result observation is
	// sampled fresh below. Original admission/claim/deadline facts stay sealed.
	if err := sampleResultCapacity(f.db.now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	results.c.Registry, results.c.Owners = owners.Registry(), owners
	f.db.sessionRevoked, f.db.userActive = true, false
	beforeDeadline := committed.localDeadline
	beforeOperation := append([]driver.Value(nil), f.db.m.op...)
	beforeReceipt := append([]driver.Value(nil), f.db.m.receipt...)
	if !staleReport {
		if err := sampleResultCapacity(time.Now().UTC().Truncate(time.Microsecond)); err != nil {
			t.Fatal(err)
		}
	}
	err = results.Finish(context.Background(), committed, DownloadResultObservation{Outcome: "interrupted"})
	sampleResultCapacity = nil
	if !beforeDeadline.Equal(committed.localDeadline) || !reflect.DeepEqual(beforeOperation, f.db.m.op) || !reflect.DeepEqual(beforeReceipt, f.db.m.receipt) {
		t.Fatal("result observation sampling changed original admission facts")
	}
	if err != nil {
		return nil, producer, err
	}
	oldCreated, _ := producer.history.CreatedAt.Time()
	groupRemaining := f.db.m.receipt[15].(time.Time).Sub(f.db.now)
	shift := groupRemaining + time.Hour
	for _, stamp := range []pd.Timestamp{producer.history.OwnerWriteExpiresAt, producer.history.ObservationExpiresAt, producer.history.RetentionExpiresAt} {
		at, e := stamp.Time()
		if e != nil {
			t.Fatal(e)
		}
		if needed := at.Sub(f.db.now) + time.Hour; needed > shift {
			shift = needed
		}
	}
	// audit_logs.created_at is DATETIME(0). Preserve its actual SQL precision
	// when aging the paired group; a fractional shift would invent impossible
	// audit timestamps and be rejected before the C1 rollback being tested.
	shift = (shift/time.Second + 1) * time.Second
	gc := newRetentionGCFixtureFromGroup(t, f, committed.operationID, shift-groupRemaining)
	delta := oldCreated.Sub(gc.d.record.CreatedAt)
	age := func(stamp pd.Timestamp) pd.Timestamp {
		at, e := stamp.Time()
		if e != nil {
			t.Fatal(e)
		}
		return systemExecutionStamp(at.Add(-delta))
	}
	h := &producer.history
	h.CreatedAt, h.OwnerWriteExpiresAt, h.ObservedAt, h.ObservationExpiresAt, h.RetentionExpiresAt = age(h.CreatedAt), age(h.OwnerWriteExpiresAt), age(h.ObservedAt), age(h.ObservationExpiresAt), age(h.RetentionExpiresAt)
	producer.run.OwnerWriteExpiresAt = h.OwnerWriteExpiresAt
	producer.run.ObservedAt, producer.run.ObservationExpiresAt = &h.ObservedAt, &h.ObservationExpiresAt
	receipt.Request.ObservedAt, receipt.Request.ObservationExpiresAt = h.ObservedAt, h.ObservationExpiresAt
	receipt.CommittedAt, receipt.RetentionExpiresAt = age(receipt.CommittedAt), age(receipt.RetentionExpiresAt)
	digests, err = pd.ResultHashes(receipt.Request)
	if err != nil {
		t.Fatal(err)
	}
	receipt.ReceiptKeyHash, receipt.RequestHash = digests.Key, digests.Request
	h.TargetHash, producer.run.TargetHash = digests.Target, digests.Target
	producer.store(t, h)
	producer.store(t, &producer.run)
	producer.store(t, &receipt)
	for n, row := range producer.rows["system_backup_producer_evidence_refs"] {
		var reference pd.ReferenceRecord
		if err = pd.DecodeStoredRecord(row, h.Scope, &reference); err != nil {
			t.Fatal(err)
		}
		reference.CreatedAt, reference.ProtectedUntil = age(reference.CreatedAt), age(reference.ProtectedUntil)
		stored, e := pd.EncodeStoredRecord(&reference)
		if e != nil {
			t.Fatal(e)
		}
		producer.rows[row.Table][n] = stored
	}
	m := &gcProducerModel{data: producer}
	for _, table := range taskDownloadSystemProducerTables {
		m.tables = append(m.tables, []driver.Value{table, "BASE TABLE", "InnoDB"})
	}
	gc.d.producerEligibility = m
	return gc, producer, nil
}

func TestGCProducerResultCapacitySamplingDoesNotRenewAdmission(t *testing.T) {
	for _, stale := range []bool{true, false} {
		name := "fresh_report"
		if stale {
			name = "stale_report"
		}
		t.Run(name, func(t *testing.T) {
			gc, producer, err := newGCProducerCollectorFixtureWithResultReport(t, stale)
			if stale {
				if gc != nil || producer == nil || !errors.Is(err, ErrCapacity) {
					t.Fatal("stale result capacity observation accepted", err)
				}
			} else if err != nil || gc == nil || producer == nil {
				t.Fatal("fresh independent result observation rejected", err)
			}
		})
	}
}

func TestDownloadRetentionGCProducerCollectorOriginalResultAndRollback(t *testing.T) {
	for _, mode := range []string{"complete", "late_eligible_run", "late_expired_reference"} {
		t.Run(mode, func(t *testing.T) {
			f, producer := newGCProducerCollectorFixture(t)
			before := cloneGCProducerRows(producer.rows)
			reserved := f.d.reserved
			if mode != "complete" {
				f.d.afterWrite = func(q string) {
					if mode == "late_eligible_run" && q == downloadGCTombstoneInsertSQL {
						producer.run.RowVersion = "6"
						producer.store(t, &producer.run)
					}
					if mode == "late_expired_reference" && q == downloadGCDeleteResultSQL {
						r := pd.ReferenceRecord{Scope: producer.history.Scope, EvidenceID: producer.history.Evidence.EvidenceID, ReferenceKind: "hold", ReferenceKeyHash: pd.Hash(strings.Repeat("f", 64)), CreatedAt: producer.history.CreatedAt, ProtectedUntil: producer.history.RetentionExpiresAt}
						stored, err := pd.EncodeStoredRecord(&r)
						if err != nil {
							t.Fatal(err)
						}
						producer.rows[stored.Table] = append(producer.rows[stored.Table], stored)
					}
				}
			}
			err := f.s.Collect(f.ctx, f.operation)
			if !reflect.DeepEqual(producer.rows, before) {
				t.Fatal("C1 original rows changed or were not restored")
			}
			if mode == "complete" {
				if err != nil || f.d.commits != f.commits+1 || f.policy.producerGuard == nil || len(f.d.stone) != 23 || len(f.d.writes) != 7 || len(f.d.m.op)+len(f.d.m.receipt)+len(f.d.resultRetention) != 0 {
					t.Fatal("concrete original producer guard not composed", err, f.d.writes, f.d.queries, f.d.calls)
				}
				return
			}
			if err == nil || f.d.commits != f.commits || f.d.rollbacks != f.rollbacks+1 || len(f.d.stone) != 0 || f.d.reserved != reserved || len(f.d.m.op) == 0 || len(f.d.resultRetention) == 0 || len(f.d.writes) == 0 {
				t.Fatal("late C1 facts did not roll back whole group", err, f.d.writes, f.d.queries, f.d.calls)
			}
		})
	}
}

func TestDownloadRetentionGCProducerInputAndGuardBoundaries(t *testing.T) {
	f := newGCProducerFixture(t)
	for _, mode := range []string{"manifest", "scope", "owner", "worker", "future_retention", "future_creation"} {
		t.Run(mode, func(t *testing.T) {
			scope := f.scope
			switch mode {
			case "manifest":
				scope.ManifestSHA256 = ""
			case "scope":
				scope.Database.Database = "other_database"
			case "owner":
				scope.Evidence.OwnerID = "installation_other"
			case "worker":
				scope.WorkerOperation = scope.Operation
			case "future_retention":
				scope.RetainUntil = f.now.Add(time.Microsecond)
			case "future_creation":
				scope.EvidenceCreatedAt = scope.AdmittedAt.Add(time.Microsecond)
			}
			before := len(f.m.queries)
			if _, err := f.service.Lock(context.Background(), f.tx, scope, f.now); err != ErrDenied || len(f.m.queries) != before {
				t.Fatal("invalid scope reached SQL", mode, err)
			}
		})
	}
	var absent *SQLDownloadGCProducerEligibility
	if _, err := absent.Lock(context.Background(), f.tx, f.scope, f.now); err != ErrDenied {
		t.Fatal("nil source accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, c := range []context.Context{nil, ctx} {
		if _, err := f.service.Lock(c, f.tx, f.scope, f.now); err != ErrDenied {
			t.Fatal("invalid context accepted")
		}
	}
	for _, config := range []DownloadGCProducerEligibilityConfig{{}, {Database: f.scope.Database, Installation: f.scope.Installation, Root: "../bad"}} {
		if _, err := NewSQLDownloadGCProducerEligibility(config); err != ErrDenied {
			t.Fatal("invalid configuration accepted")
		}
	}
	g, err := f.service.Lock(context.Background(), f.tx, f.scope, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = json.Marshal(g); err == nil || strings.Contains(fmt.Sprintf("%#v", g), f.scope.Evidence.ID) {
		t.Fatal("private guard facts serialized or formatted")
	}
	other := newGCProducerFixture(t)
	if g.Recheck(context.Background(), other.tx, f.scope, f.now) != ErrDenied || g.Recheck(context.Background(), f.tx, f.scope, f.now) != ErrDenied {
		t.Fatal("cross-transaction guard revived")
	}
}

func TestDownloadRetentionGCProducerAggregateReferenceBudget(t *testing.T) {
	for _, n := range []int{maxTaskDownloadReferences - 3, maxTaskDownloadReferences - 2} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			f := newGCProducerFixture(t)
			table := "system_backup_producer_evidence_refs"
			f.m.data.rows[table] = nil
			for i := 0; i < n; i++ {
				r := pd.ReferenceRecord{Scope: f.m.data.history.Scope, EvidenceID: f.m.data.history.Evidence.EvidenceID, ReferenceKind: "hold", ReferenceKeyHash: pd.Hash(fmt.Sprintf("%064x", i+1)), CreatedAt: f.m.data.history.CreatedAt, ProtectedUntil: f.m.data.history.RetentionExpiresAt}
				s, err := pd.EncodeStoredRecord(&r)
				if err != nil {
					t.Fatal(err)
				}
				f.m.data.rows[table] = append(f.m.data.rows[table], s)
			}
			_, err := f.service.Lock(context.Background(), f.tx, f.scope, f.now)
			if (err == nil) != (n == maxTaskDownloadReferences-3) {
				t.Fatal("aggregate four-table budget was not enforced", n, err)
			}
		})
	}
}
