package systembackupevidence

import (
	"bytes"
	"context"
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
)

// Real collector/authentication/group reconstruction/capacity SQL, scripted
// atomic transport only. Owner/reference eligibility and capacity are fixtures;
// this is not InnoDB/FK/grants, physical storage or production acceptance.
type retentionGCModel struct {
	*admissionTxDB
	early                         *gcEarlyModel
	taskEligibility               *gcTaskEligibilityModel
	producerEligibility           *gcProducerModel
	direct                        *gcDirectModel
	stone, savedStone             []driver.Value
	worker                        []driver.Value
	workerOriginal                []driver.Value
	chunk                         bool
	writes                        []string
	queries                       []string
	fail                          string
	afterWrite                    func(string)
	mutateRead                    func(string, []driver.Value) []driver.Value
	resurrectPublic, resurrectKey bool
	connectionEvents              []string
}

func (d *retentionGCModel) Connect(context.Context) (driver.Conn, error) {
	d.connectionEvents = append(d.connectionEvents, "connect")
	return d, nil
}
func (d *retentionGCModel) Close() error {
	if d.active {
		d.t.Error("GC connection closed before transaction completed")
	}
	d.connectionEvents = append(d.connectionEvents, "close")
	return nil
}
func (d *retentionGCModel) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	_, err := d.admissionTxDB.BeginTx(ctx, o)
	d.savedStone = append([]driver.Value(nil), d.stone...)
	d.workerOriginal = append([]driver.Value(nil), d.worker...)
	if d.early != nil {
		d.early.begin()
	}
	if d.taskEligibility != nil {
		d.taskEligibility.begin()
	}
	if d.producerEligibility != nil {
		if _, e := d.producerEligibility.BeginTx(ctx, o); e != nil {
			return nil, e
		}
	}
	if d.direct != nil {
		d.direct.begin()
	}
	return d, err
}
func (d *retentionGCModel) Rollback() error {
	d.resurrectPublic, d.resurrectKey = false, false
	if d.early != nil {
		d.early.rollback()
	}
	if d.taskEligibility != nil {
		d.taskEligibility.rollback()
	}
	if d.producerEligibility != nil {
		_ = d.producerEligibility.Rollback()
	}
	if d.direct != nil {
		d.direct.rollback()
	}
	d.stone = append([]driver.Value(nil), d.savedStone...)
	d.worker = append([]driver.Value(nil), d.workerOriginal...)
	return d.admissionTxDB.Rollback()
}
func (d *retentionGCModel) row(q string, v ...driver.Value) (driver.Rows, error) {
	if d.mutateRead != nil {
		v = d.mutateRead(q, append([]driver.Value(nil), v...))
	}
	return admissionTxRow(v...), nil
}
func (d *retentionGCModel) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	d.queries = append(d.queries, q)
	parameters := strings.Count(q, "?")
	if q == downloadGCDirectColumnsSQL {
		// Both '?' characters here are INSIDE the literal metadata regexp,
		// not driver parameters. This closed query has no bound arguments.
		parameters = 0
	}
	if parameters != len(a) {
		return nil, errors.New("GC query placeholder mismatch")
	}
	if d.fail == "query:"+q {
		return nil, errors.New("PRIVATE GC query")
	}
	if d.early != nil {
		if rows, ok, err := d.early.query(q, a); ok {
			return rows, err
		}
	}
	if d.direct != nil {
		if rows, ok, err := d.direct.query(q, a); ok {
			return rows, err
		}
	}
	if d.taskEligibility != nil {
		if rows, ok, err := d.taskEligibility.query(q, a); ok {
			return rows, err
		}
	}
	if d.producerEligibility != nil {
		producerQuery := q == downloadGCTaskDatabaseSQL || q == downloadGCProducerTablesSQL
		for _, definition := range producerDownloadDefinitions() {
			producerQuery = producerQuery || q == producerDownloadSQL(definition, true) || q == producerDownloadSQL(definition, false)
		}
		if producerQuery {
			return d.producerEligibility.QueryContext(ctx, q, a)
		}
	}
	switch q {
	case downloadGCAbsentOperationPublicSQL, downloadGCAbsentOperationKeySQL:
		if a[0].Value != d.saved.op[1] || q == downloadGCAbsentOperationPublicSQL && a[1].Value != d.saved.op[0] || q == downloadGCAbsentOperationKeySQL && (a[1].Value != d.saved.op[4] || a[2].Value != d.saved.op[5]) {
			return nil, errors.New("GC absent original unique key scope")
		}
		if q == downloadGCAbsentOperationPublicSQL && d.resurrectPublic || q == downloadGCAbsentOperationKeySQL && d.resurrectKey {
			return admissionTxRow(int64(9001)), nil
		}
		return &admissionTxRows{width: 1}, nil
	case downloadGCActorHintSQL:
		if len(d.m.op) != 14 || len(d.m.receipt) != 16 || len(d.resultRetention) != 11 || a[0].Value != d.m.op[1] || a[1].Value != d.m.op[0] {
			return &admissionTxRows{width: 5}, nil
		}
		return d.row(q, int64(73), "admin", d.m.op[4], d.m.receipt[5], d.resultRetention[6])
	case downloadGCWorkerSQL:
		if !d.installationLocked || a[0].Value != d.record.Manifest.Identity.Installation || a[1].Value != "sop_99999999-9999-4999-8999-999999999999" {
			return nil, errors.New("GC worker scope")
		}
		return d.row(q, d.worker...)
	case downloadGCTombstoneSourceKeySQL, downloadGCTombstoneIdempotencyKeySQL:
		if !d.opKeyLocked || d.ownerLocked {
			return nil, errors.New("GC marker key outside L3")
		}
		if len(d.stone) > 0 {
			return admissionTxRow(d.stone[0]), nil
		}
		return &admissionTxRows{width: 1}, nil
	case downloadGCTombstoneReadSQL:
		if len(d.stone) == 0 {
			return &admissionTxRows{width: 23}, nil
		}
		return d.row(q, d.stone...)
	case downloadGCEvidenceHintSQL:
		i := d.record.Manifest.Identity
		return d.row(q, i.Installation, i.OwnerType, i.OwnerID, i.Type, i.Classification, i.ContentHash, i.ContentSize, i.Media, d.record.CreatedAt)
	case downloadGCDeletedEvidenceSQL:
		r := d.record
		i := r.Manifest.Identity
		if !d.ownerLocked || len(d.groupReads) == 0 {
			return nil, errors.New("GC evidence before prefix")
		}
		if r.State != "deleted" || r.Ref != (Ref{}) || r.Claim != "" || !r.ClaimUntil.IsZero() || len(r.Manifest.Chunks) != 0 {
			return &admissionTxRows{width: 12}, nil
		}
		return d.row(q, i.Installation, i.OwnerType, i.OwnerID, i.Type, i.Classification, i.ContentHash, i.ContentSize, i.Media, r.RowVersion, r.ExpiresAt, nullTime(r.ProtectedUntil), r.CreatedAt)
	case downloadGCEmptyChunksSQL:
		if d.chunk {
			return admissionTxRow(int64(0)), nil
		}
		return &admissionTxRows{width: 1}, nil
	case "SELECT id FROM system_backup_v2_operations WHERE id=?":
		if len(d.m.op) > 0 {
			return admissionTxRow(int64(73)), nil
		}
		return &admissionTxRows{width: 1}, nil
	case "SELECT operation_id FROM system_backup_v2_download_admission_receipts WHERE operation_id=?":
		if len(d.m.receipt) > 0 {
			return admissionTxRow(int64(73)), nil
		}
		return &admissionTxRows{width: 1}, nil
	case "SELECT operation_id FROM system_backup_v2_download_result_receipts WHERE operation_id=?":
		if len(d.resultRetention) > 0 {
			return admissionTxRow(int64(73)), nil
		}
		return &admissionTxRows{width: 1}, nil
	case "SELECT id FROM system_backup_v2_strong_auth_nonces WHERE operation_id=? LIMIT 1":
		if len(d.nonce) > 0 {
			return admissionTxRow(int64(95)), nil
		}
		return &admissionTxRows{width: 1}, nil
	case "SELECT id FROM audit_logs WHERE id=?":
		if a[0].Value == d.id && len(d.body) > 0 || a[0].Value == int64(1730) && len(d.resultBody) > 0 {
			return admissionTxRow(a[0].Value), nil
		}
		return &admissionTxRows{width: 1}, nil
	}
	return d.admissionTxDB.QueryContext(ctx, q, a)
}
func (d *retentionGCModel) ExecContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	var want []driver.Value
	if strings.Count(q, "?") != len(a) {
		return nil, errors.New("GC mutation placeholder mismatch")
	}
	if d.fail == "exec:"+q {
		return nil, errors.New("PRIVATE GC write")
	}
	if d.fail == "zero:"+q {
		return admissionRecordsResult{rows: 0}, nil
	}
	switch q {
	case downloadGCTombstoneInsertSQL:
		if len(a) != 12 || len(d.stone) > 0 {
			return nil, errors.New("GC marker insert shape")
		}
		v := admissionValues(a)
		d.stone = []driver.Value{int64(777), "system-backup-compact-tombstone.v1", "operation", v[0], v[1], "admin", v[2], "getSystemBackupEvidence", v[3], v[4], "succeeded", "none", nil, nil, v[5], v[6], v[7], v[8], v[9], v[10], "standard", v[11], int64(1)}
	case downloadGCDeleteResultSQL:
		v := d.resultRetention
		if len(v) != 11 {
			return nil, errors.New("GC deleted result twice")
		}
		want = append(append([]driver.Value(nil), v[:7]...), v[8], v[7], v[9], v[10])
		d.resultRetention = nil
	case downloadGCDeleteNonceSQL:
		v := d.nonce
		if len(v) != 16 {
			return nil, errors.New("GC deleted nonce twice")
		}
		want = []driver.Value{int64(95), v[0], v[10], v[11], v[4], v[5], v[12]}
		d.nonce = nil
	case downloadGCDeleteReceiptSQL:
		v := d.m.receipt
		if len(v) != 16 {
			return nil, errors.New("GC deleted receipt twice")
		}
		want = []driver.Value{v[0], v[1], v[2], v[3], v[4], v[5], v[8], v[11], v[15]}
		d.m.receipt = nil
	case downloadGCDeleteOperationSQL:
		v := d.m.op
		if len(v) != 14 {
			return nil, errors.New("GC deleted operation twice")
		}
		want = []driver.Value{int64(73), v[1], v[0], v[2], v[3], v[6]}
		d.m.op = nil
	case downloadGCDeleteAuditSQL:
		if a[0].Value == int64(1730) {
			want = []driver.Value{int64(1730), int64(42), "system_backup.evidence_download.result", d.resultCreated}
			d.resultBody = nil
		} else if a[0].Value == d.id {
			want = []driver.Value{d.id, int64(42), "system_backup.evidence_download.intent", d.created}
			d.body = nil
		} else {
			return nil, errors.New("GC unexpected audit")
		}
	default:
		return d.admissionTxDB.ExecContext(ctx, q, a)
	}
	if want != nil && !reflect.DeepEqual(admissionValues(a), want) {
		return nil, fmt.Errorf("GC CAS does not match stored facts: %s", q)
	}
	d.writes = append(d.writes, q)
	if d.afterWrite != nil {
		d.afterWrite(q)
	}
	return admissionRecordsResult{rows: 1, id: 777}, nil
}

type retentionGCPolicy struct {
	d                             *retentionGCModel
	tx                            *sql.Tx
	scope                         DownloadRetentionGCScope
	checks                        int
	denyLock, denyGuard, nilGuard bool
	onCheck                       func(int)
	taskGuard                     *DownloadGCTaskEligibilityGuard
	producerGuard                 *DownloadGCProducerEligibilityGuard
}

func (p *retentionGCPolicy) Lock(ctx context.Context, tx *sql.Tx, s DownloadRetentionGCScope, at time.Time) (DownloadRetentionGCGuard, error) {
	if p.nilGuard {
		return (*retentionGCPolicy)(nil), nil
	}
	if p.denyLock || !p.d.opKeyLocked || p.d.ownerLocked || !digestPattern.MatchString(s.PrincipalSHA256) || s.WorkerOperation == s.Operation || s.OperationID != 73 || s.EvidenceID != 61 || s.IntentAuditID != p.d.id || s.ResultAuditID != 1730 {
		return nil, ErrDenied
	}
	p.tx, p.scope = tx, s
	if p.d.taskEligibility != nil {
		guard, err := p.d.taskEligibility.service.Lock(ctx, tx, s, at)
		if err != nil {
			return nil, err
		}
		p.taskGuard = guard
		p.d.taskEligibility.rechecking = true
	}
	if p.d.producerEligibility != nil {
		source, err := NewSQLDownloadGCProducerEligibility(DownloadGCProducerEligibilityConfig{Database: s.Database, Installation: s.Installation, Root: "evidence"})
		if err != nil {
			return nil, err
		}
		guard, err := source.Lock(ctx, tx, s, at)
		if err != nil {
			return nil, err
		}
		p.producerGuard = guard
		p.d.producerEligibility.rechecking = true
	}
	p.d.ownerLocked = true
	return p, nil
}
func (p *retentionGCPolicy) Recheck(ctx context.Context, tx *sql.Tx, s DownloadRetentionGCScope, at time.Time) error {
	p.checks++
	if p.onCheck != nil {
		p.onCheck(p.checks)
	}
	if p.denyGuard || tx != p.tx || s != p.scope || ctx.Err() != nil {
		return ErrDenied
	}
	if p.taskGuard != nil {
		return p.taskGuard.Recheck(ctx, tx, s, at)
	}
	if p.producerGuard != nil {
		return p.producerGuard.Recheck(ctx, tx, s, at)
	}
	return nil
}

type retentionGCFixture struct {
	p                  *admissionPinnedFixture
	d                  *retentionGCModel
	policy             *retentionGCPolicy
	s                  *SQLDownloadRetentionGC
	ctx                context.Context
	operation          string
	commits, rollbacks int
}

func rewindDownloadGCGroup(t *testing.T, d *admissionTxDB, overdue time.Duration) {
	t.Helper()
	delta := d.m.receipt[15].(time.Time).Sub(d.now) + overdue
	d.record.CreatedAt = d.record.CreatedAt.Add(-delta)
	for _, values := range [][]driver.Value{d.m.op, d.m.receipt, d.nonce, d.resultRetention} {
		for n, v := range values {
			if at, ok := v.(time.Time); ok {
				values[n] = at.Add(-delta)
			}
		}
	}
	r, err := DecodeCanonicalDownloadAdmissionReceipt(d.m.receipt[6].([]byte))
	if err != nil {
		t.Fatal(err)
	}
	r.AdmittedAt = r.AdmittedAt.Add(-delta)
	r.ClaimExpiresAt = r.ClaimExpiresAt.Add(-delta)
	actor, err := strconv.ParseInt(d.m.op[4].(string), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	o := DownloadAdmissionOperationFacts{Installation: d.m.op[1].(string), OperationID: d.m.op[0].(string), EvidenceID: d.m.op[2].(string), ActorID: actor, IdempotencyKey: d.m.op[5].(string), RequestHash: d.m.op[6].(string), DeadlineAt: d.m.op[9].(time.Time), AdmittedAt: d.m.op[12].(time.Time), RowVersion: 1}
	private, err := CanonicalDownloadAdmissionReceipt(r)
	if err != nil {
		t.Fatal(err)
	}
	public, err := CanonicalDownloadAdmissionOperation(o)
	if err != nil {
		t.Fatal(err)
	}
	d.m.receipt[6], d.m.receipt[7], d.m.receipt[8] = private, int64(len(private)), hash(private)
	d.m.receipt[9], d.m.receipt[10], d.m.receipt[11] = public, int64(len(public)), hash(public)
	intent, err := decodeDownloadAudit(d.body, 8192)
	if err != nil {
		t.Fatal(err)
	}
	at, err := time.Parse("2006-01-02T15:04:05.000000Z", intent["intent_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	intent["intent_at"] = at.Add(-delta).Format("2006-01-02T15:04:05.000000Z")
	d.body = canonical(intent)
	d.created = d.created.Add(-delta)
	d.consumed = d.consumed.Add(-delta)
	d.resultCreated = d.resultCreated.Add(-delta)
	result, err := decodeDownloadAudit(d.resultBody, maxDownloadResultBytes)
	if err != nil {
		t.Fatal(err)
	}
	resultAt := d.resultRetention[9].(time.Time)
	var observation DownloadResultObservation
	observation.Outcome = result["outcome"].(string)
	if _, err = fmt.Sscan(string(result["bytes_written"].(json.Number)), &observation.BytesWritten); err != nil {
		t.Fatal(err)
	}
	d.resultBody = downloadResultReceiptBody(r, d.m.receipt[15].(time.Time), observation, resultAt)
	d.resultRetention[7], d.resultRetention[8] = int64(len(d.resultBody)), hash(d.resultBody)
}

func newRetentionGCFixture(t *testing.T) *retentionGCFixture {
	t.Helper()
	f, operation := retentionGroupFixture(t, true)
	return newRetentionGCFixtureFromGroup(t, f, operation, time.Hour)
}

func newRetentionGCFixtureFromGroup(t *testing.T, f *admissionTxFixture, operation string, overdue time.Duration) *retentionGCFixture {
	t.Helper()
	p := newAdmissionPinnedFixtureFromBase(t, f)
	rewindDownloadGCGroup(t, f.db, overdue)
	r := f.db.record
	r.State = "deleted"
	r.Ref = Ref{}
	r.Claim = ""
	r.ClaimUntil = time.Time{}
	r.Manifest.Chunks = nil
	r.RowVersion += 3
	r.ExpiresAt = f.db.now.Add(-time.Hour)
	r.ProtectedUntil = f.db.now.Add(-time.Hour)
	f.db.record = r
	d := &retentionGCModel{admissionTxDB: f.db}
	d.early = newGCEarlyModel(t, d, true)
	d.direct = newGCDirectModel(d)
	db := sql.OpenDB(d)
	t.Cleanup(func() { db.Close() })
	registry := f.service.registry
	registry.DB = db
	policy := &retentionGCPolicy{d: d}
	peer := newTaskFixture(t, false)
	c := DownloadRetentionGCConfig{Registry: registry, Policy: policy, Capacity: p.configuration.Capacity, MeasuredReservationBytes: 65536, ConfigVersion: 1, ConfigSHA256: hash(f.db.config.CanonicalJSON()), OperationID: "sop_99999999-9999-4999-8999-999999999999", OperationClaim: "metadata-gc-secret", OperationRowVersion: 7, ClientCAPEM: peer.c.ClientCAPEM, ClientCASHA256: peer.c.ClientCASHA256, CertificateSHA256: peer.c.CertificateSHA256, ExpiresAt: peer.c.ExpiresAt}
	var err error
	c.References, err = NewSQLDownloadGCDirectReferences(DownloadGCDirectReferencesConfig{Database: d.identity, Installation: r.Manifest.Identity.Installation, MaintenanceReceipts: "installed"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSQLDownloadRetentionGC(c)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := s.AuthenticateRequest(peer.request)
	if err != nil {
		t.Fatal(err)
	}
	// Registry/file/certificate setup can take more than the collector's five
	// second SQL-clock skew budget on a busy Windows host. Sample the NEW GC
	// worker and its synthetic capacity observation only after that setup,
	// before its first transaction. Do not renew any original download fact,
	// move its retention cutoff, or weaken the production clock check.
	d.now = time.Now().UTC().Truncate(time.Microsecond)
	d.worker = []driver.Value{"control_metadata_gc", "system", r.Manifest.Identity.Installation, "system", "system:controller", "running", "metadata-gc-secret", d.now.Add(time.Minute), int64(7), d.now.Add(2 * time.Minute), "system-backup-operation.v1"}
	p.report.ObservedAt = d.now
	p.writeReport(t)
	return &retentionGCFixture{p, d, policy, s, ctx, operation, f.db.commits, f.db.rollbacks}
}

func TestDownloadRetentionGCOneTransactionAndPrivateFacts(t *testing.T) {
	f := newRetentionGCFixture(t)
	oldEvidence := f.d.record
	if err := f.s.Collect(f.ctx, f.operation); err != nil {
		t.Fatal(err, f.d.calls, f.d.writes)
	}
	if f.d.commits != f.commits+1 || f.d.active || len(f.d.stone) != 23 || !reflect.DeepEqual(f.d.record, oldEvidence) {
		t.Fatal("GC did not keep one commit and deleted envelope")
	}
	if len(f.d.m.op)+len(f.d.m.receipt)+len(f.d.nonce)+len(f.d.resultRetention)+len(f.d.body)+len(f.d.resultBody) != 0 {
		t.Fatal("group detail remains")
	}
	want := []string{downloadGCTombstoneInsertSQL, downloadGCDeleteResultSQL, downloadGCDeleteNonceSQL, downloadGCDeleteReceiptSQL, downloadGCDeleteOperationSQL, downloadGCDeleteAuditSQL, downloadGCDeleteAuditSQL}
	if !reflect.DeepEqual(f.d.writes, want) {
		t.Fatal("GC FK order changed")
	}
	cycle, err := strconv.ParseInt(fmt.Sprint(f.d.configCells["control_metadata_retention_seconds"]), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if f.policy.checks != 2 || !f.d.stone[19].(time.Time).Add(time.Duration(cycle)*time.Second).Equal(f.d.stone[21].(time.Time)) {
		t.Fatal("wrong standard tombstone cycle")
	}
	if bytes.Contains(canonical(f.d.stone), []byte("metadata-gc-secret")) {
		t.Fatal("raw worker claim in marker")
	}
	for _, v := range []any{f.s, *f.s, f.s.c} {
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("private GC state serialized")
		}
		if strings.Contains(fmt.Sprintf("%#v", v), "metadata-gc-secret") {
			t.Fatal("private GC claim formatted")
		}
	}
}

func TestDownloadRetentionGCWriteFailuresRollBackWholeGroup(t *testing.T) {
	for _, q := range []string{downloadGCTombstoneInsertSQL, downloadGCDeleteResultSQL, downloadGCDeleteNonceSQL, downloadGCDeleteReceiptSQL, downloadGCDeleteOperationSQL, downloadGCDeleteAuditSQL} {
		for _, mode := range []string{"exec:", "zero:"} {
			t.Run(mode+strings.Split(q, " ")[0]+fmt.Sprint(len(q)), func(t *testing.T) {
				f := newRetentionGCFixture(t)
				before := f.d.reserved
				f.d.fail = mode + q
				if err := f.s.Collect(f.ctx, f.operation); err == nil {
					t.Fatal("failed GC succeeded")
				}
				if f.d.commits != f.commits || f.d.rollbacks != f.rollbacks+1 || len(f.d.stone) != 0 || len(f.d.m.op) != 14 || len(f.d.m.receipt) != 16 || len(f.d.nonce) != 16 || len(f.d.resultRetention) != 11 || len(f.d.body) == 0 || len(f.d.resultBody) == 0 || f.d.reserved != before {
					t.Fatal("partial group/marker/budget escaped rollback")
				}
			})
		}
	}
}

func TestDownloadRetentionGCWorkerAndPeerBoundaries(t *testing.T) {
	for _, mode := range []string{"no_peer", "other_instance", "wrong_kind", "wrong_installation", "wrong_actor", "stale_claim", "stale_version", "expired_lease", "expired_deadline", "worker_schema", "config", "policy", "nil_guard", "retained", "ready", "live_claim", "chunks", "protected", "row_version", "clock_future"} {
		t.Run(mode, func(t *testing.T) {
			f := newRetentionGCFixture(t)
			ctx := f.ctx
			switch mode {
			case "no_peer":
				ctx = context.Background()
			case "other_instance":
				other := *f.s
				f.s = &other
			case "wrong_kind":
				f.d.worker[0] = "evidence_gc"
			case "wrong_installation":
				f.d.worker[2] = "installation_foreign"
			case "wrong_actor":
				f.d.worker[4] = "42"
			case "stale_claim":
				f.d.worker[6] = "other-claim"
			case "stale_version":
				f.d.worker[8] = int64(8)
			case "expired_lease":
				f.d.worker[7] = f.d.now
			case "expired_deadline":
				f.d.worker[9] = f.d.now
			case "worker_schema":
				f.d.worker[10] = "system-backup-operation.future"
			case "config":
				f.s.c.ConfigSHA256 = strings.Repeat("f", 64)
			case "policy":
				f.policy.denyLock = true
			case "nil_guard":
				f.policy.nilGuard = true
			case "retained":
				rewindDownloadGCGroup(t, f.d.admissionTxDB, -time.Hour)
			case "ready":
				f.d.record.State = "ready"
			case "live_claim":
				f.d.record.Claim = "live"
			case "chunks":
				f.d.chunk = true
			case "protected":
				f.d.record.ProtectedUntil = f.d.now.Add(time.Hour)
			case "row_version":
				f.d.record.RowVersion = 1
			case "clock_future":
				f.d.now = f.d.now.Add(time.Minute)
			}
			if err := f.s.Collect(ctx, f.operation); err == nil || len(f.d.writes) != 0 || f.d.commits != f.commits {
				t.Fatal("unsafe GC reached a write", err, f.d.writes)
			}
		})
	}
}

func TestDownloadRetentionGCMarkerReadbackIsComplete(t *testing.T) {
	for index := 0; index < 23; index++ {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			f := newRetentionGCFixture(t)
			f.d.mutateRead = func(q string, v []driver.Value) []driver.Value {
				if q != downloadGCTombstoneReadSQL {
					return v
				}
				switch value := v[index].(type) {
				case int64:
					v[index] = value + 1
				case string:
					v[index] = value + "changed"
				case time.Time:
					v[index] = value.Add(time.Microsecond)
				default:
					v[index] = "non-null"
				}
				return v
			}
			if err := f.s.Collect(f.ctx, f.operation); err == nil || f.d.commits != f.commits || len(f.d.stone) != 0 || len(f.d.m.op) != 14 {
				t.Fatal("marker projection drift escaped rollback", index, err)
			}
		})
	}
}

func TestDownloadRetentionGCFinalGuardsAndLateWrites(t *testing.T) {
	for _, mode := range []string{"initial_guard", "final_guard", "marker_changed", "evidence_changed", "claim_changed", "lease_changed", "audit_changed_after_operation", "audit_time_changed_after_result", "resurrected_operation", "resurrected_public_key", "resurrected_idempotency_key"} {
		t.Run(mode, func(t *testing.T) {
			f := newRetentionGCFixture(t)
			f.policy.onCheck = func(n int) {
				if n == 1 && mode == "initial_guard" || n == 2 && mode == "final_guard" {
					f.policy.denyGuard = true
				}
				if n != 2 {
					return
				}
				switch mode {
				case "marker_changed":
					f.d.stone[21] = f.d.now.Add(time.Second)
				case "evidence_changed":
					f.d.record.RowVersion++
				case "claim_changed":
					f.d.worker[6] = "replacement"
				case "lease_changed":
					f.d.worker[7] = f.d.now.Add(2 * time.Minute)
				case "resurrected_operation":
					f.d.m.op = append([]driver.Value(nil), f.d.saved.op...)
				}
			}
			f.d.afterWrite = func(q string) {
				if q == downloadGCDeleteAuditSQL && len(f.d.body) == 0 {
					f.d.resurrectPublic = mode == "resurrected_public_key"
					f.d.resurrectKey = mode == "resurrected_idempotency_key"
				}
				if mode == "audit_changed_after_operation" && q == downloadGCDeleteOperationSQL {
					f.d.resultBody = []byte(`{"changed":true}`)
				}
				if mode == "audit_time_changed_after_result" && q == downloadGCDeleteAuditSQL && len(f.d.resultBody) == 0 {
					f.d.created = f.d.created.Add(time.Second)
				}
			}
			if err := f.s.Collect(f.ctx, f.operation); err == nil || f.d.commits != f.commits || len(f.d.stone) != 0 || len(f.d.m.op) != 14 || len(f.d.m.receipt) != 16 || f.d.resurrectPublic || f.d.resurrectKey {
				t.Fatal("late mutation escaped whole transaction", err, f.d.writes)
			}
		})
	}
}

func TestDownloadRetentionGCUnknownCommitIsNotRetried(t *testing.T) {
	f := newRetentionGCFixture(t)
	f.d.commitUnknown = true
	if err := f.s.Collect(f.ctx, f.operation); !errors.Is(err, ErrDownloadRetentionGCCommitUnknown) {
		t.Fatal("unknown commit was concealed", err)
	}
	if f.d.commits != f.commits+1 || len(f.d.stone) != 23 || len(f.d.m.op) != 0 {
		t.Fatal("unknown commit retried or claimed rollback")
	}
}

func TestDownloadRetentionGCExpiryEquality(t *testing.T) {
	f := newRetentionGCFixture(t)
	// Audit created_at is whole seconds, but the receipt retention timestamp
	// has the original SQL clock's microsecond phase. Shift the group by an
	// INTEGER number of seconds, preserving both timestamp contracts. Choose
	// the next clock with that original phase, never below the existing sample.
	retain := f.d.m.receipt[15].(time.Time)
	at := f.d.now.Truncate(time.Second).Add(time.Duration(retain.Nanosecond()))
	if at.Before(f.d.now) {
		at = at.Add(time.Second)
	}
	if retain.Sub(at)%time.Second != 0 {
		t.Fatal("expiry fixture would fractionally shift original audits")
	}
	f.d.now = at
	rewindDownloadGCGroup(t, f.d.admissionTxDB, 0)
	if err := f.s.Collect(f.ctx, f.operation); err != nil {
		t.Fatal("exact expired cutoff denied", err, "clock", f.d.now, "capacity_sample", f.d.sample, "intent_created", f.d.created, "result_created", f.d.resultCreated, "queries", f.d.queries)
	}
}
