package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The scan and real collector share a scripted SQL connection. The scan must
// close its transaction before the collector begins. This is not InnoDB,
// physical capacity, a query-plan bound or production policy evidence.
type downloadGCBatchModel struct {
	*retentionGCModel
	upper          driver.Value
	operationTypes driver.Value
	rows           [][]driver.Value
	pageArgs       []driver.Value
	failQuery      string
	scan           bool
	scanRollbacks  int
	events         []string
}

func (m *downloadGCBatchModel) Connect(context.Context) (driver.Conn, error) { return m, nil }
func (m *downloadGCBatchModel) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	if m.scan {
		return nil, errors.New("candidate began before scan rollback")
	}
	if _, err := m.retentionGCModel.BeginTx(ctx, o); err != nil {
		return nil, err
	}
	m.events = append(m.events, "begin")
	return m, nil
}
func (m *downloadGCBatchModel) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	if q == downloadGCBatchWorkerSQL || q == downloadGCBatchSchemaSQL || q == downloadGCBatchUpperSQL || q == downloadGCBatchCandidatesSQL {
		m.queries = append(m.queries, q)
		m.scan = true
		if len(m.writes) != 0 || q != downloadGCBatchSchemaSQL && (len(a) < 1 || a[0].Value != m.record.Manifest.Identity.Installation) || q == downloadGCBatchSchemaSQL && len(a) != 0 {
			return nil, errors.New("scan changed data or installation")
		}
		m.events = append(m.events, "scan")
		if q == m.failQuery {
			return nil, errors.New("PRIVATE scan failure")
		}
		if q == downloadGCBatchWorkerSQL {
			if len(a) != 2 || a[1].Value != "sop_99999999-9999-4999-8999-999999999999" {
				return nil, errors.New("wrong scan worker")
			}
			return admissionTxRow(m.worker...), nil
		}
		if q == downloadGCBatchSchemaSQL {
			return admissionTxRow(m.operationTypes), nil
		}
		if q == downloadGCBatchUpperSQL {
			return admissionTxRow(m.upper), nil
		}
		m.pageArgs = admissionValues(a)
		return &admissionTxRows{width: 2, data: cloneGCEarlyRows(m.rows)}, nil
	}
	return m.retentionGCModel.QueryContext(ctx, q, a)
}
func (m *downloadGCBatchModel) Rollback() error {
	if m.scan {
		m.scanRollbacks++
		m.scan = false
		m.events = append(m.events, "scan_rollback")
	}
	return m.retentionGCModel.Rollback()
}
func (m *downloadGCBatchModel) Commit() error {
	if m.scan {
		return errors.New("read-only hints may not commit")
	}
	m.events = append(m.events, "collect_commit")
	return m.retentionGCModel.Commit()
}
func newDownloadGCBatchFixture(t *testing.T) (*retentionGCFixture, *downloadGCBatchModel) {
	t.Helper()
	f := newRetentionGCFixture(t)
	m := &downloadGCBatchModel{retentionGCModel: f.d, upper: int64(74), operationTypes: "enum('control_metadata_gc','evidence_download_admission')"}
	m.rows = [][]driver.Value{{int64(73), f.operation}, {int64(74), "sop_77777777-7777-4777-8777-777777777777"}}
	db := sql.OpenDB(m)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	f.s.c.Registry.DB = db
	return f, m
}

func TestDownloadRetentionGCBatchUsesFreshCollector(t *testing.T) {
	for _, mode := range []string{"collected", "revoked", "write_failed", "unknown_commit"} {
		t.Run(mode, func(t *testing.T) {
			f, m := newDownloadGCBatchFixture(t)
			original := f.d.record
			switch mode {
			case "revoked":
				f.policy.denyLock = true
			case "write_failed":
				f.d.fail = "exec:" + downloadGCTombstoneInsertSQL
			case "unknown_commit":
				f.d.commitUnknown = true
			}
			r, err := f.s.CollectBatch(f.ctx, DownloadRetentionGCBatchCursor{}, 1)
			if r.Examined != 1 || r.EndOfRange || r.Cursor.ThroughID != 74 || m.scanRollbacks != 1 || f.d.active || !reflect.DeepEqual(f.d.record, original) {
				t.Fatal("scan escaped its page or failed to close before collector", r, err, m.events)
			}
			if !reflect.DeepEqual(m.pageArgs, []driver.Value{f.s.c.Registry.Installation, int64(0), int64(74), int64(2)}) {
				t.Fatal("installation, numeric cursor or lookahead was not bound", m.pageArgs)
			}
			rollback := -1
			for n, event := range m.events {
				if event == "scan_rollback" {
					rollback = n
				}
				if n > 0 && event == "begin" && rollback < 0 {
					t.Fatal("collector used scan transaction")
				}
			}
			if len(m.events) < 5 || m.events[0] != "begin" || rollback < 0 {
				t.Fatal("scan/collector transactions not observed", m.events)
			}
			switch mode {
			case "collected":
				if err != nil || r.Collected != 1 || r.Rejected != 0 || r.Cursor.AfterID != 73 || f.d.commits != f.commits+1 || len(f.d.stone) != 23 || len(f.d.writes) != 7 || f.policy.checks != 2 {
					t.Fatal("real collector checks/one commit missing", r, err)
				}
			case "revoked":
				if err != nil || r.Collected != 0 || r.Rejected != 1 || r.Cursor.AfterID != 73 || f.d.commits != f.commits || len(f.d.writes) != 0 {
					t.Fatal("batch bypassed current authority", r, err)
				}
			case "write_failed":
				if err != ErrAudit || r.Collected != 0 || r.Cursor.AfterID != 0 || f.d.commits != f.commits || len(f.d.m.op) == 0 {
					t.Fatal("failed collector advanced cursor or lost original group", r, err)
				}
			case "unknown_commit":
				if err != ErrDownloadRetentionGCCommitUnknown || !r.CommitUnknown || r.Collected != 0 || r.Cursor.AfterID != 0 || f.d.commits != f.commits+1 || len(f.d.stone) != 23 {
					t.Fatal("unknown commit retried, counted or acknowledged", r, err)
				}
			}
		})
	}
}

func TestDownloadRetentionGCBatchScanRejectsUntrustedHints(t *testing.T) {
	for _, mode := range []string{"unsupported_schema", "null_schema", "schema_failure", "negative_upper", "upper_before_cursor", "excessive_upper", "null_upper", "upper_failure", "page_failure", "duplicate_pk", "unordered_pk", "outside_upper", "at_cursor", "bad_public_id", "null_public_id", "duplicate_public_id", "worker_id", "excess_rows"} {
		t.Run(mode, func(t *testing.T) {
			f, m := newDownloadGCBatchFixture(t)
			cursor := DownloadRetentionGCBatchCursor{}
			switch mode {
			case "unsupported_schema":
				m.operationTypes = "enum('control_metadata_gc')"
				m.upper = int64(0)
				m.rows = nil
			case "null_schema":
				m.operationTypes = nil
			case "schema_failure":
				m.failQuery = downloadGCBatchSchemaSQL
			case "negative_upper":
				m.upper = int64(-1)
			case "upper_before_cursor":
				cursor.AfterID = 75
			case "excessive_upper":
				m.upper = downloadGCBatchIDMax + 1
			case "null_upper":
				m.upper = nil
			case "upper_failure":
				m.failQuery = downloadGCBatchUpperSQL
			case "page_failure":
				m.failQuery = downloadGCBatchCandidatesSQL
			case "duplicate_pk":
				m.rows[1][0] = int64(73)
			case "unordered_pk":
				m.rows[1][0] = int64(72)
			case "outside_upper":
				m.rows[1][0] = int64(75)
			case "at_cursor":
				cursor.AfterID = 73
			case "bad_public_id":
				m.rows[0][1] = "PRIVATE invalid operation"
			case "null_public_id":
				m.rows[0][1] = nil
			case "duplicate_public_id":
				m.rows[1][1] = f.operation
			case "worker_id":
				m.rows[0][1] = f.s.c.OperationID
			case "excess_rows":
				m.rows = append(m.rows, []driver.Value{int64(75), "sop_88888888-8888-4888-8888-888888888888"})
				m.upper = int64(75)
			}
			r, err := f.s.CollectBatch(f.ctx, cursor, 1)
			if err != ErrAudit || r.Examined != 0 || r.Collected != 0 || r.EndOfRange || f.d.commits != f.commits || len(f.d.writes) != 0 || f.d.active || strings.Contains(fmt.Sprint(err), "PRIVATE") {
				t.Fatal("malformed hints reached collection or leaked raw failure", r, err)
			}
		})
	}
}

func TestDownloadRetentionGCBatchCursorAndPeerBoundaries(t *testing.T) {
	if downloadGCBatchWorkerSQL != strings.TrimSuffix(downloadGCWorkerSQL, " FOR UPDATE") {
		t.Fatal("scan worker projection diverged from the collector")
	}
	f, m := newDownloadGCBatchFixture(t)
	for _, c := range []DownloadRetentionGCBatchCursor{{AfterID: -1}, {ThroughID: -1}, {AfterID: downloadGCBatchIDMax + 1}, {ThroughID: downloadGCBatchIDMax + 1}, {AfterID: 3, ThroughID: 2}} {
		if _, err := f.s.CollectBatch(f.ctx, c, 1); err != ErrDenied {
			t.Fatal("invalid cursor accepted", c, err)
		}
	}
	for _, n := range []int{0, -1, downloadGCBatchMax + 1} {
		if _, err := f.s.CollectBatch(f.ctx, DownloadRetentionGCBatchCursor{}, n); err != ErrDenied {
			t.Fatal("unbounded page accepted", n, err)
		}
	}
	canceled, cancel := context.WithCancel(f.ctx)
	cancel()
	for _, ctx := range []context.Context{nil, context.Background(), canceled} {
		if _, err := f.s.CollectBatch(ctx, DownloadRetentionGCBatchCursor{}, 1); err != ErrDenied {
			t.Fatal("missing/canceled peer accepted", err)
		}
	}
	var absent *SQLDownloadRetentionGC
	if _, err := absent.CollectBatch(f.ctx, DownloadRetentionGCBatchCursor{}, 1); err != ErrDenied {
		t.Fatal("nil service accepted")
	}
	if len(m.events) != 0 {
		t.Fatal("invalid request opened SQL", m.events)
	}
	if _, err := json.Marshal(DownloadRetentionGCBatchResult{}); err == nil {
		t.Fatal("internal cursor serialized")
	}
}

func TestDownloadRetentionGCBatchEmptyAndPinnedRange(t *testing.T) {
	for _, mode := range []string{"empty_epoch", "closed_cursor", "empty_tail"} {
		t.Run(mode, func(t *testing.T) {
			f, m := newDownloadGCBatchFixture(t)
			m.rows = nil
			cursor := DownloadRetentionGCBatchCursor{}
			switch mode {
			case "empty_epoch":
				m.upper = int64(0)
			case "closed_cursor":
				cursor = DownloadRetentionGCBatchCursor{AfterID: 74, ThroughID: 74}
			case "empty_tail":
				cursor = DownloadRetentionGCBatchCursor{AfterID: 73, ThroughID: 74}
			}
			r, err := f.s.CollectBatch(f.ctx, cursor, 1)
			if err != nil || !r.EndOfRange || r.Examined != 0 || r.Cursor.AfterID != r.Cursor.ThroughID || f.d.commits != f.commits || f.d.active {
				t.Fatal("empty range counted as collection or left transaction", r, err)
			}
			if mode != "empty_epoch" {
				for _, q := range m.queries {
					if q == downloadGCBatchUpperSQL {
						t.Fatal("pinned range refreshed")
					}
				}
			}
		})
	}
}

func TestDownloadRetentionGCBatchChecksWorkerOnEmptyRange(t *testing.T) {
	for _, mode := range []string{"replaced_claim", "stopped_worker", "expired_lease"} {
		t.Run(mode, func(t *testing.T) {
			f, m := newDownloadGCBatchFixture(t)
			m.rows = nil
			m.upper = int64(0)
			switch mode {
			case "replaced_claim":
				m.worker[6] = "new-claim"
			case "stopped_worker":
				m.worker[5] = "succeeded"
			case "expired_lease":
				m.worker[7] = f.d.now.Add(-time.Microsecond)
			}
			r, err := f.s.CollectBatch(f.ctx, DownloadRetentionGCBatchCursor{}, 1)
			if err != ErrDenied || r.EndOfRange || r.Examined != 0 || f.d.commits != f.commits || f.d.active || len(f.d.writes) != 0 {
				t.Fatal("empty range bypassed current worker", r, err)
			}
			for _, q := range m.queries {
				if q == downloadGCBatchUpperSQL || q == downloadGCBatchCandidatesSQL {
					t.Fatal("invalid worker reached candidate scan")
				}
			}
		})
	}
}

func TestDownloadRetentionGCBatchStopsWithoutRetry(t *testing.T) {
	for _, mode := range []string{"success", "reject", "unknown", "unknown_canceled", "audit", "private_error", "cancel_after_commit", "cancel_before_result"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := []string{}
			candidates := []downloadGCBatchCandidate{{1, "first"}, {3, "second"}, {5, "third"}}
			r, err := runDownloadGCBatch(ctx, DownloadRetentionGCBatchResult{Cursor: DownloadRetentionGCBatchCursor{ThroughID: 9}}, candidates, false, func(_ context.Context, op string) error {
				calls = append(calls, op)
				if len(calls) == 2 {
					switch mode {
					case "reject":
						return ErrDenied
					case "unknown":
						return ErrDownloadRetentionGCCommitUnknown
					case "unknown_canceled":
						cancel()
						return ErrDownloadRetentionGCCommitUnknown
					case "audit":
						return ErrAudit
					case "private_error":
						return errors.New("PRIVATE transport")
					case "cancel_after_commit":
						cancel()
						return nil
					case "cancel_before_result":
						cancel()
						return ErrDenied
					}
				}
				return nil
			})
			if mode == "success" || mode == "reject" {
				want := 3
				if mode == "reject" {
					want = 2
				}
				if err != nil || r.Collected != want || r.Rejected != 3-want || r.Examined != 3 || !r.EndOfRange || r.Cursor.AfterID != 9 || !reflect.DeepEqual(calls, []string{"first", "second", "third"}) {
					t.Fatal("wrong completed page", r, err, calls)
				}
			} else {
				wantCursor, wantCollected := int64(1), 1
				if mode == "cancel_after_commit" {
					wantCursor, wantCollected = 3, 2
				}
				if err == nil || r.EndOfRange || r.Cursor.AfterID != wantCursor || r.Collected != wantCollected || r.Examined != 2 || r.Rejected != 0 || r.CommitUnknown != (mode == "unknown" || mode == "unknown_canceled") || !reflect.DeepEqual(calls, []string{"first", "second"}) || strings.Contains(fmt.Sprint(err), "PRIVATE") {
					t.Fatal("stopped outcome retried or advanced cursor", r, err, calls)
				}
			}
		})
	}
}
