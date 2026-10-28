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
	"strings"
	"testing"
	"time"
)

// These SQL-transport tests verify actual emitted statements, independent
// readback and failure handling. They do not prove real FK/locks, a full D
// admission, nonce consumption, capacity or a durable commit.
type admissionRecordsModel struct {
	t            *testing.T
	d            *downloadAuditDB
	f            DownloadAdmissionContentFacts
	op, receipt  []driver.Value
	fault        string
	writes       int
	afterReceipt func()
}

func admissionValues(args []driver.NamedValue) []driver.Value {
	out := make([]driver.Value, len(args))
	for i, arg := range args {
		out[i] = arg.Value
		if b, ok := arg.Value.([]byte); ok {
			out[i] = append([]byte(nil), b...)
		}
	}
	return out
}

type admissionRecordsResult struct {
	rows, id           int64
	rowsError, idError bool
}

func (r admissionRecordsResult) RowsAffected() (int64, error) {
	if r.rowsError {
		return 0, errors.New("PRIVATE rows error")
	}
	return r.rows, nil
}
func (r admissionRecordsResult) LastInsertId() (int64, error) {
	if r.idError {
		return 0, errors.New("PRIVATE ID error")
	}
	return r.id, nil
}

func (m *admissionRecordsModel) exec(q string, args []driver.NamedValue) (driver.Result, error) {
	m.writes++
	if strings.Count(q, "?") != len(args) {
		m.t.Fatal("placeholder mismatch", q, len(args))
	}
	result := admissionRecordsResult{rows: 1, id: 73}
	switch q {
	case downloadAdmissionOperationInsertSQL:
		if len(args) != 14 {
			m.t.Fatal("operation projection width")
		}
		if m.fault == "operation_insert" {
			return nil, errors.New("PRIVATE operation insert")
		}
		if m.fault == "operation_zero" {
			result.rows = 0
		}
		if m.fault == "operation_rows_error" {
			result.rowsError = true
		}
		if m.fault == "operation_id_zero" {
			result.id = 0
		}
		if m.fault == "operation_id_error" {
			result.idError = true
		}
		m.op = admissionValues(args)
	case downloadAdmissionReceiptInsertSQL:
		if len(args) != 16 || args[0].Value != int64(73) || args[3].Value != int64(61) || args[5].Value != m.d.id {
			m.t.Fatal("receipt not bound to actual row IDs")
		}
		if m.fault == "receipt_insert" {
			return nil, errors.New("PRIVATE receipt insert")
		}
		if m.fault == "receipt_zero" {
			result.rows = 0
		}
		if m.fault == "receipt_rows_error" {
			result.rowsError = true
		}
		m.receipt = admissionValues(args)
		if m.afterReceipt != nil {
			m.afterReceipt()
		}
	default:
		m.t.Fatal("unexpected mutation", q)
	}
	return result, nil
}

func (m *admissionRecordsModel) query(q string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.Count(q, "?") != len(args) {
		m.t.Fatal("read placeholder mismatch")
	}
	switch q {
	case downloadAdmissionKeySQL:
		return &admissionKeyRows{width: 2}, nil
	case downloadAdmissionTombstoneSQL, downloadAdmissionReceiptKeySQL:
		return &admissionKeyRows{width: 1}, nil
	case downloadAdmissionEvidenceAnchorSQL:
		if len(args) != 1 || args[0].Value != m.f.Intent.EvidenceID {
			m.t.Fatal("wrong evidence public ID")
		}
		var installation driver.Value = m.f.Intent.Installation
		version, claim, until := m.f.Record.RowVersion, m.f.Record.Claim, m.f.Record.ClaimUntil
		var protected driver.Value = m.d.now.Add(time.Minute)
		state := "ready"
		switch m.fault {
		case "evidence_null_installation":
			installation = nil
		case "evidence_foreign_installation":
			installation = "installation_other"
		case "evidence_version":
			version++
		case "evidence_claim":
			claim = "aev_" + strings.Repeat("f", 32)
		case "evidence_until":
			until = until.Add(time.Second)
		case "evidence_state":
			state = "deleted"
		case "evidence_protected":
			protected = m.d.now.Add(2 * time.Hour)
		}
		return &admissionKeyRows{width: 7, values: []driver.Value{int64(61), installation, version, claim, until, protected, state}}, nil
	case downloadAdmissionOperationReadSQL:
		if m.fault == "operation_read" {
			return nil, errors.New("PRIVATE operation read")
		}
		want := append([]driver.Value{int64(73)}, m.op...)
		if m.fault == "operation_drift" || !reflect.DeepEqual(admissionValues(args), want) {
			return &admissionKeyRows{width: 1}, nil
		}
		return &admissionKeyRows{width: 1, values: []driver.Value{int64(73)}}, nil
	case downloadAdmissionReceiptReadSQL:
		if m.fault == "receipt_read" {
			return nil, errors.New("PRIVATE receipt read")
		}
		if len(m.receipt) != 16 {
			m.t.Fatal("read before receipt insert")
		}
		want := append(append([]driver.Value(nil), m.receipt[:6]...), m.receipt[12:]...)
		if m.fault == "retention_drift" || !reflect.DeepEqual(admissionValues(args), want) {
			return &admissionKeyRows{width: 6}, nil
		}
		out := append([]driver.Value(nil), m.receipt[6:12]...)
		change := func(index int, field string, value any) {
			var body map[string]any
			if json.Unmarshal(out[index].([]byte), &body) != nil {
				m.t.Fatal("bad stored JSON")
			}
			body[field] = value
			raw := canonical(body)
			out[index], out[index+1], out[index+2] = raw, int64(len(raw)), hash(raw)
		}
		switch m.fault {
		case "receipt_rehashed":
			change(0, "subject_sha256", strings.Repeat("f", 64))
		case "public_rehashed":
			change(3, "actor_id", "43")
		case "private_noncanonical":
			raw := append([]byte("\n"), out[0].([]byte)...)
			out[0], out[1], out[2] = raw, int64(len(raw)), hash(raw)
		case "private_length":
			out[1] = int64(1)
		case "public_digest":
			out[5] = strings.Repeat("f", 64)
		case "private_public_swapped":
			out = []driver.Value{out[3], out[4], out[5], out[0], out[1], out[2]}
		case "read_wait_expired":
			m.d.now = m.d.now.Add(time.Hour)
		}
		return &admissionKeyRows{width: 6, values: out}, nil
	}
	m.t.Fatal("unexpected storage read", q)
	return nil, errors.New("unexpected read")
}

func downloadRecordsFixture(t *testing.T) (*admissionRecordsModel, *sql.Tx, *DownloadAdmissionKeyLock, *DownloadAdmissionContentBinding) {
	t.Helper()
	d, tx, audit, f := downloadBindingFixture(t)
	m := &admissionRecordsModel{t: t, d: d, f: f}
	d.extraQuery, d.extraExec = m.query, m.exec
	key, err := LockDownloadAdmissionKey(context.Background(), tx, f.Actor, f.Proof, f.Intent.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BindDownloadAdmissionContent(context.Background(), tx, audit, f)
	if err != nil {
		t.Fatal(err)
	}
	return m, tx, key, b
}

func TestDownloadAdmissionRecordsActualSQLIDsIndependentBytesAndRecheck(t *testing.T) {
	m, tx, key, b := downloadRecordsFixture(t)
	retain := m.d.now.Add(time.Hour)
	a, err := StageDownloadAdmissionRecords(context.Background(), tx, key, b, m.f.Record, retain)
	if err != nil || a == nil {
		t.Fatal(err)
	}
	if a.PendingOperationDatabaseID() != 73 || a.evidenceID != 61 || m.writes != 2 || m.d.inserts != 1 || m.d.commits != 0 || m.d.rollbacks != 0 {
		t.Fatal("wrong transaction/INSERT identity")
	}
	if bytes.Equal(m.receipt[6].([]byte), m.receipt[9].([]byte)) || bytes.Contains(m.receipt[6].([]byte), []byte(m.f.Record.Claim)) {
		t.Fatal("private/public separation or raw claim")
	}
	if _, err = json.Marshal(a); err == nil || fmt.Sprintf("%v %#v", a, a) != "DownloadAdmissionRecords DownloadAdmissionRecords" {
		t.Fatal("anchor serialized")
	}
	if err = a.Recheck(context.Background(), tx, m.f.Actor, m.f.Record); err != nil || m.writes != 2 {
		t.Fatal("readback wrote", err)
	}
	copyKey := *key
	if retry, err := StageDownloadAdmissionRecords(context.Background(), tx, &copyKey, b, m.f.Record, retain); err == nil || retry != nil || m.writes != 2 {
		t.Fatal("key copy allowed another stage")
	}
}

func TestDownloadAdmissionRecordsStageRejectsSQLFailuresAndUnboundEvidence(t *testing.T) {
	for _, fault := range []string{"evidence_null_installation", "evidence_foreign_installation", "evidence_version", "evidence_claim", "evidence_until", "evidence_state", "evidence_protected",
		"operation_insert", "operation_zero", "operation_rows_error", "operation_id_zero", "operation_id_error", "receipt_insert", "receipt_zero", "receipt_rows_error", "operation_read", "receipt_read",
		"operation_drift", "retention_drift", "receipt_rehashed", "public_rehashed", "private_noncanonical", "private_length", "public_digest", "private_public_swapped", "read_wait_expired"} {
		t.Run(fault, func(t *testing.T) {
			m, tx, key, b := downloadRecordsFixture(t)
			m.fault = fault
			retain := m.d.now.Add(time.Hour)
			if a, err := StageDownloadAdmissionRecords(context.Background(), tx, key, b, m.f.Record, retain); a != nil || err == nil {
				t.Fatal("bad storage returned anchor")
			}
			writes := m.writes
			m.fault = ""
			copyKey := *key
			if a, err := StageDownloadAdmissionRecords(context.Background(), tx, &copyKey, b, m.f.Record, retain); a != nil || err == nil || m.writes != writes {
				t.Fatal("failed key recovered")
			}
			if m.d.commits != 0 || m.d.rollbacks != 0 {
				t.Fatal("storage changed transaction ownership")
			}
		})
	}
}

func TestDownloadAdmissionRecordsRejectsLaterDriftAndFailedAnchorReuse(t *testing.T) {
	for _, fault := range []string{"evidence_foreign_installation", "evidence_version", "evidence_claim", "operation_drift", "receipt_rehashed", "public_rehashed", "retention_drift", "read_wait_expired"} {
		t.Run(fault, func(t *testing.T) {
			m, tx, key, b := downloadRecordsFixture(t)
			a, err := StageDownloadAdmissionRecords(context.Background(), tx, key, b, m.f.Record, m.d.now.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			m.fault = fault
			if a.Recheck(context.Background(), tx, m.f.Actor, m.f.Record) == nil {
				t.Fatal("later mutation accepted")
			}
			m.fault = ""
			m.d.now = m.f.Record.ClaimUntil.Add(-time.Second)
			clone := *a
			if clone.Recheck(context.Background(), tx, m.f.Actor, m.f.Record) == nil {
				t.Fatal("copied failed anchor recovered")
			}
			if m.writes != 2 || m.d.commits != 0 {
				t.Fatal("recheck mutated SQL")
			}
		})
	}
}

func TestDownloadAdmissionRecordsTransactionAndOriginalRetention(t *testing.T) {
	for _, fault := range []string{"foreign_tx", "ended_tx", "wrong_operation", "wrong_actor", "different_verification", "short_claim_retention", "short_proof_retention", "non_utc_retention", "canceled", "cancel_after_receipt"} {
		t.Run(fault, func(t *testing.T) {
			m, tx, key, b := downloadRecordsFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			retain := m.d.now.Add(time.Hour)
			switch fault {
			case "foreign_tx":
				_, tx, _, _ = downloadBindingFixture(t)
			case "ended_tx":
				tx.Rollback()
			case "wrong_operation":
				key.operationID = "sop_33333333-3333-4333-8333-333333333333"
			case "wrong_actor":
				key.actor.UserID++
			case "different_verification":
				_, _, _, other := downloadBindingFixture(t, 4*time.Minute)
				key.proof = other.Proof
			case "short_claim_retention":
				retain = m.f.Record.ClaimUntil
			case "short_proof_retention":
				retain = b.proof.ProofExpiresAt().Truncate(time.Microsecond)
			case "non_utc_retention":
				retain = retain.In(time.FixedZone("offset", 3600))
			case "canceled":
				cancel()
			case "cancel_after_receipt":
				m.afterReceipt = cancel
			}
			if a, err := StageDownloadAdmissionRecords(ctx, tx, key, b, m.f.Record, retain); a != nil || err == nil {
				t.Fatal("invalid transaction/retention accepted")
			}
		})
	}
}
