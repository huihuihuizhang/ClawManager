package systembackupproducer

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type receiptReadAuthority struct {
	db          *fakeDB
	allow       bool
	wrongDigest bool
	failRecheck bool
	checks      int
}

func (a *receiptReadAuthority) PrepareReceiptRead(context.Context, ResultRequest) (HistoricalReceiptSession, error) {
	return a, nil
}
func (a *receiptReadAuthority) AuthorizeReceiptRead(_ context.Context, _ SQL, _ ResultRequest, d ResultDigests) (HistoricalReceiptAdmission, error) {
	h := d.Request
	if a.wrongDigest {
		h = Hash(strings.Repeat("f", 64))
	}
	return HistoricalReceiptAdmission{VerifiedRequestHash: h, ReadAllowed: a.allow, IdentityExpiresAt: Timestamp(a.db.now.Add(time.Minute).Format(timeLayout))}, nil
}
func (a *receiptReadAuthority) RecheckReceiptRead(_ context.Context, _ ReadSQL, _ ResultRequest, _ ReceiptRecord, _ time.Time) error {
	a.checks++
	if a.failRecheck || !a.allow {
		return ErrGuardRequired
	}
	return nil
}

func TestHistoricalReceiptReadIndependentOfExecutionAndDomain(t *testing.T) {
	s, h, request, db, _, m := setupResult(t, "unconfigured", "candidate")
	committed, err := s.CommitResult(context.Background(), h, request)
	if err != nil {
		t.Fatal(err)
	}
	var domain DomainRecord
	loadMemoryRecord(t, m, &domain, 0)
	domain.State = "closed"
	replaceMemory(t, m, &domain)
	var grant GrantRecord
	loadMemoryRecord(t, m, &grant, 0)
	grant.State = "revoked"
	replaceMemory(t, m, &grant)
	a := &receiptReadAuthority{db: db, allow: true}
	reader, err := NewHistoricalReceiptReader(s.execution.lifecycle.db, request.Scope, a)
	if err != nil {
		t.Fatal(err)
	}
	reader.clock = func() time.Time { return db.now }
	before := cloneMemory(m.rows)
	m.events = nil
	receipt, err := reader.ReadResultReceipt(context.Background(), request)
	if err != nil || !reflect.DeepEqual(receipt, committed.Receipt) || !reflect.DeepEqual(before, m.rows) || a.checks != 1 {
		t.Fatal(receipt, err)
	}
	for _, event := range m.events {
		if strings.Contains(event, "_domains") || strings.Contains(event, "_grants") || strings.Contains(event, "_runs") || strings.Contains(event, "_evidence_") {
			t.Fatal("historical read entered execution path", event)
		}
	}
}

func TestHistoricalReceiptReadRejectsMissingAuthorityAndMismatch(t *testing.T) {
	s, h, request, db, _, m := setupResult(t, "unconfigured", "candidate")
	committed, err := s.CommitResult(context.Background(), h, request)
	if err != nil {
		t.Fatal(err)
	}
	a := &receiptReadAuthority{db: db, allow: true}
	reader, err := NewHistoricalReceiptReader(s.execution.lifecycle.db, request.Scope, a)
	if err != nil {
		t.Fatal(err)
	}
	reader.clock = func() time.Time { return db.now }
	before := cloneMemory(m.rows)
	for _, name := range []string{"denied", "digest", "recheck", "different_request", "missing", "expired"} {
		t.Run(name, func(t *testing.T) {
			a.allow, a.wrongDigest, a.failRecheck = true, false, false
			actual := detached(request)
			switch name {
			case "denied":
				a.allow = false
			case "digest":
				a.wrongDigest = true
			case "recheck":
				a.failRecheck = true
			case "different_request":
				actual.Results.Provider.Observations[0].Reason = "unsupported_api"
				actual.Results.Provider.Observations[0].Status = "unsupported"
			case "missing":
				actual.RequestKey = "another-request-key-1"
			case "expired":
				retention, _ := committed.Receipt.RetentionExpiresAt.Time()
				db.now = retention
			}
			got, err := reader.ReadResultReceipt(context.Background(), actual)
			if err == nil || !reflect.DeepEqual(got, ReceiptRecord{}) || !reflect.DeepEqual(before, m.rows) {
				t.Fatal(name, got, err)
			}
		})
	}
	if _, err := NewHistoricalReceiptReader(s.execution.lifecycle.db, request.Scope, nil); !errors.Is(err, ErrGuardRequired) {
		t.Fatal(err)
	}
	wrongScope := detached(request)
	wrongScope.Scope.Database = "other"
	if _, err := reader.ReadResultReceipt(context.Background(), wrongScope); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestHistoricalReceiptReadRejectsCorruptStoredReceipt(t *testing.T) {
	s, h, request, db, _, m := setupResult(t, "unconfigured", "candidate")
	if _, err := s.CommitResult(context.Background(), h, request); err != nil {
		t.Fatal(err)
	}
	a := &receiptReadAuthority{db: db, allow: true}
	reader, err := NewHistoricalReceiptReader(s.execution.lifecycle.db, request.Scope, a)
	if err != nil {
		t.Fatal(err)
	}
	reader.clock = func() time.Time { return db.now }
	rows := m.rows["system_backup_producer_result_receipts"]
	rows[0].Columns["record_sha256"] = []byte(strings.Repeat("x", 32))
	if receipt, err := reader.ReadResultReceipt(context.Background(), request); !errors.Is(err, ErrInvalid) || !reflect.DeepEqual(receipt, ReceiptRecord{}) {
		t.Fatal(receipt, err)
	}
}
