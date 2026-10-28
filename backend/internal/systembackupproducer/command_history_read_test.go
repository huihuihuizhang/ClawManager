package systembackupproducer

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type commandReceiptReadAuthority struct {
	db          *fakeDB
	allow       bool
	wrongDigest bool
	failRecheck bool
	checks      int
}

func (a *commandReceiptReadAuthority) PrepareCommandReceiptRead(context.Context, CommandRequest) (HistoricalCommandReceiptSession, error) {
	return a, nil
}
func (a *commandReceiptReadAuthority) AuthorizeCommandReceiptRead(_ context.Context, _ SQL, _ CommandRequest, d CommandDigests) (HistoricalReceiptAdmission, error) {
	h := d.Request
	if a.wrongDigest {
		h = Hash(strings.Repeat("f", 64))
	}
	return HistoricalReceiptAdmission{VerifiedRequestHash: h, ReadAllowed: a.allow, IdentityExpiresAt: Timestamp(a.db.now.Add(time.Minute).Format(timeLayout))}, nil
}
func (a *commandReceiptReadAuthority) RecheckCommandReceiptRead(_ context.Context, _ ReadSQL, _ CommandRequest, _ CommandReceiptRecord, _ time.Time) error {
	a.checks++
	if a.failRecheck || !a.allow {
		return ErrGuardRequired
	}
	return nil
}

func TestHistoricalCommandReceiptReadAfterDomainClose(t *testing.T) {
	s, db, _, m := setupCommands(t)
	want := requireAcquire(t, s).Receipt
	var domain DomainRecord
	loadMemoryRecord(t, m, &domain, 0)
	domain.State = "closed"
	replaceMemory(t, m, &domain)
	var grant GrantRecord
	loadMemoryRecord(t, m, &grant, 0)
	grant.State = "revoked"
	replaceMemory(t, m, &grant)
	a := &commandReceiptReadAuthority{db: db, allow: true}
	reader, err := NewHistoricalCommandReceiptReader(s.db, s.scope, a)
	if err != nil {
		t.Fatal(err)
	}
	reader.clock = func() time.Time { return db.now }
	before := cloneMemory(m.rows)
	m.events = nil
	got, err := reader.ReadCommandReceipt(context.Background(), commandFixture(t, "acquire"))
	if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(before, m.rows) || a.checks != 1 {
		t.Fatal(got, err)
	}
	for _, event := range m.events {
		if strings.Contains(event, "_domains") || strings.Contains(event, "_grants") || strings.Contains(event, "_runs") {
			t.Fatal("historical command read entered execution path", event)
		}
	}
}

func TestHistoricalCommandReceiptReadRejectsUnauthorizedAndChanged(t *testing.T) {
	s, db, _, m := setupCommands(t)
	want := requireAcquire(t, s).Receipt
	a := &commandReceiptReadAuthority{db: db, allow: true}
	reader, err := NewHistoricalCommandReceiptReader(s.db, s.scope, a)
	if err != nil {
		t.Fatal(err)
	}
	reader.clock = func() time.Time { return db.now }
	before := cloneMemory(m.rows)
	for _, name := range []string{"denied", "digest", "recheck", "changed", "missing", "expired"} {
		t.Run(name, func(t *testing.T) {
			a.allow, a.wrongDigest, a.failRecheck = true, false, false
			request := commandFixture(t, "acquire")
			switch name {
			case "denied":
				a.allow = false
			case "digest":
				a.wrongDigest = true
			case "recheck":
				a.failRecheck = true
			case "changed":
				request.ActorIdentityHash = Hash(strings.Repeat("f", 64))
			case "missing":
				request.RequestKey = "another-request-key-1"
			case "expired":
				retention, _ := want.RetentionExpiresAt.Time()
				db.now = retention
			}
			got, err := reader.ReadCommandReceipt(context.Background(), request)
			if err == nil || !reflect.DeepEqual(got, CommandReceiptRecord{}) || !reflect.DeepEqual(before, m.rows) {
				t.Fatal(name, got, err)
			}
		})
	}
	if _, err := NewHistoricalCommandReceiptReader(s.db, s.scope, nil); !errors.Is(err, ErrGuardRequired) {
		t.Fatal(err)
	}
}
