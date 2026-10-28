package systembackupproducer

import (
	"context"
	"database/sql/driver"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type domainRevokeTestEnvironment struct {
	db      *fakeDB
	m       *commandMemory
	allow   bool
	badHash bool
	fail    string
	checks  int
}

func (e *domainRevokeTestEnvironment) phase(name string) error {
	e.m.events = append(e.m.events, "domain:"+name)
	if e.fail == name {
		return ErrUnavailable
	}
	return nil
}
func (e *domainRevokeTestEnvironment) PrepareDomainRevoke(context.Context, DomainRevokeRequest) (DomainRevokeSession, error) {
	if err := e.phase("prepare"); err != nil {
		return nil, err
	}
	return e, nil
}
func (e *domainRevokeTestEnvironment) LockInstallation(context.Context, SQL, DomainRevokeRequest) error {
	return e.phase("installation")
}
func (e *domainRevokeTestEnvironment) Authorize(_ context.Context, _ SQL, r DomainRevokeRequest, _ DomainRecord) (DomainRevokeAdmission, error) {
	if err := e.phase("authorize"); err != nil {
		return DomainRevokeAdmission{}, err
	}
	h, _ := DomainRevokeHash(r)
	if e.badHash {
		h = Hash(strings.Repeat("f", 64))
	}
	return DomainRevokeAdmission{VerifiedRequestHash: h, IdentityExpiresAt: Timestamp(e.db.now.Add(time.Minute).Format(timeLayout)), ManagementAllowed: e.allow}, nil
}
func (e *domainRevokeTestEnvironment) Audit(_ context.Context, _ SQL, _ DomainRevokeRequest, stage string) error {
	return e.phase("audit:" + stage)
}
func (e *domainRevokeTestEnvironment) Recheck(_ context.Context, _ ReadSQL, _ DomainRevokeRequest, d DomainRecord, _ time.Time) error {
	e.checks++
	if d.State != "revoked" || !e.allow {
		return ErrGuardRequired
	}
	return e.phase("recheck")
}
func setupDomainRevoker(t *testing.T) (*DomainRevoker, DomainRevokeRequest, *domainRevokeTestEnvironment, *fakeDB, *commandMemory) {
	t.Helper()
	s, db, _, m := setupCommands(t)
	var d DomainRecord
	loadMemoryRecord(t, m, &d, 0)
	r := DomainRevokeRequest{Scope: d.Scope, ExpectedEpoch: d.Epoch, ExpectedRowVersion: d.RowVersion, ReasonHash: Hash(strings.Repeat("a", 64))}
	e := &domainRevokeTestEnvironment{db: db, m: m, allow: true}
	revoker, err := NewDomainRevoker(s.db, s.scope, e)
	if err != nil {
		t.Fatal(err)
	}
	revoker.clock = func() time.Time { return db.now }
	m.events = nil
	return revoker, r, e, db, m
}

func TestDomainRevokeFencesOldEpochAtomically(t *testing.T) {
	s, r, e, db, m := setupDomainRevoker(t)
	before := cloneMemory(m.rows)
	commits := db.commits
	domain, err := s.RevokeDomain(context.Background(), r)
	if err != nil || domain.State != "revoked" || domain.Epoch != "2" || domain.RowVersion != "2" || e.checks != 1 || db.commits != commits+1 {
		t.Fatal(domain, err)
	}
	var stored DomainRecord
	loadMemoryRecord(t, m, &stored, 0)
	if !reflect.DeepEqual(stored, domain) {
		t.Fatal("stored domain differs")
	}
	for table, rows := range before {
		if table != "system_backup_producer_domains" && !reflect.DeepEqual(rows, m.rows[table]) {
			t.Fatal("revocation changed child records", table)
		}
	}
	want := []string{"domain:prepare", "domain:installation", "lock:system_backup_producer_domains", "domain:authorize", "domain:audit:intent", "update:system_backup_producer_domains", "domain:audit:result", "domain:recheck"}
	if !reflect.DeepEqual(m.events, want) {
		t.Fatal("phase order", m.events)
	}
	if second, err := s.RevokeDomain(context.Background(), r); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(second, DomainRecord{}) {
		t.Fatal("old CAS replay", second, err)
	}
}

func TestDomainRevokeRejectsAndRollsBack(t *testing.T) {
	for _, name := range []string{"denied", "digest", "expected_epoch", "expected_version", "missing", "prepare", "installation", "authorize", "audit:intent", "audit:result", "recheck", "cas"} {
		t.Run(name, func(t *testing.T) {
			s, r, e, db, m := setupDomainRevoker(t)
			switch name {
			case "denied":
				e.allow = false
			case "digest":
				e.badHash = true
			case "expected_epoch":
				r.ExpectedEpoch = "2"
			case "expected_version":
				r.ExpectedRowVersion = "2"
			case "missing":
				delete(m.rows, "system_backup_producer_domains")
			case "cas":
				original := db.execRecord
				db.execRecord = func(q string, args []driver.NamedValue) (driver.Result, error) {
					if strings.HasPrefix(q, "UPDATE system_backup_producer_domains") {
						return driver.RowsAffected(0), nil
					}
					return original(q, args)
				}
			default:
				e.fail = name
			}
			before := cloneMemory(m.rows)
			got, err := s.RevokeDomain(context.Background(), r)
			if err == nil || !reflect.DeepEqual(got, DomainRecord{}) || !reflect.DeepEqual(before, m.rows) {
				t.Fatal(name, got, err)
			}
		})
	}
}
