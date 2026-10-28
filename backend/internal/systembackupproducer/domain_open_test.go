package systembackupproducer

import (
	"context"
	"database/sql/driver"
	"reflect"
	"strings"
	"testing"
	"time"
)

type domainOpenTestEnvironment struct {
	db        *fakeDB
	m         *commandMemory
	issuer    Hash
	admission Admission
	allow     bool
	badHash   bool
	fail      string
	noReport  bool
	reserved  []uint64
	checks    int
}

func (e *domainOpenTestEnvironment) phase(name string) error {
	e.m.events = append(e.m.events, "open:"+name)
	if e.fail == name {
		return ErrUnavailable
	}
	return nil
}
func (e *domainOpenTestEnvironment) PrepareDomainOpen(context.Context, DomainOpenRequest) (PreparedDomainOpen, error) {
	if err := e.phase("prepare"); err != nil {
		return PreparedDomainOpen{}, err
	}
	p := PreparedDomainOpen{Session: e, CapacityObservedAt: e.db.now}
	if e.noReport {
		p.CapacityObservedAt = time.Time{}
	}
	return p, nil
}
func (e *domainOpenTestEnvironment) LockInstallation(context.Context, SQL, DomainOpenRequest) error {
	return e.phase("installation")
}
func (e *domainOpenTestEnvironment) Authorize(_ context.Context, _ SQL, r DomainOpenRequest, _ *DomainRecord) (DomainOpenAdmission, error) {
	if err := e.phase("authorize"); err != nil {
		return DomainOpenAdmission{}, err
	}
	h, _ := DomainOpenHash(r)
	if e.badHash {
		h = Hash(strings.Repeat("f", 64))
	}
	return DomainOpenAdmission{VerifiedRequestHash: h, IdentityExpiresAt: Timestamp(e.db.now.Add(time.Minute).Format(timeLayout)), IssuerIdentityHash: e.issuer, Admission: detached(e.admission), AdmissionExpiresAt: Timestamp(e.db.now.Add(time.Hour).Format(timeLayout)), AdditionalCost: "0", ManagementAllowed: e.allow}, nil
}
func (e *domainOpenTestEnvironment) Reserve(_ context.Context, _ SQL, _ DomainOpenRequest, cost uint64) error {
	if err := e.phase("reserve"); err != nil {
		return err
	}
	e.reserved = append(e.reserved, cost)
	return nil
}
func (e *domainOpenTestEnvironment) Audit(_ context.Context, _ SQL, _ DomainOpenRequest, stage string) error {
	return e.phase("audit:" + stage)
}
func (e *domainOpenTestEnvironment) Recheck(_ context.Context, _ ReadSQL, _ DomainOpenRequest, d DomainRecord, _ time.Time) error {
	e.checks++
	if !e.allow || d.State != "open" || d.IssuerIdentityHash != e.issuer {
		return ErrGuardRequired
	}
	return e.phase("recheck")
}

func setupDomainOpener(t *testing.T) (*DomainOpener, DomainOpenRequest, *domainOpenTestEnvironment, *fakeDB, *commandMemory) {
	t.Helper()
	s, db, _, m := setupCommands(t)
	var current DomainRecord
	loadMemoryRecord(t, m, &current, 0)
	r := DomainOpenRequest{Scope: current.Scope, Operation: "rotate", ExpectedEpoch: ZeroCounter(current.Epoch), ExpectedRowVersion: ZeroCounter(current.RowVersion), DeploymentHash: Hash(strings.Repeat("a", 64))}
	e := &domainOpenTestEnvironment{db: db, m: m, issuer: Hash(strings.Repeat("e", 64)), admission: detached(current.Admission), allow: true}
	opener, err := NewDomainOpener(s.db, s.scope, e)
	if err != nil {
		t.Fatal(err)
	}
	opener.clock = func() time.Time { return db.now }
	m.events = nil
	return opener, r, e, db, m
}

func TestDomainOpenProvisionAndRotation(t *testing.T) {
	for _, operation := range []string{"provision", "rotate", "rotate_revoked"} {
		t.Run(operation, func(t *testing.T) {
			s, r, e, db, m := setupDomainOpener(t)
			var original DomainRecord
			loadMemoryRecord(t, m, &original, 0)
			if operation == "provision" {
				delete(m.rows, "system_backup_producer_domains")
				r.Operation, r.ExpectedEpoch, r.ExpectedRowVersion = "provision", "0", "0"
			} else if operation == "rotate_revoked" {
				original.State = "revoked"
				replaceMemory(t, m, &original)
			}
			before := cloneMemory(m.rows)
			got, err := s.OpenDomain(context.Background(), r)
			if err != nil || got.State != "open" || got.IssuerIdentityHash != e.issuer || e.checks != 1 {
				t.Fatal(got, err)
			}
			var stored DomainRecord
			loadMemoryRecord(t, m, &stored, 0)
			if !reflect.DeepEqual(got, stored) {
				t.Fatal("stored domain differs")
			}
			if operation == "provision" {
				if got.Epoch != "1" || got.RowVersion != "1" || got.CreatedAt != got.UpdatedAt || !reflect.DeepEqual(e.reserved, []uint64{147456}) {
					t.Fatal("provision", got, e.reserved)
				}
			} else if got.Epoch != "2" || got.RowVersion != "2" || got.CreatedAt != original.CreatedAt || !reflect.DeepEqual(e.reserved, []uint64{65536}) {
				t.Fatal("rotation", got, e.reserved)
			}
			for table, rows := range before {
				if table != "system_backup_producer_domains" && !reflect.DeepEqual(rows, m.rows[table]) {
					t.Fatal("domain open changed child table", table)
				}
			}
			if second, err := s.OpenDomain(context.Background(), r); err == nil || !reflect.DeepEqual(second, DomainRecord{}) {
				t.Fatal("old CAS replay", second, err)
			}
			_ = db
		})
	}
}

func TestDomainOpenRejectsAndRollsBack(t *testing.T) {
	for _, name := range []string{"denied", "digest", "old_epoch", "old_version", "no_report", "prepare", "installation", "authorize", "reserve", "audit:intent", "audit:result", "recheck", "cas"} {
		t.Run(name, func(t *testing.T) {
			s, r, e, db, m := setupDomainOpener(t)
			switch name {
			case "denied":
				e.allow = false
			case "digest":
				e.badHash = true
			case "old_epoch":
				r.ExpectedEpoch = "2"
			case "old_version":
				r.ExpectedRowVersion = "2"
			case "no_report":
				e.noReport = true
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
			got, err := s.OpenDomain(context.Background(), r)
			if err == nil || !reflect.DeepEqual(got, DomainRecord{}) || !reflect.DeepEqual(before, m.rows) {
				t.Fatal(name, got, err)
			}
		})
	}
}
