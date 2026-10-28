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

type fenceReadTestEnvironment struct {
	state    *fenceTestEnvironment
	allow    bool
	badHash  bool
	fail     string
	checks   int
	prepared int
}

func (e *fenceReadTestEnvironment) PrepareRecoveryFenceRead(context.Context, RecoveryFenceReadRequest) (RecoveryFenceReadSession, error) {
	e.prepared++
	if e.fail == "prepare" {
		return nil, ErrUnavailable
	}
	return e, nil
}
func (e *fenceReadTestEnvironment) LockReadInstallation(context.Context, SQL, RecoveryFenceReadRequest) error {
	if e.fail == "installation" {
		return ErrUnavailable
	}
	return nil
}
func (e *fenceReadTestEnvironment) AuthorizeRead(_ context.Context, _ SQL, r RecoveryFenceReadRequest, _ Hash) (RecoveryFenceReadAdmission, error) {
	if e.fail == "authorize" {
		return RecoveryFenceReadAdmission{}, ErrUnavailable
	}
	h, _ := RecoveryFenceReadHash(r)
	if e.badHash {
		h = Hash(strings.Repeat("f", 64))
	}
	return RecoveryFenceReadAdmission{VerifiedRequestHash: h, IdentityExpiresAt: Timestamp(e.state.db.now.Add(time.Minute).Format(timeLayout)), ReadAllowed: e.allow}, nil
}
func (e *fenceReadTestEnvironment) RecheckRead(_ context.Context, _ ReadSQL, _ RecoveryFenceReadRequest, _ RecoveryFenceObservation, _ time.Time) error {
	e.checks++
	if e.fail == "recheck" || !e.allow {
		return ErrGuardRequired
	}
	return nil
}

func setupRecoveryFenceRead(t *testing.T) (*RecoveryFenceManager, *RecoveryFenceReader, RecoveryFenceReadRequest, *fenceReadTestEnvironment, *fakeDB) {
	t.Helper()
	m, write, state, db := setupRecoveryFence(t)
	e := &fenceReadTestEnvironment{state: state, allow: true}
	reader, err := NewRecoveryFenceReader(m.db, m.scope, e)
	if err != nil {
		t.Fatal(err)
	}
	reader.clock = func() time.Time { return db.now }
	r := RecoveryFenceReadRequest{Scope: write.Scope, IdentityHash: write.IdentityHash, Nonce: "fence-read-1", BudgetUntil: Timestamp(db.now.Add(time.Minute).Format(timeLayout))}
	return m, reader, r, e, db
}

func TestRecoveryFenceReadCurrentState(t *testing.T) {
	m, reader, r, e, db := setupRecoveryFenceRead(t)
	ctx := context.Background()
	got, err := reader.ReadRecoveryFence(ctx, r)
	if err != nil || got.Found || !reflect.DeepEqual(got.Row, RecoveryFenceRow{}) {
		t.Fatal("missing observation", got, err)
	}
	write := RecoveryFenceRequest{Scope: r.Scope, Operation: "register", IdentityHash: r.IdentityHash, ExpectedEpoch: "0", ExpectedRowVersion: "0", ReasonHash: Hash(strings.Repeat("b", 64))}
	if _, err = m.ChangeFence(ctx, write); err != nil {
		t.Fatal(err)
	}
	db.events = nil
	got, err = reader.ReadRecoveryFence(ctx, r)
	if err != nil || !got.Found || got.Row.IdentityHash != r.IdentityHash || got.Row.Epoch != "1" || got.Row.RowVersion != "1" || got.Row.Revoked {
		t.Fatal("registered observation", got, err)
	}
	for _, event := range db.events {
		if strings.HasPrefix(event, "UPDATE ") || strings.HasPrefix(event, "INSERT ") || strings.HasPrefix(event, "DELETE ") {
			t.Fatal("read mutated state", event)
		}
	}
	write.Operation, write.ExpectedEpoch, write.ExpectedRowVersion = "revoke", "1", "1"
	if _, err = m.ChangeFence(ctx, write); err != nil {
		t.Fatal(err)
	}
	got, err = reader.ReadRecoveryFence(ctx, r)
	if err != nil || !got.Found || !got.Row.Revoked || got.Row.Epoch != "2" || got.Row.RowVersion != "2" {
		t.Fatal("revoked observation", got, err)
	}
	if e.checks != 3 {
		t.Fatal("read final guard absent", e.checks)
	}
}

func TestRecoveryFenceReadRejects(t *testing.T) {
	for _, name := range []string{"cross_scope", "expired", "denied", "digest", "prepare", "installation", "authorize", "recheck", "missing_table", "row_drift", "commit_unknown"} {
		t.Run(name, func(t *testing.T) {
			_, reader, r, e, db := setupRecoveryFenceRead(t)
			switch name {
			case "cross_scope":
				r.Scope.Database = "other_database"
			case "expired":
				r.BudgetUntil = Timestamp(db.now.Add(-time.Second).Format(timeLayout))
			case "denied":
				e.allow = false
			case "digest":
				e.badHash = true
			case "missing_table":
				db.queryRecord = func(string, []driver.NamedValue) (driver.Rows, error) { return nil, ErrUnavailable }
			case "row_drift":
				original := db.queryRecord
				db.queryRecord = func(q string, a []driver.NamedValue) (driver.Rows, error) {
					if q == recoveryFenceRecheck {
						return &fakeRows{values: []driver.Value{int64(1), nil, int64(1)}}, nil
					}
					return original(q, a)
				}
			case "commit_unknown":
				db.commitError = true
			default:
				e.fail = name
			}
			got, err := reader.ReadRecoveryFence(context.Background(), r)
			if err == nil || !reflect.DeepEqual(got, RecoveryFenceObservation{}) {
				t.Fatal(name, got, err)
			}
			if name == "cross_scope" && e.prepared != 0 {
				t.Fatal("cross-scope prepared authority")
			}
			if name == "commit_unknown" && !errors.Is(err, ErrCommitUnknown) {
				t.Fatal("read returned on unknown commit", err)
			}
		})
	}
}
