package systembackupcontroller

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"
)

// takeoverStore is an in-memory fake of the single-row, database-clock CAS.
// It has no runner, Job, credential, catalog, or provider side effects.
type takeoverStore struct {
	now           time.Time
	owner         string
	leaseUntil    time.Time
	nextReconcile time.Time
	rowVersion    uint64
	calls         int
}

func (s *takeoverStore) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.calls++
	if !strings.Contains(query, "UTC_TIMESTAMP(6)") || !strings.Contains(query, "row_version = row_version + 1") {
		return nil, errors.New("claim mutation did not use database time and row-version CAS")
	}
	for _, arg := range args {
		if _, ok := arg.(time.Time); ok {
			return nil, errors.New("claim mutation passed a process-clock timestamp")
		}
	}
	if !strings.Contains(query, "WHERE origin_installation_id = ? AND public_id = ?") {
		return nil, errors.New("claim mutation was not installation fenced")
	}
	if strings.Contains(query, "SET controller_owner = ?") {
		if len(args) != 6 || args[2] != "installation_test" || args[3] != validBackupTarget().PublicID {
			return nil, errors.New("unexpected claim acquisition arguments")
		}
		owner, ownerOK := args[0].(string)
		ttlMicros, ttlOK := args[1].(int64)
		version, versionOK := args[4].(uint64)
		if !ownerOK || !ttlOK || !versionOK || args[5] != owner {
			return nil, errors.New("invalid claim acquisition arguments")
		}
		if version != s.rowVersion || s.nextReconcile.After(s.now) ||
			(s.owner != "" && s.owner != owner && s.leaseUntil.After(s.now)) {
			return fixedResult(0), nil
		}
		s.owner = owner
		s.leaseUntil = s.now.Add(time.Duration(ttlMicros) * time.Microsecond)
		s.rowVersion++
		return fixedResult(1), nil
	}
	if strings.Contains(query, "SET controller_lease_expires_at = DATE_ADD") {
		if len(args) != 5 || args[1] != "installation_test" || args[2] != validBackupTarget().PublicID {
			return nil, errors.New("unexpected claim renewal arguments")
		}
		ttlMicros, ttlOK := args[0].(int64)
		version, versionOK := args[3].(uint64)
		owner, ownerOK := args[4].(string)
		if !ttlOK || !versionOK || !ownerOK {
			return nil, errors.New("invalid claim renewal arguments")
		}
		if version != s.rowVersion || owner != s.owner || !s.leaseUntil.After(s.now) {
			return fixedResult(0), nil
		}
		s.leaseUntil = s.now.Add(time.Duration(ttlMicros) * time.Microsecond)
		s.rowVersion++
		return fixedResult(1), nil
	}
	if strings.Contains(query, "SET controller_owner = NULL") {
		if len(args) != 5 || args[1] != "installation_test" || args[2] != validBackupTarget().PublicID {
			return nil, errors.New("unexpected claim release arguments")
		}
		retryMicros, retryOK := args[0].(int64)
		version, versionOK := args[3].(uint64)
		owner, ownerOK := args[4].(string)
		if !retryOK || !versionOK || !ownerOK {
			return nil, errors.New("invalid claim release arguments")
		}
		if version != s.rowVersion || owner != s.owner || !s.leaseUntil.After(s.now) {
			return fixedResult(0), nil
		}
		s.owner = ""
		s.leaseUntil = time.Time{}
		s.nextReconcile = s.now.Add(time.Duration(retryMicros) * time.Microsecond)
		s.rowVersion++
		return fixedResult(1), nil
	}
	return nil, errors.New("unexpected claim mutation")
}

func TestClaimTakeoverWaitsForDatabaseLeaseExpiryAndFencesOldLeader(t *testing.T) {
	store := &takeoverStore{now: time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC), rowVersion: 1}
	claims := ClaimCoordinator{Executor: store, InstallationID: "installation_test"}
	target := validBackupTarget()
	policy := validPolicy()
	old, err := claims.Acquire(context.Background(), target, "controller:old", 1, policy)
	if err != nil || old.RowVersion != 2 {
		t.Fatalf("old leader acquisition token=%#v err=%v", old, err)
	}
	if _, err := claims.Acquire(context.Background(), target, "controller:new", 1, policy); !errors.Is(err, ErrClaimNotAcquired) {
		t.Fatalf("stale-version contender error=%v", err)
	}
	if _, err := claims.Acquire(context.Background(), target, "controller:new", 2, policy); !errors.Is(err, ErrClaimNotAcquired) {
		t.Fatalf("live-lease contender error=%v", err)
	}
	store.now = store.now.Add(10 * time.Second)
	old, err = claims.Renew(context.Background(), old, policy)
	if err != nil || old.RowVersion != 3 {
		t.Fatalf("old leader renewal token=%#v err=%v", old, err)
	}
	oldCtx, cancelOld := context.WithCancel(context.Background())
	cancelOld()
	before := store.calls
	if _, err := claims.Renew(oldCtx, old, policy); !errors.Is(err, context.Canceled) || store.calls != before {
		t.Fatalf("canceled old leader renewed err=%v calls=%d/%d", err, store.calls, before)
	}
	store.now = store.leaseUntil.Add(-time.Microsecond)
	if _, err := claims.Acquire(context.Background(), target, "controller:new", 3, policy); !errors.Is(err, ErrClaimNotAcquired) {
		t.Fatalf("pre-expiry takeover error=%v", err)
	}
	store.now = store.leaseUntil
	current, err := claims.Acquire(context.Background(), target, "controller:new", 3, policy)
	if err != nil || current.RowVersion != 4 {
		t.Fatalf("expiry-boundary takeover token=%#v err=%v", current, err)
	}
	if _, err := claims.Renew(context.Background(), old, policy); !errors.Is(err, ErrClaimLost) {
		t.Fatalf("fenced old leader renewal error=%v", err)
	}
	if _, err := claims.Release(context.Background(), old, DefaultReconcile); !errors.Is(err, ErrClaimLost) {
		t.Fatalf("fenced old leader release error=%v", err)
	}
	version, err := claims.Release(context.Background(), current, DefaultReconcile)
	if err != nil || version != 5 {
		t.Fatalf("new leader release version=%d err=%v", version, err)
	}
	if _, err := claims.Acquire(context.Background(), target, "controller:old", 5, policy); !errors.Is(err, ErrClaimNotAcquired) {
		t.Fatalf("early requeue acquisition error=%v", err)
	}
	store.now = store.nextReconcile
	if _, err := claims.Acquire(context.Background(), target, "controller:old", 5, policy); err != nil {
		t.Fatalf("scheduled requeue acquisition: %v", err)
	}
}
