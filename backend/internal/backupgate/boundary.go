package backupgate

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"sync"
	"time"
)

const requestLeasePrefix = "smlr_"

// HoldRequest fences the complete synchronous handler with a durable lease.
// No SQL connection is held after admission. Cancellation and lease expiration
// do not prove the handler stopped, so release must wait for its actual return.
func HoldRequest(acquire context.Context, pool *sql.DB, scope string) (func(), error) {
	if pool == nil || !scopePattern.MatchString(scope) {
		return nil, errors.New("backup boundary unavailable")
	}
	lease, generation, e := grantRequestLease(acquire, pool, scope)
	var leaseOnce sync.Once
	releaseLease := func() {
		leaseOnce.Do(func() {
			if lease == "" {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := pool.ExecContext(ctx, "UPDATE system_backup_mutation_leases SET released_at=COALESCE(released_at,UTC_TIMESTAMP(6)) WHERE public_id=? AND scope=? AND generation=?", lease, scope, generation); err != nil {
				log.Print("backup request drain evidence release deferred")
			}
		})
	}
	if e != nil {
		releaseLease()
		return nil, e
	}
	return releaseLease, nil
}

// ActiveRequests is read after locking the gate row, so an admission grant
// cannot commit between the read and a phase change. Request leases need an
// idle gate to finish nested application SQL. Explicit mutation leases can
// instead finish through WriteWithLease while the gate is acquiring.
func ActiveRequests(ctx context.Context, tx *sql.Tx, scope string) (bool, error) {
	var active bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM system_backup_mutation_leases
		WHERE scope=? AND released_at IS NULL AND LEFT(public_id,5)=?)`, scope, requestLeasePrefix).Scan(&active)
	return active, err
}

// A physical SQL connection can die while its handler keeps writing files.
// This durable blocker therefore survives disconnect/TTL expiry until the
// actual unit explicitly releases it. The short shared grant locks use the
// global admission -> gate order and do not queue an exclusive lock behind
// another admitted unit's nested business SQL.
func grantRequestLease(ctx context.Context, pool *sql.DB, scope string) (string, uint64, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", 0, err
	}
	id := requestLeasePrefix + hex.EncodeToString(random[:])
	tx, err := pool.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return "", 0, err
	}
	defer tx.Rollback()
	var closed bool
	if err = tx.QueryRowContext(ctx, "SELECT owner IS NOT NULL AND close_until>UTC_TIMESTAMP(6) FROM system_backup_gate_admissions WHERE scope=? LOCK IN SHARE MODE", scope).Scan(&closed); err != nil {
		return "", 0, err
	}
	if closed {
		return "", 0, ErrMaintenance
	}
	var phase string
	var generation uint64
	if err = tx.QueryRowContext(ctx, "SELECT phase,generation FROM system_backup_gate WHERE scope=? LOCK IN SHARE MODE", scope).Scan(&phase, &generation); err != nil {
		return "", 0, err
	}
	if phase != "idle" {
		return "", 0, ErrMaintenance
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO system_backup_mutation_leases(public_id,scope,generation,expires_at) VALUES(?,?,?,TIMESTAMPADD(MINUTE,15,UTC_TIMESTAMP(6)))", id, scope, generation); err != nil {
		return "", 0, err
	}
	// Return the identity even on a lost COMMIT response so the no-work path
	// can safely release a grant which might already exist.
	return id, generation, tx.Commit()
}

// Application SQL and request fencing must observe the same physical gate.
// A second database with an identically named scope is not equivalent.
func RequireSameDatabase(ctx context.Context, business, control *sql.DB) error {
	if business == nil || control == nil {
		return errors.New("backup gate identity unavailable")
	}
	var aDB, aServer, bDB, bServer string
	if e := business.QueryRowContext(ctx, "SELECT DATABASE(),@@server_uuid").Scan(&aDB, &aServer); e != nil {
		return e
	}
	if e := control.QueryRowContext(ctx, "SELECT DATABASE(),@@server_uuid").Scan(&bDB, &bServer); e != nil {
		return e
	}
	if aDB == "" || aDB != bDB || aServer == "" || aServer != bServer {
		return errors.New("backup gate database identity mismatch")
	}
	return nil
}
