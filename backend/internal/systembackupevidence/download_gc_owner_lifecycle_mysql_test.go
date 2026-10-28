//go:build systembackup_mysql

package systembackupevidence

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

type dGCLifecycleDialTrace struct {
	mu          sync.Mutex
	connections []*dGCLifecycleFaultConn
}

const dGCLifecycleCancelSleepSeconds = 30

var dGCLifecycleCancelSQL = "SELECT SLEEP(" + strconv.Itoa(dGCLifecycleCancelSleepSeconds) + ")"

func dGCLifecyclePool(t *testing.T, f *dGCFreezeFixture) (*sql.DB, *dGCLifecycleDialTrace) {
	t.Helper()
	trace := &dGCLifecycleDialTrace{}
	// Fresh, test-owned plaintext connector only. TLS/compression are not enabled;
	// this fault mechanism is not a general proxy or a production transport.
	cfg := mysql.NewConfig()
	cfg.User = f.user
	cfg.Passwd = f.password
	cfg.Net = "tcp"
	cfg.Addr = f.cfg.Addr
	cfg.DBName = f.db
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 5 * time.Second
	cfg.WriteTimeout = 5 * time.Second
	cfg.Params = map[string]string{"time_zone": "'+00:00'", "lock_wait_timeout": "5"}
	cfg.Logger = log.New(io.Discard, "", 0)
	cfg.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != f.cfg.Addr {
			return nil, dGCLifecycleWireInvalid
		}
		connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		wire := &dGCLifecycleFaultConn{Conn: connection}
		trace.mu.Lock()
		trace.connections = append(trace.connections, wire)
		trace.mu.Unlock()
		return wire, nil
	}
	connector, err := mysql.NewConnector(cfg)
	dGCFreezeOK(t, err)
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() { dGCFreezeOK(t, db.Close()) })
	return db, trace
}
func (trace *dGCLifecycleDialTrace) first(t *testing.T) *dGCLifecycleFaultConn {
	t.Helper()
	trace.mu.Lock()
	defer trace.mu.Unlock()
	if len(trace.connections) != 1 {
		t.Fatal("lifecycle initial connection was retried")
	}
	return trace.connections[0]
}
func dGCLifecycleReleased(f *dGCFreezeFixture, id int64, budget time.Duration) bool {
	thread := f.threads[id]
	if thread <= 0 {
		return false
	}
	// The observer is independent of the canceled transaction. Closing the client
	// socket need not interrupt server-side SLEEP; the canceled case must allow
	// that test-owned statement to finish before expecting disconnect cleanup.
	ctx, cancel := context.WithTimeout(f.ctx, budget)
	defer cancel()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		var instrument string
		var tickets int
		err := f.admin.QueryRowContext(ctx, "SELECT (SELECT ENABLED FROM performance_schema.setup_instruments WHERE NAME='wait/lock/metadata/sql/mdl'),(SELECT COUNT(*) FROM performance_schema.metadata_locks WHERE OWNER_THREAD_ID=? AND OBJECT_TYPE='BACKUP LOCK')", thread).Scan(&instrument, &tickets)
		if err != nil || instrument != "YES" {
			return false
		}
		if tickets == 0 {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-tick.C:
		}
	}
}
func dGCLifecycleRead(t *testing.T, f *dGCFreezeFixture, id int) int {
	t.Helper()
	q, err := dGCFreezeIdentifier(f.db)
	dGCFreezeOK(t, err)
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	var value int
	dGCFreezeOK(t, f.admin.QueryRowContext(ctx, "SELECT v FROM "+q+".lifecycle_canary WHERE id=?", id).Scan(&value))
	return value
}
func dGCLifecycleCancelQuery(t *testing.T, f *dGCFreezeFixture, ctx context.Context, owned *downloadGCConnection, id int64, cancel context.CancelFunc) {
	t.Helper()
	done := make(chan error, 1)
	go func(tx *sql.Tx) {
		var slept int
		done <- tx.QueryRowContext(ctx, dGCLifecycleCancelSQL).Scan(&slept)
	}(owned.tx)
	observer, stop := context.WithTimeout(f.ctx, 5*time.Second)
	defer stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	started := false
	for !started {
		var n int
		err := f.admin.QueryRowContext(observer, "SELECT COUNT(*) FROM performance_schema.threads WHERE THREAD_ID=? AND PROCESSLIST_ID=? AND PROCESSLIST_COMMAND='Query' AND PROCESSLIST_INFO=?", f.threads[id], id, dGCLifecycleCancelSQL).Scan(&n)
		if err != nil {
			cancel()
			t.Fatal("lifecycle cancellation query witness unavailable")
		}
		if n == 1 {
			started = true
			break
		}
		select {
		case <-observer.Done():
			cancel()
			t.Fatal("lifecycle cancellation query was not observed")
		case <-tick.C:
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("holder query did not report the original context cancellation", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("lifecycle canceled query did not stop")
	}
}
func TestDDownloadGCOwnerLifecycleMySQL(t *testing.T) {
	f := newDGCFreezeFixture(t)
	quoted, err := dGCFreezeIdentifier(f.db)
	dGCFreezeOK(t, err)
	f.exec(t, "CREATE TABLE "+quoted+".lifecycle_canary(id INT PRIMARY KEY,v INT NOT NULL) ENGINE=InnoDB")
	for n := range dGCOwnerLifecycleCases {
		f.exec(t, "INSERT INTO "+quoted+".lifecycle_canary VALUES(?,0)", n+1)
	}
	for n, name := range dGCOwnerLifecycleCases {
		t.Run(name, func(t *testing.T) {
			releaseBudget := 5 * time.Second
			if name == "canceled_holder" {
				// Retain the long in-flight query and exact thread witness. Client
				// cancellation is checked separately within ten seconds; server cleanup
				// gets the full SLEEP duration plus ten seconds, without KILL/UNLOCK.
				releaseBudget = time.Duration(dGCLifecycleCancelSleepSeconds)*time.Second + 10*time.Second
			}
			ctx, cancel := context.WithTimeout(f.ctx, 30*time.Second)
			defer cancel()
			db, trace := dGCLifecyclePool(t, f)
			registry := SQLRegistry{DB: db, Policy: &gcConnectionPolicy{}, Installation: "installation_test", ServerUUID: f.server, Database: f.db}
			owned, _, err := beginDownloadGCConnection(ctx, registry)
			dGCFreezeOK(t, err)
			var id int64
			t.Cleanup(func() {
				_ = owned.close()
				if id > 0 && f.threads[id] > 0 && !dGCLifecycleReleased(f, id, releaseBudget) {
					t.Errorf("CLEANUP_PENDING owner lifecycle connection=%d thread=%d", id, f.threads[id])
				}
			})
			var server, database, uid, ownerServer, account, role, zone string
			dGCFreezeOK(t, owned.tx.QueryRowContext(ctx, "SELECT CONNECTION_ID(),@@server_uuid,DATABASE(),(SELECT uid FROM freeze_owner),(SELECT server_uuid FROM freeze_owner),CURRENT_USER(),CURRENT_ROLE(),@@session.time_zone").Scan(&id, &server, &database, &uid, &ownerServer, &account, &role, &zone))
			if id <= 0 || server != f.server || database != f.db || uid != f.uid || ownerServer != f.server || account != f.user+"@%" || role != "NONE" || zone != "+00:00" {
				t.Fatal("lifecycle holder identity changed")
			}
			f.pinThread(t, id)
			wire := trace.first(t)
			_, err = owned.tx.ExecContext(ctx, "LOCK INSTANCE FOR BACKUP")
			dGCFreezeOK(t, err)
			f.held(t, id)
			t.Logf("OWNER_LIFECYCLE_HELD case=%s connection=%d thread=%d holder=SHARED/EXPLICIT/GRANTED", name, id, f.threads[id])
			rowID, value := n+1, 101+n
			result, err := owned.tx.ExecContext(ctx, "UPDATE lifecycle_canary SET v=? WHERE id=?", value, rowID)
			dGCFreezeOK(t, err)
			affected, err := result.RowsAffected()
			dGCFreezeOK(t, err)
			if affected != 1 {
				t.Fatal("lifecycle canary did not update exactly one row")
			}
			commitOutcome, rollbackOutcome, unlockOutcome := "not_attempted", "not_attempted", "not_attempted"
			var closeErr error
			expectedValue := 0
			wantCommit, wantRollback, wantUnlock := int32(0), int32(1), int32(0)
			wantDropped := false
			switch name {
			case "known_commit_unlock", "known_commit_discard", "commit_reply_lost", "unlock_reply_lost":
				wantCommit, wantRollback = 1, 0
				expectedValue = value
				if name == "commit_reply_lost" {
					dGCFreezeOK(t, wire.arm(dGCLifecycleCommit))
					wantDropped = true
				}
				commitErr := owned.commit()
				if name == "commit_reply_lost" {
					if !errors.Is(commitErr, ErrDownloadRetentionGCCommitUnknown) {
						t.Fatal("lost COMMIT reply was acknowledged")
					}
					commitOutcome = "unknown"
				} else {
					dGCFreezeOK(t, commitErr)
					commitOutcome = "known"
					f.held(t, id)
					var sameID int64
					dGCFreezeOK(t, owned.conn.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&sameID))
					if sameID != id || db.Stats().InUse != 1 || db.Stats().Idle != 0 {
						t.Fatal("commit returned the holder before cleanup")
					}
				}
				if name == "known_commit_unlock" || name == "unlock_reply_lost" {
					wantUnlock = 1
					if name == "unlock_reply_lost" {
						dGCFreezeOK(t, wire.arm(dGCLifecycleUnlock))
						wantDropped = true
					}
					_, unlockErr := owned.conn.ExecContext(ctx, "UNLOCK INSTANCE")
					if name == "unlock_reply_lost" {
						if unlockErr == nil {
							t.Fatal("lost UNLOCK reply was acknowledged")
						}
						unlockOutcome = "unknown"
					} else {
						dGCFreezeOK(t, unlockErr)
						unlockOutcome = "known"
					}
				}
				closeErr = owned.close()
				if closeErr != nil {
					t.Fatal("commit cleanup claimed an unattempted rollback")
				}
			case "known_rollback_discard", "rollback_reply_lost":
				if name == "rollback_reply_lost" {
					dGCFreezeOK(t, wire.arm(dGCLifecycleRollback))
					wantDropped = true
				}
				closeErr = owned.close()
				if name == "rollback_reply_lost" {
					if closeErr != ErrDownloadRetentionGCRollbackUnknown {
						t.Fatal("lost ROLLBACK reply was acknowledged")
					}
					rollbackOutcome = "unknown"
				} else {
					dGCFreezeOK(t, closeErr)
					rollbackOutcome = "known"
				}
			case "canceled_holder":
				// The original transaction context is canceled only after the exact pinned
				// thread is observed executing the blocking query; no sleep timing guess.
				dGCLifecycleCancelQuery(t, f, ctx, owned, id, cancel)
				closeErr = owned.close()
				if closeErr != ErrDownloadRetentionGCRollbackUnknown {
					t.Fatal("canceled holder claimed an observed rollback")
				}
				rollbackOutcome = "unknown"
				wantRollback = wire.counts[dGCLifecycleRollback].Load()
				if wantRollback > 1 {
					t.Fatal("canceled holder retried rollback")
				}
			case "killed_holder":
				var currentThread int64
				dGCFreezeOK(t, f.admin.QueryRowContext(f.ctx, "SELECT THREAD_ID FROM performance_schema.threads WHERE PROCESSLIST_ID=?", id).Scan(&currentThread))
				if currentThread != f.threads[id] {
					t.Fatal("kill target changed its exact thread")
				}
				f.exec(t, "KILL CONNECTION "+strconv.FormatInt(id, 10))
				closeErr = owned.close()
				if closeErr != ErrDownloadRetentionGCRollbackUnknown {
					t.Fatal("killed holder claimed an observed rollback")
				}
				rollbackOutcome = "unknown"
				// The dead socket may reject ROLLBACK before Write, or accept its bytes and
				// then fail the read. No second attempt is allowed in either transport path.
				wantRollback = wire.counts[dGCLifecycleRollback].Load()
				if wantRollback > 1 {
					t.Fatal("killed holder retried rollback")
				}
			default:
				t.Fatal("unreviewed lifecycle case")
			}
			if again := owned.close(); again != closeErr {
				t.Fatal("repeated cleanup erased an unknown result")
			}
			releaseStarted := time.Now()
			if !dGCLifecycleReleased(f, id, releaseBudget) {
				t.Errorf("CLEANUP_PENDING owner lifecycle connection=%d thread=%d", id, f.threads[id])
				t.Fatal("exact holder ticket removal was not observed")
			}
			releaseElapsed := time.Since(releaseStarted)
			if got := dGCLifecycleRead(t, f, rowID); got != expectedValue {
				t.Fatal("fresh observer saw the wrong canary outcome")
			}
			if wire.dropped.Load() != wantDropped || wire.counts[dGCLifecycleCommit].Load() != wantCommit || wire.counts[dGCLifecycleRollback].Load() != wantRollback || wire.counts[dGCLifecycleUnlock].Load() != wantUnlock || wire.counts[dGCLifecycleLock].Load() != 1 {
				t.Fatal("lifecycle wire result or sole command count changed")
			}
			if db.Stats().OpenConnections != 0 {
				t.Fatal("holder returned to the idle pool")
			}
			fresh, err := db.Conn(f.ctx)
			dGCFreezeOK(t, err)
			var freshID int64
			var freshServer, freshDB, freshUID string
			dGCFreezeOK(t, fresh.QueryRowContext(f.ctx, "SELECT CONNECTION_ID(),@@server_uuid,DATABASE(),(SELECT uid FROM freeze_owner)").Scan(&freshID, &freshServer, &freshDB, &freshUID))
			dGCFreezeOK(t, fresh.Close())
			if freshID <= 0 || freshID == id || freshServer != f.server || freshDB != f.db || freshUID != f.uid {
				t.Fatal("cleanup reused the original physical session")
			}
			t.Logf("OWNER_LIFECYCLE case=%s connection=%d thread=%d commit=%s rollback=%s unlock=%s wire_ok_dropped=%t canary=%d original_ticket_absent=yes fresh_connection=%d release_wait=%s release_budget=%s", name, id, f.threads[id], commitOutcome, rollbackOutcome, unlockOutcome, wantDropped, expectedValue, freshID, releaseElapsed, releaseBudget)
		})
	}
	if !t.Failed() {
		t.Log("PASS owner-lifecycle cases=8 wire_reply_loss=commit/rollback/unlock production_connection_owner=yes scope=synthetic full_gc=not_run freeze_adapter=not_wired role_approval=no production_approval=no")
	}
}
