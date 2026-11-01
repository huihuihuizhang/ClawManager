package systembackupexecution

import (
	"context"
	"database/sql/driver"
	"errors"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
)

// A transparent REAL driver barrier holds only the selected actual Commit.
// Every query/update/lock is executed by MySQL; no authority is synthesized.
type aFreshRaceBarrier struct {
	armed         atomic.Int32 // 1: original104 constructor, 2: original claim Renew
	held, release chan struct{}
	once          sync.Once
	trace         *aPublisherConcurrentSQLTrace
}
type aFreshRaceConnector struct {
	driver.Connector
	barrier *aFreshRaceBarrier
}
type aFreshRaceConn struct {
	driver.Conn
	barrier *aFreshRaceBarrier
	kind    int32
	ctx     context.Context
}
type aFreshRaceTx struct {
	driver.Tx
	conn *aFreshRaceConn
	end  func()
}

// Test-only correlation for the old no-I/O-across-own-TX assertion. Global
// pool InUse cannot distinguish two legitimate concurrent executions.
type aPublisherConcurrentSQLTrace struct {
	mu           sync.Mutex
	transactions map[uint64]int
}

func aPublisherTestGoroutine() uint64 {
	var stack [96]byte
	n := runtime.Stack(stack[:], false)
	fields := strings.Fields(string(stack[:n]))
	if len(fields) < 2 || fields[0] != "goroutine" {
		panic("test goroutine trace unavailable")
	}
	id, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		panic("test goroutine trace invalid")
	}
	return id
}
func (x *aPublisherConcurrentSQLTrace) begin() func() {
	id := aPublisherTestGoroutine()
	x.mu.Lock()
	if x.transactions == nil {
		x.transactions = map[uint64]int{}
	}
	x.transactions[id]++
	x.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { x.mu.Lock(); x.transactions[id]--; x.mu.Unlock() }) }
}
func (x *aPublisherConcurrentSQLTrace) active() bool {
	id := aPublisherTestGoroutine()
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.transactions[id] > 0
}
func (x aFreshRaceTx) Rollback() error { defer x.end(); return x.Tx.Rollback() }

func (x aFreshRaceConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := x.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &aFreshRaceConn{Conn: conn, barrier: x.barrier}, nil
}
func (x *aFreshRaceConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	tx, err := x.Conn.(driver.ConnBeginTx).BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	x.kind, x.ctx = 0, ctx
	return aFreshRaceTx{tx, x, x.barrier.trace.begin()}, nil
}
func (x *aFreshRaceConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	return x.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}
func (x *aFreshRaceConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	result, err := x.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
	if err == nil || errors.Is(err, driver.ErrSkip) {
		if strings.HasPrefix(q, "INSERT INTO system_backup_v2_staging_resources(") {
			x.kind = 1
		}
		if strings.HasPrefix(q, "UPDATE system_backup_v2_backups SET controller_lease_expires_at = GREATEST(") {
			x.kind = 2
		}
	}
	return result, err
}
func (x aFreshRaceTx) Commit() error {
	defer x.end()
	if x.conn.kind != 0 && x.conn.barrier.armed.CompareAndSwap(x.conn.kind, 0) {
		close(x.conn.barrier.held)
		select {
		case <-x.conn.barrier.release:
		case <-x.conn.ctx.Done():
			return x.conn.ctx.Err()
		}
	}
	return x.Tx.Commit()
}

func aFreshFixturePolicy(t *testing.T, f *aPublicationMaterialFixture) c.LeasePolicy {
	t.Helper()
	var ttl, heartbeat, reconcile int64
	if err := f.x.history.admin.QueryRow(`SELECT controller_claim_ttl_seconds,controller_claim_heartbeat_seconds,controller_reconcile_interval_seconds FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=1`, f.x.history.original.InstallationID).Scan(&ttl, &heartbeat, &reconcile); err != nil {
		t.Fatal(err)
	}
	return c.LeasePolicy{TTL: time.Duration(ttl) * time.Second, HeartbeatInterval: time.Duration(heartbeat) * time.Second, ReconcileInterval: time.Duration(reconcile) * time.Second}
}

func TestPublicationFreshPreparationActualTaskLockRaceMySQL(t *testing.T) {
	for _, first := range []string{"104-first", "renew-first"} {
		t.Run(first, func(t *testing.T) {
			barrier := &aFreshRaceBarrier{held: make(chan struct{}), release: make(chan struct{}), trace: &aPublisherConcurrentSQLTrace{}}
			unblock := func() { barrier.once.Do(func() { close(barrier.release) }) }
			defer unblock()
			f := newAPublicationMaterialFixtureControl(t, false, func(inner driver.Connector) driver.Connector { return aFreshRaceConnector{inner, barrier} }, barrier.trace)
			h := f.x.history
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			policy, old := aFreshFixturePolicy(t, f), h.token
			claim := old
			renewDone, candidateDone := make(chan error, 1), make(chan error, 1)
			renew := func() {
				renewDone <- h.service.renewFreshOriginalPublicationPreparation(ctx, &claim, 1, policy, f.store.config, f.request)
			}
			candidate := func() {
				_, err := h.service.beginPublicationCandidate(ctx, old, 1, f.store.config, f.request)
				candidateDone <- err
			}
			if first == "104-first" {
				barrier.armed.Store(1)
				go candidate()
			} else {
				barrier.armed.Store(2)
				go renew()
			}
			select {
			case <-barrier.held:
			case <-ctx.Done():
				t.Fatal("real first transaction did not reach commit barrier", ctx.Err())
			}
			if first == "104-first" {
				go renew()
			} else {
				go candidate()
			}
			// Prove a REAL second session is waiting on an InnoDB lock, not
			// a goroutine timer or a passed test guard.
			waitCtx, stop := context.WithTimeout(ctx, 3*time.Second)
			defer stop()
			var waits int
			for waits == 0 {
				if err := h.admin.QueryRowContext(waitCtx, `SELECT COUNT(*) FROM performance_schema.data_lock_waits w JOIN performance_schema.threads t ON t.THREAD_ID=w.REQUESTING_THREAD_ID WHERE t.PROCESSLIST_DB=?`, h.owner.Identity.DeploymentBinding().Database).Scan(&waits); err != nil {
					unblock()
					<-renewDone
					<-candidateDone
					t.Fatal("real SQL lock-wait proof", err)
				}
				if waits == 0 {
					select {
					case <-time.After(10 * time.Millisecond):
					case <-waitCtx.Done():
						unblock()
						<-renewDone
						<-candidateDone
						t.Fatal("no actual second-session SQL lock wait")
					}
				}
			}
			unblock()
			renewErr, candidateErr := <-renewDone, <-candidateDone
			var version uint64
			var candidates, materials, sends, observations int
			if h.admin.QueryRow(`SELECT row_version FROM system_backup_v2_backups WHERE public_id=?`, old.Target.PublicID).Scan(&version) != nil || h.admin.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_staging_resources WHERE resource_type='remote_manifest_candidate'`).Scan(&candidates) != nil || h.admin.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_evidence WHERE public_id LIKE 'sev!_pub!_material!_%' ESCAPE '!'`).Scan(&materials) != nil || h.admin.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_job_send_intents WHERE phase='publish'`).Scan(&sends) != nil || h.admin.QueryRow(`SELECT COUNT(*) FROM system_backup_v2_job_observations WHERE phase='publish'`).Scan(&observations) != nil {
				t.Fatal("original SQL race readback")
			}
			if first == "104-first" {
				if candidateErr != nil || !errors.Is(renewErr, errOriginalPublicationPreparationExists) || claim != old || version != old.RowVersion || candidates != 1 {
					t.Fatal("104-first allowed stale delegation renewal", candidateErr, renewErr, version, candidates)
				}
			} else if renewErr != nil || candidateErr == nil || claim.RowVersion != old.RowVersion+1 || version != claim.RowVersion || candidates != 0 {
				t.Fatal("Renew-first accepted old claim104", renewErr, candidateErr, version, candidates)
			}
			if materials+sends+observations+f.secretCreates+f.secretUpdates+f.jobCreates+f.provider.puts+f.provider.gets+f.provider.heads != 0 {
				t.Fatal("race minted material or reached native publication")
			}
			t.Log("actual InnoDB waiting session observed; original task-lock order", first)
		})
	}
}

// The shared guard's ordinary mode still performs the original actual Renew
// after a real upload Job activation has persisted 104/121/107. This does not
// claim a full native C receipt: it proves the shared C guard is not fresh-only.
func TestPublicationContainerRenewalModeActualJobMySQL(t *testing.T) {
	for _, mode := range []string{"fresh-old104", "ordinary-activated-upload"} {
		t.Run(mode, func(t *testing.T) {
			f := newAPublicationMaterialFixture(t, true)
			aPublicationActualObservationDDL(t, f)
			h, ctx := f.x.history, context.Background()
			claim := h.token
			policy := aFreshFixturePolicy(t, f)
			if mode == "fresh-old104" {
				if _, err := h.service.beginPublicationCandidate(ctx, claim, 1, f.store.config, f.request); err != nil {
					t.Fatal(err)
				}
			} else {
				patches := aPublicationNativeJobAPI(t, f, "current")
				job, err := h.service.ensureStartedPublicationJob(ctx, claim, 1, f.store.config, f.request)
				if err != nil || job == nil || *patches != 1 {
					t.Fatal("actual upload activation", err)
				}
			}
			access, err := h.service.publicationAccess(ctx, claim, 1)
			if err != nil || access.Check(ctx) != nil {
				t.Fatal("actual guard access", err)
			}
			// Let the original SQL time window naturally reach the unchanged
			// existing trigger. Never shorten/extend a grant or fake access.
			if wait := time.Until(access.ValidUntil()) - 2*policy.HeartbeatInterval + time.Millisecond; wait > 0 {
				if wait > policy.TTL {
					t.Fatal("unexpected fixture trigger wait")
				}
				time.Sleep(wait)
			}
			before := aPreparationLedgerFingerprint(t, h.admin)
			guard := &publicationContainerGuard{service: h.service, claim: &claim, attempt: 1, policy: policy, access: access, freshPreparation: mode == "fresh-old104"}
			err = guard.current(ctx, true)
			var version uint64
			if h.admin.QueryRow(`SELECT row_version FROM system_backup_v2_backups WHERE public_id=?`, h.original.TaskPublicID).Scan(&version) != nil {
				t.Fatal("mode readback")
			}
			if mode == "fresh-old104" {
				if !errors.Is(err, errOriginalPublicationPreparationExists) || claim != h.token || version != h.token.RowVersion {
					t.Fatal("early fresh guard adopted104", err)
				}
			} else if err != nil || claim.RowVersion != h.token.RowVersion+1 || version != claim.RowVersion {
				t.Fatal("ordinary shared guard blocked actual Renew after104/121/107", err)
			}
			if aPreparationLedgerFingerprint(t, h.admin) != before {
				t.Fatal("guard changed original upload/capture bytes")
			}
		})
	}
}
