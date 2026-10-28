//go:build systembackup_mysql

package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

var dGCFullLifecycleCases = []string{
	"killed_after_delete", "holder_exit_before_begin", "cancel_before_begin", "takeover_after_kill",
	"two_public_holders", "foreign_holder_retained", "fresh_after_rollback", "fresh_after_success",
	"stale_registry_pool_ignored", "temp_shadow_other_session", "bad_timezone_rejected",
	"lock_wait_restored_to_bound", "public_ddl_pending", "bounded_batch_plan", "oversized_program_rejected",
}

// SHOW CREATE's allocator counter is data, including allocations rolled back
// by InnoDB. Strip only the unquoted outer table-option token. Column options,
// indexes, constraints, and strings/comments remain byte-for-byte protected.
func dGCColdSchemaPin(ddl string) string {
	if !strings.HasPrefix(ddl, "CREATE TABLE `") {
		return ""
	}
	depth, end := 0, -1
	var quote byte
	for i := strings.IndexByte(ddl, '('); i >= 0 && i < len(ddl); i++ {
		c := ddl[i]
		if quote != 0 {
			if c == '\\' && i+1 < len(ddl) {
				i++
				continue
			}
			if c == quote {
				if i+1 < len(ddl) && ddl[i+1] == quote {
					i++
				} else {
					quote = 0
				}
			}
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			quote = c
			continue
		}
		if c == '(' {
			depth++
		}
		if c == ')' {
			depth--
			if depth == 0 {
				end = i + 1
				break
			}
		}
	}
	if end < 0 {
		return ""
	}
	tail := ddl[end:]
	if !strings.HasPrefix(tail, " ENGINE=") {
		return ""
	}
	counterStart, counterEnd := -1, -1
	quote = 0
	for i := 0; i < len(tail); i++ {
		c := tail[i]
		if quote != 0 {
			if c == '\\' && i+1 < len(tail) {
				i++
				continue
			}
			if c == quote {
				if i+1 < len(tail) && tail[i+1] == quote {
					i++
				} else {
					quote = 0
				}
			}
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			quote = c
			continue
		}
		// This fixture only accepts SHOW CREATE's flat table-option tail.
		// Comments (including executable version comments), partitions and
		// nested expressions require separate review; never strip their bytes.
		if strings.ContainsRune("/*#();", rune(c)) || (c == '-' && i+1 < len(tail) && tail[i+1] == '-') {
			return ""
		}
		const token = " AUTO_INCREMENT="
		if strings.HasPrefix(strings.ToUpper(tail[i:]), " AUTO_INCREMENT") && !strings.HasPrefix(tail[i:], token) {
			return ""
		}
		if strings.HasPrefix(tail[i:], token) {
			j := i + len(token)
			start := j
			for j < len(tail) && tail[j] >= '0' && tail[j] <= '9' {
				j++
			}
			if j == start || (j < len(tail) && tail[j] != ' ' && tail[j] != '\n' && tail[j] != '\r') || counterStart >= 0 {
				return ""
			}
			value, e := strconv.ParseUint(tail[start:j], 10, 64)
			if e != nil || value == 0 {
				return ""
			}
			counterStart, counterEnd = i, j
			i = j - 1
		}
	}
	if quote != 0 {
		return ""
	}
	if counterStart >= 0 {
		return hash([]byte(ddl[:end] + tail[:counterStart] + tail[counterEnd:]))
	}
	return hash([]byte(ddl))
}

func TestDDownloadGCFullLifecycleMySQLSeed(t *testing.T) {
	if len(dGCFullLifecycleCases) != 15 {
		t.Fatal("lifecycle catalog changed")
	}
	seen := map[string]bool{}
	for _, n := range dGCFullLifecycleCases {
		if seen[n] {
			t.Fatal("duplicate lifecycle case")
		}
		seen[n] = true
	}
	a := "CREATE TABLE `x` (\n `id` bigint NOT NULL AUTO_INCREMENT,\n `s` varchar(80) COMMENT 'keep ) AUTO_INCREMENT=91',\n PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='AUTO_INCREMENT=22'"
	b := strings.Replace(a, " ENGINE=InnoDB", " ENGINE=InnoDB AUTO_INCREMENT=42", 1)
	if dGCColdSchemaPin(a) != dGCColdSchemaPin(b) || dGCColdSchemaPin(b) != dGCColdSchemaPin(strings.Replace(b, "AUTO_INCREMENT=42", "AUTO_INCREMENT=900", 1)) {
		t.Fatal("allocator counter treated as schema")
	}
	for _, changed := range []string{strings.Replace(a, "bigint", "int", 1), strings.Replace(a, "AUTO_INCREMENT=91", "AUTO_INCREMENT=92", 1), strings.Replace(a, "AUTO_INCREMENT=22", "AUTO_INCREMENT=23", 1), strings.Replace(a, "PRIMARY KEY (`id`)", "UNIQUE KEY (`id`)", 1)} {
		if dGCColdSchemaPin(a) == dGCColdSchemaPin(changed) {
			t.Fatal("semantic table definition ignored")
		}
	}
	for _, bad := range []string{"unknown CREATE format", strings.Replace(b, "AUTO_INCREMENT=42", "AUTO_INCREMENT=42 AUTO_INCREMENT=43", 1), strings.Replace(b, "AUTO_INCREMENT=42", "AUTO_INCREMENT=-1", 1), strings.Replace(b, "AUTO_INCREMENT=42", "AUTO_INCREMENT=", 1), strings.Replace(b, "AUTO_INCREMENT=42", "AUTO_INCREMENT=0", 1), b + " COMMENT='unclosed"} {
		if dGCColdSchemaPin(bad) != "" {
			t.Fatal("unknown/duplicate allocator format accepted")
		}
	}
	for _, suffix := range []string{" /* keep AUTO_INCREMENT=42 */", " /*!50100 AUTO_INCREMENT=42 */", " -- AUTO_INCREMENT=42", " # AUTO_INCREMENT=42", " PARTITION BY HASH (`id` AUTO_INCREMENT=42)"} {
		for _, n := range []string{"42", "99"} {
			if dGCColdSchemaPin(a+strings.ReplaceAll(suffix, "42", n)) != "" {
				t.Fatal("unknown comment/nested tail accepted")
			}
		}
	}
	escaped := "CREATE TABLE `x` (\n `a)``b` int COMMENT 'it\\'s ) AUTO_INCREMENT=91'\n) ENGINE=InnoDB COMMENT='x'' AUTO_INCREMENT=22'"
	if dGCColdSchemaPin(escaped) == "" || dGCColdSchemaPin(escaped) != dGCColdSchemaPin(strings.Replace(escaped, " ENGINE=InnoDB", " ENGINE=InnoDB AUTO_INCREMENT=23", 1)) {
		t.Fatal("quoted delimiter/escaped comment parsing changed")
	}
	if downloadGCBatchMax != 128 || !strings.Contains(downloadGCBatchCandidatesSQL, "ORDER BY id LIMIT ?") {
		t.Fatal("batch bound changed")
	}
	t.Log("PASS full_lifecycle_seed cases=15 actual_mysql=not_run domain=synthetic_known_tasks physical_capacity=no production=no")
}

var errGCFullLifecycle = errors.New("gc_full_lifecycle_fixture_denied")

type dGCLifecycleHook struct {
	t                         *testing.T
	f                         *dGCColdFixture
	mode                      string
	ready, release            chan struct{}
	once, releaseOnce         sync.Once
	sid                       int64
	killed, exited, waitBound bool
}
type dGCLifecycleConnector struct {
	inner driver.Connector
	h     *dGCLifecycleHook
}

func (c dGCLifecycleConnector) Driver() driver.Driver { return c.inner.Driver() }
func (c dGCLifecycleConnector) Connect(ctx context.Context) (driver.Conn, error) {
	x, e := c.inner.Connect(ctx)
	if e != nil {
		return nil, e
	}
	r, e := dGCLifecycleRow(ctx, x, "SELECT @@server_uuid,DATABASE(),CURRENT_USER(),CONNECTION_ID()")
	if e != nil || len(r) != 4 || dGCLifecycleString(r[0]) != c.h.f.p.role.c.Database.ServerUUID || dGCLifecycleString(r[1]) != c.h.f.p.role.c.Database.Database || dGCLifecycleString(r[2]) != c.h.f.p.role.c.Account {
		x.Close()
		return nil, errGCFullLifecycle
	}
	c.h.sid, e = dGCLifecycleInt(r[3])
	if e != nil || c.h.sid <= 0 {
		x.Close()
		return nil, errGCFullLifecycle
	}
	c.h.f.p.ddl.pinThread(c.h.t, c.h.sid)
	if c.h.mode == "bad_timezone_rejected" {
		_, e = x.(driver.ExecerContext).ExecContext(ctx, "SET SESSION time_zone = '+01:00'", nil)
	}
	if c.h.mode == "lock_wait_restored_to_bound" {
		_, e = x.(driver.ExecerContext).ExecContext(ctx, "SET SESSION lock_wait_timeout = 17", nil)
	}
	if e != nil {
		x.Close()
		return nil, e
	}
	return &dGCLifecycleConn{Conn: x, h: c.h}, nil
}

type dGCLifecycleConn struct {
	driver.Conn
	h *dGCLifecycleHook
}

func (c *dGCLifecycleConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	if o.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || o.ReadOnly {
		return nil, errGCFullLifecycle
	}
	if c.h.mode == "holder_exit_before_begin" {
		c.h.exited = true
		_ = c.Conn.Close()
		return nil, errGCFullLifecycle
	}
	if c.h.mode == "cancel_before_begin" {
		c.h.f.cancel()
		return nil, ctx.Err()
	}
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
}
func (c *dGCLifecycleConn) ExecContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	r, e := c.Conn.(driver.ExecerContext).ExecContext(ctx, q, a)
	if e != nil {
		return nil, e
	}
	if c.h.mode == "lock_wait_restored_to_bound" && q == "SET SESSION lock_wait_timeout = ?" {
		v, e := dGCLifecycleRow(ctx, c.Conn, "SELECT @@session.lock_wait_timeout")
		if e != nil || len(v) != 1 {
			return nil, errGCFullLifecycle
		}
		n, e := dGCLifecycleInt(v[0])
		if e != nil || n != int64(c.h.f.collector.freeze.wait) {
			return nil, errGCFullLifecycle
		}
		c.h.waitBound = true
	}
	return r, nil
}
func (c *dGCLifecycleConn) QueryContext(ctx context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	r, e := c.Conn.(driver.QueryerContext).QueryContext(ctx, q, a)
	if e != nil {
		return nil, e
	}
	c.h.f.trace.Lock()
	final := c.h.f.trace.finalTicket
	c.h.f.trace.Unlock()
	if q == downloadGCFreezeHeldSQL && final {
		var hookErr error
		c.h.once.Do(func() {
			if c.h.mode == "killed_after_delete" || c.h.mode == "takeover_after_kill" {
				hookErr = c.h.kill(ctx)
				return
			}
			if c.h.mode == "pause" {
				close(c.h.ready)
				select {
				case <-c.h.release:
				case <-ctx.Done():
					hookErr = ctx.Err()
				}
			}
		})
		if hookErr != nil {
			r.Close()
			return nil, hookErr
		}
	}
	return r, nil
}
func dGCLifecycleString(v driver.Value) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case uint64:
		return strconv.FormatUint(x, 10)
	}
	return ""
}
func dGCLifecycleInt(v driver.Value) (int64, error) {
	return strconv.ParseInt(dGCLifecycleString(v), 10, 64)
}
func dGCLifecycleRow(ctx context.Context, c driver.Conn, q string) ([]driver.Value, error) {
	r, e := c.(driver.QueryerContext).QueryContext(ctx, q, nil)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	v := make([]driver.Value, len(r.Columns()))
	if e = r.Next(v); e != nil {
		return nil, e
	}
	if r.Next(make([]driver.Value, len(v))) != io.EOF {
		return nil, errGCFullLifecycle
	}
	return v, nil
}
func (h *dGCLifecycleHook) kill(ctx context.Context) error {
	f := h.f
	p := f.collector.freeze.authority.(*dGCColdPolicy).profile
	if h.sid <= 0 || p.holder != h.sid {
		return errGCFullLifecycle
	}
	var run, uid, server, user, db string
	var thread int64
	if f.p.ddl.admin.QueryRowContext(ctx, "SELECT run_namespace,namespace_uid,server_uuid FROM d_invariant_run_marker WHERE id=1").Scan(&run, &uid, &server) != nil || run != os.Getenv("D_INVARIANT_RUN") || uid != f.p.ddl.uid || server != f.p.ddl.server {
		return errGCFullLifecycle
	}
	if f.p.ddl.admin.QueryRowContext(ctx, "SELECT THREAD_ID,PROCESSLIST_USER,PROCESSLIST_DB FROM performance_schema.threads WHERE PROCESSLIST_ID=?", h.sid).Scan(&thread, &user, &db) != nil || thread != f.p.ddl.threads[h.sid] || user != f.p.role.user || db != f.p.role.c.Database.Database {
		return errGCFullLifecycle
	}
	if _, e := f.p.ddl.admin.ExecContext(ctx, "KILL CONNECTION "+strconv.FormatInt(h.sid, 10)); e != nil {
		return e
	}
	h.killed = true
	return nil
}
func dGCLifecycleAttach(t *testing.T, f *dGCColdFixture, mode string) *dGCLifecycleHook {
	t.Helper()
	h := &dGCLifecycleHook{t: t, f: f, mode: mode, ready: make(chan struct{}), release: make(chan struct{})}
	f.trace.inner = dGCLifecycleConnector{f.trace.inner, h}
	t.Cleanup(h.resume)
	return h
}
func (h *dGCLifecycleHook) resume() { h.releaseOnce.Do(func() { close(h.release) }) }
func dGCLifecycleAsync(f *dGCColdFixture) chan error {
	ch := make(chan error, 1)
	go func() {
		e := error(ErrDenied)
		defer func() { ch <- e }()
		e = f.collector.Collect(f.ctx, f.model.operation)
	}()
	return ch
}
func dGCLifecycleReady(t *testing.T, h *dGCLifecycleHook, done chan error) {
	t.Helper()
	select {
	case <-h.ready:
	case e := <-done:
		t.Fatalf("public owner ended before barrier: %v", boundary(e))
	case <-time.After(8 * time.Second):
		t.Fatal("public owner barrier not reached within original bounds")
	}
}
func dGCLifecycleDone(t *testing.T, done chan error) error {
	t.Helper()
	select {
	case e := <-done:
		return e
	case <-time.After(32 * time.Second):
		t.Fatal("public owner exceeded its original context")
		return ErrDenied
	}
}
func dGCFullLifecycleReleased(t *testing.T, f *dGCColdFixture, sid int64) {
	t.Helper()
	if sid <= 0 {
		t.Fatal("missing original holder")
	}
	until := time.Now().Add(3 * time.Second)
	for len(f.p.ddl.tickets(t, sid)) != 0 {
		if time.Now().After(until) {
			t.Fatal("original holder still owns backup lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func dGCLifecycleReport(t *testing.T, f *dGCColdFixture) {
	t.Helper()
	f.model.p.report.ObservedAt = aDownloadMFANow(t, f.p.ddl.ctx, f.p.role.root)
	f.model.p.writeReport(t)
}
func dGCLifecycleInputs(t *testing.T, f *dGCColdFixture) {
	t.Helper()
	pins := aGCRoleMetadata(t, f.p.ddl.ctx, f.p.role.root)
	f.collector.freeze.worker.c.Metadata = pins
	f.collector.freeze.scope.Metadata = pins
	o, e := f.collector.freeze.observer.Read(f.p.ddl.ctx)
	dGCFreezeOK(t, e)
	f.collector.freeze.programs = o.Digests().Combined
	f.collector.freeze.scope.ProgramsSHA256 = o.Digests().Combined
	dGCLifecycleReport(t, f)
}
func dGCLifecyclePreserved(t *testing.T, f *dGCColdFixture) {
	t.Helper()
	if f.fingerprint(t, false) != f.before || f.fingerprint(t, true) != f.evidenceBefore {
		t.Fatal("group, ledger, tombstone or retained evidence changed on rejection")
	}
}
func dGCLifecycleCommitted(t *testing.T, f *dGCColdFixture, e error) {
	t.Helper()
	if e != nil {
		t.Fatal("public owner did not commit", boundary(e))
	}
	if f.fingerprint(t, true) != f.evidenceBefore {
		t.Fatal("retained envelope changed")
	}
	for _, q := range []string{"SELECT COUNT(*) FROM system_backup_v2_operations WHERE id=73", "SELECT COUNT(*) FROM system_backup_v2_download_admission_receipts WHERE operation_id=73", "SELECT COUNT(*) FROM system_backup_v2_download_result_receipts WHERE operation_id=73", "SELECT COUNT(*) FROM system_backup_v2_strong_auth_nonces WHERE operation_id=73", "SELECT COUNT(*) FROM audit_logs WHERE id IN(1729,1730)"} {
		var n int
		dGCFreezeOK(t, f.p.role.root.QueryRowContext(f.p.ddl.ctx, q).Scan(&n))
		if n != 0 {
			t.Fatal("known committed group remains")
		}
	}
	var stones int
	var reserved int64
	dGCFreezeOK(t, f.p.role.root.QueryRowContext(f.p.ddl.ctx, "SELECT COUNT(*) FROM system_backup_v2_compact_tombstones WHERE source_public_id=?", f.model.operation).Scan(&stones))
	dGCFreezeOK(t, f.p.role.root.QueryRowContext(f.p.ddl.ctx, "SELECT reserved_bytes FROM system_backup_v2_metadata_reservations WHERE id=1").Scan(&reserved))
	if stones != 1 || reserved != 65536 {
		t.Fatal("committed marker/ledger is not exact")
	}
}

// A later invocation has its own authenticated context and protocol admission.
// It retains the original operation deadline, config and historical group.
func dGCLifecycleNext(t *testing.T, f *dGCColdFixture, claim string, version int64) *dGCColdFixture {
	t.Helper()
	old := f.collector
	prior := old.freeze.authority.(*dGCColdPolicy)
	p := *prior
	p.profile = &dGCFullProfileAuthority{f: f.p, t: t}
	p.mode = "commit"
	p.collector = nil
	peer := newTaskFixture(t, false)
	c := old.c
	c.Policy = &p
	c.OperationClaim = claim
	c.OperationRowVersion = version
	c.ClientCAPEM = peer.c.ClientCAPEM
	c.ClientCASHA256 = peer.c.ClientCASHA256
	c.CertificateSHA256 = peer.c.CertificateSHA256
	c.ExpiresAt = earlier(c.ExpiresAt, peer.c.ExpiresAt)
	connector, e := mysql.NewConnector(f.p.role.cfg.Clone())
	dGCFreezeOK(t, e)
	trace := &dGCColdTrace{inner: connector, mode: "commit"}
	c.Freeze = &DownloadGCFullFreezeConfig{Connector: trace, WaitSeconds: old.freeze.wait, Worker: old.freeze.worker.c, Observer: f.p.observerConfig, ProgramsSHA256: old.freeze.programs}
	s, e := NewSQLDownloadRetentionGC(c)
	dGCFreezeOK(t, e)
	p.collector = s
	ctx, e := s.AuthenticateRequest(peer.request)
	dGCFreezeOK(t, e)
	ctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	trace.cancel = cancel
	n := &dGCColdFixture{p: f.p, model: f.model, collector: s, trace: trace, ctx: ctx, cancel: cancel, before: f.fingerprint(t, false), evidenceBefore: f.evidenceBefore}
	dGCLifecycleReport(t, n)
	return n
}

func TestDDownloadGCFullLifecycleMySQL(t *testing.T) {
	raw, e := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	dGCFreezeOK(t, e)
	if hash(raw) != os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256") || hash(raw) != hash(aDownloadMFASeed) {
		t.Fatal("lifecycle capsule differs from binary")
	}
	input, e := decodeADownloadMFAInputs(raw)
	dGCFreezeOK(t, e)
	for _, name := range dGCFullLifecycleCases {
		t.Run(name, func(t *testing.T) {
			dGCLifecycleCase(t, input, name)
			t.Logf("FULL_LIFECYCLE_CASE name=%s actual_sql=yes public_collect=yes authority=synthetic_known_tasks physical=synthetic production=no", name)
		})
	}
	t.Log("PASS full_lifecycle_candidate cases=15 actual_sql=yes public_collect=yes old42_full33_cold7_not_recounted=yes production_approval=no")
}

func dGCLifecycleCase(t *testing.T, input aDownloadMFAInputs, name string) {
	t.Helper()
	if name == "two_public_holders" {
		dGCLifecycleTwo(t, input)
		return
	}
	mode := "commit"
	if name == "fresh_after_rollback" {
		mode = "late_policy_denied"
	}
	f := newDGCColdFixture(t, input, mode)
	switch name {
	case "killed_after_delete", "holder_exit_before_begin", "cancel_before_begin", "bad_timezone_rejected", "lock_wait_restored_to_bound":
		h := dGCLifecycleAttach(t, f, name)
		e := f.collector.Collect(f.ctx, f.model.operation)
		if name == "lock_wait_restored_to_bound" {
			dGCLifecycleCommitted(t, f, e)
			if !h.waitBound {
				t.Fatal("owner did not restore the exact bounded wait")
			}
		} else {
			if e == nil {
				t.Fatal("faulted owner reported success")
			}
			dGCLifecyclePreserved(t, f)
			if name == "killed_after_delete" && (!h.killed || f.trace.writes != 7) {
				t.Fatal("original holder was not killed after all deletes")
			}
			if name != "killed_after_delete" && (f.trace.begins != 0 || f.trace.writes != 0) {
				t.Fatal("invalid pre-Begin session reached work")
			}
		}
		dGCFullLifecycleReleased(t, f, h.sid)
	case "takeover_after_kill":
		dGCLifecycleTakeover(t, f)
	case "foreign_holder_retained":
		c, id := f.p.ddl.holder(t)
		defer c.Close()
		dGCLifecycleReport(t, f)
		dGCLifecycleCommitted(t, f, f.collector.Collect(f.ctx, f.model.operation))
		dGCFullLifecycleReleased(t, f, f.collector.freeze.authority.(*dGCColdPolicy).profile.holder)
		f.p.ddl.held(t, id)
		f.p.ddl.command(t, c, "UNLOCK INSTANCE")
		f.p.ddl.released(t, id)
	case "fresh_after_rollback", "fresh_after_success":
		e := f.collector.Collect(f.ctx, f.model.operation)
		if name == "fresh_after_rollback" {
			if e == nil {
				t.Fatal("late deny committed")
			}
			dGCLifecyclePreserved(t, f)
		} else {
			dGCLifecycleCommitted(t, f, e)
		}
		id := f.collector.freeze.authority.(*dGCColdPolicy).profile.holder
		dGCFullLifecycleReleased(t, f, id)
		n := dGCLifecycleNext(t, f, f.collector.c.OperationClaim, f.collector.c.OperationRowVersion)
		e = n.collector.Collect(n.ctx, n.model.operation)
		if name == "fresh_after_rollback" {
			dGCLifecycleCommitted(t, n, e)
		} else {
			if e == nil || n.trace.writes != 0 {
				t.Fatal("absent original group was retried as new work")
			}
			dGCLifecyclePreserved(t, n)
		}
		nid := n.collector.freeze.authority.(*dGCColdPolicy).profile.holder
		if nid == id {
			t.Fatal("later invocation reused original physical session")
		}
		dGCFullLifecycleReleased(t, n, nid)
	case "stale_registry_pool_ignored":
		dGCFullLifecyclePool(t, f)
	case "temp_shadow_other_session":
		dGCLifecycleTemp(t, f)
	case "public_ddl_pending":
		dGCLifecycleDDL(t, f)
	case "bounded_batch_plan":
		dGCLifecycleScale(t, f)
	case "oversized_program_rejected":
		db, _ := dGCFreezeIdentifier(f.p.role.c.Database.Database)
		dGCColdExec(t, f.p.ddl.ctx, f.p.role.root, "CREATE VIEW "+db+".gc_lifecycle_oversized AS SELECT '"+strings.Repeat("x", 17000)+"' AS v")
		var n int
		dGCFreezeOK(t, f.p.role.root.QueryRowContext(f.p.ddl.ctx, "SELECT OCTET_LENGTH(VIEW_DEFINITION) FROM information_schema.VIEWS WHERE TABLE_SCHEMA=? AND TABLE_NAME='gc_lifecycle_oversized'", f.p.role.c.Database.Database).Scan(&n))
		if n <= 16384 {
			t.Fatal("field-size overflow control was not present")
		}
		if _, e := f.collector.freeze.observer.Read(f.p.ddl.ctx); e == nil {
			t.Fatal("observer accepted oversized field")
		}
		if f.collector.Collect(f.ctx, f.model.operation) == nil || f.trace.begins != 0 || f.trace.writes != 0 {
			t.Fatal("oversized metadata reached protected transaction")
		}
		dGCLifecyclePreserved(t, f)
		dGCFullLifecycleReleased(t, f, f.collector.freeze.authority.(*dGCColdPolicy).profile.holder)
	default:
		t.Fatal("unregistered lifecycle case")
	}
}

func dGCLifecycleTakeover(t *testing.T, f *dGCColdFixture) {
	t.Helper()
	ctx, db := f.p.ddl.ctx, f.p.role.root
	var originalDeadline time.Time
	dGCFreezeOK(t, db.QueryRowContext(ctx, "SELECT deadline_at FROM system_backup_v2_operations WHERE id=74 AND public_id=?", f.collector.c.OperationID).Scan(&originalDeadline))
	now := aDownloadMFANow(t, ctx, db)
	lease := now.Add(8 * time.Second)
	if !lease.Before(originalDeadline) {
		t.Fatal("fixture original operation deadline too short")
	}
	r, e := db.ExecContext(ctx, "UPDATE system_backup_v2_operations SET claim_expires_at=? WHERE id=74 AND public_id=? AND row_version=7 AND claim_owner=? AND status='running'", lease, f.collector.c.OperationID, f.collector.c.OperationClaim)
	dGCFreezeOK(t, e)
	n, e := r.RowsAffected()
	dGCFreezeOK(t, e)
	if n != 1 {
		t.Fatal("original short fixture lease not installed")
	}
	f.before = f.fingerprint(t, false)
	h := dGCLifecycleAttach(t, f, "takeover_after_kill")
	dGCLifecycleReport(t, f)
	if e = f.collector.Collect(f.ctx, f.model.operation); e == nil || !h.killed || f.trace.writes != 7 {
		t.Fatal("original public holder was not killed after work")
	}
	dGCFullLifecycleReleased(t, f, h.sid)
	dGCLifecyclePreserved(t, f)
	for now.Before(lease) {
		if ctx.Err() != nil {
			t.Fatal("fixture expired while waiting for original lease")
		}
		time.Sleep(20 * time.Millisecond)
		now = aDownloadMFANow(t, ctx, db)
	}
	claim := "full-lifecycle-successor"
	newLease := earlier(now.Add(30*time.Second), originalDeadline)
	r, e = db.ExecContext(ctx, "UPDATE system_backup_v2_operations SET claim_owner=?,claim_expires_at=?,row_version=row_version+1 WHERE id=74 AND public_id=? AND row_version=7 AND claim_owner=? AND claim_expires_at<=UTC_TIMESTAMP(6) AND deadline_at=? AND deadline_at>UTC_TIMESTAMP(6)", claim, newLease, f.collector.c.OperationID, f.collector.c.OperationClaim, originalDeadline)
	dGCFreezeOK(t, e)
	n, e = r.RowsAffected()
	dGCFreezeOK(t, e)
	if n != 1 {
		t.Fatal("natural-expiry takeover CAS failed")
	}
	var afterDeadline time.Time
	var version int64
	dGCFreezeOK(t, db.QueryRowContext(ctx, "SELECT deadline_at,row_version FROM system_backup_v2_operations WHERE id=74").Scan(&afterDeadline, &version))
	if !afterDeadline.Equal(originalDeadline) || version != 8 {
		t.Fatal("takeover renewed original deadline or lost fence")
	}
	stale := dGCLifecycleNext(t, f, f.collector.c.OperationClaim, 7)
	before := stale.fingerprint(t, false)
	if stale.collector.Collect(stale.ctx, stale.model.operation) == nil || stale.trace.writes != 0 || stale.fingerprint(t, false) != before {
		t.Fatal("fresh peer renewed stale worker fence")
	}
	successor := dGCLifecycleNext(t, f, claim, 8)
	dGCLifecycleCommitted(t, successor, successor.collector.Collect(successor.ctx, successor.model.operation))
	id := successor.collector.freeze.authority.(*dGCColdPolicy).profile.holder
	if id == h.sid {
		t.Fatal("takeover reused killed physical session")
	}
	dGCFullLifecycleReleased(t, successor, id)
	t.Log("FULL_LIFECYCLE_TAKEOVER natural_expiry=yes original_deadline_unchanged=yes old_fence_denied=yes new_fence_committed=yes")
}

func dGCLifecycleTwo(t *testing.T, input aDownloadMFAInputs) {
	t.Helper()
	a := newDGCColdFixture(t, input, "commit")
	b := newDGCColdFixture(t, input, "commit")
	dGCLifecycleInputs(t, a)
	dGCLifecycleInputs(t, b)
	ha, hb := dGCLifecycleAttach(t, a, "pause"), dGCLifecycleAttach(t, b, "pause")
	da, db := dGCLifecycleAsync(a), dGCLifecycleAsync(b)
	dGCLifecycleReady(t, ha, da)
	dGCLifecycleReady(t, hb, db)
	if ha.sid == hb.sid {
		t.Fatal("public holders share a physical session")
	}
	a.p.ddl.held(t, ha.sid)
	b.p.ddl.held(t, hb.sid)
	ha.resume()
	dGCLifecycleCommitted(t, a, dGCLifecycleDone(t, da))
	dGCFullLifecycleReleased(t, a, ha.sid)
	b.p.ddl.held(t, hb.sid)
	hb.resume()
	dGCLifecycleCommitted(t, b, dGCLifecycleDone(t, db))
	dGCFullLifecycleReleased(t, b, hb.sid)
	t.Logf("FULL_LIFECYCLE_HOLDERS first=%d second=%d distinct=yes first_released_second_retained=yes", ha.sid, hb.sid)
}

func dGCFullLifecyclePool(t *testing.T, f *dGCColdFixture) {
	t.Helper()
	pool := f.p.role.db
	pool.SetMaxIdleConns(1)
	pool.SetMaxOpenConns(1)
	c, e := pool.Conn(f.p.ddl.ctx)
	dGCFreezeOK(t, e)
	var id int64
	dGCFreezeOK(t, c.QueryRowContext(f.p.ddl.ctx, "SELECT CONNECTION_ID()").Scan(&id))
	for _, q := range []string{"SET @gc_lifecycle_pool=77", "SET SESSION time_zone='+01:00'", "SET SESSION lock_wait_timeout=17"} {
		_, e = c.ExecContext(f.p.ddl.ctx, q)
		dGCFreezeOK(t, e)
	}
	_, e = c.ExecContext(f.p.ddl.ctx, "CREATE TEMPORARY TABLE gc_lifecycle_forbidden(id INT)")
	var denied *mysql.MySQLError
	// CREATE_TMP_ACL is database-scoped. MySQL 8.4 create_table_precheck
	// rejects it in check_access with ER_DBACCESS_DENIED_ERROR (1044),
	// before table-level check_grant (1142) is reached.
	if !errors.As(e, &denied) || denied.Number != 1044 {
		t.Fatal("Full role TEMP privilege was widened or denial not native")
	}
	dGCFreezeOK(t, c.Close())
	dGCLifecycleReport(t, f)
	dGCLifecycleCommitted(t, f, f.collector.Collect(f.ctx, f.model.operation))
	next, e := pool.Conn(f.p.ddl.ctx)
	dGCFreezeOK(t, e)
	defer next.Close()
	var again, variable, wait int64
	var zone string
	dGCFreezeOK(t, next.QueryRowContext(f.p.ddl.ctx, "SELECT CONNECTION_ID(),@gc_lifecycle_pool,@@session.time_zone,@@session.lock_wait_timeout").Scan(&again, &variable, &zone, &wait))
	holder := f.collector.freeze.authority.(*dGCColdPolicy).profile.holder
	if again != id || holder == id || variable != 77 || zone != "+01:00" || wait != 17 {
		t.Fatal("public owner borrowed or reset shared registry session")
	}
	dGCFullLifecycleReleased(t, f, holder)
	_ = next.Raw(func(any) error { return driver.ErrBadConn })
	t.Log("FULL_LIFECYCLE_POOL pooled_state_preserved=yes public_fresh_distinct=yes temp_permission_denied=yes")
}

func dGCLifecycleTemp(t *testing.T, f *dGCColdFixture) {
	t.Helper()
	ctx := f.p.ddl.ctx
	c, e := f.p.ddl.admin.Conn(ctx)
	dGCFreezeOK(t, e)
	defer func() { _ = c.Raw(func(any) error { return driver.ErrBadConn }); _ = c.Close() }()
	var uid, server, run string
	dGCFreezeOK(t, c.QueryRowContext(ctx, "SELECT run_namespace,namespace_uid,server_uuid FROM d_invariant_run_marker WHERE id=1").Scan(&run, &uid, &server))
	if run != os.Getenv("D_INVARIANT_RUN") || uid != f.p.ddl.uid || server != f.p.ddl.server {
		t.Fatal("TEMP control outside original UID/server")
	}
	db, e := dGCFreezeIdentifier(f.p.role.c.Database.Database)
	dGCFreezeOK(t, e)
	_, e = c.ExecContext(ctx, "USE "+db)
	dGCFreezeOK(t, e)
	var id int64
	dGCFreezeOK(t, c.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&id))
	_, e = c.ExecContext(ctx, "CREATE TEMPORARY TABLE audit_logs(id BIGINT PRIMARY KEY,v INT NOT NULL)")
	dGCFreezeOK(t, e)
	_, e = c.ExecContext(ctx, "INSERT INTO audit_logs VALUES(1729,777)")
	dGCFreezeOK(t, e)
	dGCLifecycleReport(t, f)
	dGCLifecycleCommitted(t, f, f.collector.Collect(f.ctx, f.model.operation))
	var v int
	dGCFreezeOK(t, c.QueryRowContext(ctx, "SELECT v FROM audit_logs WHERE id=1729").Scan(&v))
	if v != 777 || id == f.collector.freeze.authority.(*dGCColdPolicy).profile.holder {
		t.Fatal("foreign temporary shadow affected public worker")
	}
	_, e = c.ExecContext(ctx, "DROP TEMPORARY TABLE audit_logs")
	dGCFreezeOK(t, e)
	t.Log("FULL_LIFECYCLE_TEMP same_schema_foreign_shadow_preserved=yes fresh_worker_real_group=yes grants_added=no")
}

func dGCLifecycleDDL(t *testing.T, f *dGCColdFixture) {
	t.Helper()
	h := dGCLifecycleAttach(t, f, "pause")
	done := dGCLifecycleAsync(f)
	dGCLifecycleReady(t, h, done)
	c, waiter := f.p.ddl.conn(t, f.p.ddl.admin)
	defer c.Close()
	schema, e := dGCFreezeIdentifier(f.p.ddl.db)
	dGCFreezeOK(t, e)
	ddlDone := make(chan error, 1)
	go func() {
		_, e := c.ExecContext(f.p.ddl.ctx, "ALTER TABLE "+schema+".canary ADD COLUMN lifecycle_added INT NULL")
		ddlDone <- e
	}()
	until := time.Now().Add(time.Second)
	for !dGCFreezeWitness(f.p.ddl.tickets(t, waiter), false) {
		select {
		case <-ddlDone:
			t.Fatal("DDL finished without exact pending backup-lock witness")
		default:
		}
		if time.Now().After(until) {
			t.Fatal("DDL pending witness not observed within original scope")
		}
		time.Sleep(5 * time.Millisecond)
	}
	f.p.ddl.held(t, h.sid)
	h.resume()
	err := dGCLifecycleDone(t, done)
	if err == nil {
		dGCLifecycleCommitted(t, f, err)
	} else {
		dGCLifecyclePreserved(t, f)
	}
	dGCFullLifecycleReleased(t, f, h.sid)
	select {
	case e := <-ddlDone:
		dGCFreezeOK(t, e)
	case <-time.After(5 * time.Second):
		t.Fatal("owned DDL did not complete after original release")
	}
	f.p.ddl.released(t, waiter)
	var n int
	dGCFreezeOK(t, f.p.ddl.admin.QueryRowContext(f.p.ddl.ctx, "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME='canary' AND COLUMN_NAME='lifecycle_added'", f.p.ddl.db).Scan(&n))
	if n != 1 {
		t.Fatal("DDL effect missing")
	}
	outcome := "committed"
	if err != nil {
		outcome = "denied_atomic"
	}
	t.Logf("FULL_LIFECYCLE_DDL holder=%d waiter=%d granted_and_pending=yes outcome=%s released_then_effect=yes", h.sid, waiter, outcome)
}

func dGCLifecyclePlan(t *testing.T, f *dGCColdFixture, q string, args ...any) {
	t.Helper()
	var raw []byte
	dGCFreezeOK(t, f.p.role.db.QueryRowContext(f.p.ddl.ctx, "EXPLAIN FORMAT=JSON "+q, args...).Scan(&raw))
	var plan any
	if json.Unmarshal(raw, &plan) != nil {
		t.Fatal("EXPLAIN JSON invalid")
	}
	nodes, indexed := 0, true
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if _, ok := x["table_name"]; ok {
				nodes++
				access, _ := x["access_type"].(string)
				key, _ := x["key"].(string)
				if access == "ALL" || access == "index" || key == "" {
					indexed = false
				}
			}
			for _, v := range x {
				walk(v)
			}
		case []any:
			for _, v := range x {
				walk(v)
			}
		}
	}
	walk(plan)
	if nodes == 0 {
		t.Fatal("EXPLAIN contains no table access witness")
	}
	t.Logf("FULL_LIFECYCLE_PLAN sha256=%s table_nodes=%d range_indexed=%t production_scale_approved=no", hash(raw), nodes, indexed)
}
func dGCLifecycleScale(t *testing.T, f *dGCColdFixture) {
	t.Helper()
	ctx, db := f.p.ddl.ctx, f.p.role.root
	now := aDownloadMFANow(t, ctx, db)
	empty := []byte("[]")
	const insert = `INSERT INTO system_backup_v2_operations(id,public_id,origin_installation_id,operation_type,target_type,target_public_id,actor_type,actor_id,endpoint,idempotency_key,request_hash,external_action_public_ids_canonical_json,external_action_public_ids_size_bytes,external_action_public_ids_sha256,status,failure_category,deadline_at,started_at,finished_at,created_at,updated_at) VALUES(?, ?,?,'control_metadata_gc','system',?,'system','system:controller','CollectSystemBackupControlMetadata',?,?,?,2,?,'failed','validation_failed',?,?,?,?,?)`
	for i := 0; i < 512; i++ {
		dGCColdExec(t, ctx, db, insert, 1000+i, fmt.Sprintf("sop_c0000000-0000-4000-8000-%012x", i+1), f.p.role.c.Installation, f.p.role.c.Installation, fmt.Sprintf("gc-lifecycle-inert-%04d", i), hash([]byte("inert")), empty, hash(empty), now.Add(-time.Second), now.Add(-2*time.Second), now.Add(-time.Second), now.Add(-2*time.Second), now.Add(-time.Second))
	}
	dGCLifecyclePlan(t, f, downloadGCBatchCandidatesSQL, f.p.role.c.Installation, int64(0), int64(5000), 129)
	dGCLifecyclePlan(t, f, downloadGCActorHintSQL, f.p.role.c.Installation, f.model.operation)
	if _, e := f.collector.CollectBatch(f.ctx, DownloadRetentionGCBatchCursor{}, 129); e == nil || f.trace.connections != 0 {
		t.Fatal("invalid page limit acquired a public owner")
	}
	dGCLifecycleReport(t, f)
	result, e := f.collector.CollectBatch(f.ctx, DownloadRetentionGCBatchCursor{ThroughID: 5000}, 128)
	if e != nil || result.Examined != 1 || result.Collected != 1 || result.Rejected != 0 || !result.EndOfRange || result.CommitUnknown || result.RollbackUnknown || result.ReleaseUnknown {
		t.Fatal("bounded public batch did not collect exactly the original eligible group")
	}
	dGCLifecycleCommitted(t, f, e)
	var n int
	dGCFreezeOK(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_operations WHERE id BETWEEN 1000 AND 1511").Scan(&n))
	if n != 512 {
		t.Fatal("batch mutated unrelated inert rows")
	}
	t.Log("FULL_LIFECYCLE_SCALE inert_rows=512 explicit_frame=5000 page_limit=128 invalid129_denied=yes eligible_collected=1 production_scale_approved=no")
}
