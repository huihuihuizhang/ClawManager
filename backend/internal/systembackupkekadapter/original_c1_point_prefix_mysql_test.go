//go:build systembackup_mysql

package systembackupkekadapter

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

type aPointNativeQuery struct {
	done chan struct{}
	got  RuntimeInstalledSQLSnapshot
	err  error
}

func aPointNativeStartQuery(t *testing.T, ctx context.Context, f *aPointNativeFixture, tx *sql.Tx) *aPointNativeQuery {
	t.Helper()
	child, cancel := context.WithCancel(ctx)
	q := &aPointNativeQuery{done: make(chan struct{})}
	go func() { defer close(q.done); q.got, q.err = f.query(child, tx) }()
	t.Cleanup(func() {
		cancel()
		tx.Rollback()
		select {
		case <-q.done:
		case <-time.After(5 * time.Second):
			t.Error("owned real query did not stop after cancellation/rollback")
		}
	})
	return q
}

func aPointNativeFinishQuery(t *testing.T, q *aPointNativeQuery) {
	t.Helper()
	select {
	case <-q.done:
	case <-time.After(5 * time.Second):
		t.Fatal("actual mixed reader did not finish after its exact blocker released")
	}
}

// A polling interval only bounds observation overhead. A real wait edge between
// the actual connection IDs is mandatory; elapsed sleep never establishes order.
func aPointNativeWait(t *testing.T, ctx context.Context, f *aPointNativeFixture, requester, blocker uint64, table, index string) uint64 {
	t.Helper()
	query := `SELECT rt.PROCESSLIST_ID FROM performance_schema.data_lock_waits w
JOIN performance_schema.data_locks r ON r.ENGINE=w.ENGINE AND r.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID
JOIN performance_schema.data_locks b ON b.ENGINE=w.ENGINE AND b.ENGINE_LOCK_ID=w.BLOCKING_ENGINE_LOCK_ID
JOIN performance_schema.threads rt ON rt.THREAD_ID=w.REQUESTING_THREAD_ID
JOIN performance_schema.threads bt ON bt.THREAD_ID=w.BLOCKING_THREAD_ID
WHERE r.OBJECT_SCHEMA=? AND r.OBJECT_NAME=? AND b.OBJECT_SCHEMA=r.OBJECT_SCHEMA AND b.OBJECT_NAME=r.OBJECT_NAME
AND (?=0 OR rt.PROCESSLIST_ID=?) AND bt.PROCESSLIST_ID=?
AND r.LOCK_TYPE='RECORD' AND r.LOCK_STATUS='WAITING' AND b.LOCK_STATUS='GRANTED'`
	args := []any{f.database.Database, table, requester, requester, blocker}
	if index != "" {
		query += " AND r.INDEX_NAME=?"
		args = append(args, index)
	}
	query += " LIMIT 1"
	until := time.NewTimer(3 * time.Second)
	defer until.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var observed uint64
		err := f.db.QueryRowContext(ctx, query, args...).Scan(&observed)
		if err == nil && observed != 0 {
			return observed
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			t.Fatal("actual lock-wait observation", table, err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("native wait context expired")
		case <-until.C:
			t.Fatal("exact native connection wait edge not observed", table, requester, blocker)
		case <-tick.C:
		}
	}
}

func aPointNativeFenceLocks(t *testing.T, ctx context.Context, f *aPointNativeFixture, connection uint64) int {
	t.Helper()
	var count int
	if err := f.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM performance_schema.data_locks l
JOIN performance_schema.threads t ON t.THREAD_ID=l.THREAD_ID
WHERE l.OBJECT_SCHEMA=? AND l.OBJECT_NAME='system_backup_v2_kek_fences'
AND l.LOCK_TYPE='RECORD' AND l.LOCK_STATUS='GRANTED' AND t.PROCESSLIST_ID=?`, f.database.Database, connection).Scan(&count); err != nil {
		t.Fatal("actual fence lock observation", err)
	}
	return count
}

func aPointNativeParentX(t *testing.T, ctx context.Context, f *aPointNativeFixture, tx *sql.Tx) {
	t.Helper()
	var id int64
	if err := tx.QueryRowContext(ctx, "SELECT id FROM system_backup_v2_evidence WHERE public_id=? FOR UPDATE", f.publicID).Scan(&id); err != nil || id != f.evidence {
		t.Fatal("actual source parent X", err)
	}
}

func aPointNativeChunksX(t *testing.T, ctx context.Context, f *aPointNativeFixture, tx *sql.Tx) {
	t.Helper()
	rows, err := tx.QueryContext(ctx, "SELECT id FROM system_backup_v2_evidence_chunks WHERE evidence_id=? ORDER BY chunk_index FOR UPDATE", f.evidence)
	if err != nil {
		t.Fatal("actual source child X", err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		n++
	}
	if rows.Err() != nil || rows.Close() != nil || n != len(f.chunkIDs) {
		t.Fatal("actual source chunk EOF")
	}
}

func aPointNativeFenceX(t *testing.T, ctx context.Context, f *aPointNativeFixture, tx *sql.Tx) {
	t.Helper()
	var epoch uint64
	if err := tx.QueryRowContext(ctx, "SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=? FOR UPDATE", f.record.Binding.InstallationID).Scan(&epoch); err != nil || epoch != f.want.FenceAfter {
		t.Fatal("actual writer fence X", epoch, err)
	}
}

// Real MySQL8.4/SAN-TLS, real private prefix and real QueryMixed; fixture source
// comparisons/signatures are MODELS. No real producer authority or full17 is
// tested. Every fixture schema/DDL is owned/cleaned by censusOriginalMySQL.
func TestOriginalC1PointPrefixNativeMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	f := aPointNativeSetup(t, ctx)
	t.Run("query-waits-parent-before-source-chunks-and-fence", func(t *testing.T) {
		writer, writerID := aPointNativeTx(t, ctx, f.db)
		aPointNativeParentX(t, ctx, f, writer)
		query, queryID := aPointNativeTx(t, ctx, f.db)
		q := aPointNativeStartQuery(t, ctx, f, query)
		aPointNativeWait(t, ctx, f, queryID, writerID, "system_backup_v2_evidence", "PRIMARY")
		if aPointNativeFenceLocks(t, ctx, f, queryID) != 0 {
			t.Fatal("query acquired fence before blocked source parent")
		}
		// This is the original SQL lock sequence, not a constructed opaque
		// OriginalC1EvidenceSource. Its authorization is explicitly a MODEL.
		aPointNativeChunksX(t, ctx, f, writer)
		aPointNativeFenceX(t, ctx, f, writer)
		if writer.Rollback() != nil {
			t.Fatal("source writer rollback")
		}
		aPointNativeFinishQuery(t, q)
		if q.err != nil || !SameRuntimeInstalledSQLRows(f.want, q.got) {
			t.Fatal("reader after original source sequence", q.err)
		}
		if query.Rollback() != nil {
			t.Fatal("query rollback")
		}
	})
	t.Run("known-primary-points-allow-fence-owner-new-evidence-and-chunk", func(t *testing.T) {
		writer, writerID := aPointNativeTx(t, ctx, f.db)
		aPointNativeFenceX(t, ctx, f, writer)
		query, queryID := aPointNativeTx(t, ctx, f.db)
		q := aPointNativeStartQuery(t, ctx, f, query)
		aPointNativeWait(t, ctx, f, queryID, writerID, "system_backup_v2_kek_fences", "PRIMARY")
		// The real reader has completed every early C1 point lock and now
		// waits on this exact fence owner. A tail chunk range would block the
		// following actual INSERT, creating the opposite wait edge.
		var now time.Time
		if writer.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil {
			t.Fatal("writer SQL clock")
		}
		id := aPointNativeEvidence(t, ctx, writer, f.record.Binding.InstallationID, "sev_88888888-0000-4000-8000-000000000001", 1, now)
		aPointNativeChunk(t, ctx, writer, id, 0)
		aPointNativeWait(t, ctx, f, queryID, writerID, "system_backup_v2_kek_fences", "PRIMARY")
		if writer.Rollback() != nil {
			t.Fatal("new evidence/chunk writer rollback")
		}
		aPointNativeFinishQuery(t, q)
		if q.err != nil || !SameRuntimeInstalledSQLRows(f.want, q.got) {
			t.Fatal("PK prefix blocked or changed original universe", q.err)
		}
		if query.Rollback() != nil {
			t.Fatal("query rollback")
		}
	})
	for _, mode := range []string{"missing-known-evidence", "missing-known-chunk", "drift-known-evidence", "drift-known-chunk", "extra-chunk-rejected-by-full-mixed-eof"} {
		t.Run(mode, func(t *testing.T) {
			tx, connection := aPointNativeTx(t, ctx, f.db)
			var err error
			switch mode {
			case "missing-known-evidence":
				_, err = tx.ExecContext(ctx, "DELETE FROM system_backup_v2_evidence WHERE id=?", f.evidence)
			case "missing-known-chunk":
				_, err = tx.ExecContext(ctx, "DELETE FROM system_backup_v2_evidence_chunks WHERE id=?", f.chunkIDs[0])
			case "drift-known-evidence":
				_, err = tx.ExecContext(ctx, "UPDATE system_backup_v2_evidence SET last_checked_at=UTC_TIMESTAMP(6) WHERE id=?", f.evidence)
			case "drift-known-chunk":
				_, err = tx.ExecContext(ctx, "UPDATE system_backup_v2_evidence_chunks SET gcm_tag=? WHERE id=?", []byte("changed-tag-0001"), f.chunkIDs[0])
			case "extra-chunk-rejected-by-full-mixed-eof":
				aPointNativeChunk(t, ctx, tx, f.evidence, 2)
				if err = lockOriginalC1ComparisonRows(ctx, tx, f.c1); err != nil {
					t.Fatal("early point helper must leave unknown row detection to full EOF", err)
				}
			}
			if err != nil {
				t.Fatal("native counterexample mutation", mode, err)
			}
			if _, err = f.query(ctx, tx); err == nil {
				t.Fatal("actual mixed reader accepted missing/drift/extra native rows", mode)
			}
			locks := aPointNativeFenceLocks(t, ctx, f, connection)
			if mode == "extra-chunk-rejected-by-full-mixed-eof" && locks == 0 {
				t.Fatal("unknown extra chunk failed before real full mixed/fence stage")
			}
			if mode != "extra-chunk-rejected-by-full-mixed-eof" && locks != 0 {
				t.Fatal("known row counterexample passed early prefix into fence")
			}
			if tx.Rollback() != nil {
				t.Fatal("counterexample rollback")
			}
		})
	}
	// Last: the actual monotone authority Put commits its real revocation and
	// epoch change. Earlier subtests leave the original baseline unchanged.
	t.Run("query-waits-fence-before-actual-authority-put-mapping", func(t *testing.T) {
		block, blockID := aPointNativeTx(t, ctx, f.db)
		var revision uint64
		if err := block.QueryRowContext(ctx, "SELECT row_version FROM system_backup_installation_kek_authority WHERE installation_id=? AND identity_hash=? AND registry_version=? FOR UPDATE", f.record.Binding.InstallationID, f.record.Binding.ConfigRef.IdentityHash, f.record.Binding.ConfigRef.Version).Scan(&revision); err != nil || revision != 1 {
			t.Fatal("actual mapping blocker", err)
		}
		next := f.record
		next.Revision, next.GenerateRevoked = "native-point-prefix-r2", true
		raw, sig := signOwner(next, f.key)
		putCtx, stop := context.WithCancel(ctx)
		defer stop()
		putDone := make(chan struct{})
		var putErr error
		go func() { defer close(putDone); _, putErr = f.writer.Put(putCtx, raw, sig, 1) }()
		t.Cleanup(func() {
			stop()
			block.Rollback()
			select {
			case <-putDone:
			case <-time.After(5 * time.Second):
				t.Error("owned Put did not stop")
			}
		})
		putID := aPointNativeWait(t, ctx, f, 0, blockID, "system_backup_installation_kek_authority", "PRIMARY")
		if aPointNativeFenceLocks(t, ctx, f, putID) == 0 {
			t.Fatal("actual Put did not acquire original fence before mapping")
		}
		query, queryID := aPointNativeTx(t, ctx, f.db)
		q := aPointNativeStartQuery(t, ctx, f, query)
		aPointNativeWait(t, ctx, f, queryID, putID, "system_backup_v2_kek_fences", "PRIMARY")
		if block.Rollback() != nil {
			t.Fatal("mapping blocker release")
		}
		select {
		case <-putDone:
		case <-time.After(5 * time.Second):
			t.Fatal("actual Put did not finish after mapping release")
		}
		if putErr != nil {
			t.Fatal("actual monotone Put", putErr)
		}
		aPointNativeFinishQuery(t, q)
		if q.err == nil {
			t.Fatal("old mixed mapping accepted after actual revocation/epoch change")
		}
		if query.Rollback() != nil {
			t.Fatal("query rollback")
		}
		var epoch uint64
		var actual, actualSig []byte
		if f.db.QueryRowContext(ctx, "SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=?", f.record.Binding.InstallationID).Scan(&epoch) != nil || epoch != f.want.FenceAfter+1 {
			t.Fatal("independent Put epoch readback")
		}
		if f.db.QueryRowContext(ctx, originalQuery, f.record.Binding.InstallationID, f.record.Binding.ConfigRef.IdentityHash, f.record.Binding.ConfigRef.Version).Scan(&actual, &actualSig) != nil || string(actual) != string(raw) || string(actualSig) != string(sig) {
			t.Fatal("independent Put exact mapping readback")
		}
	})
}
