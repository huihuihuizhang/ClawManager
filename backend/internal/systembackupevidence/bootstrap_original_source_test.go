package systembackupevidence

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"reflect"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// These tests exercise only the concrete original evidence source and the
// actual D transaction executor with the existing SQL protocol model. They do
// not supply another missing bootstrap owner or claim native SQL admission.
func originalEvidenceFixture(t *testing.T) (*systemResultTestFixture, *BootstrapOriginalEvidenceSource) {
	t.Helper()
	f := newSystemResultTestFixture(t)
	r := f.systemPendingTestFixture.env.record
	r.State, r.RowVersion, r.Ref.ImmutableVersion = "ready", 3, "Exact.Version/1"
	source, err := NewBootstrapOriginalEvidenceSource([]BootstrapOriginalEvidenceEntry{{Record: r, Channel: f.channel, Expected: f.rb.Request.Evidence}})
	if err != nil {
		t.Fatal(err)
	}
	return f, source
}

type originalEvidenceReadProbe struct {
	data                       *systemPendingTestDB
	evidenceReads, chunksReads int
}

func (p *originalEvidenceReadProbe) Driver() driver.Driver { return p.data.Driver() }
func (p *originalEvidenceReadProbe) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := p.data.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &originalEvidenceProbeConn{Conn: conn, probe: p}, nil
}

type originalEvidenceProbeConn struct {
	driver.Conn
	probe *originalEvidenceReadProbe
}

func (c *originalEvidenceProbeConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, options)
}
func (c *originalEvidenceProbeConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, " FROM system_backup_v2_evidence ") {
		c.probe.evidenceReads++
	}
	if strings.Contains(query, " FROM system_backup_v2_evidence_chunks ") {
		c.probe.chunksReads++
	}
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}

func runOriginalEvidence(t *testing.T, f *systemResultTestFixture, source *BootstrapOriginalEvidenceSource, wantChunks bool, after func(context.Context, *pd.Transaction, *BootstrapOriginalEvidenceLock, []pd.ResultEvidence) error) (bool, error) {
	t.Helper()
	var guard *BootstrapOriginalEvidenceLock
	rechecked := false
	// The real caller-owned transaction establishes bootstrap's controlled
	// clock via GuardInTx. Generic Run intentionally supplies no such capability.
	// The probe only counts forwarded driver reads; it cannot authorize a lock.
	policy := systemPublicationTestPolicy{hash: pd.Hash(strings.Repeat("a", 64)), until: f.d.now.Add(time.Minute), guard: func(_ context.Context, _ pd.ReadSQL, _ time.Time) error {
		if guard == nil || !rechecked {
			return ErrDenied
		}
		return nil
	}}
	probe := &originalEvidenceReadProbe{data: f.d}
	db := sql.OpenDB(probe)
	defer db.Close()
	runner, err := pd.NewTransactions(db, f.b.Scope, policy)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	entered, afterEntered := false, false
	err = runner.GuardInTx(ctx, tx, func(ctx context.Context, tx *pd.Transaction) error {
		entered = true
		var facts []pd.ResultEvidence
		var err error
		guard, facts, err = source.Lock(ctx, tx)
		if err != nil {
			return err
		}
		if len(facts) != 1 || !reflect.DeepEqual(facts[0].Evidence, f.rb.Request.Evidence) || facts[0].RowVersion != "3" {
			t.Fatal("did not independently read exact original evidence")
		}
		if after != nil {
			afterEntered = true
			if err := after(ctx, tx, guard, facts); err != nil {
				return err
			}
		}
		err = guard.Recheck(ctx, tx)
		rechecked = err == nil
		return err
	})
	if !entered || probe.evidenceReads == 0 || wantChunks && probe.chunksReads == 0 || after != nil && !afterEntered {
		t.Fatalf("fault did not reach original source rows/chunks: entered=%v evidence=%d chunks=%d after=%v err=%v", entered, probe.evidenceReads, probe.chunksReads, afterEntered, err)
	}
	if err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func TestBootstrapOriginalEvidenceReadsCompleteRowsAndChunks(t *testing.T) {
	f, source := originalEvidenceFixture(t)
	writes := f.d.writes
	before, err := source.ComparisonBytes()
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := source.ExpectedBindings()
	if err != nil {
		t.Fatal(err)
	}
	*bindings[0].ImmutableVersion = "caller-mutated"
	out, err := runOriginalEvidence(t, f, source, true, func(_ context.Context, _ *pd.Transaction, _ *BootstrapOriginalEvidenceLock, facts []pd.ResultEvidence) error {
		*facts[0].Evidence.ImmutableVersion = "caller-mutated"
		return nil
	})
	if err != nil || !out || f.d.writes != writes {
		t.Fatal("data source touched write path or failed detached facts", err)
	}
	after, err := source.ComparisonBytes()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("public comparison facts mutated original source")
	}
}

func TestBootstrapOriginalEvidenceRejectsActualSQLDriftAndEOF(t *testing.T) {
	for _, mode := range []string{"missing", "version", "claimed", "object_version", "content", "chunk", "retention", "evidence_extra", "evidence_columns", "evidence_iterate", "evidence_close", "chunks_missing", "chunks_extra", "chunks_columns", "chunks_iterate", "chunks_close"} {
		t.Run(mode, func(t *testing.T) {
			f, source := originalEvidenceFixture(t)
			switch mode {
			case "missing":
				f.d.row = nil
			case "version":
				f.d.row["row_version"] = int64(4)
			case "claimed":
				f.d.row["claim_owner"], f.d.row["claim_expires_at"] = "gc-owner", f.d.now.Add(time.Minute)
			case "object_version":
				f.d.row["storage_immutable_version"] = "exact.Version/1"
			case "content":
				f.d.row["content_checksum"] = strings.Repeat("f", 64)
			case "chunk":
				f.d.chunks[0]["gcm_tag"] = []byte("wrong")
			case "retention":
				f.d.row["protected_until"] = f.d.now
			default:
				f.d.queryMode = mode
			}
			writes := f.d.writes
			out, err := runOriginalEvidence(t, f, source, mode == "chunk" || strings.HasPrefix(mode, "chunks_"), nil)
			if err == nil || out || f.d.writes != writes {
				t.Fatal("accepted corrupt/incomplete evidence", mode, err)
			}
		})
	}
}

func TestBootstrapOriginalEvidenceRecheckAndCopyFailuresLatch(t *testing.T) {
	for _, mode := range []string{"health", "next", "chunk", "copy", "foreign_context"} {
		t.Run(mode, func(t *testing.T) {
			f, source := originalEvidenceFixture(t)
			out, err := runOriginalEvidence(t, f, source, true, func(ctx context.Context, tx *pd.Transaction, guard *BootstrapOriginalEvidenceLock, _ []pd.ResultEvidence) error {
				switch mode {
				case "health":
					f.d.row["observed_health"] = "healthy"
				case "next":
					f.d.row["next_reconcile_at"] = f.d.now
				case "chunk":
					f.d.chunks[0]["gcm_tag"] = []byte("wrong")
				case "copy":
					copy := *guard
					if copy.Recheck(ctx, tx) == nil || !guard.failed {
						t.Fatal("value copy failed to poison original")
					}
				case "foreign_context":
					foreign := context.WithValue(ctx, struct{}{}, "foreign")
					if guard.Recheck(foreign, tx) == nil || guard.Recheck(ctx, tx) == nil {
						t.Fatal("restored context revived failed evidence guard")
					}
				}
				return nil
			})
			if err == nil || out {
				t.Fatal("final guard ignored evidence drift or failed session", mode)
			}
		})
	}
}
