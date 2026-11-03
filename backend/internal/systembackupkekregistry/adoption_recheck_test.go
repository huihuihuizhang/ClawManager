package systembackupkekregistry

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"
)

// Declared SQL/source model only; real signatures/native hold are not inferred.
func adoptionRecheckSources() []CoverageSource {
	out := []CoverageSource{}
	for _, p := range []Partition{HoldsAndCatalog, InflightAndUnknownWrites, RestoreAndPrune, RetainedArtifacts} {
		out = append(out, CoverageSource{Partition: p, SourceID: "original-" + string(p), SnapshotRevision: "original-snapshot", FenceRevision: "original-fence", AdoptionSource: SourceRecord{SourceID: "original-owner", RecordID: "sev_original", RecordVersion: "r1", ContentSHA256: strings.Repeat("a", 64)}})
	}
	return out
}

type adoptionRecheckConnector struct {
	state      *coverageScanState
	binding    []driver.Value
	references []Reference
	onCoverage func()
}

func (c adoptionRecheckConnector) Driver() driver.Driver { return coverageScanDriver{} }
func (c adoptionRecheckConnector) Connect(context.Context) (driver.Conn, error) {
	return &adoptionRecheckConn{coverageScanConn{c.state}, c}, nil
}

type adoptionRecheckConn struct {
	coverageScanConn
	data adoptionRecheckConnector
}

func (c *adoptionRecheckConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(q, " FROM system_backup_v2_kek_bindings ") && c.data.binding != nil {
		return &coverageScanRows{columns: strings.Split(bindingReadColumns, ","), values: [][]driver.Value{c.data.binding}}, nil
	}
	if strings.Contains(q, " FROM system_backup_v2_kek_references ") && c.data.references != nil {
		rows := &coverageScanRows{columns: []string{"partition", "id", "version", "identity", "registry", "state", "digest", "raw"}}
		for _, r := range c.data.references {
			raw, digest, e := hashJSON(r)
			if e != nil {
				return nil, e
			}
			rows.values = append(rows.values, []driver.Value{string(r.Partition), r.SourceRecordID, r.SourceRecordVersion, r.Key.IdentityHash, r.Key.RegistryVersion, string(r.State), digest, raw})
		}
		return rows, nil
	}
	rows, e := c.coverageScanConn.QueryContext(ctx, q, args)
	if strings.Contains(q, " FROM system_backup_v2_kek_coverage ") && c.data.onCoverage != nil {
		c.data.onCoverage()
	}
	return rows, e
}

func TestRecheckAdoptionReadsActualPostWriteIndex(t *testing.T) {
	for _, mode := range []string{"current", "unordered-source", "before-adoption", "already-covered", "missing-source", "typed-nil", "nil-references", "wrong-installation", "wrong-database", "wrong-epoch", "missing-partition", "extra-coverage", "coverage-drift", "binding-drift", "unknown-reference-added", "source-refused", "foreign-context", "foreign-transaction", "expired-before", "expired-during-read", "clock-rewind", "source-renewal", "source-set-drift"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			original := Snapshot{InstallationID: bindingReadFixture().InstallationID, Database: DatabaseIdentity{"original-server", "original-db"}, Epoch: 7, ObservedAt: now.Add(-time.Second), Bindings: []BindingFacts{}, References: []Reference{}, Coverage: []CoverageSource{}}
			current := cloneSnapshot(original)
			current.Epoch++
			current.Coverage = adoptionRecheckSources()
			state := &coverageScanState{current: current, clock: now}
			connector := adoptionRecheckConnector{state: state}
			prepared := &coverageScanPrepared{snapshot: cloneSnapshot(original), until: now.Add(time.Minute)}
			prepared.snapshot.Coverage = adoptionRecheckSources()
			switch mode {
			case "unordered-source":
				prepared.snapshot.Coverage[0], prepared.snapshot.Coverage[3] = prepared.snapshot.Coverage[3], prepared.snapshot.Coverage[0]
			case "nil-references":
				prepared.snapshot.References = nil
			case "wrong-database":
				state.current.Database.ServerUUID = "foreign"
			case "wrong-epoch":
				state.current.Epoch++
			case "missing-partition":
				state.current.Coverage = state.current.Coverage[:3]
			case "extra-coverage":
				extra := state.current.Coverage[0]
				extra.SourceID += "-unexpected"
				state.current.Coverage = append(state.current.Coverage, extra)
			case "coverage-drift":
				state.current.Coverage[0].FenceRevision = "changed"
			case "binding-drift":
				for _, v := range bindingReadFixtureRow(t).values {
					if n, ok := v.(uint64); ok {
						v = int64(n)
					}
					connector.binding = append(connector.binding, v)
				}
			case "unknown-reference-added":
				b := bindingReadFixture()
				connector.references = []Reference{{Partition: RetainedArtifacts, State: ReferenceUnknown, SourceRecordID: "unresolved-original", SourceRecordVersion: "r1", Key: b.Key}}
			case "expired-before":
				prepared.until = now
			case "expired-during-read":
				connector.onCoverage = func() { state.clock = prepared.until }
			}
			db := sql.OpenDB(connector)
			defer db.Close()
			tx, e := db.BeginTx(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			bound := &Bound{tx: tx, installationID: original.InstallationID, epoch: original.Epoch + 1, original: original}
			if mode == "before-adoption" {
				bound.epoch = original.Epoch
			}
			if mode == "already-covered" {
				bound.original.Coverage = adoptionRecheckSources()
			}
			if mode == "wrong-installation" {
				bound.installationID = "foreign"
			}
			expectedView := SQLReadView(tx)
			if mode == "foreign-transaction" {
				other, e := db.BeginTx(ctx, nil)
				if e != nil {
					t.Fatal(e)
				}
				defer other.Rollback()
				expectedView = other
			}
			calls := 0
			prepared.check = func(actual context.Context, view SQLReadView, locked LockedSnapshot, stamp time.Time) error {
				calls++
				if actual != ctx || view != expectedView {
					return errors.New("not original source ctx/transaction")
				}
				if !SameSnapshotFacts(locked.Facts(), original) || stamp.Before(original.ObservedAt) {
					t.Fatal("source recheck lost original snapshot")
				}
				switch mode {
				case "source-refused":
					return errors.New("original source revoked/refused")
				case "clock-rewind":
					state.clock = now.Add(-time.Microsecond)
				case "source-renewal":
					prepared.until = prepared.until.Add(time.Hour)
				case "source-set-drift":
					prepared.snapshot.Coverage[0].SnapshotRevision = "changed"
				}
				return nil
			}
			var source PreparedCoverage = prepared
			if mode == "missing-source" {
				source = nil
			}
			if mode == "typed-nil" {
				var missing *coverageScanPrepared
				source = missing
			}
			actualCtx := context.Context(ctx)
			if mode == "foreign-context" {
				child, stop := context.WithCancel(ctx)
				defer stop()
				actualCtx = child
			}
			beforeSnapshot, beforeEpoch := bound.Snapshot().Facts(), bound.epoch
			e = bound.RecheckAdoption(actualCtx, source)
			if mode == "current" || mode == "unordered-source" {
				if e != nil || calls != 1 {
					t.Fatal("valid original adoption rejected", e, calls)
				}
			} else if !errors.Is(e, ErrKEKCoverage) {
				t.Fatal("post-write drift/unknown source accepted", mode, e)
			}
			if !SameSnapshotFacts(bound.Snapshot().Facts(), beforeSnapshot) || bound.epoch != beforeEpoch {
				t.Fatal("readback mutated original snapshot or epoch")
			}
		})
	}
}
