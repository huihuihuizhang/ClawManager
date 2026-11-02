package systembackupkekregistry

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Synthetic read-only SQL transport: verifies refusal/current-fact/clock
// behavior, not InnoDB locks, physical writers or authentic owner receipts.
type coverageScanState struct {
	current Snapshot
	clock   time.Time
	queries int
}
type coverageScanConnector struct{ state *coverageScanState }
type coverageScanDriver struct{}
type coverageScanConn struct{ state *coverageScanState }
type coverageScanTx struct{}
type coverageScanRows struct {
	columns []string
	values  [][]driver.Value
}

func (coverageScanConnector) Driver() driver.Driver { return coverageScanDriver{} }
func (c coverageScanConnector) Connect(context.Context) (driver.Conn, error) {
	return &coverageScanConn{c.state}, nil
}
func (coverageScanDriver) Open(string) (driver.Conn, error)   { return nil, errors.New("connector only") }
func (*coverageScanConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not used") }
func (*coverageScanConn) Close() error                        { return nil }
func (*coverageScanConn) Begin() (driver.Tx, error)           { return coverageScanTx{}, nil }
func (coverageScanTx) Commit() error                          { return errors.New("scan must not commit") }
func (coverageScanTx) Rollback() error                        { return nil }
func (r *coverageScanRows) Columns() []string                 { return r.columns }
func (*coverageScanRows) Close() error                        { return nil }
func (r *coverageScanRows) Next(out []driver.Value) error {
	if len(r.values) == 0 {
		return io.EOF
	}
	copy(out, r.values[0])
	r.values = r.values[1:]
	return nil
}
func (c *coverageScanConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	c.state.queries++
	s := c.state
	switch {
	case strings.HasPrefix(query, "SELECT epoch FROM"):
		return &coverageScanRows{[]string{"epoch"}, [][]driver.Value{{int64(s.current.Epoch)}}}, nil
	case query == "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)":
		return &coverageScanRows{[]string{"server", "database", "now"}, [][]driver.Value{{s.current.Database.ServerUUID, s.current.Database.Database, s.clock}}}, nil
	case query == "SELECT UTC_TIMESTAMP(6)":
		return &coverageScanRows{[]string{"now"}, [][]driver.Value{{s.clock}}}, nil
	case strings.Contains(query, " FROM system_backup_v2_kek_bindings "), strings.Contains(query, " FROM system_backup_v2_kek_references "):
		return &coverageScanRows{columns: []string{"empty"}}, nil
	case strings.Contains(query, " FROM system_backup_v2_kek_coverage "):
		rows := &coverageScanRows{columns: []string{"partition", "source_id", "digest", "raw"}}
		for _, source := range s.current.Coverage {
			raw, digest, err := hashJSON(source)
			if err != nil {
				return nil, err
			}
			rows.values = append(rows.values, []driver.Value{string(source.Partition), source.SourceID, digest, raw})
		}
		return rows, nil
	}
	return nil, errors.New("unexpected scan query")
}

type coverageScanPrepared struct {
	snapshot Snapshot
	until    time.Time
	check    func(context.Context, SQLReadView, LockedSnapshot, time.Time) error
}

func (p *coverageScanPrepared) Sources() []CoverageSource { return cloneSnapshot(p.snapshot).Coverage }
func (p *coverageScanPrepared) References() []Reference   { return cloneSnapshot(p.snapshot).References }
func (p *coverageScanPrepared) ExpectedEpoch() uint64     { return p.snapshot.Epoch }
func (p *coverageScanPrepared) ValidUntil() time.Time     { return p.until }
func (p *coverageScanPrepared) Recheck(ctx context.Context, tx SQLReadView, locked LockedSnapshot, now time.Time) error {
	return p.check(ctx, tx, locked, now)
}

func TestCompleteScanRequiresCurrentOriginalSourceAndPreservesFenceAndExpiry(t *testing.T) {
	for _, mode := range []string{"current", "no-source", "typed-nil", "unknown-references", "missing-partition", "changed-epoch", "changed-database", "changed-coverage", "source-refused", "expired-before-source", "expired-after-source"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			original := Snapshot{InstallationID: "original_install", Database: DatabaseIdentity{"original-server", "original-db"}, Epoch: 7, ObservedAt: now.Add(-time.Second), Bindings: []BindingFacts{}, References: []Reference{}, Coverage: []CoverageSource{}}
			for _, partition := range []Partition{HoldsAndCatalog, InflightAndUnknownWrites, RestoreAndPrune, RetainedArtifacts} {
				original.Coverage = append(original.Coverage, CoverageSource{Partition: partition, SourceID: "original-" + string(partition), SnapshotRevision: "snapshot-v1", FenceRevision: "fence-v1", AdoptionSource: SourceRecord{SourceID: "owner", RecordID: "sev_original", RecordVersion: "v1", ContentSHA256: strings.Repeat("a", 64)}})
			}
			state := &coverageScanState{current: cloneSnapshot(original), clock: now}
			db := sql.OpenDB(coverageScanConnector{state})
			defer db.Close()
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			bound := &Bound{tx: tx, installationID: original.InstallationID, epoch: original.Epoch, original: original}
			prepared := &coverageScanPrepared{snapshot: cloneSnapshot(original), until: now.Add(time.Minute)}
			calls := 0
			prepared.check = func(_ context.Context, view SQLReadView, locked LockedSnapshot, sampled time.Time) error {
				calls++
				if view != tx || !SameSnapshotFacts(locked.Facts(), original) || !sampled.Equal(now) {
					t.Fatal("source escaped original transaction/facts/time")
				}
				if mode == "source-refused" {
					return errors.New("original source absent")
				}
				if mode == "expired-after-source" {
					state.clock = prepared.until
				}
				return nil
			}
			var source PreparedCoverage = prepared
			switch mode {
			case "typed-nil":
				var absent *coverageScanPrepared
				source = absent
			case "unknown-references":
				prepared.snapshot.References = nil
			case "missing-partition":
				bound.original.Coverage = bound.original.Coverage[:3]
			case "changed-epoch":
				state.current.Epoch++
			case "changed-database":
				state.current.Database.ServerUUID = "foreign"
			case "changed-coverage":
				state.current.Coverage[0].SnapshotRevision = "changed"
			case "expired-before-source":
				prepared.until = now
			}
			var result LockedSnapshot
			if mode == "no-source" {
				result, err = bound.CompleteScan(context.Background())
			} else {
				result, err = bound.CompleteScan(context.Background(), source)
			}
			if mode == "current" {
				if err != nil || calls != 1 || !SameSnapshotFacts(result.Facts(), original) || !result.Facts().ObservedAt.Equal(now) {
					t.Fatal("valid synthetic current read rejected", err, calls)
				}
				copy := result.Facts()
				copy.Coverage[0].SnapshotRevision = "caller-mutated"
				if !reflect.DeepEqual(result.Facts().Coverage, original.Coverage) {
					t.Fatal("caller mutated locked scan facts")
				}
			} else if !errors.Is(err, ErrKEKCoverage) {
				t.Fatal("incomplete/stale/expired source completed scan", mode, err)
			}
			if mode == "no-source" || mode == "typed-nil" || mode == "unknown-references" || mode == "missing-partition" {
				if state.queries != 0 || calls != 0 {
					t.Fatal("missing source reached SQL", mode, state.queries, calls)
				}
			}
		})
	}
}
