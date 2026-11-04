package systembackupproducer

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Models only SQL dispatch/authorization. The original consumer, snapshots,
// final guard and domain CAS all execute; native principal grants remain a
// separate Root/D1 test requirement.
func TestBootstrapSharedChildrenKeepExclusiveDomainAndFinalReadback(t *testing.T) {
	consumer, request, e := setupIndependentBootstrap(t)
	previous := e.db.queryRecord
	shared := map[string]int{}
	domains := 0
	e.db.queryRecord = func(q string, args []driver.NamedValue) (driver.Rows, error) {
		if strings.Contains(q, " FROM system_backup_producer_") {
			table := strings.Fields(strings.SplitN(q, " FROM ", 2)[1])[0]
			if table == "system_backup_producer_domains" {
				if !strings.HasSuffix(q, " FOR UPDATE") {
					t.Fatal("domain lost original exclusive close lock", q)
				}
				domains++
			} else {
				if table == "system_backup_producer_command_receipts" || !strings.HasSuffix(q, " FOR SHARE") {
					return nil, ErrUnavailable
				}
				shared[table]++
			}
		}
		for _, source := range []string{"system_backup_v2_evidence_chunks", "users", "audit_logs"} {
			if strings.Contains(q, " FROM "+source+" ") {
				if !strings.HasSuffix(q, " FOR SHARE") {
					return nil, ErrUnavailable
				}
				shared[source]++
			}
		}
		return previous(q, args)
	}
	if out, err := consumeIndependentBootstrap(context.Background(), consumer, request); err != nil || out.Replayed {
		t.Fatal("select-only child consumer", out, err)
	}
	if domains < 2 {
		t.Fatal("missing original domain lock/final guard", domains)
	}
	for _, suffix := range []string{"grants", "runs", "targets", "evidence_bindings", "result_receipts", "evidence_refs"} {
		if shared["system_backup_producer_"+suffix] < 2 {
			t.Fatal("missing initial AND final shared read", suffix, shared)
		}
	}
	for _, source := range []string{"system_backup_v2_evidence_chunks", "users", "audit_logs"} {
		if shared[source] == 0 {
			t.Fatal("readonly source not checked", source)
		}
	}
	var domain DomainRecord
	loadMemoryRecord(t, e.m, &domain, 0)
	if domain.State != "closed" {
		t.Fatal("original domain was not closed atomically")
	}
}

func TestBootstrapSharedChildrenValidDriftStillRollsBack(t *testing.T) {
	consumer, request, e := setupIndependentBootstrap(t)
	before := cloneMemory(e.m.rows)
	commits := e.db.commits
	e.beforeRecheck = func() {
		var grant GrantRecord
		loadMemoryRecord(t, e.m, &grant, 0)
		advanceRecord(t, &grant)
		row, err := EncodeStoredRecord(&grant)
		if err != nil {
			t.Fatal(err)
		}
		e.m.rows[row.Table][0] = row
	}
	if _, err := consumeIndependentBootstrap(context.Background(), consumer, request); err == nil {
		t.Fatal("validly reencoded shared child changed during bootstrap")
	}
	if e.db.commits != commits || e.configured || !reflect.DeepEqual(e.m.rows, before) {
		t.Fatal("failed final readback left bootstrap/domain/child state")
	}
}

func TestBootstrapSharedChildPrivateReadTokenAndFailureLatch(t *testing.T) {
	for _, mode := range []string{"success", "absent", "domain", "command", "typed-nil", "transaction-copy"} {
		t.Run(mode, func(t *testing.T) {
			runner, state, _ := setupTx(t)
			record := recordFixture(t, "GrantRecord")
			queries := 0
			state.queryRecord = func(q string, args []driver.NamedValue) (driver.Rows, error) {
				queries++
				if !strings.HasSuffix(q, " FOR SHARE") {
					t.Fatal("child promoted to exclusive read", q)
				}
				assertRecordQuery(t, strings.TrimSuffix(q, " FOR SHARE")+" FOR UPDATE", args, record)
				return rowsForRecord(t, record, mode != "absent"), nil
			}
			var retained *Transaction
			var token *bootstrapSharedRecord
			result, err := runner.Run(context.Background(), func(ctx context.Context, tx *Transaction) error {
				retained = tx
				out := any(&GrantRecord{})
				key := keyForRecord(record)
				switch mode {
				case "domain":
					out = &DomainRecord{}
					key = RecordKey{}
				case "command":
					out = &CommandReceiptRecord{}
				case "typed-nil":
					out = (*GrantRecord)(nil)
				case "transaction-copy":
					copy := *tx
					_, _ = copy.lockBootstrapSharedRecord(ctx, key, out)
					return nil
				}
				token, _ = tx.lockBootstrapSharedRecord(ctx, key, out)
				// Intentionally ignore a source read error: the original transaction
				// must still refuse COMMIT through its shared failure latch.
				return nil
			})
			if mode == "success" {
				if err != nil || !result.Committed() || token == nil || queries != 1 {
					t.Fatal("original private shared read", err)
				}
				if _, ok := any(token).(*LockedRecord); ok {
					t.Fatal("shared read became a public write token")
				}
				if _, err := json.Marshal(token); !errors.Is(err, ErrInvalid) {
					t.Fatal("serializable read token", err)
				}
				if _, err := retained.lockBootstrapSharedRecord(context.Background(), keyForRecord(record), &GrantRecord{}); !errors.Is(err, ErrGuardRequired) {
					t.Fatal("shared source escaped completed transaction", err)
				}
			} else if err == nil || result.Committed() {
				t.Fatal("ignored invalid/shared-source read committed", mode, err)
			}
			if mode != "success" && mode != "absent" && queries != 0 {
				t.Fatal("invalid child type or transaction reached SQL", mode, queries)
			}
		})
	}
}
