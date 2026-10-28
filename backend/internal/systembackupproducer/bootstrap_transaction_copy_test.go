package systembackupproducer

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type copiedTransactionPolicy struct {
	base *fakePolicy
	copy *Transaction
	mode string
}

func (p *copiedTransactionPolicy) LockAndAuthorize(ctx context.Context, tx SQL, scope Scope) (GuardPlan, error) {
	return p.base.LockAndAuthorize(ctx, tx, scope)
}
func (p *copiedTransactionPolicy) Recheck(ctx context.Context, read ReadSQL, scope Scope, plan GuardPlan, now time.Time) error {
	// Deliberately ignore a copied capability's error. The original guard must
	// still refuse commit and no late SQL may reach the driver.
	p.useCopy(ctx)
	return p.base.Recheck(ctx, read, scope, plan, now)
}
func (p *copiedTransactionPolicy) useCopy(ctx context.Context) {
	switch p.mode {
	case "exec":
		_, _ = p.copy.ExecContext(ctx, "UPDATE synthetic SET value=2")
	case "query":
		rows, _ := p.copy.QueryContext(ctx, "SELECT value FROM synthetic")
		if rows != nil {
			rows.Close()
		}
	case "row":
		var value int
		row := p.copy.QueryRowContext(ctx, "SELECT value FROM synthetic")
		if row != nil {
			_ = row.Scan(&value)
		}
	case "cas":
		_ = p.copy.CAS(ctx, "UPDATE synthetic SET value=2")
	case "record":
		var domain DomainRecord
		_, _ = p.copy.LockRecord(ctx, RecordKey{}, &domain)
	case "insert":
		_ = p.copy.InsertRecord(ctx, nil, &DomainRecord{})
	case "replace":
		_ = p.copy.ReplaceRecord(ctx, nil, &DomainRecord{})
	case "sample":
		_, _ = p.copy.SampleTime(ctx)
	case "identity":
		_ = SameBootstrapTransaction(p.copy, p.copy)
	}
}

func TestBootstrapIndependentTransactionValueCopiesCannotEscapeWork(t *testing.T) {
	for _, ownership := range []string{"owned", "caller_owned"} {
		for _, mode := range []string{"exec", "query", "row", "cas", "record", "insert", "replace", "sample", "identity"} {
			t.Run(ownership+"/"+mode, func(t *testing.T) {
				runner, s, base := setupTx(t)
				p := &copiedTransactionPolicy{base: base, mode: mode}
				runner.policy = p
				work := func(ctx context.Context, tx *Transaction) error {
					// Reflect performs an intentional adversarial value copy without
					// disabling the default vet copylocks check for production code.
					value := reflect.New(reflect.TypeOf(Transaction{}))
					value.Elem().Set(reflect.ValueOf(tx).Elem())
					p.copy = value.Interface().(*Transaction)
					return nil
				}
				ctx := context.Background()
				var err error
				if ownership == "owned" {
					var receipt CommitReceipt
					receipt, err = runner.Run(ctx, work)
					if receipt.Committed() {
						t.Fatal("value copy escaped closed Work and committed")
					}
				} else {
					var tx *sql.Tx
					tx, err = runner.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
					if err != nil {
						t.Fatal(err)
					}
					err = runner.GuardInTx(ctx, tx, work)
					tx.Rollback()
				}
				if !errors.Is(err, ErrGuardRequired) || s.commits != 0 || s.rollbacks != 1 {
					t.Fatal("copied capability did not poison original guard", err, s.commits, s.rollbacks)
				}
				for _, event := range s.events {
					if event == "UPDATE synthetic SET value=2" || strings.Contains(event, "FROM system_backup_producer_") {
						t.Fatal("copy dispatched late SQL", event)
					}
				}
			})
		}
	}
}
