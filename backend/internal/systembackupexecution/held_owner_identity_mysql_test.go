package systembackupexecution

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"os"
	"strings"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
)

// Transparent native driver result fault: only the named identity value is
// changed after an actual row arrives. This tests transport/identity checks;
// it never changes the server UUID, account, database, clock or SQL grants.
type dHeldIdentityRows struct {
	driver.Rows
	fault *dHeldClockDelay
}

func (r *dHeldIdentityRows) Next(values []driver.Value) error {
	err := r.Rows.Next(values)
	if err == nil && r.fault.armed.CompareAndSwap(true, false) {
		for index, column := range r.Rows.Columns() {
			if strings.EqualFold(column, r.fault.identityField) {
				values[index] = []byte("foreign-current-identity")
				r.fault.fired.Store(true)
			}
		}
	}
	return err
}

// Keep the exact original deployment/current-grant implementation, exposing
// only its prior independent callback interface for the native comparison.
type dSeparateHeldAuthorization struct{ original c.ExecutionAuthorization }
type dSeparateHeldGuard struct{ original c.ExecutionAuthorizationGuard }

func (o dSeparateHeldAuthorization) AuthorizeExecution(ctx context.Context, tx *sql.Tx, a d.Authority, now time.Time) (c.ExecutionAuthorizationGuard, error) {
	guard, err := o.original.AuthorizeExecution(ctx, tx, a, now)
	if err != nil {
		return nil, err
	}
	return dSeparateHeldGuard{guard}, nil
}
func (g dSeparateHeldGuard) ValidUntil() time.Time { return g.original.ValidUntil() }
func (g dSeparateHeldGuard) RecheckExecution(ctx context.Context, tx *sql.Tx, a d.Authority, now time.Time) error {
	return g.original.RecheckExecution(ctx, tx, a, now)
}

func TestHeldOwnerCurrentNativeIdentityResponseRejectsDrift(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires disposable local MySQL")
	}
	fault := &dHeldClockDelay{}
	owner, _, _, _, a, _, _, _, refresh := newConsumerMySQLFixtureOptions(t, &consumerFixtureOptions{WrapControlConnector: func(conn driver.Connector) driver.Connector {
		return dHeldClockConnector{Connector: conn, delay: fault}
	}})
	refresh()
	ctx := context.Background()
	for _, field := range []string{"CURRENT_USER()", "@@server_uuid", "DATABASE()"} {
		for _, combined := range []bool{false, true} {
			fault.identityField = field
			fault.armed.Store(false)
			fault.fired.Store(false)
			store := owner.Gate.Authority
			if !combined {
				store.Authorization = dSeparateHeldAuthorization{store.Authorization}
			}
			tx, err := store.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			func() {
				defer tx.Rollback()
				guard, err := store.Bind(ctx, tx, a)
				if err != nil || guard.Recheck(ctx, tx) != nil {
					t.Fatal("native original identity baseline", field, combined, err)
				}
				fault.armed.Store(true)
				if guard.Recheck(ctx, tx) == nil || !fault.fired.Load() || !guard.ValidUntil().IsZero() || guard.Recheck(ctx, tx) == nil {
					t.Fatal("native current identity drift accepted/not exercised", field, combined)
				}
			}()
		}
	}
}
