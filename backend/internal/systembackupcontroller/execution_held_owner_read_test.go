package systembackupcontroller

import (
	d "clawreef/internal/systembackupdispatch"
	"context"
	"database/sql"
	"testing"
	"time"
)

// The opaque read cannot be caller-minted. These boundary probes perform no
// SQL on rejection; current combined SQL acceptance is covered independently
// by the real MySQL/mTLS fixture and its mutation/expiry comparisons.
func TestHeldExecutionReadRejectsUnissuedForeignAndConsumedInputs(t *testing.T) {
	identity, _, _, _, _, _ := pinnedGrantDataFixture(t)
	for _, name := range []string{"zero", "context", "transaction", "authority", "zero-clock", "closed", "consumed"} {
		t.Run(name, func(t *testing.T) {
			store, model := newExecutionModel(t)
			ctx := context.Background()
			tx, err := store.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			read := newHeldExecutionRead(ctx, tx, store, model.a, executionSnapshot{})
			input, current, transaction, now := model.a, ctx, tx, model.now
			switch name {
			case "zero":
				read = &HeldExecutionRead{}
			case "context":
				var cancel context.CancelFunc
				current, cancel = context.WithCancel(ctx)
				defer cancel()
			case "transaction":
				other, _ := newExecutionModel(t)
				transaction, err = other.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
				if err != nil {
					t.Fatal(err)
				}
				defer transaction.Rollback()
			case "authority":
				input.AttemptNo++
			case "zero-clock":
				now = time.Time{}
			case "closed":
				read.state.active = false
			case "consumed":
				read.state.used = true
			}
			before := len(model.queries)
			if read.registerOwner(current, transaction, input, identity, now) == nil || len(model.queries) != before {
				t.Fatal("unissued/foreign/consumed read was accepted or issued SQL", name)
			}
			if _, err := read.finish(); err == nil {
				t.Fatal("unvalidated read satisfied originating guard")
			}
		})
	}
}

func TestHeldExecutionReadCopyCannotFinishOriginal(t *testing.T) {
	// A caller can copy an opaque value, but only the ORIGINAL private result
	// is inspected by its originating guard after the synchronous callback.
	original := newHeldExecutionRead(context.Background(), nil, SQLExecutionAuthority{}, d.Authority{}, executionSnapshot{})
	copy := *original
	if _, err := copy.finish(); err == nil || !original.state.active {
		t.Fatal("copied instance finished or closed original state")
	}
	*original = copy
	if _, err := original.finish(); err == nil || original.state.active {
		t.Fatal("copyback authenticated the original unused callback")
	}
}

type heldReadTestOwner struct {
	*executionAuth
	legacy, combined int
}

func (o *heldReadTestOwner) AuthorizeExecution(context.Context, *sql.Tx, d.Authority, time.Time) (ExecutionAuthorizationGuard, error) {
	return o, nil
}
func (o *heldReadTestOwner) RecheckExecution(ctx context.Context, tx *sql.Tx, a d.Authority, now time.Time) error {
	o.legacy++
	return o.executionAuth.RecheckExecution(ctx, tx, a, now)
}
func (o *heldReadTestOwner) SupportsHeldExecutionRecheck() bool { return true }
func (o *heldReadTestOwner) PrepareHeldExecutionRecheck(context.Context, *sql.Tx, d.Authority, time.Time, *HeldExecutionRead) error {
	o.combined++
	return nil // An owner claiming success without registering its closed identity.
}

func TestHeldExecutionReadCannotBypassFallbackOrOmitFacts(t *testing.T) {
	for _, kind := range []string{"non-application-capture", "preflight", "unused-held-read"} {
		t.Run(kind, func(t *testing.T) {
			store, model := newExecutionModel(t)
			owner := &heldReadTestOwner{executionAuth: store.Authorization.(*executionAuth)}
			store.Authorization = owner
			if kind == "preflight" {
				model.a.TaskPublicID = "spf_01234567-89ab-cdef-0123-456789abcdef"
				model.a.TaskType, model.a.Phase = "preflight", "preflight"
				model.a.MaintenanceOwner, model.a.MaintenanceFencingToken = "", 0
				model.status, model.attempt, model.gate = "running", "running", "idle"
			}
			ctx := context.Background()
			tx, err := store.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			guard, err := store.Bind(ctx, tx, model.a)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "unused-held-read" {
				// Driver-model-only flag selects the opaque callback protocol;
				// no SQL gate/task/receipt or native proof is manufactured.
				guard.state.first.heldCapture = true
				if guard.Recheck(ctx, tx) == nil || owner.combined != 1 || owner.legacy != 0 || !guard.ValidUntil().IsZero() {
					t.Fatal("unused current read accepted owner success")
				}
			} else if guard.Recheck(ctx, tx) != nil || owner.legacy != 1 || owner.combined != 0 {
				t.Fatal("non-held/preflight skipped original callback or used held-only reads")
			}
		})
	}
}
