package systembackupproducer

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// This synthetic authority checks the placement of real bounded local reads;
// its file is test material and supplies no deployment/bootstrap permission.
type callbackPhaseAuthority struct {
	*independentBootstrapSession
	path, hash, mode       string
	write                  BootstrapSQL
	copiedRead             BootstrapReadSQL
	inFinal, calledInFinal bool
	checks                 int
}

func (a *callbackPhaseAuthority) PrepareBootstrapConsumption(ctx context.Context, r BootstrapConsumptionRequest) (PreparedBootstrapAuthority, error) {
	prepared, err := a.independentBootstrapSession.PrepareBootstrapConsumption(ctx, r)
	prepared.Session = a
	return prepared, err
}
func (a *callbackPhaseAuthority) LockOperation(ctx context.Context, tx BootstrapSQL, r BootstrapConsumptionRequest, h Hash, id string) (BootstrapOperation, error) {
	a.write = tx
	return a.independentBootstrapSession.LockOperation(ctx, tx, r, h, id)
}
func (a *callbackPhaseAuthority) WriteBootstrap(ctx context.Context, tx BootstrapSQL, r BootstrapConsumptionRequest, f BootstrapConsumptionFacts, id string, h Hash, now time.Time) (BootstrapWriteResult, error) {
	out, err := a.independentBootstrapSession.WriteBootstrap(ctx, tx, r, f, id, h, now)
	if err != nil {
		return out, err
	}
	switch a.mode {
	case "removed":
		if err = os.Remove(a.path); err != nil {
			return out, err
		}
	case "changed":
		if err = os.WriteFile(a.path, []byte("changed controlled test material"), 0600); err != nil {
			return out, err
		}
	case "expired_before_callback":
		a.db.now = a.db.now.Add(6 * time.Second)
	}
	return out, nil
}
func (a *callbackPhaseAuthority) Recheck(ctx context.Context, read BootstrapReadSQL, r BootstrapConsumptionRequest, f BootstrapConsumptionFacts, now time.Time) error {
	a.checks++
	if a.inFinal {
		a.calledInFinal = true
		return ErrGuardRequired
	}
	if !SameBootstrapTransaction(a.write, read) {
		return ErrGuardRequired
	}
	if err := a.independentBootstrapSession.Recheck(ctx, read, r, f, now); err != nil {
		return err
	}
	// The private concrete type does not prevent reflection from copying its
	// whole value. The issued capability and every copy must close together.
	copy := reflect.New(reflect.ValueOf(read).Elem().Type())
	copy.Elem().Set(reflect.ValueOf(read).Elem())
	a.copiedRead = copy.Interface().(BootstrapReadSQL)
	if !SameBootstrapTransaction(a.write, a.copiedRead) {
		return ErrGuardRequired
	}
	if a.mode == "panic" {
		panic("controlled callback panic")
	}
	if a.mode == "retained_write" {
		_, err := a.write.ExecContext(ctx, "UPDATE synthetic SET value=2")
		return err
	}
	if a.mode == "invalid_read_sql" {
		// A swallowed readonly-SQL violation must still poison this Work.
		var value int
		_ = read.QueryRowContext(ctx, "UPDATE synthetic SET value=2").Scan(&value)
	}
	raw, err := os.ReadFile(a.path)
	if err != nil || len(raw) > 1024 {
		return ErrUnavailable
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != a.hash {
		return ErrConflict
	}
	if a.mode == "late_wait" {
		a.db.now = a.db.now.Add(6 * time.Second)
	}
	return nil
}

type callbackPhasePolicy struct {
	inner     *bootstrapConsumptionPolicy
	authority *callbackPhaseAuthority
}

func (p callbackPhasePolicy) LockAndAuthorize(ctx context.Context, tx SQL, scope Scope) (GuardPlan, error) {
	return p.inner.LockAndAuthorize(ctx, tx, scope)
}
func (p callbackPhasePolicy) Recheck(ctx context.Context, read ReadSQL, scope Scope, plan GuardPlan, now time.Time) error {
	p.authority.inFinal = true
	defer func() { p.authority.inFinal = false }()
	return p.inner.Recheck(ctx, read, scope, plan, now)
}

func TestBootstrapIndependentControlledFileChecksBeforeFinalGuard(t *testing.T) {
	for _, mode := range []string{"normal", "removed", "changed", "retained_write", "invalid_read_sql", "expired_before_callback", "late_wait", "panic"} {
		t.Run(mode, func(t *testing.T) {
			consumer, request, base := setupIndependentBootstrap(t)
			file := filepath.Join(t.TempDir(), "original-material")
			original := []byte("original controlled test material")
			if err := os.WriteFile(file, original, 0600); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(original)
			a := &callbackPhaseAuthority{independentBootstrapSession: base, path: file, hash: hex.EncodeToString(sum[:]), mode: mode}
			consumer.environment = a
			ctx := context.Background()
			prepared, err := consumer.PrepareBootstrapConsumption(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			state := prepared.state
			if !state.used.CompareAndSwap(false, true) {
				t.Fatal("test preparation already used")
			}
			inner := &bootstrapConsumptionPolicy{request: detached(state.request), hash: state.hash, authority: state.authority}
			// Test-only policy wrapper marks the EXACT entry into the generic
			// fixed-guard phase. The production consumer has no Policy parameter.
			runner, err := NewTransactions(consumer.db, consumer.scope, callbackPhasePolicy{inner, a})
			if err != nil {
				t.Fatal(err)
			}
			tx, err := consumer.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			before := cloneMemory(base.m.rows)
			commits := base.db.commits
			panicked := false
			func() {
				defer func() {
					if value := recover(); value != nil {
						if mode != "panic" || value != "controlled callback panic" {
							panic(value)
						}
						panicked, err = true, ErrGuardRequired
					}
				}()
				err = runner.GuardInTx(ctx, tx, inner.write)
			}()
			if mode == "panic" {
				if !panicked || inner.callbacksComplete || base.readRetained == nil {
					t.Fatal("missing callback panic before final guard")
				}
			}
			if a.checks == 1 {
				dispatched := len(base.db.events)
				for _, read := range []BootstrapReadSQL{base.readRetained, a.copiedRead} {
					if read == nil {
						t.Fatal("missing original or copied callback view")
					}
					if _, e := read.SampleTime(ctx); !errors.Is(e, ErrGuardRequired) {
						t.Fatal("retained sampling capability remained open", mode, e)
					}
					if _, e := read.QueryContext(ctx, "SELECT 1"); !errors.Is(e, ErrGuardRequired) {
						t.Fatal("retained SQL capability remained open", mode, e)
					}
					if e := read.QueryRowContext(ctx, "SELECT 1").Scan(new(int)); e == nil {
						t.Fatal("retained single-row SQL capability remained open", mode)
					}
					if SameBootstrapTransaction(a.write, read) {
						t.Fatal("retained transaction identity remained active", mode)
					}
				}
				if len(base.db.events) != dispatched {
					t.Fatal("closed original or copied read view dispatched SQL", mode)
				}
			}
			if a.calledInFinal {
				t.Fatal("file callback ran in fixed FinalGuard")
			}
			if mode == "normal" {
				if err != nil || a.checks != 1 || !inner.callbacksComplete {
					t.Fatal("legal pre-guard original file check failed", err, a.checks)
				}
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
				if base.db.commits != commits+1 {
					t.Fatal("missing sole commit")
				}
				return
			}
			if err == nil {
				t.Fatal("invalid material/callback escaped guard", mode)
			}
			if mode == "retained_write" && !errors.Is(err, ErrGuardRequired) {
				t.Fatal("write capability was still open during source checks", err)
			}
			if mode == "expired_before_callback" && a.checks != 0 {
				t.Fatal("expired plan invoked source callback")
			}
			if mode != "expired_before_callback" && a.checks != 1 {
				t.Fatal("negative case failed before intended callback", mode, err, a.checks)
			}
			if err = tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			if base.db.commits != commits || !reflect.DeepEqual(before, base.m.rows) || base.configured {
				t.Fatal("source failure did not roll all staged changes back")
			}
		})
	}
}
