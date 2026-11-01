package systembackupcontroller

import (
	"context"
	"database/sql"
	"testing"
)

func TestExecutionRecheckOriginalRequiresExactStoreAndInput(t *testing.T) {
	for _, name := range []string{"same", "context", "transaction", "input", "database", "installation", "scope", "enabled", "owner-identity"} {
		t.Run(name, func(t *testing.T) {
			store, model := newExecutionModel(t)
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
			original := store
			input := model.a
			otherTx := tx
			switch name {
			case "context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
			case "transaction":
				other, _ := newExecutionModel(t)
				otherTx, err = other.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
				if err != nil {
					t.Fatal(err)
				}
				defer otherTx.Rollback()
			case "input":
				input.ClaimRowVersion++
			case "database":
				other, _ := newExecutionModel(t)
				original.DB = other.DB
			case "installation":
				original.InstallationID += "-other"
			case "scope":
				original.ApplicationScope = "other"
			case "enabled":
				original.DeploymentEnabled = false
			case "owner-identity":
				// Equal fields in a DIFFERENT mutable policy are not the owner
				// whose original callback this guard retains.
				copy := *store.Authorization.(*executionAuth)
				original.Authorization = &copy
			}
			before := model.reads
			checks := 0
			if name != "owner-identity" {
				store.Authorization.(*executionAuth).onRecheck = func() { checks++ }
			}
			err = guard.RecheckOriginal(ctx, otherTx, original, input)
			if name == "same" {
				if err != nil || checks != 1 || model.reads <= before {
					t.Fatal("same original guard skipped current callback/facts", err, checks, model.reads, before)
				}
			} else if err == nil || guard.Recheck(context.Background(), tx) == nil || !guard.ValidUntil().IsZero() {
				t.Fatal("foreign original binding accepted or revived", err)
			}
		})
	}
}

func TestExecutionRecheckOriginalRetainsCurrentFactsAndOwner(t *testing.T) {
	for _, drift := range []string{"version", "owner", "config", "expired", "attempt", "fence", "disabled", "grant"} {
		t.Run(drift, func(t *testing.T) {
			store, model := newExecutionModel(t)
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
			if drift == "grant" {
				store.Authorization.(*executionAuth).deny = true
			} else {
				model.drift = drift
			}
			if guard.RecheckOriginal(ctx, tx, store, model.a) == nil || !guard.ValidUntil().IsZero() {
				t.Fatal("current original fact/owner drift accepted", drift)
			}
		})
	}
}
