package systembackupsecurity

import (
	"context"
	"database/sql"
	"testing"
)

func TestRuntimeDatabaseIdentityOnTransactionConnection(t *testing.T) {
	svc, g, _, state := bootstrapServiceFixture(t)
	identity := DatabaseIdentity{ServerUUID: g.ServerUUID, Database: g.Database}
	check := func(expected DatabaseIdentity) error {
		t.Helper()
		tx, err := svc.DB.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		return expected.check(context.Background(), tx)
	}
	if err := check(identity); err != nil {
		t.Fatal("correct identity denied", err)
	}
	wrong := identity
	wrong.Database = "another_database"
	if err := check(wrong); err != ErrRegistrationUnavailable {
		t.Fatal("database mismatch admitted", err)
	}
	state.wrongDB = true
	if err := check(identity); err != ErrRegistrationUnavailable {
		t.Fatal("server mismatch admitted", err)
	}
	if err := check(DatabaseIdentity{}); err != ErrRegistrationUnavailable {
		t.Fatal("missing pin admitted", err)
	}
	// Production registration authorization rejects the wrong DB before trying
	// to load any role registry or accepting a committed request retry.
	tx, err := svc.DB.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	authority := configuredAuthority{database: identity}
	if err = authority.Authorize(context.Background(), tx, RegistrationActor{}, ProviderProofTarget{}, RegistrationConfig{}); err != ErrRegistrationUnavailable {
		t.Fatal("authority failed to pin DB", err)
	}
}
