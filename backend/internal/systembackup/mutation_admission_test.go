package systembackup

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"clawreef/internal/backupgate"
)

func TestMutationAdmissionClosesWhileIdleAndExistingLeaseCanFinish(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db := controlDB(t)
	g := Gate{DB: db}
	const scope = "mutation-admission"
	if err := g.EnsureScope(ctx, scope); err != nil {
		t.Fatal(err)
	}
	lease, err := g.AcquireMutation(ctx, scope, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer g.ReleaseMutation(context.Background(), lease)
	// Keep the real gate idle using an already admitted complete request.
	release, err := backupgate.HoldRequest(ctx, db, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err = g.Begin(ctx, scope, "capture", RegistryHash(), 5*time.Second, 30*time.Second); !errors.Is(err, ErrMaintenance) {
		t.Fatal("gate passed the admitted request", err)
	}
	var phase string
	if err = db.QueryRowContext(ctx, "SELECT phase FROM system_backup_gate WHERE scope=?", scope).Scan(&phase); err != nil || phase != "idle" {
		t.Fatal("fixture did not retain the idle drain window", phase, err)
	}
	newLease, err := g.AcquireMutation(ctx, scope, time.Minute)
	if err == nil {
		_ = g.ReleaseMutation(ctx, newLease)
		t.Fatal("new mutation crossed closed admission while gate remained idle")
	}
	if !errors.Is(err, ErrMaintenance) {
		t.Fatal(err)
	}
	release()
	if _, err = db.ExecContext(ctx, "CREATE TABLE mutation_admission_writes(id INT PRIMARY KEY) ENGINE=InnoDB"); err != nil {
		t.Fatal(err)
	}
	if err = g.WriteWithLease(ctx, lease, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO mutation_admission_writes VALUES(1)")
		return err
	}); err != nil {
		t.Fatal("closing new admission prevented an existing writer from draining", err)
	}
	if err = g.CancelAdmission(ctx, scope, "capture"); err != nil {
		t.Fatal(err)
	}
	newLease, err = g.AcquireMutation(ctx, scope, time.Minute)
	if err != nil {
		t.Fatal("normal mutation admission did not resume", err)
	}
	if err = g.ReleaseMutation(ctx, newLease); err != nil {
		t.Fatal(err)
	}
}

func TestMutationLeaseGrantDoesNotQueueBehindAnAdmittedRequest(t *testing.T) {
	ctx := context.Background()
	db := controlDB(t)
	g := Gate{DB: db}
	const scope = "mutation-shared-grant"
	if err := g.EnsureScope(ctx, scope); err != nil {
		t.Fatal(err)
	}
	release, err := backupgate.HoldRequest(ctx, db, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	grant, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
	defer cancel()
	lease, err := g.AcquireMutation(grant, scope, time.Minute)
	if err != nil {
		t.Fatal("grant queued an exclusive gate lock behind an admitted request", err)
	}
	if err = g.ReleaseMutation(ctx, lease); err != nil {
		t.Fatal(err)
	}
}
