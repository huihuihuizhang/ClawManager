//go:build systembackup_mysql

package systembackupkekadapter

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	mysql "github.com/go-sql-driver/mysql"
)

// Native SQL lock/state DATA test, not a B physical writer-hold proof.
func TestRuntimeInstallationGateMySQLFirstPrefixRefusesOriginalHolder(t *testing.T) {
	if os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE") == "" || os.Getenv("A_SIGNING_MYSQL_SERVER_UUID") == "" {
		t.Fatal("pinned disposable MySQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	db, _ := censusOriginalMySQL(t, ctx)
	installation := "installation_runtime_gate_fixture"
	for _, state := range []string{"absent", "idle", "acquiring", "held", "releasing"} {
		t.Run(state, func(t *testing.T) {
			tx, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			if state != "absent" {
				var now time.Time
				if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil {
					t.Fatal("SQL time")
				}
				var owner, heartbeat, lease, acquireTimeout, holdTimeout, acquiring, held, releasing, acquisitionDeadline, absolute any
				fence := 0
				if state != "idle" {
					owner = "original-fixture-owner"
					heartbeat = now
					lease = now.Add(180 * time.Second)
					acquireTimeout = 10
					acquiring = now
					acquisitionDeadline = now.Add(10 * time.Second)
				}
				if state == "held" || state == "releasing" {
					fence = 1
					held = now
					holdTimeout = 120
					absolute = now.Add(120 * time.Second)
				}
				if state == "releasing" {
					releasing = now
				}
				values := []any{installation, c.CaptureGateScope, state, 180, fence, owner, heartbeat, lease, acquireTimeout, holdTimeout, acquiring, held, releasing, acquisitionDeadline, absolute, now, now, now}
				query := `INSERT INTO system_backup_v2_maintenance_locks(origin_installation_id,scope,gate_state,lock_ttl_seconds,fencing_token,lock_owner,heartbeat_at,lease_expires_at,gate_acquisition_timeout_seconds,quiesce_max_hold_seconds,acquiring_started_at,held_at,release_started_at,acquisition_deadline_at,absolute_hold_deadline_at,state_changed_at,created_at,updated_at) VALUES (` + strings.TrimSuffix(strings.Repeat("?,", len(values)), ",") + `)`
				if _, e := tx.ExecContext(ctx, query, values...); e != nil {
					t.Fatal("actual gate state fixture", e)
				}
			}
			e = LockOriginalRuntimeInstallationGate(ctx, tx, installation)
			if (e == nil) != (state == "absent" || state == "idle") {
				t.Fatal("original holder gate ignored", e)
			}
			if tx.Rollback() != nil {
				t.Fatal("fixture rollback")
			}
		})
	}
	// An idle gate is held until the producer transaction ends; the original B
	// transition cannot overtake it while the producer acquires later prefixes.
	if _, e := db.ExecContext(ctx, `INSERT INTO system_backup_v2_maintenance_locks(origin_installation_id,scope,lock_ttl_seconds) VALUES (?,?,180)`, installation, c.CaptureGateScope); e != nil {
		t.Fatal(e)
	}
	tx, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if LockOriginalRuntimeInstallationGate(ctx, tx, installation) != nil {
		t.Fatal("idle gate")
	}
	other, e := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		t.Fatal(e)
	}
	defer other.Rollback()
	if _, e = other.ExecContext(ctx, "SET SESSION innodb_lock_wait_timeout=1"); e != nil {
		t.Fatal(e)
	}
	var state string
	e = other.QueryRowContext(ctx, `SELECT gate_state FROM system_backup_v2_maintenance_locks WHERE origin_installation_id=? AND scope=? FOR UPDATE`, installation, c.CaptureGateScope).Scan(&state)
	var native *mysql.MySQLError
	if !errors.As(e, &native) || native.Number != 1205 {
		t.Fatal("native B prefix failed to wait on producer's original gate", e)
	}
	if other.Rollback() != nil || tx.Rollback() != nil {
		t.Fatal("owned gate transactions rollback")
	}
}
