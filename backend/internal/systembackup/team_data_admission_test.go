package systembackup

import (
	"clawreef/internal/backupgate"
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTeamDataWorkerDefersClaimWhileSharedAdmissionClosed(t *testing.T) {
	s := teamDataJobFixture(t)
	s.cfg.InstallationID = "shared-admission"
	s.cfg.DeadlineSeconds = 60
	j, e := s.Create(context.Background(), 1, "shared-admission-closed", "backup", "")
	if e != nil {
		t.Fatal(e)
	}
	s.cfg.Disabled = true // execute must not run; avoids external source IO.
	var requests atomic.Int32
	restore := backupgate.ConfigureWorkBoundary(func(context.Context) (func(), error) { requests.Add(1); return nil, backupgate.ErrMaintenance })
	defer restore()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = s.runOwned(ctx)
	actual, e := s.Get(context.Background(), j.ID)
	if e != nil || actual.Status != "pending" || requests.Load() == 0 {
		t.Fatal("closed source gate did not preserve pending work", e, actual.Status, requests.Load())
	}
}

func TestTeamDataWorkerPermitCoversActualExecutionAndSettlement(t *testing.T) {
	s := teamDataJobFixture(t)
	s.cfg.InstallationID = "shared-admission-execution"
	s.cfg.DeadlineSeconds = 60
	j, e := s.Create(context.Background(), 1, "shared-admission-complete", "backup", "")
	if e != nil {
		t.Fatal(e)
	}
	s.cfg.Disabled = true
	var enters, releases atomic.Int32
	restore := backupgate.ConfigureWorkBoundary(func(context.Context) (func(), error) {
		enters.Add(1)
		return func() {
			actual, e := s.Get(context.Background(), j.ID)
			if e != nil || actual.Status != "failed" {
				t.Error("permit released before execution settlement", e, actual.Status)
			}
			releases.Add(1)
		}, nil
	})
	defer restore()
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	_ = s.runOwned(ctx)
	if enters.Load() != 1 || releases.Load() != 1 {
		t.Fatal("execution did not own exactly one shared permit", enters.Load(), releases.Load())
	}
}

// The callback is the same SQL admission used by the server bootstrap. Unlike
// the refusal fixture above, this holds and releases a real physical gate in
// the SAME database as the pending TeamData task.
func TestTeamDataWorkerUsesSamePhysicalGateBeforeClaim(t *testing.T) {
	s := teamDataJobFixture(t)
	for _, file := range []string{"079_add_system_backup_control.sql", "080_add_backup_dependency_health.sql", "081_add_backup_controller_coordination.sql", "082_add_backup_attempt_request.sql", "083_add_backup_strong_auth_nonce.sql", "084_add_backup_external_actions.sql", "085_add_backup_capture_coordination.sql", "086_add_backup_capture_abort.sql", "087_add_backup_stage_resources.sql", "088_add_backup_core_publication.sql", "089_add_backup_gate_admission.sql", "090_add_backup_restore_job_executions.sql", "091_add_backup_job_send_intents.sql", "092_allow_owned_backup_restore_workspaces.sql", "111_backup_engine_selection.sql"} {
		ddl, e := os.ReadFile("../db/migrations/" + file)
		if e != nil {
			t.Fatal(e)
		}
		for _, q := range strings.Split(string(ddl), ";") {
			if strings.TrimSpace(q) != "" {
				if _, e = s.db.Exec(q); e != nil {
					t.Fatal(e)
				}
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	gate := Gate{DB: s.db}
	if e := gate.EnsureScope(ctx, "team-data-source"); e != nil {
		t.Fatal(e)
	}
	owner, e := gate.Begin(ctx, "team-data-source", "original-formal-backup", RegistryHash(), time.Second, 5*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	owner, e = gate.Hold(ctx, owner)
	if e != nil {
		t.Fatal(e)
	}
	restore := backupgate.ConfigureWorkBoundary(func(c context.Context) (func(), error) { return backupgate.HoldRequest(c, s.db, "team-data-source") })
	defer restore()
	j, e := s.Create(ctx, 1, "physical-source-gate", "backup", "")
	if e != nil {
		t.Fatal(e)
	}
	s.cfg.Disabled = true
	s.cfg.DeadlineSeconds = 60
	connection, e := s.db.Conn(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer connection.Close()
	if e = s.executeAdmitted(ctx, connection, j); !errors.Is(e, backupgate.ErrMaintenance) {
		t.Fatal("closed physical source admitted execution", e)
	}
	actual, e := s.Get(ctx, j.ID)
	if e != nil || actual.Status != "pending" || actual.Phase != "waiting_for_source" {
		t.Fatal("closed gate consumed task", e, actual.Status)
	}
	if _, e = s.db.ExecContext(ctx, "UPDATE system_team_data_backup_jobs SET created_at=TIMESTAMPADD(HOUR,8,UTC_TIMESTAMP(6)),updated_at=TIMESTAMPADD(SECOND,-61,UTC_TIMESTAMP(6)) WHERE public_id=?", j.ID); e != nil {
		t.Fatal(e)
	}
	if e = s.executeAdmitted(ctx, connection, j); !errors.Is(e, backupgate.ErrMaintenance) {
		t.Fatal(e)
	}
	expired, e := s.Get(ctx, j.ID)
	if e != nil || expired.Status != "failed" || expired.Error != "source_gate_wait_timed_out" || expired.StartedAt != nil {
		t.Fatal("unclaimed timeout did not settle safely", e, expired.Status, expired.Error)
	}
	var physicalPhase string
	if e = s.db.QueryRowContext(ctx, "SELECT phase FROM system_backup_gate WHERE scope='team-data-source'").Scan(&physicalPhase); e != nil || physicalPhase != "held" {
		t.Fatal("waiting timeout released another capture", e, physicalPhase)
	}
	s.cfg.Disabled = false
	j, e = s.Retry(ctx, 1, j.ID, "retry-source-after-original-timeout")
	if e != nil {
		t.Fatal(e)
	}
	s.cfg.Disabled = true
	if e = gate.BeginRelease(ctx, owner); e != nil {
		t.Fatal(e)
	}
	if e = gate.FinishRelease(ctx, owner); e != nil {
		t.Fatal(e)
	}
	if e = s.executeAdmitted(ctx, connection, j); e != nil {
		t.Fatal("reopened source did not admit queued task", e)
	}
	actual, e = s.Get(ctx, j.ID)
	if e != nil || actual.Status != "failed" || actual.Error != "feature_disabled" {
		t.Fatal("admitted work did not finish once", e, actual.Status, actual.Error)
	}
	var outstanding int
	if e = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_mutation_leases WHERE scope='team-data-source' AND released_at IS NULL").Scan(&outstanding); e != nil || outstanding != 0 {
		t.Fatal("finished work leaked gate permit", e, outstanding)
	}
}
