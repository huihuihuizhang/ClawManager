package systembackupread

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestGetTaskBaseScopesAndRedactsFourKinds(t *testing.T) {
	for _, tc := range []struct {
		kind          TaskKind
		table, prefix string
	}{
		{BackupTask, "system_backup_v2_backups", "sbk_"},
		{DrillTask, "system_backup_v2_restore_drills", "sdr_"},
		{PreflightTask, "system_backup_v2_preflights", "spf_"},
		{VerificationTask, "system_backup_v2_artifact_verifications", "sav_"},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			fixture := makePageFixture(tc.table, string(tc.kind), tc.prefix)
			db := sql.OpenDB(pageConnector{fixture})
			defer db.Close()
			service, err := NewService(db, fixture, []byte(strings.Repeat("k", 32)))
			if err != nil {
				t.Fatal(err)
			}
			id := fixture.rows[0][1].(string)
			task, err := service.GetTaskBase(context.Background(), tc.kind, id)
			if err != nil || task.PublicID != id || task.OriginInstallationID != "installation_test" || task.TaskType != tc.kind {
				t.Fatal("incorrect detail base", task, err)
			}
			if fixture.rechecks != 1 || len(fixture.queries) != 1 || !strings.Contains(fixture.queries[0], "WHERE origin_installation_id=? AND public_id=?") {
				t.Fatal("detail did not use one scoped query and final recheck", fixture.queries, fixture.rechecks)
			}
			encoded, err := json.Marshal(task)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"config_snapshot_json", "failure_message", "controller_owner", "artifact_uri", "\"id\""} {
				if strings.Contains(string(encoded), forbidden) {
					t.Fatal("sensitive detail base", forbidden)
				}
			}
		})
	}
}

func TestGetTaskBaseFailsClosedOnInvalidMissingAndRevoked(t *testing.T) {
	fixture := makePageFixture("system_backup_v2_backups", "backup", "sbk_")
	db := sql.OpenDB(pageConnector{fixture})
	defer db.Close()
	service, err := NewService(db, fixture, []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetTaskBase(context.Background(), BackupTask, "sdr_00000000-0000-4000-8000-000000000003"); !errors.Is(err, ErrInvalid) || len(fixture.queries) != 0 {
		t.Fatal("wrong kind queried database", err)
	}
	id := "sbk_00000000-0000-4000-8000-000000000009"
	if _, err := service.GetTaskBase(context.Background(), BackupTask, id); !errors.Is(err, ErrNotFound) || fixture.rechecks != 1 {
		t.Fatal("authorized miss did not recheck", err, fixture.rechecks)
	}
	fixture.recheckErr = true
	if _, err := service.GetTaskBase(context.Background(), BackupTask, id); !errors.Is(err, ErrDenied) {
		t.Fatal("revocation racing a miss became 404", err)
	}
	fixture.recheckErr = false
	fixture.deny = true
	queries := len(fixture.queries)
	if _, err := service.GetTaskBase(context.Background(), BackupTask, fixture.rows[0][1].(string)); !errors.Is(err, ErrDenied) || len(fixture.queries) != queries {
		t.Fatal("denied detail queried task", err)
	}
	fixture.deny = false
	fixture.badQuery = true
	if _, err := service.GetTaskBase(context.Background(), BackupTask, fixture.rows[0][1].(string)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("database error looked like 404", err)
	}
	fixture.badQuery = false
	fixture.rows[0][2] = "installation_other"
	if _, err := service.GetTaskBase(context.Background(), BackupTask, fixture.rows[0][1].(string)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("wrong installation row escaped", err)
	}
}

func TestDetailBuilderRunsWithinAuthorizedTransactionBeforeFinalRecheck(t *testing.T) {
	fixture := makePageFixture("system_backup_v2_backups", "backup", "sbk_")
	db := sql.OpenDB(pageConnector{fixture})
	defer db.Close()
	reader, err := NewReader(db, fixture)
	if err != nil {
		t.Fatal(err)
	}
	id := fixture.rows[0][1].(string)
	called := false
	build := func(ctx context.Context, tx detailReadSQL, item TaskHeader) (string, error) {
		called = true
		if item.PublicID != id || item.InstallationID != "installation_test" || fixture.rechecks != 0 {
			t.Fatal("builder received a wrong or already committed task", item, fixture.rechecks)
		}
		var count uint64
		if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(id),0) FROM system_backup_v2_backups WHERE origin_installation_id=?", item.InstallationID).Scan(&count); err != nil || count != 3 {
			t.Fatal("builder could not read in the same scoped transaction", count, err)
		}
		fixture.recheckErr = true
		return "must-not-escape", nil
	}
	result, err := readTaskInTransaction(context.Background(), reader, BackupTask, id, build)
	if !called || result != "" || !errors.Is(err, ErrDenied) || fixture.rechecks != 1 || len(fixture.queries) != 2 {
		t.Fatal("revoked detail builder result escaped", result, err, fixture.rechecks, fixture.queries)
	}
	fixture.recheckErr = false
	if result, err := readTaskInTransaction(context.Background(), reader, BackupTask, id,
		func(context.Context, detailReadSQL, TaskHeader) (string, error) {
			return "partial", errors.New("owner projection missing")
		}); result != "" || !errors.Is(err, ErrUnavailable) {
		t.Fatal("partial owner projection escaped", result, err)
	}
	if result, err := readTaskInTransaction[string](context.Background(), reader, BackupTask, id, nil); result != "" || !errors.Is(err, ErrUnavailable) {
		t.Fatal("nil detail builder accepted", result, err)
	}
}
