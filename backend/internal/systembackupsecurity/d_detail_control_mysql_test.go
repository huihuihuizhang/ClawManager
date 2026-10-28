//go:build systembackup_mysql

package systembackupsecurity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackupread"
)

// Called only by the existing pinned, fresh-schema probe after its four task
// fixtures and execution history are present. No production grants or Owner
// artifact/report facts are inferred from these synthetic rows.
func dCheckDetailControlMySQL(t *testing.T, db *sql.DB, ownScope, foreignScope *SystemBackupReadScope,
	installation, backupID string, otherKinds []struct {
		kind systembackupread.TaskKind
		id   string
	}) {
	t.Helper()
	ctx := ownScope.Context()
	reader, err := systembackupread.NewReader(db, ownScope)
	mysqlMust(t, err)
	foreignReader, err := systembackupread.NewReader(db, foreignScope)
	mysqlMust(t, err)
	t.Run("detail_control_four_kinds_and_installation_isolation", func(t *testing.T) {
		targets := append([]struct {
			kind systembackupread.TaskKind
			id   string
		}{{systembackupread.BackupTask, backupID}}, otherKinds...)
		for _, target := range targets {
			t.Run(string(target.kind), func(t *testing.T) {
				s, e := reader.ReadTaskDetailControl(ctx, target.kind, target.id)
				mysqlMust(t, e)
				if s.Execution().Task().PublicID != target.id || s.Execution().Task().InstallationID != installation ||
					len(s.Execution().Attempts()) != 2 || len(s.Execution().JobObservations()) != 1 {
					t.Fatal("detail lost authorized task/execution history")
				}
				b, backup := s.Backup()
				d, drill := s.Drill()
				p, preflight := s.Preflight()
				v, verification := s.Verification()
				if backup != (target.kind == systembackupread.BackupTask) || drill != (target.kind == systembackupread.DrillTask) ||
					preflight != (target.kind == systembackupread.PreflightTask) || verification != (target.kind == systembackupread.VerificationTask) {
					t.Fatal("incorrect detail kind")
				}
				if backup && (b.Matrix != "k8s-single-node" || b.Runner != "k8s" || len(b.RequestedParts) != 1 || b.RequestedParts[0] != "mysql" || b.Consistency.Valid || b.Bytes.Valid) ||
					drill && (d.Source.PublicID != backupID || d.CleanupStatus != "not_started") ||
					preflight && (p.Source.PublicID != backupID || p.Compatibility != "supported") ||
					verification && (v.Source.PublicID != backupID || !v.StateBefore.Valid || v.StateBefore.String != "staging") {
					t.Fatal("persisted detail columns were not read accurately")
				}
				if _, e := json.Marshal(s); !errors.Is(e, systembackupread.ErrInvalid) {
					t.Fatal("internal detail became a public response", e)
				}
				cross, e := foreignReader.ReadTaskDetailControl(foreignScope.Context(), target.kind, target.id)
				if !errors.Is(e, systembackupread.ErrNotFound) || cross.Execution().Task().PublicID != "" {
					t.Fatal("foreign task detail was visible", e)
				}
			})
		}
	})
	t.Run("events_public_dto_four_kinds_scoped_cutoff", func(t *testing.T) {
		targets := append([]struct {
			kind systembackupread.TaskKind
			id   string
		}{{systembackupread.BackupTask, backupID}}, otherKinds...)
		service, e := systembackupread.NewService(db, ownScope, []byte(strings.Repeat("e", 32)))
		mysqlMust(t, e)
		foreignService, e := systembackupread.NewService(db, foreignScope, []byte(strings.Repeat("e", 32)))
		mysqlMust(t, e)
		for _, target := range targets {
			t.Run(string(target.kind), func(t *testing.T) {
				requestID := "req_d_event_dto_probe_" + string(target.kind)
				t.Cleanup(func() {
					_, err := db.ExecContext(context.Background(), "DELETE FROM system_backup_v2_events WHERE origin_installation_id=? AND request_id=?", installation, requestID)
					mysqlMust(t, err)
				})
				detail, err := reader.ReadTaskDetailControl(ctx, target.kind, target.id)
				mysqlMust(t, err)
				at := detail.Execution().Task().CreatedAt.Add(time.Second)
				insert := func(message string) {
					_, err := db.ExecContext(ctx, "INSERT INTO system_backup_v2_events(origin_installation_id,target_type,target_public_id,event_type,level,message,request_id,created_at) VALUES(?,?,?,'task_status_changed','info',?,?,?)", installation, string(target.kind), target.id, message, requestID, at)
					mysqlMust(t, err)
				}
				insert("redacted first")
				insert("redacted second")
				insert("redacted third")
				first, err := service.ListTaskEventsDTO(ctx, target.kind, target.id, 2, "")
				mysqlMust(t, err)
				if first.InstallationID != installation || first.TaskRowVersion != detail.Execution().Task().RowVersion || len(first.Resource.Items) != 2 || first.Resource.Items[0].Message != "redacted third" || first.Resource.Items[1].Message != "redacted second" || first.Resource.NextCursor == nil {
					t.Fatal("public event page lost database identity/order", first)
				}
				insert("backdated after cutoff")
				last, err := service.ListTaskEventsDTO(ctx, target.kind, target.id, 2, *first.Resource.NextCursor)
				mysqlMust(t, err)
				if len(last.Resource.Items) != 1 || last.Resource.Items[0].Message != "redacted first" || last.Resource.NextCursor != nil {
					t.Fatal("cutoff admitted a newly inserted event", last)
				}
				cross, err := foreignService.ListTaskEventsDTO(foreignScope.Context(), target.kind, target.id, 2, "")
				if !errors.Is(err, systembackupread.ErrNotFound) || cross.InstallationID != "" || cross.Resource.Items != nil {
					t.Fatal("foreign public events visible", cross, err)
				}
			})
		}
	})
	t.Run("detail_control_same_snapshot_as_task_and_execution", func(t *testing.T) {
		var domain string
		var version uint64
		mysqlMust(t, db.QueryRowContext(ctx, "SELECT target_failure_domain_id,row_version FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=?", installation, backupID).Scan(&domain, &version))
		defer func() {
			_, e := db.ExecContext(ctx, "UPDATE system_backup_v2_backups SET target_failure_domain_id=?,row_version=row_version+1 WHERE origin_installation_id=? AND public_id=?", domain, installation, backupID)
			mysqlMust(t, e)
		}()
		racedScope := dTaskExecutionSnapshotScope{base: ownScope, taskID: backupID, advance: func(ctx context.Context) error {
			_, e := db.ExecContext(ctx, "UPDATE system_backup_v2_backups SET target_failure_domain_id='detail-after-snapshot',row_version=row_version+1 WHERE origin_installation_id=? AND public_id=?", installation, backupID)
			return e
		}}
		racedReader, e := systembackupread.NewReader(db, racedScope)
		mysqlMust(t, e)
		s, e := racedReader.ReadTaskDetailControl(ctx, systembackupread.BackupTask, backupID)
		mysqlMust(t, e)
		b, ok := s.Backup()
		if !ok || b.FailureDomain != domain || s.Execution().Task().RowVersion != version {
			t.Fatal("detail mixed task/control columns from different snapshots")
		}
		var currentDomain string
		var currentVersion uint64
		mysqlMust(t, db.QueryRowContext(ctx, "SELECT target_failure_domain_id,row_version FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=?", installation, backupID).Scan(&currentDomain, &currentVersion))
		if currentDomain != "detail-after-snapshot" || currentVersion != version+1 {
			t.Fatal("competing control-field update did not commit")
		}
	})
	t.Run("detail_control_unsigned_bytes_and_nullable_consistency", func(t *testing.T) {
		_, e := db.ExecContext(ctx, "UPDATE system_backup_v2_backups SET artifact_bytes=CAST('18446744073709551615' AS UNSIGNED),row_version=row_version+1 WHERE origin_installation_id=? AND public_id=?", installation, backupID)
		mysqlMust(t, e)
		defer func() {
			_, e := db.ExecContext(ctx, "UPDATE system_backup_v2_backups SET artifact_bytes=NULL,row_version=row_version+1 WHERE origin_installation_id=? AND public_id=?", installation, backupID)
			mysqlMust(t, e)
		}()
		s, e := reader.ReadTaskDetailControl(ctx, systembackupread.BackupTask, backupID)
		mysqlMust(t, e)
		b, ok := s.Backup()
		if !ok || !b.Bytes.Valid || b.Bytes.V != ^uint64(0) || b.Consistency.Valid {
			t.Fatal("MySQL unsigned/null facts changed", b.Bytes, b.Consistency)
		}
	})
	t.Run("detail_control_catalog_verification_null_states", func(t *testing.T) {
		var id string
		for _, target := range otherKinds {
			if target.kind == systembackupread.VerificationTask {
				id = target.id
			}
		}
		if id == "" {
			t.Fatal("verification fixture missing")
		}
		_, e := db.ExecContext(ctx, `UPDATE system_backup_v2_artifact_verifications SET source_artifact_type='catalog_import',
		 source_public_id='sci_000000d1-0000-4000-8000-000000000001',artifact_state_before=NULL,artifact_state_after=NULL,
		 usable_before=TRUE,usable_after=TRUE,unusable_reason_before='none',unusable_reason_after='none',row_version=row_version+1
		 WHERE origin_installation_id=? AND public_id=?`, installation, id)
		mysqlMust(t, e)
		defer func() {
			_, e := db.ExecContext(ctx, `UPDATE system_backup_v2_artifact_verifications SET source_artifact_type='backup',source_public_id=?,
			 artifact_state_before='staging',artifact_state_after='staging',usable_before=FALSE,usable_after=FALSE,
			 unusable_reason_before='not_committed',unusable_reason_after='not_committed',row_version=row_version+1
			 WHERE origin_installation_id=? AND public_id=?`, backupID, installation, id)
			mysqlMust(t, e)
		}()
		s, e := reader.ReadTaskDetailControl(ctx, systembackupread.VerificationTask, id)
		mysqlMust(t, e)
		v, ok := s.Verification()
		if !ok || v.Source.Type != "catalog_import" || v.StateBefore.Valid || v.StateAfter.Valid || !v.UsableBefore || !v.UsableAfter {
			t.Fatal("imported saved readability was confused with local artifact state")
		}
	})
}
