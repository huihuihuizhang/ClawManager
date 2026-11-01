package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
)

// All mutations occur in the SAME actual transaction after its original Bind.
// The old independent Stage Bind is a comparison, not an expected authority
// renewal: changes that it admits still MUST be rejected by the original guard.
// This narrow fixture deliberately has mutable rows; it is not a formal task.
func assertProviderStageOriginalCurrentSQL(t *testing.T, owner *PublicJobOwner, admin *sql.DB, authority d.Authority, job d.JobBinding, invocation worker.Invocation, lease worker.KeyUseLease) {
	t.Helper()
	ctx := context.Background()
	in, err := owner.readExecutionInput(ctx, authority)
	if err != nil {
		t.Fatal(err)
	}
	invocationHash, err := invocation.Hash()
	if err != nil {
		t.Fatal(err)
	}
	pod := BoundPod{Namespace: job.Namespace, Name: "capture-pod", UID: lease.Identity.PodUID, ServiceAccountUID: lease.Identity.ServiceAccountUID}
	request := worker.ControlRequest{Action: "key-check", Invocation: invocation, InvocationSHA256: invocationHash}
	// NewDeliveredCaptureKeyJob already performed its actual original key-check,
	// so the committed reference is unknown; replaying reserve would be invalid.
	var state string
	if owner.Gate.Authority.DB.QueryRowContext(ctx, "SELECT reference_state FROM system_backup_v2_kek_references").Scan(&state) != nil || state != "unknown" {
		t.Fatal("original constructor did not enter the current unknown-reference phase", state)
	}
	prepared, err := owner.prepareProviderPermit(ctx, in, job, pod, request)
	if err != nil {
		t.Fatal("original Stage comparison preparation", err)
	}
	if prepared.StageOriginal(ctx, nil, lease, "key-check", nil) == nil {
		t.Fatal("nil original guard accepted")
	}
	for _, test := range []struct {
		table, column, value string
		oldAllowed           bool
	}{
		{"", "healthy", "", true},
		{"backups", "row_version", "row_version+1", false},
		{"backups", "maintenance_lock_owner", "CONCAT(maintenance_lock_owner,' ')", false},
		{"backups", "maintenance_fencing_token", "maintenance_fencing_token+1", false},
		{"backups", "controller_lease_expires_at", "TIMESTAMPADD(SECOND,1,controller_lease_expires_at)", true},
		{"backups", "controller_owner", "CONCAT(controller_owner,' ')", false},
		{"backups", "schema_version", "UPPER(schema_version)", false},
		{"backups", "task_type", "'Backup'", false},
		{"backups", "status", "'Capturing'", false},
		{"backups", "request_id", "CONCAT(request_id,' ')", false},
		{"backups", "config_snapshot_json", "CONCAT(config_snapshot_json,' ')", false},
		{"maintenance_locks", "row_version", "row_version+1", true},
		{"maintenance_locks", "fencing_token", "fencing_token+1", false},
		{"maintenance_locks", "lease_expires_at", "TIMESTAMPADD(SECOND,1,lease_expires_at)", true},
		{"maintenance_locks", "absolute_hold_deadline_at", "TIMESTAMPADD(SECOND,1,absolute_hold_deadline_at)", true},
		{"maintenance_locks", "lock_owner", "CONCAT(lock_owner,' ')", false},
		{"installation_state", "row_version", "row_version+1", true},
		{"installation_state", "last_effective_enabled", "0", false},
		{"installation_state", "schema_version", "UPPER(schema_version)", false},
		{"attempts", "row_version", "row_version+1", true},
		{"attempts", "status", "'Running'", false},
		{"backups", "controller_lease_expires_at", "UTC_TIMESTAMP(6)", false},
		{"backups", "deadline_at", "UTC_TIMESTAMP(6)", false},
		{"maintenance_locks", "lease_expires_at", "UTC_TIMESTAMP(6)", false},
		{"maintenance_locks", "absolute_hold_deadline_at", "UTC_TIMESTAMP(6)", false},
	} {
		t.Run("stage-original-"+test.table+"-"+test.column+"-"+test.value, func(t *testing.T) {
			for _, reuse := range []bool{false, true} {
				tx, err := owner.Gate.Authority.DB.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				func() {
					defer tx.Rollback()
					guard, err := owner.Gate.Authority.Bind(ctx, tx, authority)
					if err != nil || guard.Recheck(ctx, tx) != nil {
						t.Fatal("original pre-mutation guard", err)
					}
					before := providerStageRows(t, ctx, tx)
					if test.table != "" {
						table := "system_backup_v2_" + test.table
						var original, changed []byte
						if tx.QueryRowContext(ctx, "SELECT "+test.column+" FROM "+table).Scan(&original) != nil {
							t.Fatal("original current SQL field")
						}
						result, err := tx.ExecContext(ctx, "UPDATE "+table+" SET "+test.column+"="+test.value)
						if err != nil {
							t.Fatal(err)
						}
						count, err := result.RowsAffected()
						if err != nil || count != 1 || tx.QueryRowContext(ctx, "SELECT "+test.column+" FROM "+table).Scan(&changed) != nil || bytes.Equal(original, changed) {
							t.Fatal("current SQL mutation not independently observed", count, err)
						}
					}
					var stageErr error
					if reuse {
						stageErr = prepared.StageOriginal(ctx, tx, lease, "key-check", guard)
					} else {
						stageErr = prepared.Stage(ctx, tx, lease, "key-check")
					}
					allowed := test.oldAllowed && !reuse || test.table == ""
					if (stageErr == nil) != allowed {
						t.Fatal("old/new Stage decision", reuse, allowed, stageErr)
					}
					if providerStageRows(t, ctx, tx) != before {
						t.Fatal("Stage comparison added/changed original permit or registry rows", reuse)
					}
					if reuse && !allowed && (guard.Recheck(ctx, tx) == nil || !guard.ValidUntil().IsZero()) {
						t.Fatal("failed original guard revived")
					}
				}()
			}
		})
	}
	// Only this owned narrow fixture permits the original transaction to make
	// these two inserts, so its own post-Bind writes are visible to both paths.
	var database, account string
	if owner.Gate.Authority.DB.QueryRowContext(ctx, "SELECT DATABASE(),CURRENT_USER()").Scan(&database, &account) != nil {
		t.Fatal("owned scope fixture identity")
	}
	parts := strings.Split(account, "@")
	run := strings.TrimPrefix(database, "ad_d_consumer_")
	decoded, decodeErr := hex.DecodeString(run)
	if decodeErr != nil || len(decoded) != 8 || database != "ad_d_consumer_"+run || len(parts) != 2 || parts[0] != "ad_d_read_"+run || parts[1] != "127.0.0.1" {
		t.Fatal("scope mutation fixture is not independently owned")
	}
	for _, table := range []string{"system_backup_v2_attempts", "system_backup_v2_operations"} {
		if _, err := admin.ExecContext(ctx, "GRANT INSERT ON `"+database+"`.`"+table+"` TO '"+parts[0]+"'@'127.0.0.1'"); err != nil {
			t.Fatal("owned fixture post-Bind mutation grant", err)
		}
	}
	for _, scope := range []string{"latest-attempt", "pending-cancel", "running-cancel"} {
		t.Run("stage-original-"+scope, func(t *testing.T) {
			for _, reuse := range []bool{false, true} {
				tx, err := owner.Gate.Authority.DB.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				func() {
					defer tx.Rollback()
					guard, err := owner.Gate.Authority.Bind(ctx, tx, authority)
					if err != nil || guard.Recheck(ctx, tx) != nil {
						t.Fatal("original scope baseline", err)
					}
					before := providerStageRows(t, ctx, tx)
					var result sql.Result
					var count uint64
					if scope == "latest-attempt" {
						result, err = tx.ExecContext(ctx, "INSERT INTO system_backup_v2_attempts(target_type,target_public_id,attempt_no,phase,status,row_version) VALUES('backup',?,?,'capture','running',1)", authority.TaskPublicID, authority.AttemptNo+1)
						if err == nil {
							err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_attempts WHERE target_public_id=? AND attempt_no=?", authority.TaskPublicID, authority.AttemptNo+1).Scan(&count)
						}
					} else {
						status := strings.TrimSuffix(scope, "-cancel")
						result, err = tx.ExecContext(ctx, "INSERT INTO system_backup_v2_operations(origin_installation_id,target_type,target_public_id,operation_type,status) VALUES(?,'backup',?,'cancel',?)", authority.InstallationID, authority.TaskPublicID, status)
						if err == nil {
							err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_operations WHERE origin_installation_id=? AND target_public_id=? AND operation_type='cancel' AND status=?", authority.InstallationID, authority.TaskPublicID, status).Scan(&count)
						}
					}
					if err != nil || count != 1 {
						t.Fatal("scope insert independently observed", count, err)
					}
					if affected, err := result.RowsAffected(); err != nil || affected != 1 {
						t.Fatal("scope insert not applied", affected, err)
					}
					if reuse {
						err = prepared.StageOriginal(ctx, tx, lease, "key-check", guard)
					} else {
						err = prepared.Stage(ctx, tx, lease, "key-check")
					}
					if err == nil || providerStageRows(t, ctx, tx) != before {
						t.Fatal("current scope mutation accepted or wrote original permit/reference", reuse, err)
					}
					if reuse && (!guard.ValidUntil().IsZero() || guard.Recheck(ctx, tx) == nil) {
						t.Fatal("failed original scope guard revived")
					}
				}()
			}
		})
	}
}

func assertProviderStageOriginalIssuerExpiry(t *testing.T, owner *PublicJobOwner, authority d.Authority, job d.JobBinding, invocation worker.Invocation, lease worker.KeyUseLease) {
	t.Helper()
	ctx := context.Background()
	in, err := owner.readExecutionInput(ctx, authority)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := invocation.Hash()
	if err != nil {
		t.Fatal(err)
	}
	pod := BoundPod{Namespace: job.Namespace, Name: "capture-pod", UID: lease.Identity.PodUID, ServiceAccountUID: lease.Identity.ServiceAccountUID}
	prepared, err := owner.prepareProviderPermit(ctx, in, job, pod, worker.ControlRequest{Action: "key-check", Invocation: invocation, InvocationSHA256: hash})
	if err != nil || !prepared.ValidUntil().Equal(lease.Until) {
		t.Fatal("original issuer is not the real fixed lease bound", err)
	}
	tx, err := owner.Gate.Authority.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	guard, err := owner.Gate.Authority.Bind(ctx, tx, authority)
	if err != nil || guard.Recheck(ctx, tx) != nil || !guard.ValidUntil().After(lease.Until) {
		t.Fatal("original longer business authority is not healthy", err)
	}
	before := providerStageRows(t, ctx, tx)
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !now.Before(lease.Until) {
		t.Fatal("original issuer was already expired before wait")
	}
	// Wait for the actual originally signed issuer and persisted use window;
	// never edit the grant, lease, nonce, receipt or any original row.
	wait := time.Until(lease.Until) + 50*time.Millisecond
	if wait <= 0 || wait > 10*time.Second {
		t.Fatal("unexpected original issuer test wait", wait)
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-timer.C:
	}
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || now.Before(lease.Until) || now.Before(prepared.ValidUntil()) {
		t.Fatal("actual SQL time did not cross original issuer window")
	}
	if prepared.Stage(ctx, tx, lease, "key-check") == nil || prepared.StageOriginal(ctx, tx, lease, "key-check", guard) == nil {
		t.Fatal("expired original issuer/use window accepted")
	}
	if providerStageRows(t, ctx, tx) != before || !guard.ValidUntil().IsZero() || guard.Recheck(ctx, tx) == nil {
		t.Fatal("expired Stage wrote a permit/reference or revived original guard")
	}
}

type providerStageRowCounts struct {
	evidence, references, bindings, coverage uint64
	epoch                                    uint64
}

func providerStageRows(t *testing.T, ctx context.Context, tx *sql.Tx) providerStageRowCounts {
	t.Helper()
	var observed providerStageRowCounts
	if tx.QueryRowContext(ctx, `SELECT
(SELECT COUNT(*) FROM system_backup_v2_evidence),
(SELECT COUNT(*) FROM system_backup_v2_kek_references),
(SELECT COUNT(*) FROM system_backup_v2_kek_bindings),
(SELECT COUNT(*) FROM system_backup_v2_kek_coverage),
(SELECT epoch FROM system_backup_v2_kek_fences)`).Scan(&observed.evidence, &observed.references, &observed.bindings, &observed.coverage, &observed.epoch) != nil {
		t.Fatal("independent original Stage row/epoch census")
	}
	return observed
}
