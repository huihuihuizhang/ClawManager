package systembackupexecution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	controller "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
	batchv1 "k8s.io/api/batch/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var ErrJobUncertain = errors.New("original backup Job send is unresolved")

type JobDriver struct {
	Plans  PlanStore
	Client kubernetes.Interface
}

func (d JobDriver) planned(ctx context.Context, claim controller.ClaimToken, phase, unit string) (ExecutionPlan, PlannedJob, error) {
	var p ExecutionPlan
	if d.Client == nil {
		return p, PlannedJob{}, ErrPlan
	}
	stored, err := d.Plans.Load(ctx, claim)
	if err != nil {
		return p, PlannedJob{}, err
	}
	defer clear(stored.CanonicalJSON)
	if json.Unmarshal(stored.CanonicalJSON, &p) != nil || p.Validate() != nil || stored.SchemaVersion != executionPlanSchema || p.InstallationID != d.Plans.InstallationID || p.TaskID != claim.Target.PublicID {
		return p, PlannedJob{}, ErrPlan
	}
	for _, j := range p.Jobs {
		if j.Phase == phase && j.UnitKey == unit {
			return p, j, nil
		}
	}
	return p, PlannedJob{}, ErrPlan
}

// phaseLock is held only for a bounded control operation. It verifies public
// task authority; a persisted send intent is committed BEFORE the network call.
func (d JobDriver) phaseLock(ctx context.Context, tx *sql.Tx, claim controller.ClaimToken, phase string) (int64, error) {
	_, _, capacity, err := d.Plans.lock(ctx, tx, claim)
	if err != nil {
		return 0, err
	}
	var valid bool
	err = tx.QueryRowContext(ctx, `SELECT deadline_at>TIMESTAMPADD(SECOND,10,UTC_TIMESTAMP(6)) AND controller_lease_expires_at>TIMESTAMPADD(SECOND,10,UTC_TIMESTAMP(6)) AND
((? IN ('capture','secret_capture') AND status IN ('preparing','ready_for_capture','acquiring_gate','capturing')) OR (?='publish' AND status='publishing'))
FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=?`, phase, phase, d.Plans.InstallationID, claim.Target.PublicID).Scan(&valid)
	if err != nil {
		return 0, err
	}
	if !valid {
		return 0, controller.ErrClaimLost
	}
	return capacity, nil
}

func (d JobDriver) namespace(ctx context.Context, j PlannedJob) error {
	ns, err := d.Client.CoreV1().Namespaces().Get(ctx, j.Job.Namespace, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if string(ns.UID) != j.NamespaceUID || ns.DeletionTimestamp != nil {
		return ErrPlan
	}
	return nil
}

// Ensure sends a planned Job at most once. Subsequent calls, including after a
// lost response, only GET and bind its actual UID. A missing sent Job is unknown
// execution, not permission to create another source reader.
func (d JobDriver) Ensure(ctx context.Context, claim controller.ClaimToken, phase, unit string) (*batchv1.Job, error) {
	p, j, err := d.planned(ctx, claim, phase, unit)
	if err != nil {
		return nil, err
	}
	step, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err = d.namespace(step, j); err != nil {
		return nil, err
	}
	tx, err := d.Plans.DB.BeginTx(step, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	capacity, err := d.phaseLock(step, tx, claim, phase)
	if err != nil {
		return nil, err
	}
	var state, hash, ns, name, namespaceUID string
	var uid sql.NullString
	err = tx.QueryRowContext(step, `SELECT send_state,spec_sha256,namespace_name,namespace_uid,job_name,job_uid FROM system_backup_v2_job_send_intents
WHERE origin_installation_id=? AND task_public_id=? AND phase=? AND job_unit_key=? FOR UPDATE`, p.InstallationID, p.TaskID, phase, unit).Scan(&state, &hash, &ns, &namespaceUID, &name, &uid)
	if errors.Is(err, sql.ErrNoRows) {
		if err = (security.RegistrationCapacity{ReportFile: d.Plans.CapacityReportFile}).Reserve(step, tx, capacity, 8192); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(step, "INSERT IGNORE INTO system_backup_v2_attempts(target_type,target_public_id,attempt_no,phase) VALUES('backup',?,1,?)", p.TaskID, phase); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(step, `INSERT INTO system_backup_v2_job_send_intents(origin_installation_id,task_public_id,phase,job_unit_key,namespace_name,namespace_uid,job_name,spec_sha256)
VALUES(?,?,?,?,?,?,?,?)`, p.InstallationID, p.TaskID, phase, unit, j.Job.Namespace, j.NamespaceUID, j.Job.Name, plannedSpecHash(j)); err != nil {
			return nil, err
		}
		state, hash, ns, namespaceUID, name = "planned", plannedSpecHash(j), j.Job.Namespace, j.NamespaceUID, j.Job.Name
	} else if err != nil {
		return nil, err
	}
	if hash != plannedSpecHash(j) || ns != j.Job.Namespace || namespaceUID != j.NamespaceUID || name != j.Job.Name {
		return nil, ErrPlan
	}
	send := state == "planned"
	if send {
		if _, err = tx.ExecContext(step, `UPDATE system_backup_v2_job_send_intents SET send_state='sending',send_started_at=UTC_TIMESTAMP(6)
WHERE origin_installation_id=? AND task_public_id=? AND phase=? AND job_unit_key=? AND send_state='planned'`, p.InstallationID, p.TaskID, phase, unit); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	want := boundJob(p, j)
	var got *batchv1.Job
	if send {
		// Keep current claim locked across the bounded send. If its response is
		// lost the already-committed intent prevents a new sender after takeover.
		guard, e := d.Plans.DB.BeginTx(step, nil)
		if e != nil {
			return nil, e
		}
		defer guard.Rollback()
		if _, e = d.phaseLock(step, guard, claim, phase); e != nil {
			return nil, e
		}
		got, err = d.Client.BatchV1().Jobs(j.Job.Namespace).Create(step, want, metav1.CreateOptions{})
		if e = guard.Commit(); e != nil {
			return nil, ErrJobUncertain
		}
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return nil, ErrJobUncertain
		}
	}
	if got == nil || err != nil {
		got, err = d.Client.BatchV1().Jobs(j.Job.Namespace).Get(step, j.Job.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil, ErrJobUncertain
		}
		if err != nil {
			return nil, err
		}
	}
	if !sameJob(want, got) || uid.Valid && uid.String != string(got.UID) {
		return nil, ErrPlan
	}
	if err = d.bind(step, claim, p, j, got); err != nil {
		return nil, err
	}
	return got, nil
}

func (d JobDriver) bind(ctx context.Context, claim controller.ClaimToken, p ExecutionPlan, j PlannedJob, got *batchv1.Job) error {
	tx, err := d.Plans.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = d.phaseLock(ctx, tx, claim, j.Phase); err != nil {
		return err
	}
	var state string
	var uid sql.NullString
	if err = tx.QueryRowContext(ctx, `SELECT send_state,job_uid FROM system_backup_v2_job_send_intents WHERE origin_installation_id=? AND task_public_id=? AND phase=? AND job_unit_key=? FOR UPDATE`, p.InstallationID, p.TaskID, j.Phase, j.UnitKey).Scan(&state, &uid); err != nil {
		return err
	}
	if state == "bound" {
		if !uid.Valid || uid.String != string(got.UID) {
			return ErrPlan
		}
		return tx.Commit()
	}
	if state != "sending" || uid.Valid {
		return ErrPlan
	}
	if _, err = tx.ExecContext(ctx, `UPDATE system_backup_v2_job_send_intents SET send_state='bound',job_uid=?,bound_at=UTC_TIMESTAMP(6) WHERE origin_installation_id=? AND task_public_id=? AND phase=? AND job_unit_key=?`, string(got.UID), p.InstallationID, p.TaskID, j.Phase, j.UnitKey); err != nil {
		return err
	}
	return tx.Commit()
}
