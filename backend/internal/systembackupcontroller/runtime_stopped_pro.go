package systembackupcontroller

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"time"

	"clawreef/internal/systembackup/flow"
	b "clawreef/internal/systembackup/publicadapter"
	q "clawreef/internal/systembackup/quiesce"
	d "clawreef/internal/systembackupdispatch"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Stored in the real task's runtime_controls.resumed_json. The prepare and
// stopped receipts retain their original bytes/anchor throughout recovery.
// Neither decoding this record nor its hash can mint a native opaque handle.
type RuntimeStoppedProRecord struct {
	Version   string
	Request   q.StoppedProNodeObservationRequest
	Prepare   q.StoppedProNodeObservationResponse
	Stopped   *q.StoppedProNodeObservationResponse `json:",omitempty"`
	Recovered *q.StoppedProNodeObservationResponse `json:",omitempty"`
}

func stoppedProSpec(s b.RuntimeWriterSpec) (q.StoppedProBaseline, error) {
	var baseline q.StoppedProBaseline
	if s.Kind != "stopped" || s.Source.Status != "stopped" || s.Source.Mode != "pro" || s.Source.OS != "linux" || s.Source.Generation <= 0 || json.Unmarshal([]byte(s.StoppedProBaseline), &baseline) != nil || baseline.InstanceID != uint64(s.Source.ID) || baseline.UserID != uint64(s.Source.UserID) || baseline.InstanceGeneration != uint64(s.Source.Generation) || baseline.SourceKey != s.Stopped.UID || s.Stopped.Running || s.Stopped.Generation != int64(s.Source.Generation) || q.StoppedProBaselineSHA256(baseline) != s.Stopped.Checkpoint {
		return baseline, ErrExecutionRecord
	}
	return baseline, nil
}

func (o *SQLRuntimeControl) stoppedProRead(ctx context.Context, a d.Authority, id string, s flow.State, recovery bool) (runtimeControlRow, RuntimeStoppedProRecord, error) {
	var row runtimeControlRow
	var record RuntimeStoppedProRecord
	err := o.transaction(ctx, a, recovery, func(tx *sql.Tx) error {
		var err error
		row, err = readRuntimeControl(ctx, tx, a, id)
		if err != nil || row.Spec.Stopped != s || runtimeWriterID(row.Spec) != id || originalRuntimeState(ctx, tx, a, id, s) != nil {
			return ErrExecutionRecord
		}
		if _, err = stoppedProSpec(row.Spec); err != nil {
			return err
		}
		source, err := sourceRow(ctx, tx, row.Spec.Source.ID)
		if err != nil || source != row.Spec.Source {
			return ErrExecutionRecord
		}
		if len(row.Resumed) > 0 && string(row.Resumed) != "null" {
			if json.Unmarshal(row.Resumed, &record) != nil || record.Version != "runtime-current-stopped-pro.v1" {
				return ErrExecutionRecord
			}
		}
		return nil
	})
	return row, record, err
}

// Current API and SQL storage rechecks run through the deployment-owned source
// material reader outside SQL locks. It also rechecks the observer file pins.
func (o *SQLRuntimeControl) stoppedProCurrent(ctx context.Context, a d.Authority, row runtimeControlRow) (q.StoppedProBaseline, error) {
	baseline, err := stoppedProSpec(row.Spec)
	if err != nil || o.cfg.StoppedProObserver == nil || o.cfg.StoppedProBaseline == nil {
		return baseline, ErrExecutionRecord
	}
	current, err := o.cfg.StoppedProBaseline(ctx, a, row.Spec.Source)
	if err != nil || !reflect.DeepEqual(current, baseline) {
		return baseline, ErrExecutionRecord
	}
	return baseline, nil
}

func (o *SQLRuntimeControl) stoppedProRequest(ctx context.Context, a d.Authority, row runtimeControlRow, baseline q.StoppedProBaseline) (q.StoppedProNodeObservationRequest, error) {
	var request q.StoppedProNodeObservationRequest
	if len(baseline.Volumes) == 0 {
		return request, ErrExecutionRecord
	}
	nodeUID := baseline.Volumes[0].DataNodeUID
	for _, v := range baseline.Volumes {
		if v.DataNodeUID != nodeUID {
			return request, ErrExecutionRecord
		}
	}
	nodes, err := o.cfg.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return request, ErrExecutionRecord
	}
	name := ""
	for _, node := range nodes.Items {
		if string(node.UID) == nodeUID {
			if name != "" || node.DeletionTimestamp != nil {
				return request, ErrExecutionRecord
			}
			name = node.Name
		}
	}
	if name == "" {
		return request, ErrExecutionRecord
	}
	err = o.transaction(ctx, a, false, func(tx *sql.Tx) error {
		var generation, acquire uint64
		var registry string
		var writers []byte
		var until time.Time
		if tx.QueryRowContext(ctx, `SELECT gate_generation,acquire_token,registry_sha256,writers_json,hold_until FROM system_backup_v2_runtime_captures WHERE task_public_id=? AND application_scope=? FOR SHARE`, a.TaskPublicID, o.cfg.Gate.Authority.ApplicationScope).Scan(&generation, &acquire, &registry, &writers, &until) != nil || generation != a.MaintenanceFencingToken || recordHash(writers) != registry || !time.Now().Before(until) {
			return ErrExecutionRecord
		}
		var phase, owner string
		var currentGeneration, currentToken uint64
		if tx.QueryRowContext(ctx, `SELECT phase,COALESCE(owner,''),generation,fencing_token FROM system_backup_gate WHERE scope=? FOR SHARE`, o.cfg.Gate.Authority.ApplicationScope).Scan(&phase, &owner, &currentGeneration, &currentToken) != nil || phase != "acquiring" || owner != a.TaskPublicID || currentGeneration != generation || currentToken != acquire {
			return ErrExecutionRecord
		}
		raw, _ := json.Marshal(struct {
			Authority                        d.Authority
			GateGeneration, AcquisitionToken uint64
			Registry                         string
			Baseline                         q.StoppedProBaseline
			Until                            time.Time
		}{a, generation, acquire, registry, baseline, until})
		reservation := recordHash(raw)
		request = q.StoppedProNodeObservationRequest{Action: "prepare", Baseline: baseline, OriginalReservationIdentitySHA256: reservation, OriginalStateSHA256: q.StoppedProOriginalStateSHA256(row.Spec.Stopped), Binding: q.ObservationBinding{
			Kind: q.StoppedProObservationProtocol, InstallationID: a.InstallationID, OperationID: a.TaskPublicID, ReservationID: reservation, InventorySHA256: registry,
			Namespace: o.cfg.Namespace, NamespaceUID: baseline.NamespaceUID, Node: name, NodeUID: nodeUID, Generation: uint64(row.Spec.Source.Generation), FenceEpoch: acquire, ExpiresAt: until.UTC().Truncate(time.Microsecond),
		}}
		request.NativeScopeSHA256 = q.StoppedProNativeScopeSHA256(request)
		return nil
	})
	return request, err
}

func (o *SQLRuntimeControl) stoppedProObserve(ctx context.Context, a d.Authority, row runtimeControlRow, record RuntimeStoppedProRecord, phase string) (*q.VerifiedStoppedProNodeObservation, error) {
	if _, err := o.stoppedProCurrent(ctx, a, row); err != nil {
		return nil, err
	}
	request := record.Request
	request.Action = phase
	if phase != "prepare" {
		request.Anchor = record.Prepare.Anchor
	}
	proof, err := o.cfg.StoppedProObserver.ObserveWriter(ctx, request, row.Spec.Stopped)
	if err != nil || proof == nil {
		return nil, ErrSourceRecoveryStoppedWitnessRequired
	}
	boot := record.Prepare.BootID
	if phase == "prepare" {
		boot = proof.Response().BootID
	}
	if proof.Recheck(ctx, request.Binding, phase, boot, q.StoppedProBaselineSHA256(request.Baseline), request.OriginalReservationIdentitySHA256, request.OriginalStateSHA256, request.NativeScopeSHA256, time.Now()) != nil {
		return nil, ErrSourceRecoveryStoppedWitnessRequired
	}
	if _, err := o.stoppedProCurrent(ctx, a, row); err != nil {
		return nil, err
	}
	return proof, nil
}

func (o *SQLRuntimeControl) stoppedProSave(ctx context.Context, a d.Authority, id string, row runtimeControlRow, record RuntimeStoppedProRecord, proof *q.VerifiedStoppedProNodeObservation, recovery, complete bool) error {
	if proof == nil {
		return ErrExecutionRecord
	}
	return o.transaction(ctx, a, recovery, func(tx *sql.Tx) error {
		actual, err := readRuntimeControl(ctx, tx, a, id)
		if err != nil || actual.Version != row.Version || actual.Spec != row.Spec || actual.Completed != row.Completed || originalRuntimeState(ctx, tx, a, id, row.Spec.Stopped) != nil {
			return ErrExecutionRecord
		}
		current, err := sourceRow(ctx, tx, row.Spec.Source.ID)
		if err != nil || current != row.Spec.Source {
			return ErrExecutionRecord
		}
		var now time.Time
		if tx.QueryRowContext(ctx, `SELECT UTC_TIMESTAMP(6)`).Scan(&now) != nil {
			return ErrExecutionRecord
		}
		phase := proof.Response().Action
		if proof.Recheck(ctx, record.Request.Binding, phase, record.Prepare.BootID, q.StoppedProBaselineSHA256(record.Request.Baseline), record.Request.OriginalReservationIdentitySHA256, record.Request.OriginalStateSHA256, record.Request.NativeScopeSHA256, now) != nil {
			return ErrExecutionRecord
		}
		raw, err := json.Marshal(record)
		if err != nil {
			return err
		}
		stopped := actual.Stopped
		if record.Stopped != nil {
			body, _ := json.Marshal(record.Stopped)
			digest := recordHash(body)
			if stopped.Valid && stopped.String != digest {
				return ErrExecutionRecord
			}
			stopped = sql.NullString{String: digest, Valid: true}
		}
		if complete && (!stopped.Valid || record.Recovered == nil) {
			return ErrExecutionRecord
		}
		result, err := tx.ExecContext(ctx, `UPDATE system_backup_v2_runtime_controls SET resumed_json=?,stopped_sha256=?,restart_completed=?,row_version=row_version+1 WHERE task_public_id=? AND attempt_no=? AND writer_id=? AND row_version=?`, raw, stopped, complete, a.TaskPublicID, a.AttemptNo, id, row.Version)
		if err != nil {
			return err
		}
		ok, err := exactlyOneRow(result)
		if err != nil || !ok {
			return ErrExecutionRecord
		}
		return nil
	})
}

func (o *SQLRuntimeControl) StoppedProControl(ctx context.Context, a d.Authority, id, phase string, s flow.State) error {
	recovery := phase == "recovery-stopped" || phase == "recovered-stopped"
	if phase != "prepare-stopped" && phase != "stopped" && !recovery {
		return ErrExecutionRecord
	}
	row, record, err := o.stoppedProRead(ctx, a, id, s, recovery)
	if err != nil {
		return err
	}
	if phase == "prepare-stopped" {
		if record.Version == "" {
			baseline, err := o.stoppedProCurrent(ctx, a, row)
			if err != nil {
				return err
			}
			request, err := o.stoppedProRequest(ctx, a, row, baseline)
			if err != nil {
				return err
			}
			record = RuntimeStoppedProRecord{Version: "runtime-current-stopped-pro.v1", Request: request}
			proof, err := o.stoppedProObserve(ctx, a, row, record, "prepare")
			if err != nil {
				return err
			}
			record.Prepare = proof.Response()
			if err = o.stoppedProSave(ctx, a, id, row, record, proof, false, false); err != nil {
				return err
			}
			row, record, err = o.stoppedProRead(ctx, a, id, s, false)
			if err != nil {
				return err
			}
		}
		if record.Stopped != nil {
			_, err = o.stoppedProObserve(ctx, a, row, record, "stopped")
			return err
		}
		proof, err := o.stoppedProObserve(ctx, a, row, record, "stopped")
		if err != nil {
			return err
		}
		response := proof.Response()
		record.Stopped = &response
		return o.stoppedProSave(ctx, a, id, row, record, proof, false, false)
	}
	if record.Version == "" || record.Prepare.Anchor == "" {
		return ErrSourceRecoveryStoppedWitnessRequired
	}
	if phase == "recovered-stopped" {
		if _, err = o.stoppedProObserve(ctx, a, row, record, "recovery-stopped"); err != nil {
			return err
		}
		proof, err := o.stoppedProObserve(ctx, a, row, record, phase)
		if err != nil {
			return err
		}
		if row.Completed {
			return nil
		}
		response := proof.Response()
		record.Recovered = &response
		return o.stoppedProSave(ctx, a, id, row, record, proof, true, true)
	}
	_, err = o.stoppedProObserve(ctx, a, row, record, phase)
	return err
}
