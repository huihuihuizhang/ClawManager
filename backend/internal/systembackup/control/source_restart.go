package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"clawreef/internal/systembackup/flow"
)

// SourceBinding is frozen in the encrypted execution plan. Control and source
// schemas must be on the SAME MySQL server so claim, generation reservation and
// binding updates share a transaction. No second connection/fence approximation.
type SourceBinding struct {
	Database, ServerUUID, Mode, PodName, Namespace, PodUID, GatewayID, Workspace string
	InstanceID, UserID, Generation, Port, UsedSlots                              int
	RuntimePodID                                                                 int64
	Deployment                                                                   bool
}
type RestartResult struct {
	PodUID, PodName, PodIP, GatewayID string
	Port                              int
}
type SourceRestarter struct {
	Journal PauseJournal
	Binding SourceBinding
	Writer  string
}

func (r SourceRestarter) valid() bool {
	b := r.Binding
	return sqlName.MatchString(b.Database) && b.ServerUUID != "" && (b.Mode == "lite" || b.Mode == "pro") && b.InstanceID > 0 && b.UserID > 0 && b.Generation > 0 && b.Generation < 2147483647 && r.Writer != "" && (b.Mode != "lite" || (b.RuntimePodID > 0 && b.UsedSlots > 0 && b.Port > 0 && b.Port <= 65535 && b.GatewayID == fmt.Sprintf("gw-%d-%d", b.InstanceID, b.Generation)))
}
func (r SourceRestarter) source(ctx context.Context, tx *sql.Tx, dispatched bool, result []byte) error {
	b := r.Binding
	schema := "`" + b.Database + "`."
	var uuid string
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&uuid) != nil || uuid != b.ServerUUID {
		return ErrFence
	}
	var user, generation int
	var mode, status string
	var pod, namespace sql.NullString
	if tx.QueryRowContext(ctx, "SELECT user_id,runtime_generation,instance_mode,status,pod_name,pod_namespace FROM "+schema+"instances WHERE id=? FOR UPDATE", b.InstanceID).Scan(&user, &generation, &mode, &status, &pod, &namespace) != nil {
		return ErrConflict
	}
	expected := b.Generation
	if dispatched {
		expected++
	}
	var completed RestartResult
	if len(result) > 0 && json.Unmarshal(result, &completed) != nil {
		return ErrConflict
	}
	expectedPod := b.PodName
	if completed.PodName != "" {
		expectedPod = completed.PodName
	}
	if user != b.UserID || generation != expected || mode != b.Mode || status != "running" || pod.String != expectedPod || namespace.String != b.Namespace {
		return ErrConflict
	}
	if b.Mode == "lite" {
		var podID int64
		var gateway, path, state string
		var port, bindingGeneration int
		if tx.QueryRowContext(ctx, "SELECT runtime_pod_id,gateway_id,gateway_port,workspace_path,state,generation FROM "+schema+"instance_runtime_bindings WHERE instance_id=? FOR UPDATE", b.InstanceID).Scan(&podID, &gateway, &port, &path, &state, &bindingGeneration) != nil {
			return ErrConflict
		}
		expectedGateway, expectedGeneration := b.GatewayID, b.Generation
		if len(result) > 0 {
			expectedGateway = fmt.Sprintf("gw-%d-%d", b.InstanceID, b.Generation+1)
			expectedGeneration++
		}
		if podID != b.RuntimePodID || gateway != expectedGateway || port != b.Port || path != b.Workspace || state != "running" || bindingGeneration != expectedGeneration {
			return ErrConflict
		}
		var uid string
		var slots int
		if tx.QueryRowContext(ctx, "SELECT pod_uid,used_slots FROM "+schema+"runtime_pods WHERE id=? FOR UPDATE", b.RuntimePodID).Scan(&uid, &slots) != nil || uid != b.PodUID || slots != b.UsedSlots {
			return ErrConflict
		}
	}
	return nil
}
func (r SourceRestarter) paused(ctx context.Context, tx *sql.Tx, state flow.State) (bool, []byte, error) {
	var raw, result []byte
	var sent bool
	var active int
	if tx.QueryRowContext(ctx, "SELECT "+pendingWorkersSQL, r.Journal.Task.ID, r.Journal.Task.ID).Scan(&active) != nil || active != 0 {
		return false, nil, ErrNotReady
	}
	if tx.QueryRowContext(ctx, "SELECT original_json,restart_dispatched,restart_result FROM system_backup_pauses WHERE task_id=? AND writer_id=? FOR UPDATE", r.Journal.Task.ID, r.Writer).Scan(&raw, &sent, &result) != nil {
		return false, nil, ErrNotReady
	}
	var original flow.State
	if json.Unmarshal(raw, &original) != nil || original != state {
		return false, nil, ErrConflict
	}
	return sent, result, nil
}
func (r SourceRestarter) Claim(ctx context.Context, state flow.State) (bool, error) {
	if !r.valid() || !state.Running {
		return false, ErrInvalid
	}
	claimed := false
	e := r.Journal.transaction(ctx, r.Journal.Identity, true, func(tx *sql.Tx) error {
		sent, result, e := r.paused(ctx, tx, state)
		if e != nil {
			return e
		}
		if e = r.source(ctx, tx, sent, result); e != nil {
			return e
		}
		if sent {
			return nil
		}
		b := r.Binding
		if e = changed(tx.ExecContext(ctx, "UPDATE `"+b.Database+"`.instances SET runtime_generation=?,updated_at=UTC_TIMESTAMP(6) WHERE id=? AND runtime_generation=?", b.Generation+1, b.InstanceID, b.Generation)); e != nil {
			return e
		}
		if e = changed(tx.ExecContext(ctx, "UPDATE system_backup_pauses SET restart_dispatched=TRUE WHERE task_id=? AND writer_id=? AND restart_dispatched=FALSE", r.Journal.Task.ID, r.Writer)); e != nil {
			return e
		}
		claimed = true
		return nil
	})
	return claimed && e == nil, e
}
func (r SourceRestarter) Complete(ctx context.Context, state flow.State, result RestartResult) error {
	if !r.valid() || !state.Running {
		return ErrInvalid
	}
	b := r.Binding
	if (b.Mode == "lite" && (result.GatewayID != fmt.Sprintf("gw-%d-%d", b.InstanceID, b.Generation+1) || result.Port != b.Port || result.PodUID != b.PodUID)) || (b.Mode == "pro" && (result.PodUID == "" || (!b.Deployment && result.PodUID == b.PodUID) || result.PodName == "" || result.GatewayID != "")) {
		return ErrConflict
	}
	raw, _ := json.Marshal(result)
	return r.Journal.transaction(ctx, r.Journal.Identity, true, func(tx *sql.Tx) error {
		sent, previous, e := r.paused(ctx, tx, state)
		if e != nil || !sent {
			return ErrFence
		}
		if e = r.source(ctx, tx, true, previous); e != nil {
			return e
		}
		if len(previous) > 0 {
			if string(previous) != string(raw) {
				return ErrConflict
			}
			return nil
		}
		if b.Mode == "lite" {
			e = changed(tx.ExecContext(ctx, "UPDATE `"+b.Database+"`.instance_runtime_bindings SET gateway_id=?,generation=?,gateway_pid=NULL,last_health_at=UTC_TIMESTAMP(6),error_message=NULL,updated_at=UTC_TIMESTAMP(6) WHERE instance_id=? AND generation=? AND runtime_pod_id=?", result.GatewayID, b.Generation+1, b.InstanceID, b.Generation, b.RuntimePodID))
		} else {
			_, e = tx.ExecContext(ctx, "UPDATE `"+b.Database+"`.instances SET pod_name=?,pod_ip=?,updated_at=UTC_TIMESTAMP(6) WHERE id=? AND runtime_generation=?", result.PodName, result.PodIP, b.InstanceID, b.Generation+1)
		}
		if e != nil {
			return ErrNotReady
		}
		return changed(tx.ExecContext(ctx, "UPDATE system_backup_pauses SET restart_result=? WHERE task_id=? AND writer_id=? AND restart_dispatched=TRUE AND restart_result IS NULL", raw, r.Journal.Task.ID, r.Writer))
	})
}

// Guard proves source identity and the exclusive maintenance barrier. Recovery
// additionally requires the original pause and completed collector cleanup.
func (r SourceRestarter) Guard(ctx context.Context, recovery bool, state flow.State) error {
	if !r.valid() {
		return ErrInvalid
	}
	return r.Journal.transaction(ctx, r.Journal.Identity, recovery, func(tx *sql.Tx) error {
		if !recovery {
			return r.source(ctx, tx, false, nil)
		}
		sent, result, e := r.paused(ctx, tx, state)
		if e != nil {
			return e
		}
		return r.source(ctx, tx, sent, result)
	})
}
