package systembackupexecution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
)

type observedSourceRuntimeBinding struct {
	Instance, RuntimePod, Generation, Port, PID int
	Gateway, Workspace, State                   string
}
type observedSourceRuntimePod struct {
	ID                                                int
	UID, Name, Namespace, Endpoint, Deployment, State string
	Draining                                          bool
}
type observedSourceWriterRegistry struct {
	bindings     []observedSourceRuntimeBinding
	pods         []observedSourceRuntimePod
	participants []string
	sha256       string
}

func (x *sourceSQLObservation) observeWriterRegistry(ctx context.Context) (*observedSourceWriterRegistry, error) {
	if x.recheck(ctx) != nil {
		return nil, ErrSourceWriterObservationIncomplete
	}
	tx, err := x.source.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, ErrSourceWriterObservationIncomplete
	}
	defer tx.Rollback()
	if x.delegation.service.checkSourceIdentity(ctx, tx) != nil {
		return nil, ErrSourceWriterObservationIncomplete
	}
	out := &observedSourceWriterRegistry{bindings: []observedSourceRuntimeBinding{}, pods: []observedSourceRuntimePod{}, participants: []string{}}
	rows, err := tx.QueryContext(ctx, `SELECT instance_id,COALESCE(runtime_pod_id,0),COALESCE(generation,0),COALESCE(gateway_port,0),COALESCE(gateway_pid,0),COALESCE(gateway_id,''),COALESCE(workspace_path,''),state FROM instance_runtime_bindings ORDER BY instance_id`)
	if err != nil {
		return nil, ErrSourceWriterObservationIncomplete
	}
	for rows.Next() {
		var row observedSourceRuntimeBinding
		if ctx.Err() != nil || len(out.bindings) >= 10000 || rows.Scan(&row.Instance, &row.RuntimePod, &row.Generation, &row.Port, &row.PID, &row.Gateway, &row.Workspace, &row.State) != nil || row.Instance <= 0 || (len(out.bindings) > 0 && out.bindings[len(out.bindings)-1].Instance >= row.Instance) {
			rows.Close()
			return nil, ErrSourceWriterObservationIncomplete
		}
		out.bindings = append(out.bindings, row)
	}
	if errors.Join(rows.Err(), rows.Close()) != nil {
		return nil, ErrSourceWriterObservationIncomplete
	}
	rows, err = tx.QueryContext(ctx, `SELECT id,COALESCE(pod_uid,''),pod_name,namespace,COALESCE(agent_endpoint,''),deployment_name,state,draining FROM runtime_pods ORDER BY id`)
	if err != nil {
		return nil, ErrSourceWriterObservationIncomplete
	}
	for rows.Next() {
		var row observedSourceRuntimePod
		if ctx.Err() != nil || len(out.pods) >= 10000 || rows.Scan(&row.ID, &row.UID, &row.Name, &row.Namespace, &row.Endpoint, &row.Deployment, &row.State, &row.Draining) != nil || row.ID <= 0 || (len(out.pods) > 0 && out.pods[len(out.pods)-1].ID >= row.ID) {
			rows.Close()
			return nil, ErrSourceWriterObservationIncomplete
		}
		out.pods = append(out.pods, row)
	}
	if errors.Join(rows.Err(), rows.Close()) != nil || x.delegation.service.checkSourceIdentity(ctx, tx) != nil || tx.Commit() != nil || x.recheck(ctx) != nil {
		return nil, ErrSourceWriterObservationIncomplete
	}
	// Participant registry belongs to control SQL, not the source reader role.
	control, err := x.control.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, ErrSourceWriterObservationIncomplete
	}
	defer control.Rollback()
	rows, err = control.QueryContext(ctx, "SELECT participant_id FROM system_backup_participants WHERE scope=? ORDER BY participant_id", x.delegation.service.Config.ApplicationScope)
	if err != nil {
		return nil, ErrSourceWriterObservationIncomplete
	}
	seenParticipants := map[string]bool{}
	for rows.Next() {
		var id string
		if ctx.Err() != nil || len(out.participants) >= 10000 || rows.Scan(&id) != nil || id == "" || len(id) > 128 || seenParticipants[id] {
			rows.Close()
			return nil, ErrSourceWriterObservationIncomplete
		}
		seenParticipants[id] = true
		out.participants = append(out.participants, id)
	}
	if errors.Join(rows.Err(), rows.Close()) != nil || control.Commit() != nil || x.recheck(ctx) != nil {
		return nil, ErrSourceWriterObservationIncomplete
	}
	want := append([]string{}, x.delegation.service.Config.RuntimeSources.LeaseParticipants...)
	sort.Strings(want)
	sort.Strings(out.participants)
	if len(want) != len(out.participants) {
		return nil, ErrSourceWriterObservationIncomplete
	}
	for i := range want {
		if want[i] != out.participants[i] {
			return nil, ErrSourceWriterObservationIncomplete
		}
	}
	raw, err := json.Marshal(struct {
		Bindings     []observedSourceRuntimeBinding
		Pods         []observedSourceRuntimePod
		Participants []string
	}{out.bindings, out.pods, out.participants})
	if err != nil || len(raw) > 8<<20 {
		return nil, ErrSourceWriterObservationIncomplete
	}
	out.sha256 = hash(raw)
	return out, nil
}
