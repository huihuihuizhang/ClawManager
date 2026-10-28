package control

import (
	"context"
	"encoding/json"
	"sort"

	"clawreef/internal/systembackup/quiesce"
	corev1 "k8s.io/api/core/v1"
)

// AppProcess identifies a single container incarnation, not a reusable Pod name.
// Records survive restarts; no lease expiry implies that a writer has exited.
type AppProcess struct {
	ID, Namespace, NodeUID, ImageID string
	Pod                             quiesce.PodIdentity
}
type ProcessGate struct {
	Store   SQLStore
	Process AppProcess
}

func (g ProcessGate) Enter(ctx context.Context, name string) (func() error, error) {
	if !g.Process.valid() {
		return nil, ErrInvalid
	}
	return g.Store.enter(ctx, name, g.Process.ID)
}
func (p AppProcess) valid() bool {
	return identifier.MatchString(p.ID) && p.Namespace != "" && p.NodeUID != "" && p.ImageID != "" && p.Pod.UID != "" && p.Pod.Node != "" && p.Pod.Name != "" && len(p.Pod.Containers) == 1 && p.Pod.Containers[0] != ""
}

// IdentifyApplication requires the observed running container. Call before any
// application migration or background worker starts. A restarted container gets
// a new ID even when Kubernetes reuses the Pod UID.
func IdentifyApplication(pod *corev1.Pod, node *corev1.Node, container string) (AppProcess, error) {
	if pod == nil || node == nil || pod.DeletionTimestamp != nil || pod.Spec.NodeName != node.Name || node.UID == "" {
		return AppProcess{}, ErrNotReady
	}
	for _, s := range pod.Status.ContainerStatuses {
		if s.Name != container {
			continue
		}
		if s.State.Running == nil || s.ContainerID == "" || s.ImageID == "" {
			return AppProcess{}, ErrNotReady
		}
		id, e := NewID()
		if e != nil {
			return AppProcess{}, e
		}
		p := AppProcess{ID: id, Namespace: pod.Namespace, NodeUID: string(node.UID), ImageID: s.ImageID, Pod: quiesce.PodIdentity{Name: pod.Name, UID: string(pod.UID), Node: node.Name, Containers: []string{s.ContainerID}}}
		if !p.valid() {
			return AppProcess{}, ErrInvalid
		}
		return p, nil
	}
	return AppProcess{}, ErrNotReady
}
func (s SQLStore) RegisterApplication(ctx context.Context, p AppProcess) error {
	if !p.valid() {
		return ErrInvalid
	}
	raw, _ := json.Marshal(p)
	tx, e := s.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var closed bool
	if tx.QueryRowContext(ctx, "SELECT closed FROM system_backup_maintenance WHERE id=1 FOR UPDATE").Scan(&closed) != nil {
		return ErrNotReady
	}
	if closed {
		return ErrConflict
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO system_backup_app_processes(process_id,identity_json,revoked,created_at_ms) VALUES(?,?,FALSE,"+dbNow+")", p.ID, raw); e != nil || tx.Commit() != nil {
		return ErrNotReady
	}
	return nil
}
func (s SQLStore) Applications(ctx context.Context) ([]AppProcess, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT process_id,identity_json FROM system_backup_app_processes WHERE revoked=FALSE ORDER BY process_id")
	if e != nil {
		return nil, ErrNotReady
	}
	defer rows.Close()
	var out []AppProcess
	for rows.Next() {
		var id string
		var raw []byte
		var p AppProcess
		if rows.Scan(&id, &raw) != nil || json.Unmarshal(raw, &p) != nil || !p.valid() || id != p.ID || len(out) >= 10000 {
			return nil, ErrNotReady
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

type MutationPermit struct{ Token, Participant, Process string }

func (s SQLStore) PendingMutations(ctx context.Context) ([]MutationPermit, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT token,participant,process_id FROM system_backup_mutations ORDER BY token")
	if e != nil {
		return nil, ErrNotReady
	}
	defer rows.Close()
	var out []MutationPermit
	for rows.Next() {
		var p MutationPermit
		if rows.Scan(&p.Token, &p.Participant, &p.Process) != nil || len(out) >= 10000 {
			return nil, ErrNotReady
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ResolveApplication requires BOTH positive CRI termination and independent
// completion of remote effects (SQL sessions, remote requests, child jobs).
// The gate is locked closed for the entire proof/commit interval. Unknown legacy
// permits remain blocking; neither TTL nor a missing Pod is evidence.
func (s SQLStore) ResolveApplication(ctx context.Context, t Task, p AppProcess, proof func(context.Context, AppProcess, []MutationPermit) error) error {
	if !p.valid() || proof == nil {
		return ErrInvalid
	}
	tx, e := s.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if s.Fence(ctx, tx, t) != nil {
		return ErrFence
	}
	var owner string
	var closed bool
	if tx.QueryRowContext(ctx, "SELECT task_id,closed FROM system_backup_maintenance WHERE id=1 FOR UPDATE").Scan(&owner, &closed) != nil || !closed || owner != t.ID {
		return ErrFence
	}
	var raw []byte
	var revoked bool
	if tx.QueryRowContext(ctx, "SELECT identity_json,revoked FROM system_backup_app_processes WHERE process_id=? FOR UPDATE", p.ID).Scan(&raw, &revoked) != nil {
		return ErrNotReady
	}
	expected, _ := json.Marshal(p)
	if string(expected) != string(raw) {
		return ErrConflict
	}
	if revoked {
		return nil
	}
	rows, e := tx.QueryContext(ctx, "SELECT token,participant,process_id FROM system_backup_mutations WHERE process_id=? ORDER BY token FOR UPDATE", p.ID)
	if e != nil {
		return ErrNotReady
	}
	var permits []MutationPermit
	for rows.Next() {
		var v MutationPermit
		if rows.Scan(&v.Token, &v.Participant, &v.Process) != nil || v.Process != p.ID || len(permits) >= 10000 {
			rows.Close()
			return ErrNotReady
		}
		permits = append(permits, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return ErrNotReady
	}
	sort.Slice(permits, func(i, j int) bool { return permits[i].Token < permits[j].Token })
	if e = proof(ctx, p, permits); e != nil {
		return ErrNotReady
	}
	if s.Fence(ctx, tx, t) != nil {
		return ErrFence
	}
	if _, e = tx.ExecContext(ctx, "UPDATE system_backup_app_processes SET revoked=TRUE WHERE process_id=? AND revoked=FALSE", p.ID); e != nil {
		return ErrNotReady
	}
	evidence, _ := json.Marshal(permits)
	if _, e = tx.ExecContext(ctx, "INSERT INTO system_backup_mutation_resolutions(task_id,process_id,permits_json,resolved_at_ms) VALUES(?,?,?,"+dbNow+")", t.ID, p.ID, evidence); e != nil {
		return ErrNotReady
	}
	if _, e = tx.ExecContext(ctx, "DELETE FROM system_backup_mutations WHERE process_id=?", p.ID); e != nil || tx.Commit() != nil {
		return ErrNotReady
	}
	return nil
}
