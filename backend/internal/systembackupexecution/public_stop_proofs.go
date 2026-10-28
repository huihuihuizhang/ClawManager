package systembackupexecution

import (
	"clawreef/internal/systembackup/quiesce"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

type SQLStopProofs struct {
	Gate      c.SQLCaptureGate
	Authority d.Authority
}

func (s SQLStopProofs) Save(ctx context.Context, p quiesce.ExitWitness) error {
	if p.PodUID == "" || p.NodeUID == "" || p.ResourceVersion == "" || len(p.Containers) == 0 {
		return c.ErrExecutionRecord
	}
	raw := quiesce.WitnessBytes(p)
	if len(raw) > 65536 {
		return c.ErrExecutionRecord
	}
	tx, e := s.Gate.Authority.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = s.Gate.Recovery.CheckTx(ctx, tx, s.Authority); e != nil {
		return e
	}
	var old []byte
	var digest string
	e = tx.QueryRowContext(ctx, "SELECT proof_json,proof_sha256 FROM system_backup_v2_runtime_stop_proofs WHERE task_public_id=? AND pod_uid=? FOR SHARE", s.Authority.TaskPublicID, p.PodUID).Scan(&old, &digest)
	if e == nil {
		var original quiesce.ExitWitness
		if json.Unmarshal(old, &original) != nil || hash(old) != digest || !quiesce.SameExitWitness(original, p) {
			return c.ErrExecutionRecord
		}
		return nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO system_backup_v2_runtime_stop_proofs(task_public_id,pod_uid,proof_json,proof_sha256) VALUES(?,?,?,?)", s.Authority.TaskPublicID, p.PodUID, raw, hash(raw)); e != nil {
		return e
	}
	if e = s.Gate.Recovery.CheckTx(ctx, tx, s.Authority); e != nil {
		return e
	}
	return tx.Commit()
}
func (s SQLStopProofs) Load(ctx context.Context, pod string) (quiesce.ExitWitness, error) {
	var p quiesce.ExitWitness
	if e := s.Gate.Recovery.Check(ctx, s.Authority); e != nil {
		return p, e
	}
	var raw []byte
	var digest string
	e := s.Gate.Authority.DB.QueryRowContext(ctx, "SELECT proof_json,proof_sha256 FROM system_backup_v2_runtime_stop_proofs WHERE task_public_id=? AND pod_uid=?", s.Authority.TaskPublicID, pod).Scan(&raw, &digest)
	if e != nil {
		return p, e
	}
	if len(raw) > 65536 || hash(raw) != digest || json.Unmarshal(raw, &p) != nil || p.PodUID != pod {
		return p, c.ErrExecutionRecord
	}
	return p, nil
}
func (o *PublicJobOwner) StopWitness(a d.Authority) quiesce.KubeletStopWitness {
	return o.StopWitnessIn(a, o.Namespace)
}
func (o *PublicJobOwner) StopWitnessIn(a d.Authority, namespace string) quiesce.KubeletStopWitness {
	return quiesce.KubeletStopWitness{Client: o.Client, Watches: o.WatchClient, Namespace: namespace, NodeUIDs: o.Security.NodeUIDs, Store: SQLStopProofs{Gate: o.Gate, Authority: a}, Timeout: 2 * time.Minute}
}
