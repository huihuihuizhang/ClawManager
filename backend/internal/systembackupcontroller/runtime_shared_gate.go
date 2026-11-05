package systembackupcontroller

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"time"

	app "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/domain"
	q "clawreef/internal/systembackup/quiesce"
	d "clawreef/internal/systembackupdispatch"
)

// The concrete frame contains only real opaque native-client observations.
// It is created outside the SQL lock; verification performs SQL/local reads
// only in the SAME common held transition, never native network I/O.
type runtimeSharedHoldVerifier struct {
	owner     *SQLRuntimeControl
	authority d.Authority
	frame     *runtimeSharedHeldFrame
}

func (v *runtimeSharedHoldVerifier) VerifyNativeCaptureHeld(ctx context.Context, tx *sql.Tx) error {
	if v == nil || v.owner == nil || v.frame == nil || tx == nil {
		return ErrExecutionRecord
	}
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil {
		return ErrExecutionRecord
	}
	if err := v.frame.recheck(ctx, now); err != nil {
		return err
	}
	sources, err := domain.ReadSourceInstances(ctx, tx)
	if err == nil {
		sources, err = v.owner.cfg.RuntimeTestScope.RuntimeInstances(sources)
	}
	if err != nil || !bytes.Equal(mustSharedJSON(sources), mustSharedJSON(v.frame.book.Definition.Sources)) {
		return ErrExecutionRecord
	}
	var raw []byte
	var digest string
	if tx.QueryRowContext(ctx, `SELECT proof_json,proof_sha256 FROM system_backup_v2_runtime_stop_proofs WHERE task_public_id=? AND pod_uid LIKE ? ORDER BY pod_uid DESC LIMIT 1 FOR SHARE`, v.authority.TaskPublicID, sharedTaskKey(v.authority)).Scan(&raw, &digest) != nil || recordHash(raw) != digest {
		return ErrExecutionRecord
	}
	var current runtimeSharedBook
	if json.Unmarshal(raw, &current) != nil || !bytes.Equal(mustSharedJSON(current.Definition), mustSharedJSON(v.frame.book.Definition)) {
		return ErrExecutionRecord
	}
	for _, actor := range current.Actors {
		if actor.Request.Binding.Generation != v.authority.MaintenanceFencingToken || actor.Request.Binding.OperationID != v.authority.TaskPublicID {
			return ErrExecutionRecord
		}
	}
	return nil
}

// Returned only by the actual production RuntimeControl. Existing participants,
// task state, SQL/object admission and recovery remain on the original gate.
func (o *SQLRuntimeControl) SharedCaptureGate() SQLCaptureGate {
	g := o.cfg.Gate
	if o.cfg.Shared != nil {
		g.sharedNative = o
		o.cfg.Gate.sharedNative = o
	}
	return g
}

func (g SQLCaptureGate) holdSharedNative(ctx context.Context, a d.Authority, claim app.VersionedGateClaim, ownership app.GateOwnership) (app.GateOwnership, error) {
	if g.sharedNative == nil {
		return (app.Gate{DB: g.Authority.DB}).HoldVersionedCapture(ctx, claim, ownership)
	}
	frame, err := g.sharedNative.sharedCheckAll(ctx, a)
	if err != nil {
		return ownership, err
	}
	verifier := &runtimeSharedHoldVerifier{owner: g.sharedNative, authority: a, frame: frame}
	return (app.Gate{DB: g.Authority.DB}).HoldVersionedCaptureNative(ctx, claim, ownership, verifier)
}

func (o *SQLRuntimeControl) sharedRecoveryFrame(ctx context.Context, a d.Authority) (*runtimeSharedHeldFrame, error) {
	book, _, err := o.readSharedTaskBook(ctx, a, true)
	if err != nil || book.Stage != "all-recovered" {
		return nil, ErrExecutionRecoveryRequired
	}
	frame := &runtimeSharedHeldFrame{book: book}
	for i, actor := range book.Actors {
		// Untouched/unknown actors require a separate current native witness;
		// an absent record or original SQL error is never a recovery proof.
		if actor.Agent == nil || actor.Request.Anchor == "" || actor.Last == nil || actor.Last.Phase != "completed" {
			return nil, ErrExecutionRecoveryRequired
		}
		proof, err := o.sharedNodeCall(ctx, a, i, "complete", true)
		if err != nil || proof.Response().Action != "complete" || proof.Response().Phase != "completed" {
			return nil, ErrExecutionRecoveryRequired
		}
		frame.proofs = append(frame.proofs, proof)
	}
	return frame, nil
}

func (frame *runtimeSharedHeldFrame) verifyRecoveryTx(ctx context.Context, tx *sql.Tx) error {
	if frame == nil || tx == nil || len(frame.proofs) == 0 || len(frame.proofs) != len(frame.book.Actors) {
		return ErrExecutionRecoveryRequired
	}
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil {
		return ErrExecutionRecord
	}
	for i, proof := range frame.proofs {
		r := frame.book.Actors[i].Request
		if proof.Recheck(ctx, r.Binding, "complete", r.Original.BootID, r.Original.OriginalSHA256, r.Anchor, q.SharedRuntimeNodeCohortSHA(r), q.SharedRuntimeNodeSourcePathsSHA(r), now) != nil {
			return ErrExecutionRecoveryRequired
		}
	}
	for _, source := range frame.book.Definition.Sources {
		if source.Mode != "lite" {
			continue
		}
		actual, err := sourceRow(ctx, tx, source.ID)
		if err != nil || actual != source {
			return ErrExecutionRecord
		}
	}
	return nil
}
