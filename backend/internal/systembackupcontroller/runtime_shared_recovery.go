package systembackupcontroller

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	q "clawreef/internal/systembackup/quiesce"
	d "clawreef/internal/systembackupdispatch"
)

const sharedTaskRecoveryScope = "original_shared_container_source_recovered"

type runtimeSharedRecoveryTranscript struct {
	Request  q.SharedRuntimeNodeRequest
	Response q.SharedRuntimeNodeResponse
}
type RuntimeSharedRecoveryFacts struct {
	Version    string
	Original   b.FrozenWriter
	Definition runtimeSharedDefinition
	Spec       *b.RuntimeWriterSpec
	Sources    []b.InstanceIdentity
	Native     []runtimeSharedRecoveryTranscript
}

// The actual page-source observer calls this branch before legacy v1 gateway
// recovery. It acquires NEW actual native complete observations; SQL/history
// JSON alone cannot manufacture a source-recovered observation.
func (o *SQLRuntimeControl) ObserveSharedTaskSourceRecovery(ctx context.Context, in d.Input, writer b.FrozenWriter) (SourceRecoveryObservation, bool, error) {
	var out SourceRecoveryObservation
	if o == nil || o.cfg.Shared == nil {
		return out, false, nil
	}
	book, _, err := o.readSharedTaskBook(ctx, in.Authority, true)
	if err != nil {
		return out, true, err
	}
	var spec *b.RuntimeWriterSpec
	if !strings.HasPrefix(writer.ID, "shared-agent/") {
		err = o.transaction(ctx, in.Authority, true, func(tx *sql.Tx) error {
			row, err := readRuntimeControl(ctx, tx, in.Authority, writer.ID)
			if err != nil {
				return err
			}
			if row.Spec.Kind == "shared" {
				value := row.Spec
				spec = &value
				if !row.Completed || value.Stopped != writer.Original || originalRuntimeState(ctx, tx, in.Authority, writer.ID, writer.Original) != nil {
					return ErrSourceRecoveryProofRequired
				}
			}
			return nil
		})
		if err != nil {
			return out, true, err
		}
		if spec == nil {
			return out, false, nil
		}
	} else {
		found := false
		for _, g := range book.Definition.Groups {
			if len(g.Members) == 0 && writer.ID == "shared-agent/"+g.Key && writer.Original.UID == g.Key && writer.Original.Generation == g.Generation && writer.Original.Running && writer.Original.Checkpoint == recordHash(mustSharedJSON(g)) {
				found = true
			}
		}
		if !found {
			return out, true, ErrSourceRecoveryProofRequired
		}
	}
	frame, err := o.sharedRecoveryFrame(ctx, in.Authority)
	if err != nil {
		return out, true, err
	}
	facts := RuntimeSharedRecoveryFacts{Version: "source-recovery-shared-runtime.v1", Original: writer, Definition: frame.book.Definition, Spec: spec, Native: []runtimeSharedRecoveryTranscript{}}
	for _, proof := range frame.proofs {
		facts.Native = append(facts.Native, runtimeSharedRecoveryTranscript{proof.Request(), proof.Response()})
	}
	err = o.transaction(ctx, in.Authority, true, func(tx *sql.Tx) error {
		if err := frame.verifyRecoveryTx(ctx, tx); err != nil {
			return err
		}
		for _, source := range book.Definition.Sources {
			if source.Mode != "lite" {
				continue
			}
			actual, err := sourceRow(ctx, tx, source.ID)
			if err != nil || actual != source {
				return ErrSourceRecoveryProofRequired
			}
			facts.Sources = append(facts.Sources, actual)
		}
		return nil
	})
	if err != nil {
		return out, true, err
	}
	fullRaw := mustSharedJSON(facts)
	if len(fullRaw) > 65535 {
		return out, true, ErrSourceRecoveryProofRequired
	}
	digest := recordHash(fullRaw)
	key := "shared-task.v1/" + strconv.FormatUint(in.Authority.AttemptNo, 10) + "/recovery/" + digest
	err = o.transaction(ctx, in.Authority, true, func(tx *sql.Tx) error {
		var old []byte
		var oldSHA string
		err := tx.QueryRowContext(ctx, `SELECT proof_json,proof_sha256 FROM system_backup_v2_runtime_stop_proofs WHERE task_public_id=? AND pod_uid=? FOR UPDATE`, in.Authority.TaskPublicID, key).Scan(&old, &oldSHA)
		if err == nil {
			if oldSHA != digest || !bytes.Equal(old, fullRaw) {
				return ErrExecutionRecord
			}
			return nil
		}
		if err != sql.ErrNoRows {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO system_backup_v2_runtime_stop_proofs(task_public_id,pod_uid,proof_json,proof_sha256) VALUES(?,?,?,?)`, in.Authority.TaskPublicID, key, fullRaw, digest)
		return err
	})
	if err != nil {
		return out, true, err
	}
	summary := runtimeSharedRecoverySummary{Version: "source-recovery-shared-runtime-ref.v1", Original: writer, Spec: spec, DefinitionSHA256: recordHash(mustSharedJSON(facts.Definition)), PayloadSHA256: digest}
	out = SourceRecoveryObservation{WriterID: writer.ID, OriginalSHA256: recordHash(mustSharedJSON(writer.Original)), Scope: sharedTaskRecoveryScope, Facts: mustSharedJSON(summary), References: []SourceRecoverySQLReference{{Kind: "runtime_stop", Identity: key, SHA256: digest}}}
	return out, true, nil
}

// Pure historical verification of real observer transcripts, bound to the
// authenticated original plan and immutable original SQL journal reference.
// Does not create/renew native scope or extend the original capture window.
func validateFullSharedTaskRecoveryLeaf(a d.Authority, writer b.FrozenWriter, leaf sourceRecoveryLeaf, instances map[int]b.InstanceIdentity) error {
	var facts RuntimeSharedRecoveryFacts
	if json.Unmarshal(leaf.Facts, &facts) != nil || facts.Version != "source-recovery-shared-runtime.v1" || facts.Original != writer || facts.Definition.Task != a.TaskPublicID || facts.Definition.Attempt != a.AttemptNo || len(facts.Native) == 0 || len(facts.Native) != len(facts.Definition.Groups) {
		return ErrSourceRecoveryProofRequired
	}
	for i, transcript := range facts.Native {
		r, response := transcript.Request, transcript.Response
		g := facts.Definition.Groups[i]
		if r.Action != "complete" || response.Action != "complete" || response.Phase != "completed" || response.RequestSHA256 != q.SharedRuntimeNodeRequestSHA256(r) || r.Binding.OperationID != a.TaskPublicID || r.Binding.ReservationID != g.OperationID || r.Binding.Generation != a.MaintenanceFencingToken || r.Binding.InventorySHA256 != facts.Definition.InventorySHA256 || r.AgentPod.UID != g.Pod.UID || r.Current == nil || r.Current.Phase != "completed" || r.Current.OriginalSHA256 != r.Original.OriginalSHA256 || response.OriginalSHA256 != r.Original.OriginalSHA256 || response.BootID != r.Original.BootID || response.Anchor != r.Anchor || response.CohortSHA256 != q.SharedRuntimeNodeCohortSHA(r) || response.SourcePathsSHA256 != q.SharedRuntimeNodeSourcePathsSHA(r) || !bytes.Equal(mustSharedJSON(response.Facts), mustSharedJSON(q.SharedRuntimeNodeFacts("complete"))) || response.FinishedAt.Before(response.StartedAt) || !response.FinishedAt.Before(response.ValidUntil) || response.ValidUntil.Sub(response.StartedAt) > 15*time.Second {
			return ErrSourceRecoveryProofRequired
		}
	}
	if facts.Spec == nil {
		found := false
		for _, g := range facts.Definition.Groups {
			if len(g.Members) == 0 && writer.ID == "shared-agent/"+g.Key && writer.Original.UID == g.Key && writer.Original.Generation == g.Generation {
				found = true
			}
		}
		if !found {
			return ErrSourceRecoveryProofRequired
		}
		return nil
	}
	spec := *facts.Spec
	if spec.Kind != "shared" || runtimeWriterID(spec) != writer.ID || spec.Stopped != writer.Original || instances[spec.Source.ID] != spec.Source {
		return ErrSourceRecoveryProofRequired
	}
	matched := false
	for _, source := range facts.Sources {
		if source == spec.Source {
			matched = true
		}
	}
	if !matched {
		return ErrSourceRecoveryProofRequired
	}
	delete(instances, spec.Source.ID)
	return nil
}

// Compact CE bodies retain the existing 8192-byte bound. Complete native
// transcripts are immutable SQL witness bytes, referenced by exact SHA.
type runtimeSharedRecoverySummary struct {
	Version                         string
	Original                        b.FrozenWriter
	Spec                            *b.RuntimeWriterSpec
	DefinitionSHA256, PayloadSHA256 string
}

func validateSharedTaskRecoveryLeaf(a d.Authority, writer b.FrozenWriter, leaf sourceRecoveryLeaf, instances map[int]b.InstanceIdentity) error {
	var summary runtimeSharedRecoverySummary
	if json.Unmarshal(leaf.Facts, &summary) != nil || summary.Version != "source-recovery-shared-runtime-ref.v1" || summary.Original != writer || !executionHash.MatchString(summary.DefinitionSHA256) || !executionHash.MatchString(summary.PayloadSHA256) || len(leaf.References) != 1 || leaf.References[0].Kind != "runtime_stop" || leaf.References[0].SHA256 != summary.PayloadSHA256 {
		return ErrSourceRecoveryProofRequired
	}
	if summary.Spec == nil {
		if !strings.HasPrefix(writer.ID, "shared-agent/") {
			return ErrSourceRecoveryProofRequired
		}
		return nil
	}
	spec := *summary.Spec
	if spec.Kind != "shared" || runtimeWriterID(spec) != writer.ID || spec.Stopped != writer.Original || instances[spec.Source.ID] != spec.Source {
		return ErrSourceRecoveryProofRequired
	}
	delete(instances, spec.Source.ID)
	return nil
}
func (o *SQLRuntimeControl) LoadSharedTaskRecoveryFacts(ctx context.Context, a d.Authority, ob SourceRecoveryObservation) (RuntimeSharedRecoveryFacts, error) {
	var facts RuntimeSharedRecoveryFacts
	var summary runtimeSharedRecoverySummary
	if o.cfg.Gate.Recovery.Check(ctx, a) != nil || ob.Scope != sharedTaskRecoveryScope || json.Unmarshal(ob.Facts, &summary) != nil || len(ob.References) != 1 || ob.References[0].SHA256 != summary.PayloadSHA256 {
		return facts, ErrSourceRecoveryProofRequired
	}
	var raw []byte
	var digest string
	if o.cfg.Gate.Authority.DB.QueryRowContext(ctx, `SELECT proof_json,proof_sha256 FROM system_backup_v2_runtime_stop_proofs WHERE task_public_id=? AND pod_uid=?`, a.TaskPublicID, ob.References[0].Identity).Scan(&raw, &digest) != nil || digest != summary.PayloadSHA256 || recordHash(raw) != digest || json.Unmarshal(raw, &facts) != nil || recordHash(mustSharedJSON(facts.Definition)) != summary.DefinitionSHA256 {
		return facts, ErrSourceRecoveryProofRequired
	}
	return facts, nil
}
