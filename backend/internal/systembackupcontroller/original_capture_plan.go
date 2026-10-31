package systembackupcontroller

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"strings"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
	batchv1 "k8s.io/api/batch/v1"
)

// OriginalCapturePlan is authenticated historical data for ONE control request.
// Its private state cannot be supplied by a worker or reused with another
// request context. It conveys no current execution or provider authority.
type OriginalCapturePlan struct {
	ctx     context.Context
	records SQLExecutionRecords
	input   []byte
	stamp   originalCaptureStamp
	parts   map[string]originalCapturePart
}

type originalCapturePart struct {
	namespace, name, invocation, request string
	generation                           uint64
}

type originalCaptureStamp struct {
	Profile, Config                                                                    []byte
	ProfileHash, Orchestrator, SourceProfile, Matrix, Topology, Runner, Purpose, Parts string
	PlanHash, KeyRef, SealedHash                                                       string
	SealedSize                                                                         int64
}

type originalCaptureQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readOriginalCaptureStamp(ctx context.Context, q originalCaptureQuery, a d.Authority, lock bool) (originalCaptureStamp, error) {
	var s originalCaptureStamp
	query := `SELECT i.profile_json,i.profile_sha256,b.config_snapshot_json,b.source_orchestrator,b.source_profile,b.matrix_key,b.datasource_topology,b.runner,b.task_purpose,b.requested_parts,r.payload_sha256,r.key_ref,SHA2(r.sealed_payload,256),OCTET_LENGTH(r.sealed_payload)
FROM system_backup_v2_backups b JOIN system_backup_v2_execution_inputs i ON i.origin_installation_id=b.origin_installation_id AND i.task_public_id=b.public_id AND i.task_type='backup'
JOIN system_backup_v2_execution_records r ON r.origin_installation_id=b.origin_installation_id AND r.task_public_id=b.public_id AND r.attempt_no=? AND r.phase=? AND r.record_kind='plan'
WHERE b.origin_installation_id=? AND b.public_id=?`
	if lock {
		query += " FOR SHARE"
	}
	err := q.QueryRowContext(ctx, query, a.AttemptNo, a.Phase, a.InstallationID, a.TaskPublicID).Scan(&s.Profile, &s.ProfileHash, &s.Config, &s.Orchestrator, &s.SourceProfile, &s.Matrix, &s.Topology, &s.Runner, &s.Purpose, &s.Parts, &s.PlanHash, &s.KeyRef, &s.SealedHash, &s.SealedSize)
	if err != nil || len(s.Profile) > 262144 || len(s.Config) > 262144 || s.SealedSize < 1 || s.SealedSize > (8<<20)+4096 || !executionHash.MatchString(s.PlanHash) || !executionHash.MatchString(s.SealedHash) || recordHash(s.Profile) != s.ProfileHash || s.KeyRef == "" {
		return originalCaptureStamp{}, ErrExecutionRecord
	}
	return s, nil
}

func (s originalCaptureStamp) matches(in d.Input) bool {
	var identity struct {
		Installation string `json:"installation_id"`
		Profile      string `json:"source_profile"`
		Revision     string `json:"revision"`
	}
	if json.Unmarshal(s.Profile, &identity) != nil || identity.Installation != in.Authority.InstallationID || identity.Profile != in.ProfileID || identity.Revision != in.ProfileRevision || !bytes.Equal(s.Config, in.ConfigSnapshot) {
		return false
	}
	spec := d.BackupSpec{SourceOrchestrator: s.Orchestrator, SourceProfile: s.SourceProfile, MatrixKey: s.Matrix, DatasourceTopology: s.Topology, Runner: s.Runner, TaskPurpose: s.Purpose, RequestedParts: strings.Split(s.Parts, ",")}
	return in.Backup != nil && reflect.DeepEqual(spec, *in.Backup)
}

// OpenOriginalCapturePlan performs the original key resolution, authenticated
// decryption, complete input binding and complete discovery validation once.
// Returned plan/discovery values are detached from the private matching data.
func (s SQLExecutionRecords) OpenOriginalCapturePlan(ctx context.Context, in d.Input) (d.Plan, b.Discovery, *OriginalCapturePlan, error) {
	var desc b.Discovery
	if !s.ready() || ctx == nil || !reflect.TypeOf(ctx).Comparable() || ctx.Err() != nil {
		return d.Plan{}, desc, nil, ErrExecutionRecord
	}
	stamp, err := readOriginalCaptureStamp(ctx, s.Authority.DB, in.Authority, false)
	if err != nil || !stamp.matches(in) {
		return d.Plan{}, desc, nil, ErrExecutionRecord
	}
	plan, err := s.LoadPlan(ctx, in)
	if err != nil {
		return d.Plan{}, desc, nil, err
	}
	failed := true
	defer func() {
		if failed {
			clear(plan.CanonicalJSON)
		}
	}()
	if plan.SHA256 != stamp.PlanHash {
		return d.Plan{}, desc, nil, ErrExecutionRecord
	}
	inner, err := d.UnwrapTaskPlan(in, plan, b.PlanVersion)
	if err != nil {
		return d.Plan{}, desc, nil, err
	}
	defer clear(inner.CanonicalJSON)
	desc, err = b.DescribePlan(in, inner)
	if err != nil {
		return d.Plan{}, desc, nil, err
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return d.Plan{}, desc, nil, ErrExecutionRecord
	}
	p := &OriginalCapturePlan{ctx: ctx, records: s, input: raw, stamp: stamp, parts: map[string]originalCapturePart{}}
	for _, part := range desc.Parts {
		var job batchv1.Job
		if hash := recordHash(part.Intent.SpecJSON); hash != part.Intent.SpecSHA256 || json.Unmarshal(part.Intent.SpecJSON, &job) != nil || recordHash(part.InvocationJSON) != part.InvocationSHA256 {
			return d.Plan{}, desc, nil, ErrExecutionRecord
		}
		intent, e := kube.Intent("Job", &job)
		if e != nil || intent.Identity.Owner != in.Authority.TaskPublicID {
			return d.Plan{}, desc, nil, ErrExecutionRecord
		}
		if _, exists := p.parts[part.Intent.JobUnitKey]; exists {
			return d.Plan{}, desc, nil, ErrExecutionRecord
		}
		p.parts[part.Intent.JobUnitKey] = originalCapturePart{namespace: part.Intent.Namespace, name: part.Intent.Name, generation: part.Intent.Generation, invocation: part.InvocationSHA256, request: intent.RequestSHA256}
	}
	failed = false
	return plan, desc, p, nil
}

func (p *OriginalCapturePlan) matches(ctx context.Context, s SQLExecutionRecords, in d.Input) bool {
	if p == nil || ctx == nil || !reflect.TypeOf(ctx).Comparable() || ctx != p.ctx || ctx.Err() != nil || !reflect.DeepEqual(s, p.records) {
		return false
	}
	raw, err := json.Marshal(in)
	defer clear(raw)
	return err == nil && bytes.Equal(raw, p.input)
}

// MatchPart accepts only an exact part of this original authenticated plan.
// The issuer must still perform every current workload/grant/capability check
// and Stage under the original key-use transaction.
func (p *OriginalCapturePlan) MatchPart(ctx context.Context, s SQLExecutionRecords, in d.Input, job d.JobBinding, inv worker.Invocation) (string, string, error) {
	if !p.matches(ctx, s, in) {
		return "", "", ErrExecutionRecord
	}
	part, exists := p.parts[job.JobUnitKey]
	hash, err := inv.Hash()
	if !exists || err != nil || inv.ProviderKey == nil || part.namespace != job.Namespace || part.name != job.Name || part.generation != job.Generation || part.invocation != hash {
		return "", "", ErrExecutionRecord
	}
	return p.stamp.PlanHash, part.request, nil
}

// RecheckTx compares the CURRENT complete input and sealed record, including
// key_ref and the actual ciphertext digest/size, while the caller retains its
// original authority and Job locks. It neither renews nor caches authority.
func (p *OriginalCapturePlan) RecheckTx(ctx context.Context, tx *sql.Tx, s SQLExecutionRecords, in d.Input) error {
	if tx == nil || !p.matches(ctx, s, in) {
		return ErrExecutionRecord
	}
	stamp, err := readOriginalCaptureStamp(ctx, tx, in.Authority, true)
	if err != nil || !reflect.DeepEqual(stamp, p.stamp) {
		return ErrExecutionRecord
	}
	return nil
}
