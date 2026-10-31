package systembackupexecution

import (
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"os"

	sourceData "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/domain"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	sh "clawreef/internal/systembackupskillhub"
	w "clawreef/internal/systembackupwire"
)

// The normal Job Evidence poll consumes the ORIGINAL encrypted journal and
// original frozen plan. The actual independently supplied Unwrapper rechecks
// its own exact provider operation/current authority before and after AEAD use.
// No capture credential is promoted into read/unwrap authority here.
func (o *PublicJobOwner) observeFormalCandidateResult(ctx context.Context, a d.Authority, j d.JobBinding) (*d.EvidenceRef, error) {
	var digest sql.NullString
	if err := o.Gate.Authority.DB.QueryRowContext(ctx, `SELECT candidate_sha256 FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND attempt_no=? AND phase=? AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND observed_uid=?`, a.TaskPublicID, a.AttemptNo, a.Phase, j.Namespace, j.Name, j.UID).Scan(&digest); err != nil {
		return nil, err
	}
	if !digest.Valid {
		return nil, nil
	}
	if o.FormalKeys == nil {
		return nil, d.ErrNotReady
	}
	record, err := o.ReadFormalCandidate(ctx, a, j, false)
	if err != nil {
		return nil, err
	}
	in, plan, desc, err := o.input(ctx, a, false)
	if err != nil {
		return nil, err
	}
	part, err := partFor(desc, j.JobUnitKey)
	if err != nil {
		return nil, err
	}
	var invocation worker.Invocation
	if json.Unmarshal(part.InvocationJSON, &invocation) != nil || !worker.ValidateFormalCaptureResult(invocation, &record.Candidate) {
		return nil, c.ErrExecutionRecord
	}
	keys, err := openFormalCandidateKeys(ctx, o.FormalKeys, FormalCandidateReadScope{Authority: a, Job: j, Invocation: invocation, Candidate: record.Candidate, CapturePod: record.Pod, CaptureGrantSHA256: record.ExecutionGrantSHA256})
	if err != nil {
		return nil, err
	}
	defer keys.Close()
	ctx, cancel := context.WithDeadline(ctx, keys.ValidUntil())
	defer cancel()
	custody, err := staging.OpenSealCustody(o.Staging)
	if err != nil {
		return nil, err
	}
	defer custody.Close()
	source, err := o.Staging.OpenRoot(a.TaskPublicID)
	if err != nil {
		return nil, err
	}
	defer source.Close()
	if err = o.Gate.Check(ctx, a); err != nil {
		return nil, err
	}
	observed, err := observeOriginalFormalCandidate(ctx, source, custody, staging.CustodyPolicy{Installation: a.InstallationID, MaxBytes: o.SealCustodyMaxBytes}, workerSealScope(a, j, invocation), invocation, record.Candidate, keys)
	if err != nil {
		return nil, err
	}
	if err = o.Gate.Check(ctx, a); err != nil {
		return nil, err
	}
	inner, err := d.UnwrapTaskPlan(in, plan, b.PlanVersion)
	if err != nil {
		return nil, err
	}
	defer clear(inner.CanonicalJSON)
	result, err := b.BuildFormalPartResult(in, inner, j.JobUnitKey, j, record.Candidate, b.SealedPart{Reference: observed.Reference(), ContentSHA256: observed.Ciphertext().SHA256, EvidenceIDs: []string{}})
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(result)
	if err != nil || !inlineResultBody(raw) || b.ValidatePartResult(in, inner, j, raw) != nil {
		return nil, c.ErrExecutionRecord
	}
	if err = o.saveResult(ctx, a, j, raw); err != nil {
		return nil, err
	}
	ref := resultEvidenceRef(a, j, hash(raw))
	return &ref, nil
}

func observeOriginalFormalCandidate(ctx context.Context, source, custody *os.Root, policy staging.CustodyPolicy, scope staging.SealScope, i worker.Invocation, candidate worker.FormalCaptureResult, keys w.Unwrapper) (staging.FormalObservation, error) {
	if !worker.ValidateFormalCaptureResult(i, &candidate) || i.ProviderKey == nil || keys == nil {
		return staging.FormalObservation{}, d.ErrNotReady
	}
	spec := w.StreamSpec{Request: i.ProviderKey.Request, Path: i.Request.ArtifactName, MaxPlaintextBytes: i.Request.MaxCompressedBytes, MaxFrames: i.FormalCapture.MaxFrames}
	if database := i.Request.Database; database != nil {
		return staging.ObserveFormalManaged(ctx, source, custody, policy, scope, candidate.Ciphertext, candidate.Envelope, spec, keys, func(compressed io.Reader) error {
			z, err := gzip.NewReader(compressed)
			if err != nil {
				return d.ErrNotReady
			}
			defer z.Close()
			snapshot, err := domain.Decode(z, domain.Limits{MaxRows: database.MaxRows, MaxBytes: i.Request.MaxArchiveBytes})
			if err != nil {
				return d.ErrNotReady
			}
			defer func() {
				for _, table := range snapshot.Tables {
					for _, row := range table.Rows {
						for _, cell := range row {
							clear(cell.Bytes)
						}
					}
				}
			}()
			var rows, memory int64
			for _, table := range snapshot.Tables {
				rows += int64(len(table.Rows))
				for _, row := range table.Rows {
					for column, cell := range row {
						memory += int64(len(cell.Bytes) + len(column) + 128)
					}
				}
			}
			if rows != candidate.Rows || len(snapshot.Tables) != candidate.Tables || memory > database.MaxMemoryBytes || z.Close() != nil {
				return d.ErrNotReady
			}
			if database.SourceScope == domain.BusinessTableSourceScope && (database.CaptureSchema == nil || domain.VerifyBusinessCapturedSnapshot(snapshot, *database.CaptureSchema) != nil) {
				return d.ErrNotReady
			}
			if database.TeamsInventory != nil && domain.VerifyTeamCapture(snapshot, *database.TeamsInventory) != nil {
				return d.ErrNotReady
			}
			if database.SkillsInventory != nil && domain.VerifySkillCapture(snapshot, *database.SkillsInventory) != nil {
				return d.ErrNotReady
			}
			return nil
		})
	}
	if i.Request.SourceRedis != nil {
		return staging.ObserveFormalManaged(ctx, source, custody, policy, scope, candidate.Ciphertext, candidate.Envelope, spec, keys, func(compressed io.Reader) error {
			z, err := gzip.NewReader(compressed)
			if err != nil {
				return d.ErrNotReady
			}
			defer z.Close()
			snapshot, err := sourceData.ReadSourceRedisSnapshot(ctx, z, *i.Request.SourceRedis)
			if err != nil {
				return d.ErrNotReady
			}
			defer sourceData.ClearSourceRedisSnapshot(snapshot)
			if z.Close() != nil {
				return d.ErrNotReady
			}
			return nil
		})
	}
	if i.Request.SkillWorkspace != nil {
		// Inert proof derives from the exact authenticated captured tar, not a
		// second source read or a worker-provided "proof succeeded" flag.
		return staging.ObserveFormalManaged(ctx, source, custody, policy, scope, candidate.Ciphertext, candidate.Envelope, spec, keys, func(compressed io.Reader) error {
			z, err := gzip.NewReader(compressed)
			if err != nil {
				return d.ErrNotReady
			}
			defer z.Close()
			limited := &io.LimitedReader{R: z, N: i.Request.MaxArchiveBytes + 1}
			if sh.VerifyWorkspaceCapture(ctx, limited, *i.Request.SkillWorkspace) != nil || limited.N <= 0 {
				return d.ErrNotReady
			}
			if z.Close() != nil {
				return d.ErrNotReady
			}
			return nil
		})
	}
	return staging.ObserveFormalManaged(ctx, source, custody, policy, scope, candidate.Ciphertext, candidate.Envelope, spec, keys)
}
