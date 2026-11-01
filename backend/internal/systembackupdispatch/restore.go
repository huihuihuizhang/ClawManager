package systembackupdispatch

import (
	"bytes"
	"context"
	"errors"
	"time"
)

// DrillSpec is the original admitted task projection. Checksums and target
// references bind intent; none authenticates an archive or grants target IO.
type DrillSpec struct {
	SourceType, SourcePublicID, ManifestSHA256, AcceptanceSHA256, CatalogSHA256 string
	TargetProfile, TargetConfigRef, TargetConfigSHA256                          string
	Purpose, CleanupPolicy                                                      string
	// Verify uses its own phase-bound plan and references the prior durable
	// restore outcome/revocation evidence. These references are not proof.
	RestoredPlanSHA256, RestoreResultSHA256, RevocationEvidenceSHA256 string
}

// RestorePorts deliberately exposes no source-writer recovery, Job creation,
// credential or target-write operations. A later full-source composition must
// add its concrete authenticated input before those capabilities are supplied.
type RestorePorts interface {
	CheckRestore(context.Context, Authority, DrillSpec) error
}

type RestoreResult struct {
	Evidence []EvidenceRef
}

// RestoreRunner has independent operations. Capture Runner.Recover continues
// to mean recovery of interrupted source capture, never data restoration.
type RestoreRunner interface {
	Restore(context.Context, Input, DrillSpec, Plan, RestorePorts) (RestoreResult, error)
	Verify(context.Context, Input, DrillSpec, Plan, RestorePorts) (RestoreResult, error)
}

var ErrRestoreSourceUnavailable = errors.New("complete authenticated restore source unavailable")

type RestoreDispatcher struct {
	Runner      RestoreRunner
	Ports       RestorePorts
	PlanVersion string
}

func (d RestoreDispatcher) Ready() error {
	if missing(d.Runner) || missing(d.Ports) || !taskPlanToken.MatchString(d.PlanVersion) {
		return ErrNotReady
	}
	return nil
}

func (d RestoreDispatcher) Restore(ctx context.Context, in Input, spec DrillSpec, plan Plan) (RestoreResult, error) {
	return d.run(ctx, in, spec, plan, "restore")
}

func (d RestoreDispatcher) Verify(ctx context.Context, in Input, spec DrillSpec, plan Plan) (RestoreResult, error) {
	return d.run(ctx, in, spec, plan, "verify")
}

func (d RestoreDispatcher) run(ctx context.Context, in Input, spec DrillSpec, plan Plan, phase string) (RestoreResult, error) {
	if missing(ctx) || ctx.Err() != nil || d.Ready() != nil || in.Authority.Phase != phase {
		return RestoreResult{}, ErrNotReady
	}
	inner, err := UnwrapRestoreTaskPlan(in, spec, plan, d.PlanVersion)
	if err != nil {
		return RestoreResult{}, err
	}
	clear(inner.CanonicalJSON)
	if !time.Now().Before(in.Authority.DeadlineAt) {
		return RestoreResult{}, context.DeadlineExceeded
	}
	in = cloneTaskInput(in)
	plan.CanonicalJSON = bytes.Clone(plan.CanonicalJSON)
	if err = d.Ports.CheckRestore(ctx, in.Authority, spec); err != nil {
		return RestoreResult{}, err
	}
	if err = ctx.Err(); err != nil {
		return RestoreResult{}, err
	}
	if !time.Now().Before(in.Authority.DeadlineAt) {
		return RestoreResult{}, context.DeadlineExceeded
	}
	var result RestoreResult
	if phase == "restore" {
		result, err = d.Runner.Restore(ctx, in, spec, plan, d.Ports)
	} else {
		result, err = d.Runner.Verify(ctx, in, spec, plan, d.Ports)
	}
	// Preserve observations alongside errors, including an uncertain result
	// returned as the forward scope ends. D's recorder owns their disposition.
	result.Evidence = append([]EvidenceRef(nil), result.Evidence...)
	if ctx.Err() != nil {
		err = errors.Join(err, ctx.Err())
	}
	if !time.Now().Before(in.Authority.DeadlineAt) {
		err = errors.Join(err, context.DeadlineExceeded)
	}
	return result, err
}
