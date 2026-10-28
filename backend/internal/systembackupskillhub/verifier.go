package systembackupskillhub

import (
	"context"
	"errors"
)

// RestoreVerificationRequest is a local, complete Skill Hub invocation, not a
// frozen public Runner DTO. The authority must bind every input to one sealed
// artifact, target generation and frozen capacity configuration.
type RestoreVerificationRequest struct {
	Restore               RestoreRequest
	Inventory             []FrozenObject
	Captured              []CapturedObject
	Targets               map[string]RestoredObjectLocation
	ObjectLimits          ObjectCaptureLimits
	WorkspaceEvidenceRefs []string
}

// RestoreVerificationAuthority authenticates the actual configured object
// reader's isolated root, read-only credentials and target generation, as well
// as all input receipts/proofs. SQL credentials are independently authenticated
// by SQLRestoreVerifier.Authority. Recheck must confirm that target isolation
// and authority remained valid across the SQL/object/workspace sequence.
// Implementations must not use hash syntax or a caller-provided flag as proof.
type RestoreVerificationAuthority interface {
	VerifyRestoreVerification(context.Context, VersionReader, RestoreVerificationRequest) error
	RecheckRestoreVerification(context.Context, VersionReader, RestoreVerificationRequest) error
}

type WorkspaceVerificationRequest struct {
	Restore           RestoreRequest
	UnpackagedBlobIDs []int
	EvidenceRefs      []string
}

// WorkspaceRestoreVerifier is the B-owned read/proof capability. It must verify
// evidence authentication, artifact/target binding and complete coverage of the
// supplied bindings, job workspace paths and unpackaged blobs (including their
// expected source content). A valid sev_ string alone is never sufficient.
type WorkspaceRestoreVerifier interface {
	VerifySkillHubWorkspace(context.Context, WorkspaceVerificationRequest) error
}

// RestoreVerifier wires the existing SQL and object implementations together.
// It invokes only read/proof operations; SQL authority must verify SELECT-only
// credentials. There is no default/no-op authority adapter.
type RestoreVerifier struct {
	SQL       SQLRestoreVerifier
	Objects   VersionReader
	Workspace WorkspaceRestoreVerifier
	Authority RestoreVerificationAuthority
}

// RestoreVerificationSummary contains only redacted statistics, never a public
// aggregate status or eligibility claim. Non-zero omitted metadata MUST become
// disqualifying public warnings; the adapter must not drop this field.
type RestoreVerificationSummary struct {
	SQLRows                    int64
	Objects                    int64
	WorkspaceBindings          int64
	UnpackagedBlobs            int64
	ObjectsWithOmittedMetadata int64
}

var ErrWorkspaceProof = errors.New("skill hub workspace restore proof unavailable")

// Verify returns no partial summary on any failed stage. The order is full
// preflight -> authority -> real SQL snapshot -> exact target objects -> B's
// workspace verification -> final authority. No write/publish capability is used.
func (v RestoreVerifier) Verify(ctx context.Context, request RestoreVerificationRequest) (RestoreVerificationSummary, error) {
	var empty RestoreVerificationSummary
	if err := checkContext(ctx); err != nil {
		return empty, err
	}
	if v.SQL.DB == nil || nilObjectAdapter(v.SQL.Authority) || nilObjectAdapter(v.Objects) || nilObjectAdapter(v.Workspace) || nilObjectAdapter(v.Authority) {
		return empty, ErrRestoreAuthority
	}
	frozen, objects, err := freezeVerificationRequest(ctx, request)
	if err != nil {
		return empty, err
	}
	if err := v.Authority.VerifyRestoreVerification(ctx, v.Objects, cloneVerificationRequest(frozen)); err != nil {
		return empty, restoreFailure(ctx, ErrRestoreAuthority)
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := v.SQL.Verify(ctx, frozen.Restore); err != nil {
		return empty, err
	}
	if err := VerifyObjectRestorePlan(ctx, v.Objects, objects, frozen.ObjectLimits); err != nil {
		return empty, err
	}
	workspace := WorkspaceVerificationRequest{Restore: cloneRestoreRequest(frozen.Restore),
		UnpackagedBlobIDs: append([]int(nil), objects.UnpackagedBlobIDs...),
		EvidenceRefs:      append([]string(nil), frozen.WorkspaceEvidenceRefs...)}
	if err := v.Workspace.VerifySkillHubWorkspace(ctx, workspace); err != nil {
		return empty, restoreFailure(ctx, ErrWorkspaceProof)
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := v.Authority.RecheckRestoreVerification(ctx, v.Objects, cloneVerificationRequest(frozen)); err != nil {
		return empty, restoreFailure(ctx, ErrRestoreAuthority)
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	result := RestoreVerificationSummary{Objects: int64(len(objects.Objects)),
		WorkspaceBindings: int64(len(frozen.Restore.Source.Bindings)), UnpackagedBlobs: int64(len(objects.UnpackagedBlobIDs)),
		ObjectsWithOmittedMetadata: int64(objects.ObjectsWithOmittedMetadata)}
	for _, table := range tables(frozen.Restore.Source) {
		result.SQLRows += int64(table.rows.Len())
	}
	return result, nil
}

func freezeVerificationRequest(ctx context.Context, request RestoreVerificationRequest) (RestoreVerificationRequest, ObjectRestorePlan, error) {
	var empty RestoreVerificationRequest
	var noObjects ObjectRestorePlan
	restore, err := freezeRestoreRequest(ctx, request.Restore)
	if err != nil {
		return empty, noObjects, err
	}
	if int64(len(request.WorkspaceEvidenceRefs)) > restore.Limits.MaxMappingEntries {
		return empty, noObjects, ErrCapacity
	}
	var bytes int64
	seen := map[string]bool{}
	for _, ref := range request.WorkspaceEvidenceRefs {
		if err := ctx.Err(); err != nil {
			return empty, noObjects, err
		}
		if int64(len(ref)) > restore.Limits.MaxMappingBytes-bytes {
			return empty, noObjects, ErrCapacity
		}
		bytes += int64(len(ref))
		if len(ref) > 256 || !evidenceIDPattern.MatchString(ref) || seen[ref] {
			return empty, noObjects, ErrWorkspaceProof
		}
		seen[ref] = true
	}
	objects, err := PrepareObjectRestore(ctx, restore.Source.Blobs, restore.Mapping.ObjectKeys,
		request.Inventory, request.Captured, request.Targets, request.ObjectLimits)
	if err != nil {
		return empty, noObjects, err
	}
	if (len(restore.Source.Bindings) > 0 || len(restore.Source.Jobs) > 0 || len(objects.UnpackagedBlobIDs) > 0) && len(seen) == 0 {
		return empty, noObjects, ErrWorkspaceProof
	}
	// Captured input selectors are also cloned for authority callbacks. Validate
	// their optional metadata and aggregate size before that extra copy.
	selectors := make([]FrozenObject, len(request.Captured))
	for i, item := range request.Captured {
		selectors[i] = item.Object
	}
	if _, err := PrepareObjectCapture(ctx, nil, selectors, request.ObjectLimits); err != nil {
		return empty, noObjects, err
	}
	request.Restore = restore
	return cloneVerificationRequest(request), objects, nil
}

func cloneFrozenObject(in FrozenObject) FrozenObject {
	if in.Metadata != nil {
		m := cloneMetadata(*in.Metadata)
		in.Metadata = &m
	}
	return in
}

func cloneVerificationRequest(in RestoreVerificationRequest) RestoreVerificationRequest {
	out := in
	out.Restore = cloneRestoreRequest(in.Restore)
	out.Inventory = make([]FrozenObject, len(in.Inventory))
	for i, item := range in.Inventory {
		out.Inventory[i] = cloneFrozenObject(item)
	}
	out.Captured = make([]CapturedObject, len(in.Captured))
	for i, item := range in.Captured {
		item.Object = cloneFrozenObject(item.Object)
		item.Digest.Properties = cloneProperties(item.Digest.Properties)
		out.Captured[i] = item
	}
	out.Targets = make(map[string]RestoredObjectLocation, len(in.Targets))
	for key, value := range in.Targets {
		out.Targets[key] = value
	}
	out.WorkspaceEvidenceRefs = append([]string(nil), in.WorkspaceEvidenceRefs...)
	return out
}
