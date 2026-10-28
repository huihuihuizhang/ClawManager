package systembackupdispatch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"time"
)

const TaskPlanVersion = "system-backup-task-plan.v1"
const maxInnerPlan = 4 << 20
const maxTaskPlan = 8 << 20

var taskPlanHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var taskPlanToken = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var taskPlanInstallation = regexp.MustCompile(`^installation_[A-Za-z0-9._:-]{1,115}$`)
var taskPlanID = regexp.MustCompile(`^(sbk|spf)_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type taskPlanBinding struct {
	InstallationID   string    `json:"installation_id"`
	PublicID         string    `json:"task_public_id"`
	Kind             string    `json:"task_type"`
	RequestID        string    `json:"request_id"`
	ConfigVersion    uint64    `json:"config_version"`
	ConfigSHA256     string    `json:"config_sha256"`
	AttemptNo        uint64    `json:"attempt_no"`
	Phase            string    `json:"phase"`
	ProfileID        string    `json:"profile_id"`
	ProfileRevision  string    `json:"profile_revision"`
	Deadline         time.Time `json:"deadline_at"`
	BackupSpecSHA256 string    `json:"backup_spec_sha256"`
}
type taskPlanEnvelope struct {
	Version      string          `json:"schema_version"`
	Binding      taskPlanBinding `json:"binding"`
	InnerVersion string          `json:"runner_plan_version"`
	InnerSHA256  string          `json:"runner_plan_sha256"`
	// Base64 through []byte deliberately preserves every original B byte.
	// RawMessage would compact/re-encode a differently formatted inner plan.
	InnerBytes []byte `json:"runner_plan_bytes"`
}
type taskBoundRunner struct {
	inner   Runner
	version string
}

func taskPlanDigest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }

func planBinding(in Input) (taskPlanBinding, error) {
	a := in.Authority
	if !taskPlanInstallation.MatchString(a.InstallationID) || !taskPlanID.MatchString(a.TaskPublicID) || !taskPlanToken.MatchString(a.RequestID) || !taskPlanToken.MatchString(a.ClaimOwner) || a.ClaimRowVersion == 0 || a.ConfigVersion == 0 || a.AttemptNo == 0 || !taskPlanHash.MatchString(a.ConfigSHA256) || a.DeadlineAt.IsZero() || !taskPlanToken.MatchString(in.ProfileID) || !taskPlanToken.MatchString(in.ProfileRevision) || len(in.ConfigSnapshot) < 2 || len(in.ConfigSnapshot) > 262144 || !json.Valid(in.ConfigSnapshot) || taskPlanDigest(in.ConfigSnapshot) != a.ConfigSHA256 {
		return taskPlanBinding{}, ErrNotReady
	}
	if a.TaskType == "backup" {
		if a.TaskPublicID[:4] != "sbk_" || a.Phase != "capture" || ValidateBackupSpec(in.Backup) != nil {
			return taskPlanBinding{}, ErrNotReady
		}
	} else if a.TaskType != "preflight" || a.TaskPublicID[:4] != "spf_" || a.Phase != "preflight" {
		return taskPlanBinding{}, ErrNotReady
	}
	raw, err := json.Marshal(in.Backup)
	if err != nil {
		return taskPlanBinding{}, ErrNotReady
	}
	return taskPlanBinding{a.InstallationID, a.TaskPublicID, a.TaskType, a.RequestID, a.ConfigVersion, a.ConfigSHA256, a.AttemptNo, a.Phase, in.ProfileID, in.ProfileRevision, a.DeadlineAt.UTC().Round(0), taskPlanDigest(raw)}, nil
}

func cloneTaskInput(in Input) Input {
	in.ConfigSnapshot = bytes.Clone(in.ConfigSnapshot)
	in.Jobs = append([]JobBinding(nil), in.Jobs...)
	if in.Backup != nil {
		b := *in.Backup
		b.RequestedParts = append([]string(nil), b.RequestedParts...)
		in.Backup = &b
	}
	return in
}

// BindTaskRunner is D's mandatory adapter around the real B runner. It binds
// original task purpose/parts/source specification in addition to B's plan
// binding. It does NOT alter B's private version or raw plan bytes/signature.
// The returned plan is integrity metadata, not a custody proof or a grant:
// the real WorkStore must still encrypt/persist it through A-owned facilities.
func BindTaskRunner(inner Runner, expectedInnerVersion string) (Runner, error) {
	if missing(inner) || !taskPlanToken.MatchString(expectedInnerVersion) {
		return nil, ErrNotReady
	}
	return &taskBoundRunner{inner: inner, version: expectedInnerVersion}, nil
}

func validInnerPlan(p Plan, version string) bool {
	b := bytes.TrimSpace(p.CanonicalJSON)
	return p.SchemaVersion == version && len(p.CanonicalJSON) > 0 && len(p.CanonicalJSON) <= maxInnerPlan && len(b) > 0 && b[0] == '{' && json.Valid(b) && taskPlanHash.MatchString(p.SHA256) && taskPlanDigest(p.CanonicalJSON) == p.SHA256
}

func (r *taskBoundRunner) Prepare(ctx context.Context, in Input, ports Ports) (Plan, error) {
	if r == nil || missing(ctx) || ctx.Err() != nil || missing(ports) {
		return Plan{}, ErrNotReady
	}
	binding, err := planBinding(in)
	if err != nil {
		return Plan{}, err
	}
	call := cloneTaskInput(in)
	inner, err := r.inner.Prepare(ctx, call, ports)
	if err != nil {
		return Plan{}, err
	}
	after, checkErr := planBinding(call)
	if checkErr != nil || after != binding || ctx.Err() != nil || !validInnerPlan(inner, r.version) {
		return Plan{}, ErrNotReady
	}
	raw, err := json.Marshal(taskPlanEnvelope{TaskPlanVersion, binding, inner.SchemaVersion, inner.SHA256, bytes.Clone(inner.CanonicalJSON)})
	if err != nil || len(raw) > maxTaskPlan {
		return Plan{}, ErrNotReady
	}
	return Plan{TaskPlanVersion, raw, taskPlanDigest(raw)}, nil
}

// UnwrapTaskPlan is D's materializer boundary before B DescribePlan. It checks
// the exact original task/config/profile/spec and inner version/SHA, returns a
// detached copy of the SAME B bytes, and grants no Job/capture/read authority.
func UnwrapTaskPlan(in Input, p Plan, expectedInnerVersion string) (Plan, error) {
	binding, err := planBinding(in)
	if err != nil || !taskPlanToken.MatchString(expectedInnerVersion) || p.SchemaVersion != TaskPlanVersion || len(p.CanonicalJSON) == 0 || len(p.CanonicalJSON) > maxTaskPlan || !taskPlanHash.MatchString(p.SHA256) || taskPlanDigest(p.CanonicalJSON) != p.SHA256 {
		return Plan{}, ErrNotReady
	}
	var e taskPlanEnvelope
	dec := json.NewDecoder(bytes.NewReader(p.CanonicalJSON))
	dec.DisallowUnknownFields()
	if dec.Decode(&e) != nil || dec.Decode(new(any)) != io.EOF {
		return Plan{}, ErrNotReady
	}
	canonical, err := json.Marshal(e)
	if err != nil || !bytes.Equal(canonical, p.CanonicalJSON) || e.Version != TaskPlanVersion || e.Binding != binding {
		return Plan{}, ErrNotReady
	}
	inner := Plan{e.InnerVersion, bytes.Clone(e.InnerBytes), e.InnerSHA256}
	if !validInnerPlan(inner, expectedInnerVersion) {
		return Plan{}, ErrNotReady
	}
	return inner, nil
}

func (r *taskBoundRunner) Capture(ctx context.Context, in Input, p Plan, ports Ports) ([]ModuleResult, error) {
	if r == nil || missing(ctx) || ctx.Err() != nil || missing(ports) {
		return nil, ErrNotReady
	}
	inner, err := UnwrapTaskPlan(in, p, r.version)
	if err != nil {
		return nil, err
	}
	return r.inner.Capture(ctx, cloneTaskInput(in), inner, ports)
}
func (r *taskBoundRunner) Recover(ctx context.Context, in Input, p Plan, ports Ports) (RecoveryResult, error) {
	if r == nil || missing(ctx) || ctx.Err() != nil || missing(ports) {
		return RecoveryResult{}, ErrNotReady
	}
	inner, err := UnwrapTaskPlan(in, p, r.version)
	if err != nil {
		return RecoveryResult{}, err
	}
	// Recovery deliberately delegates to the fresh recovery scope/ports; it
	// cannot be authorized by a saved plan or a stale forward-work claim.
	return r.inner.Recover(ctx, cloneTaskInput(in), inner, ports)
}
