package systembackupdispatch

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"time"
)

const RestoreTaskPlanVersion = "system-backup-restore-task-plan.v1"

var drillPlanID = regexp.MustCompile(`^sdr_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var restoreSourceID = regexp.MustCompile(`^(sbk|sci)_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type restorePlanBinding struct {
	InstallationID, TaskPublicID, TaskType, RequestID string
	ConfigVersion                                     uint64
	ConfigSHA256                                      string
	AttemptNo                                         uint64
	Phase, ProfileID, ProfileRevision                 string
	DeadlineAt                                        time.Time
	Spec                                              DrillSpec
}

type restorePlanEnvelope struct {
	Version                   string
	Binding                   restorePlanBinding
	InnerVersion, InnerSHA256 string
	InnerBytes                []byte
}

// ValidateRestoreInput checks the closed drill metadata contract only. Current
// SQL authority and source/target authentication remain separate requirements.
func ValidateRestoreInput(in Input, spec DrillSpec) error {
	a := in.Authority
	if !taskPlanInstallation.MatchString(a.InstallationID) || !drillPlanID.MatchString(a.TaskPublicID) || a.TaskType != "drill" || (a.Phase != "restore" && a.Phase != "normalize" && a.Phase != "verify") || !taskPlanToken.MatchString(a.RequestID) || !taskPlanToken.MatchString(a.ClaimOwner) || a.ClaimRowVersion == 0 || a.ConfigVersion == 0 || a.AttemptNo == 0 || a.AttemptNo > uint64(^uint32(0)) || !taskPlanHash.MatchString(a.ConfigSHA256) || a.DeadlineAt.IsZero() || a.MaintenanceOwner != "" || a.MaintenanceFencingToken != 0 || !taskPlanToken.MatchString(in.ProfileID) || !taskPlanToken.MatchString(in.ProfileRevision) || in.Backup != nil || len(in.ConfigSnapshot) < 2 || len(in.ConfigSnapshot) > 262144 || !json.Valid(in.ConfigSnapshot) || taskPlanDigest(in.ConfigSnapshot) != a.ConfigSHA256 {
		return ErrNotReady
	}
	if !restoreSourceID.MatchString(spec.SourcePublicID) || !taskPlanHash.MatchString(spec.ManifestSHA256) || !taskPlanHash.MatchString(spec.TargetConfigSHA256) || !taskPlanToken.MatchString(spec.TargetConfigRef) || (spec.TargetProfile != "cluster" && spec.TargetProfile != "single-node") || (spec.Purpose != "acceptance" && spec.Purpose != "functional_test") || (spec.CleanupPolicy != "delete-on-success" && spec.CleanupPolicy != "retain-always") {
		return ErrNotReady
	}
	if spec.SourceType == "backup" {
		if spec.SourcePublicID[:4] != "sbk_" || !taskPlanHash.MatchString(spec.AcceptanceSHA256) || spec.CatalogSHA256 != "" {
			return ErrNotReady
		}
	} else if spec.SourceType != "catalog_import" || spec.SourcePublicID[:4] != "sci_" || !taskPlanHash.MatchString(spec.CatalogSHA256) || (spec.AcceptanceSHA256 != "" && !taskPlanHash.MatchString(spec.AcceptanceSHA256)) {
		return ErrNotReady
	}
	if a.Phase == "verify" {
		if !taskPlanHash.MatchString(spec.RestoredPlanSHA256) || !taskPlanHash.MatchString(spec.RestoreResultSHA256) || !taskPlanHash.MatchString(spec.RevocationEvidenceSHA256) {
			return ErrNotReady
		}
	} else if spec.RestoredPlanSHA256 != "" || spec.RestoreResultSHA256 != "" || spec.RevocationEvidenceSHA256 != "" {
		return ErrNotReady
	}
	return nil
}

func restoreBinding(in Input, spec DrillSpec) (restorePlanBinding, error) {
	if ValidateRestoreInput(in, spec) != nil {
		return restorePlanBinding{}, ErrNotReady
	}
	a := in.Authority
	return restorePlanBinding{a.InstallationID, a.TaskPublicID, a.TaskType, a.RequestID, a.ConfigVersion, a.ConfigSHA256, a.AttemptNo, a.Phase, in.ProfileID, in.ProfileRevision, a.DeadlineAt.UTC().Round(0), spec}, nil
}

// BindRestoreTaskPlan preserves the exact target planner bytes. This envelope
// must be encrypted and persisted by D; its hash alone provides no custody,
// source authentication, target isolation or execution authority.
func BindRestoreTaskPlan(in Input, spec DrillSpec, inner Plan, expectedInnerVersion string) (Plan, error) {
	binding, err := restoreBinding(in, spec)
	if err != nil || !taskPlanToken.MatchString(expectedInnerVersion) || !validInnerPlan(inner, expectedInnerVersion) {
		return Plan{}, ErrNotReady
	}
	raw, err := json.Marshal(restorePlanEnvelope{RestoreTaskPlanVersion, binding, inner.SchemaVersion, inner.SHA256, bytes.Clone(inner.CanonicalJSON)})
	if err != nil || len(raw) > maxTaskPlan {
		return Plan{}, ErrNotReady
	}
	return Plan{RestoreTaskPlanVersion, raw, taskPlanDigest(raw)}, nil
}

func UnwrapRestoreTaskPlan(in Input, spec DrillSpec, plan Plan, expectedInnerVersion string) (Plan, error) {
	binding, err := restoreBinding(in, spec)
	if err != nil || !taskPlanToken.MatchString(expectedInnerVersion) || plan.SchemaVersion != RestoreTaskPlanVersion || len(plan.CanonicalJSON) == 0 || len(plan.CanonicalJSON) > maxTaskPlan || !taskPlanHash.MatchString(plan.SHA256) || taskPlanDigest(plan.CanonicalJSON) != plan.SHA256 {
		return Plan{}, ErrNotReady
	}
	var envelope restorePlanEnvelope
	decoder := json.NewDecoder(bytes.NewReader(plan.CanonicalJSON))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(new(any)) != io.EOF {
		return Plan{}, ErrNotReady
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, plan.CanonicalJSON) || envelope.Version != RestoreTaskPlanVersion || envelope.Binding != binding || !taskPlanToken.MatchString(envelope.InnerVersion) {
		return Plan{}, ErrNotReady
	}
	inner := Plan{envelope.InnerVersion, bytes.Clone(envelope.InnerBytes), envelope.InnerSHA256}
	if !validInnerPlan(inner, expectedInnerVersion) {
		return Plan{}, ErrNotReady
	}
	return inner, nil
}
