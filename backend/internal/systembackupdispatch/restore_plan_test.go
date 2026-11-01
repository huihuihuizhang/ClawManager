package systembackupdispatch

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func restorePlanFixture(t *testing.T, phase string) (Input, DrillSpec, Plan, Plan) {
	t.Helper()
	config := []byte(`{"fixture":true}`)
	in := Input{Authority: Authority{InstallationID: "installation_test", TaskPublicID: "sdr_11111111-1111-4111-8111-111111111111", TaskType: "drill", RequestID: "request-1", ConfigVersion: 1, ConfigSHA256: taskPlanDigest(config), AttemptNo: 2, Phase: phase, ClaimOwner: "controller-1", ClaimRowVersion: 3, DeadlineAt: time.Now().UTC().Add(time.Minute)}, ConfigSnapshot: config, ProfileID: "cluster", ProfileRevision: "r1"}
	spec := DrillSpec{SourceType: "backup", SourcePublicID: "sbk_22222222-2222-4222-8222-222222222222", ManifestSHA256: strings.Repeat("a", 64), AcceptanceSHA256: strings.Repeat("b", 64), TargetProfile: "cluster", TargetConfigRef: "isolated-fixture", TargetConfigSHA256: strings.Repeat("c", 64), Purpose: "functional_test", CleanupPolicy: "retain-always"}
	if phase == "verify" {
		spec.RestoredPlanSHA256 = strings.Repeat("d", 64)
		spec.RestoreResultSHA256 = strings.Repeat("e", 64)
		spec.RevocationEvidenceSHA256 = strings.Repeat("f", 64)
	}
	raw := []byte(" { \"fixture_only\": true } \n")
	inner := Plan{SchemaVersion: "fixture-target-plan.v1", CanonicalJSON: raw, SHA256: taskPlanDigest(raw)}
	plan, err := BindRestoreTaskPlan(in, spec, inner, "fixture-target-plan.v1")
	if err != nil {
		t.Fatal(err)
	}
	return in, spec, inner, plan
}

func TestRestoreTaskPlanPreservesBytesAndRequiresOriginalTask(t *testing.T) {
	in, spec, inner, plan := restorePlanFixture(t, "restore")
	got, err := UnwrapRestoreTaskPlan(in, spec, plan, "fixture-target-plan.v1")
	if err != nil || !bytes.Equal(got.CanonicalJSON, inner.CanonicalJSON) {
		t.Fatal("inner plan changed", err)
	}
	got.CanonicalJSON[0] = 'x'
	again, err := UnwrapRestoreTaskPlan(in, spec, plan, "fixture-target-plan.v1")
	if err != nil || !bytes.Equal(again.CanonicalJSON, inner.CanonicalJSON) {
		t.Fatal("returned plan alias", err)
	}
	// Renewable authority is not frozen; all current checks still belong to D.
	in.Authority.ClaimOwner = "controller-2"
	in.Authority.ClaimRowVersion++
	if _, err := UnwrapRestoreTaskPlan(in, spec, plan, "fixture-target-plan.v1"); err != nil {
		t.Fatal("fresh claim cannot consume original intent", err)
	}
	for _, changed := range []string{"task", "kind", "phase", "attempt", "request", "config", "profile", "deadline", "manifest", "acceptance", "source", "target", "purpose", "cleanup", "capture-gate", "backup-spec", "unknown-envelope-field", "unknown-inner-version"} {
		t.Run(changed, func(t *testing.T) {
			in, spec, _, plan := restorePlanFixture(t, "restore")
			switch changed {
			case "task":
				in.Authority.TaskPublicID = "sdr_33333333-3333-4333-8333-333333333333"
			case "kind":
				in.Authority.TaskType = "restore_drill"
			case "phase":
				in.Authority.Phase = "verify"
			case "attempt":
				in.Authority.AttemptNo++
			case "request":
				in.Authority.RequestID = "different-request"
			case "config":
				in.ConfigSnapshot = []byte(`{"different":true}`)
				in.Authority.ConfigSHA256 = taskPlanDigest(in.ConfigSnapshot)
			case "profile":
				in.ProfileRevision = "r2"
			case "deadline":
				in.Authority.DeadlineAt = in.Authority.DeadlineAt.Add(time.Second)
			case "manifest":
				spec.ManifestSHA256 = strings.Repeat("d", 64)
			case "acceptance":
				spec.AcceptanceSHA256 = strings.Repeat("d", 64)
			case "source":
				spec.SourcePublicID = "sbk_33333333-3333-4333-8333-333333333333"
			case "target":
				spec.TargetConfigSHA256 = strings.Repeat("d", 64)
			case "purpose":
				spec.Purpose = "acceptance"
			case "cleanup":
				spec.CleanupPolicy = "delete-on-success"
			case "capture-gate":
				in.Authority.MaintenanceOwner = "capture-owner"
				in.Authority.MaintenanceFencingToken = 1
			case "backup-spec":
				in.Backup = &BackupSpec{}
			case "unknown-envelope-field":
				plan.CanonicalJSON = append([]byte(`{"Unknown":true,`), plan.CanonicalJSON[1:]...)
				plan.SHA256 = taskPlanDigest(plan.CanonicalJSON)
			case "unknown-inner-version":
				var envelope restorePlanEnvelope
				if json.Unmarshal(plan.CanonicalJSON, &envelope) != nil {
					t.Fatal("fixture envelope")
				}
				envelope.InnerVersion = "future-unreviewed-target.v999"
				plan.CanonicalJSON, _ = json.Marshal(envelope)
				plan.SHA256 = taskPlanDigest(plan.CanonicalJSON)
			}
			if _, err := UnwrapRestoreTaskPlan(in, spec, plan, "fixture-target-plan.v1"); err == nil {
				t.Fatal("different intent accepted")
			}
		})
	}
}

func TestRestoreSourceMetadataDoesNotAcceptMismatchedKinds(t *testing.T) {
	in, spec, _, _ := restorePlanFixture(t, "verify")
	spec.SourceType = "catalog_import"
	if ValidateRestoreInput(in, spec) == nil {
		t.Fatal("backup ID treated as catalog")
	}
	spec.SourcePublicID = "sci_22222222-2222-4222-8222-222222222222"
	spec.CatalogSHA256 = strings.Repeat("d", 64)
	if ValidateRestoreInput(in, spec) != nil {
		t.Fatal("catalog metadata shape rejected")
	}
	in.Authority.Phase = "verifying"
	if ValidateRestoreInput(in, spec) == nil {
		t.Fatal("status treated as phase")
	}
}
