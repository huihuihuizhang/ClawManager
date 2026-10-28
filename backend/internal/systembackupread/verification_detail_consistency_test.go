package systembackupread

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"reflect"
	"testing"
)

func assertVerificationConsistency(t *testing.T, entry string, mutate func(map[string]driver.Value), valid bool) {
	t.Helper()
	var f *detailControlFixture
	var r *Reader
	var complete *verificationDetailFixture
	if entry == "control" {
		f = newDetailControlFixture(VerificationTask)
		r = detailControlReader(t, f)
	} else {
		complete = newVerificationDetailFixture()
		f = complete.detailControlFixture
		r = verificationDetailReader(t, complete, nil)
	}
	mutate(f.values)
	if complete != nil {
		mode := "artifact_health"
		if f.values["verification_scope"] == "full" {
			mode = "artifact_full"
		}
		for _, check := range complete.checks {
			check[7] = mode
		}
	}
	var err error
	var empty bool
	if entry == "control" {
		var got TaskDetailControlSnapshot
		got, err = r.ReadTaskDetailControl(context.Background(), VerificationTask, f.rows[0][1].(string))
		empty = reflect.ValueOf(got).IsZero()
		if err == nil && valid {
			v, ok := got.Verification()
			if !ok || v.UsableBefore != f.values["usable_before"].(bool) || v.UsableAfter != f.values["usable_after"].(bool) || v.DecisionReason != f.values["decision_reason"].(string) {
				t.Fatal("saved observation was replaced")
			}
		}
	} else {
		got, e := r.ReadVerificationDetail(context.Background(), f.rows[0][1].(string))
		err = e
		empty = reflect.ValueOf(got).IsZero()
		if err == nil && valid && (got.UsableBefore != f.values["usable_before"].(bool) || got.UsableAfter != f.values["usable_after"].(bool) || got.DecisionReason != f.values["decision_reason"].(string)) {
			t.Fatal("public observation was replaced")
		}
	}
	if valid {
		if err != nil || empty || f.commits != 1 || f.rechecks != 1 || f.rollbacks != 0 || f.options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
			t.Fatalf("consistent observation rejected: err=%v empty=%t commit=%d recheck=%d rollback=%d", err, empty, f.commits, f.rechecks, f.rollbacks)
		}
	} else if !errors.Is(err, ErrUnavailable) || !empty || f.commits != 0 || f.rechecks != 0 || f.rollbacks != 1 {
		t.Fatalf("contradictory observation escaped: err=%v empty=%t commit=%d recheck=%d rollback=%d", err, empty, f.commits, f.rechecks, f.rollbacks)
	}
}

func TestVerificationDetailRejectsUsableNonCommittedLifecycle(t *testing.T) {
	for _, entry := range []string{"control", "public"} {
		for _, side := range []string{"before", "after"} {
			for _, state := range []string{"staging", "deleting", "delete_failed", "deleted", "corrupt"} {
				t.Run(entry+"/"+side+"/"+state, func(t *testing.T) {
					assertVerificationConsistency(t, entry, func(v map[string]driver.Value) {
						v["verification_scope"] = "full"
						v["artifact_state_"+side] = state
						v["usable_"+side] = true
						v["unusable_reason_"+side] = "none"
					}, false)
				})
			}
		}
	}
}
func TestVerificationDetailRestorationDecisionConsistency(t *testing.T) {
	cases := []struct {
		name, scope, decision string
		before, after, valid  bool
	}{
		{"full_restores", "full", "restored_usable", false, true, true},
		{"health_unavailable", "health", "unchanged", false, false, true},
		{"health_already_usable", "health", "unchanged", true, true, true},
		{"full_already_usable", "full", "unchanged", true, true, true},
		{"full_still_unusable", "full", "verification_inconclusive", false, false, true},
		{"health_restored_without_transition", "health", "restored_usable", false, false, false},
		{"health_restored_already_usable", "health", "restored_usable", true, true, false},
		{"full_restored_already_usable", "full", "restored_usable", true, true, false},
		{"full_restored_still_unusable", "full", "restored_usable", false, false, false},
		{"full_restored_became_unusable", "full", "restored_usable", true, false, false},
		{"health_false_to_true", "health", "unchanged", false, true, false},
		{"health_false_to_true_restored", "health", "restored_usable", false, true, false},
	}
	for _, entry := range []string{"control", "public"} {
		for _, source := range []string{"backup", "catalog_import"} {
			for _, c := range cases {
				t.Run(entry+"/"+source+"/"+c.name, func(t *testing.T) {
					assertVerificationConsistency(t, entry, func(v map[string]driver.Value) {
						v["verification_scope"], v["decision_reason"] = c.scope, c.decision
						v["usable_before"], v["usable_after"] = c.before, c.after
						v["artifact_state_before"], v["artifact_state_after"] = "committed", "committed"
						if source == "catalog_import" {
							v["source_artifact_type"], v["source_public_id"] = source, "sci_00000000-0000-4000-8000-000000000003"
							v["artifact_state_before"], v["artifact_state_after"] = nil, nil
						}
						v["unusable_reason_before"], v["unusable_reason_after"] = "provider_unavailable", "provider_unavailable"
						if c.before {
							v["unusable_reason_before"] = "none"
						}
						if c.after {
							v["unusable_reason_after"] = "none"
						}
					}, c.valid)
				})
			}
		}
	}
}
