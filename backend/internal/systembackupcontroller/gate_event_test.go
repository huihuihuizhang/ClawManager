package systembackupcontroller

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestInsertGateTransitionEventUsesClosedRedactedSystemProjection(t *testing.T) {
	executor := &recordedExec{rows: 1}
	err := insertGateTransitionEvent(
		context.Background(), executor, validGateKey(), GateIdle, GateAcquiring,
		gateReasonCaptureRequested, "Maintenance gate acquisition started.",
	)
	if err != nil {
		t.Fatalf("insertGateTransitionEvent: %v", err)
	}
	if len(executor.queries) != 1 || len(executor.args) != 1 {
		t.Fatalf("queries=%#v args=%#v", executor.queries, executor.args)
	}
	query := executor.queries[0]
	for _, required := range []string{
		"INSERT INTO system_backup_events",
		"'system'",
		"'gate_changed'",
		"'info'",
		"task_status",
		"details_present",
		"detail_previous_status",
		"detail_current_status",
		"detail_reason",
		"request_id",
	} {
		if !strings.Contains(query, required) {
			t.Fatalf("event SQL missing %q: %s", required, query)
		}
	}
	wantArgs := []any{
		"installation_primary",
		"installation_primary",
		"Maintenance gate acquisition started.",
		GateIdle,
		GateAcquiring,
		gateReasonCaptureRequested,
	}
	if !reflect.DeepEqual(executor.args[0], wantArgs) {
		t.Fatalf("event args=%#v want=%#v", executor.args[0], wantArgs)
	}
}

func TestInsertGateTransitionEventRequiresExactlyOneRowAndValidStates(t *testing.T) {
	executor := &recordedExec{rows: 0}
	if err := insertGateTransitionEvent(context.Background(), executor, validGateKey(), GateHeld, GateReleasing, gateReasonReleaseRequested, "Maintenance gate release started."); err == nil {
		t.Fatal("zero-row gate event accepted")
	}
	executor = &recordedExec{rows: 1}
	if err := insertGateTransitionEvent(context.Background(), executor, validGateKey(), GateState("unknown"), GateIdle, gateReasonAcquisitionAborted, "Maintenance gate acquisition aborted."); err == nil {
		t.Fatal("invalid gate event state accepted")
	}
	if len(executor.queries) != 0 {
		t.Fatalf("invalid gate event reached persistence: %#v", executor.queries)
	}
}
