package domain

import "testing"

func TestRunningOnlyRuntimeTestScopeRetainsCompleteSQL(t *testing.T) {
	rows := []SourceInstance{
		{ID: 7, UserID: 3, Generation: 1, Type: "openclaw", Mode: "lite", Status: "running", OS: "linux"},
		{ID: 8, UserID: 3, Generation: 1, Type: "hermes", Mode: "lite", Status: "running", OS: "linux"},
		{ID: 11, UserID: 3, Generation: 1, Type: "openclaw", Mode: "lite", Status: "running", OS: "linux"},
		{ID: 12, UserID: 3, Generation: 1, Type: "openclaw", Mode: "pro", Status: "stopped", OS: "linux"},
		{ID: 13, UserID: 3, Generation: 1, Type: "opencode", Mode: "lite", Status: "error", OS: "linux"},
		{ID: 14, UserID: 3, Generation: 1, Type: "deepseek-harness", Mode: "lite", Status: "error", OS: "linux"},
	}
	scope, err := NewRunningOnlyRuntimeTestScope("installation", "server", "db", "namespace-uid", rows)
	if err != nil || scope.Version != RunningOnlyRuntimeTestScopeVersion || len(scope.Deferred) != 3 || scope.Deferred[0] != rows[3] {
		t.Fatal("exact v2 scope was not produced", err)
	}
	runtime, err := scope.RuntimeInstances(rows)
	if err != nil || len(runtime) != 3 || runtime[0] != rows[0] || runtime[1] != rows[1] || runtime[2] != rows[2] || len(rows) != 6 {
		t.Fatal("runtime projection changed SQL inventory", err)
	}
	v1, err := NewKnownErrorLiteRuntimeTestScope("installation", "server", "db", "namespace-uid", rows)
	if err != nil || v1.Version != RuntimeTestScopeVersion || v1.IsDeferred(rows[3]) {
		t.Fatal("legacy scope unexpectedly deferred Pro", err)
	}
	changed := append([]SourceInstance(nil), rows...)
	changed[3].Generation++
	if scope.Validate(changed) == nil || scope.Validate(rows[:5]) == nil {
		t.Fatal("changed complete source accepted")
	}
	changed[0].Status = "stopped"
	if _, err := NewRunningOnlyRuntimeTestScope("installation", "server", "db", "namespace-uid", changed); err == nil {
		t.Fatal("extra stopped source accepted")
	}
}

func TestRunningTenantRuntimeTestScope(t *testing.T) {
	rows := []SourceInstance{
		{ID: 1, UserID: 1, Generation: 1, Type: "openclaw", Mode: "lite", Backend: "gateway", Status: "running", OS: "linux"},
		{ID: 2, UserID: 1, Generation: 1, Type: "openclaw", Mode: "pro", Backend: "desktop", Pod: "tenant-pod", Namespace: "tenant", Status: "running", OS: "linux"},
		{ID: 3, UserID: 1, Generation: 1, Type: "hermes", Mode: "lite", Backend: "gateway", Status: "running", OS: "linux"},
		{ID: 4, UserID: 1, Type: "deepseek-harness", Mode: "lite", Backend: "gateway", Status: "error", OS: "linux"},
		{ID: 5, UserID: 1, Generation: 1, Type: "openclaw", Mode: "lite", Backend: "gateway", Status: "stopped", OS: "linux"},
		{ID: 6, UserID: 1, Type: "opencode", Mode: "lite", Backend: "gateway", Status: "error", OS: "linux"},
		{ID: 7, UserID: 1, Generation: 1, Type: "openclaw", Mode: "lite", Backend: "gateway", Status: "running", OS: "linux"},
		{ID: 8, UserID: 1, Generation: 1, Type: "openclaw", Mode: "lite", Backend: "gateway", Status: "running", OS: "linux"},
	}
	scope, err := NewRunningOnlyRuntimeTestScope("installation", "server", "db", "namespace-uid", rows)
	if err != nil || scope.Version != RunningTenantRuntimeTestScopeVersion || !scope.RunningOnly() {
		t.Fatal("running tenant scope rejected", err)
	}
	active, err := scope.RuntimeInstances(rows)
	if err != nil || len(active) != 5 || active[1] != rows[1] || !scope.IsDeferred(rows[3]) || !scope.IsDeferred(rows[4]) || !scope.IsDeferred(rows[5]) {
		t.Fatal("wrong runtime roster", active, err)
	}
	rows[3].Pod = "unresolved-writer"
	if _, err := NewRunningOnlyRuntimeTestScope("installation", "server", "db", "namespace-uid", rows); err == nil {
		t.Fatal("an error instance with a Pod was deferred")
	}
}
