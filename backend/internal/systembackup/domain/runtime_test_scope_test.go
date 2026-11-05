package domain

import (
	"reflect"
	"testing"
)

func runtimeScopeFixture() []SourceInstance {
	return []SourceInstance{
		{ID: 11, UserID: 2, Generation: 3, Type: "openclaw", Mode: "lite", OS: "linux", Status: "running", Workspace: "/workspaces/a"},
		{ID: 12, UserID: 2, Generation: 1, Type: "hermes", Mode: "pro", OS: "linux", Status: "stopped", Workspace: "/workspaces/b"},
		{ID: 31, UserID: 2, Generation: 0, Type: "opencode", Mode: "lite", OS: "linux", Status: "error", Workspace: ""},
		{ID: 42, UserID: 3, Generation: 2, Type: "deepseek-harness", Mode: "lite", OS: "linux", Status: "error", Workspace: "/workspaces/d"},
	}
}

func TestRuntimeTestScopeKeepsRawSQLAndDefersOnlyExactOriginalRows(t *testing.T) {
	raw := runtimeScopeFixture()
	before := append([]SourceInstance{}, raw...)
	s, e := NewKnownErrorLiteRuntimeTestScope("synthetic-installation", "synthetic-server", "synthetic-db", "synthetic-namespace", raw)
	if e != nil {
		t.Fatal(e)
	}
	selected, e := s.RuntimeInstances(raw)
	if e != nil || !reflect.DeepEqual(selected, raw[:2]) || !reflect.DeepEqual(raw, before) || len(s.Deferred) != 2 || s.Deferred[0].Generation != 0 {
		t.Fatal("scope lost, mutated or incorrectly included raw SQL sources")
	}
	clone := s.Clone()
	clone.Deferred[0].ID = 999
	if s.Deferred[0].ID != 31 || clone.Validate(raw) == nil {
		t.Fatal("clone aliases or altered ID accepted")
	}
	var strict *RuntimeTestScope
	full, e := strict.RuntimeInstances(raw)
	if e != nil || !reflect.DeepEqual(full, raw) || strict.IsDeferred(raw[2]) {
		t.Fatal("default scope deferred a source")
	}
}

func TestRuntimeTestScopeRejectsUnknownErrorsAndEveryOriginalRowDrift(t *testing.T) {
	original := runtimeScopeFixture()
	s, e := NewKnownErrorLiteRuntimeTestScope("synthetic-installation", "synthetic-server", "synthetic-db", "synthetic-namespace", original)
	if e != nil {
		t.Fatal(e)
	}
	changes := map[string]func([]SourceInstance) []SourceInstance{
		"generation":   func(x []SourceInstance) []SourceInstance { x[2].Generation++; return x },
		"status":       func(x []SourceInstance) []SourceInstance { x[2].Status = "running"; return x },
		"type":         func(x []SourceInstance) []SourceInstance { x[2].Type = "hermes"; return x },
		"owner":        func(x []SourceInstance) []SourceInstance { x[2].UserID++; return x },
		"workspace":    func(x []SourceInstance) []SourceInstance { x[2].Workspace = "/changed"; return x },
		"other-source": func(x []SourceInstance) []SourceInstance { x[0].Generation++; return x },
		"new-error": func(x []SourceInstance) []SourceInstance {
			return append(x, SourceInstance{ID: 99, UserID: 3, Type: "opencode", Mode: "lite", Status: "error"})
		},
		"missing": func(x []SourceInstance) []SourceInstance { return x[:3] },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			changed := change(append([]SourceInstance{}, original...))
			if s.Validate(changed) == nil {
				t.Fatal("original scope drift accepted")
			}
			if _, e := s.RuntimeInstances(changed); e == nil {
				t.Fatal("drift returned a runtime projection")
			}
		})
	}
	extra := append(append([]SourceInstance{}, original...), SourceInstance{ID: 99, UserID: 3, Generation: 0, Type: "unknown", Mode: "lite", Status: "error"})
	if _, e := NewKnownErrorLiteRuntimeTestScope("i", "s", "d", "n", extra); e == nil {
		t.Fatal("unknown error accepted during issuance")
	}
}
