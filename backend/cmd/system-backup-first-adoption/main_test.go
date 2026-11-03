package main

import (
	"bytes"
	"context"
	"testing"
)

func TestFirstAdoptionCLIRejectsUnselectedAuthority(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"empty", nil},
		{"unknown_action", []string{"-action", "grant-from-json"}},
		{"diagnostic_is_separate", []string{"-mode", "round-trip"}},
		{"caller_coverage_refused", []string{"-coverage-file", "caller.json"}},
		{"caller_evidence_refused", []string{"-records-file", "caller.json"}},
		{"claim_json_refused", []string{"-reservation-file", "caller.json"}},
		{"key_argv_refused", []string{"-private-key", "forbidden"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if run(context.Background(), tc.args, &out) != 2 || out.Len() != 0 {
				t.Fatal("unselected source/authority reached production caller")
			}
		})
	}
	if run(nil, nil, &bytes.Buffer{}) != 2 || run(context.Background(), nil, nil) != 2 {
		t.Fatal("missing caller dependency accepted")
	}
}
