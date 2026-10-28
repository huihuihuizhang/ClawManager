package profile

import (
	"testing"

	"clawreef/internal/systembackup/worker"
)

func TestPreflightUsesFrozenRestorePolicyAndLimits(t *testing.T) {
	source := identitySnapshotFixture()
	for _, name := range []string{"valid", "missing", "nil", "duplicate", "rows", "memory"} {
		t.Run(name, func(t *testing.T) {
			spec := &worker.DatabaseSpec{MaxRows: 100, MaxMemoryBytes: 1 << 20}
			w := work{Invocation: worker.Invocation{Request: worker.Request{Operation: "restore-database", Database: spec}}}
			p := plan{Work: []work{w}}
			switch name {
			case "missing":
				p.Work = nil
			case "nil":
				p.Work[0].Invocation.Request.Database = nil
			case "duplicate":
				p.Work = append(p.Work, w)
			case "rows":
				spec.MaxRows = 1
			case "memory":
				spec.MaxMemoryBytes = 1
			}
			got, e := preflightSpec(p, source)
			if name == "valid" {
				if e != nil || got != spec {
					t.Fatal("preflight lost frozen policy", e)
				}
			} else if e == nil {
				t.Fatal("invalid restore preflight accepted")
			}
		})
	}
}
