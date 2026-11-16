package quiesce

import (
	"strings"
	"testing"
	"time"
)

// Correlation and seal DATA tests only; native process coverage is separate.
func TestColdProcessKindCannotBecomeFilesystemCut(t *testing.T) {
	r := nodeGatewayZeroWholeRequest()
	r.Binding.Kind = NodeObservationColdProcesses
	r.SourcePaths = nil
	if !nodeObservationPhaseDataValid(r, r.Binding.Node) {
		t.Fatal("process prepare refused")
	}
	r.SourcePaths = []string{"/invented-root"}
	if nodeObservationPhaseDataValid(r, r.Binding.Node) {
		t.Fatal("process proof accepted file scope")
	}
	r.Binding.Kind = NodeObservationWholePodColdCut
	r.SourcePaths = nil
	if nodeObservationPhaseDataValid(r, r.Binding.Node) {
		t.Fatal("empty host cut accepted")
	}
	for _, action := range []string{"prepare", "stopped", "recovery-stopped", "recovered", "recovery-source-stopped", "recovery-reconciled"} {
		facts := nodeProcessFacts(action)
		if len(facts) == 0 {
			t.Fatal("missing process phase", action)
		}
		for _, fact := range facts {
			if strings.Contains(fact, "mount") || strings.Contains(fact, "writer") || strings.Contains(fact, "source_fd") {
				t.Fatal("filesystem claim leaked", fact)
			}
		}
	}
}

func TestColdProcessRecoveryKeepsOriginalKindAndActorScope(t *testing.T) {
	for _, action := range []string{"recovery-source-stopped", "recovery-reconciled"} {
		t.Run(action, func(t *testing.T) {
			o, r, anchor := scopedRecoveryData(t, action)
			r.Binding.Kind = NodeObservationColdProcesses
			anchor.Binding, anchor.Paths = r.Binding, nil
			var err error
			r.Anchor, err = o.seal(anchor)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = o.originalNodeObservationAnchor(r, time.Now()); err != nil {
				t.Fatal(err)
			}
			hash, err := OriginalRecoveryScopeSHA256(r, r.RecoveryAffectedPods)
			if err != nil || hash == "" {
				t.Fatal("process recovery scope not pinned", err)
			}
			r.Binding.Kind = NodeObservationWholePodColdCut
			if _, err = o.originalNodeObservationAnchor(r, time.Now()); err == nil {
				t.Fatal("process seal relabeled as host cut")
			}
			r.Binding.Kind = NodeObservationColdProcesses
			r.Pods[0].UID = "foreign-original"
			if _, err = o.originalNodeObservationAnchor(r, time.Now()); err == nil {
				t.Fatal("foreign actor accepted")
			}
		})
	}
}
