package systembackupexecution

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// Detached time DATA tests only, never a synthetic authorized observation.
// The production entry calls both actual concrete readers before this join.
func TestRuntimeSixPartWindowPreservesFirstObservationAndMinimumDeadline(t *testing.T) {
	start := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	for _, fault := range []string{"current", "source-expired", "publisher-expired", "original-expired", "clock-backward", "source-before-start", "publisher-future", "publisher-not-before"} {
		t.Run(fault, func(t *testing.T) {
			now, original := start.Add(4*time.Second), start.Add(30*time.Second)
			source := SourceDependencyObservation{checkedAt: start.Add(time.Second), until: start.Add(20 * time.Second)}
			publisher := PublicationDependencyObservation{checkedAt: start.Add(2 * time.Second), notBefore: start.Add(-time.Minute), until: start.Add(10 * time.Second)}
			switch fault {
			case "source-expired":
				source.until = now
			case "publisher-expired":
				publisher.until = now
			case "original-expired":
				original = now
			case "clock-backward":
				now = start.Add(-time.Microsecond)
			case "source-before-start":
				source.checkedAt = start.Add(-time.Microsecond)
			case "publisher-future":
				publisher.checkedAt = now.Add(time.Microsecond)
			case "publisher-not-before":
				publisher.notBefore = now.Add(time.Microsecond)
			}
			until, err := runtimeReadinessWindow(start, now, original, source, publisher)
			if (err == nil) != (fault == "current") || err == nil && !until.Equal(publisher.until) {
				t.Fatal("original window renewed, expired evidence accepted, or minimum lost", fault, until, err)
			}
		})
	}
}

func TestRuntimeSixPartReadinessDoesNotPromoteMissingSourceOrProvider(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, scope := range []string{"six-part", "platform-workspace", "runtime-workspace"} {
		s := &DeploymentService{ForwardEnabled: true, Config: DeploymentConfig{CaptureScope: scope}}
		if proof, err := s.observeSixPartRuntimeReadiness(ctx); err == nil || proof != nil {
			t.Fatal("missing original runtime/consumer/provider produced a readiness proof")
		}
		if s.runtimeReadiness.Load() != nil || s.publishedSixPartCapability() {
			t.Fatal("failed observation cached an approval")
		}
		var public struct {
			Parts      []string `json:"parts"`
			Acceptance bool     `json:"acceptance_ready"`
		}
		if json.Unmarshal(s.PublicCapability(), &public) != nil || public.Acceptance || scope == "six-part" && len(public.Parts) != 0 || scope != "six-part" && (len(public.Parts) != 1 || public.Parts[0] != "workspace") {
			t.Fatal("missing runtime promoted capability or changed workspace semantics")
		}
	}
}
