package worker

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"clawreef/internal/systembackup/domain"
)

// Attach diagnostics only to this database invocation, never the frozen
// request, candidate receipt, control protocol, claim or publication evidence.
// The synchronous final report also runs on rejection/unknown provider outcome.
func startDatabaseCaptureTiming(ctx context.Context, i Invocation, job formalKeyUse, env *FormalCaptureEnvironment) (context.Context, func(error)) {
	if i.Request.Database == nil {
		return ctx, func(error) {}
	}
	digest, err := i.Hash()
	if err != nil {
		return ctx, func(error) {}
	}
	timings := &domain.CaptureTimings{}
	ctx = domain.WithCaptureTimings(ctx, timings)
	finishTotal := domain.BeginCaptureTiming(ctx, domain.CaptureWorkerTotal)
	var keyUntil time.Time
	if original, ok := job.(*CaptureKeyJob); ok && original != nil {
		keyUntil = original.until
	}
	keyWindow := captureDeadlineSample(keyUntil)
	sourceWindow := captureDeadlineSample(env.SourceValidUntil)
	requestWindow := captureDeadlineSample(i.Request.Deadline)
	if original := env.SourceAuthorize; original != nil {
		env.SourceAuthorize = func(ctx context.Context, inv Invocation) error {
			finish := domain.BeginCaptureTiming(ctx, domain.CaptureSourceAuthorize)
			err := original(ctx, inv)
			finish.Finish(err)
			return err
		}
	}
	return ctx, func(err error) {
		finishTotal.Finish(err)
		keyWindow.finish(keyUntil)
		sourceWindow.finish(env.SourceValidUntil)
		requestWindow.finish(i.Request.Deadline)
		report := struct {
			Version           string                       `json:"schema_version"`
			InvocationSHA256  string                       `json:"invocation_sha256"`
			CandidateReturned bool                         `json:"candidate_returned"`
			Samples           []domain.CaptureTimingSample `json:"samples"`
			KeyWindow         captureDeadlineTiming        `json:"original_key_window"`
			SourceWindow      captureDeadlineTiming        `json:"source_window"`
			RequestWindow     captureDeadlineTiming        `json:"request_window"`
		}{"database-capture-timing.v1", digest, err == nil, timings.Snapshot(), keyWindow, sourceWindow, requestWindow}
		encoded, encodeErr := json.Marshal(report)
		if encodeErr == nil {
			log.Printf("[system-backup-database-timing] %s", encoded)
		}
	}
}

// Separate original bounds, in remaining microseconds, never an inferred
// effective lease or authorization. Unknown key bounds (e.g. a test model) stay
// unknown; a negative end value must not be clamped or interpreted as permission.
type captureDeadlineTiming struct {
	Known            bool  `json:"known"`
	StartRemainingUS int64 `json:"start_remaining_us"`
	EndRemainingUS   int64 `json:"end_remaining_us"`
}

func captureDeadlineSample(until time.Time) captureDeadlineTiming {
	if until.IsZero() {
		return captureDeadlineTiming{}
	}
	return captureDeadlineTiming{Known: true, StartRemainingUS: time.Until(until).Microseconds()}
}

func (s *captureDeadlineTiming) finish(until time.Time) {
	if s.Known {
		s.EndRemainingUS = time.Until(until).Microseconds()
	}
}

// The exact original operation runs once with its original context. Timing
// never caches a result, catches an error or changes the before/after order.
func measuredCaptureKeyCheck(ctx context.Context, check func(context.Context) error) error {
	finish := domain.BeginCaptureTiming(ctx, domain.CaptureKeyCheck)
	err := check(ctx)
	finish.Finish(err)
	return err
}
