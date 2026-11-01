package worker

import (
	"context"
	"errors"
	"log"
	"time"
)

func logOriginalDescriptionWorkerFailure(stage, action string, ctx context.Context, until time.Time, status int, cause error) {
	class := "rejected"
	if ctx == nil {
		class = "context_missing"
	} else if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(cause, context.DeadlineExceeded) {
		class = "context_deadline"
	} else if ctx.Err() != nil || errors.Is(cause, context.Canceled) {
		class = "context_canceled"
	}
	switch action {
	case "ready", "key-reserve", "key-check", "key-begin", "key-end", "candidate", "description-pull":
	default:
		action = "other"
	}
	remaining := int64(0)
	if !until.IsZero() {
		remaining = time.Until(until).Microseconds()
	}
	log.Printf("[system-backup-description] stage=%s action=%s class=%s http_status=%d bound_known=%t remaining_us=%d", stage, action, class, status, !until.IsZero(), remaining)
}
