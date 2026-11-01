package systembackupexecution

import (
	"context"
	"log"
	"time"

	c "clawreef/internal/systembackupcontroller"
)

// Stage values are source-code literals, never error/request/payload strings.
// No SQL/provider work is performed and no authorization decision is changed.
func logOriginalControlEvidenceRejection(stage string, ctx context.Context, until time.Time, started time.Time) {
	state := "active"
	if ctx == nil {
		state = "missing"
	} else if ctx.Err() == context.DeadlineExceeded {
		state = "deadline"
	} else if ctx.Err() != nil {
		state = "canceled"
	}
	remaining := int64(0)
	if !until.IsZero() {
		remaining = time.Until(until).Microseconds()
	}
	log.Printf("[system-backup-ce] stage=%s sentinel=ce_rejected context=%s remaining_us=%d elapsed_us=%d", stage, state, remaining, time.Since(started).Microseconds())
}

func logOriginalExecutionBindDiagnostic(v c.ExecutionBindDiagnostic) {
	log.Printf("[system-backup-ce] stage=controller-source-execution-bind-detail boundary=%s class=%s sql_number=%d sql_state=%s", v.Stage(), v.Class(), v.SQLNumber(), v.SQLState())
}
