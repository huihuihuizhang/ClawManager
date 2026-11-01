package systembackupexecution

import (
	"context"
	"errors"
	"log"
	"time"

	"clawreef/internal/systembackup/worker"
	cd "clawreef/internal/systembackupcapturedescription"
	c "clawreef/internal/systembackupcontroller"
	"github.com/go-sql-driver/mysql"
)

func originalDescriptionControlRequest(request worker.ControlRequest) bool {
	return request.Invocation.Request.Operation == cd.Operation && request.Invocation.Request.CaptureDescription != nil
}

// Log fixed phase/class/driver metadata only. Never format an error message,
// request, authority, SQL argument, token, source record or response body.
func logOriginalDescriptionFailure(stage string, ctx context.Context, until time.Time, claimVersion, epoch uint64, cause error) {
	class := "authority_or_record"
	if ctx == nil {
		class = "context_missing"
	} else if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(cause, context.DeadlineExceeded) {
		class = "context_deadline"
	} else if ctx.Err() != nil || errors.Is(cause, context.Canceled) {
		class = "context_canceled"
	}
	number, state := uint16(0), "00000"
	var sqlErr *mysql.MySQLError
	if errors.As(cause, &sqlErr) {
		number = sqlErr.Number
		state = string(sqlErr.SQLState[:])
		for _, b := range sqlErr.SQLState {
			if b < '0' || b > '9' && b < 'A' || b > 'Z' {
				state = "invalid"
				break
			}
		}
	}
	remaining := int64(0)
	if !until.IsZero() {
		remaining = time.Until(until).Microseconds()
	}
	log.Printf("[system-backup-description] stage=%s class=%s sql_number=%d sql_state=%s claim_version=%d epoch=%d bound_known=%t remaining_us=%d", stage, class, number, state, claimVersion, epoch, !until.IsZero(), remaining)
}

func logOriginalDescriptionBindDiagnostic(v c.ExecutionBindDiagnostic) {
	log.Printf("[system-backup-description] stage=controller-key-check-bind boundary=%s class=%s sql_number=%d sql_state=%s reason=%s", v.Stage(), v.Class(), v.SQLNumber(), v.SQLState(), v.Reason())
}

func logOriginalDescriptionKeyUseRejection(now time.Time, current worker.KeyUseLease, raw []byte) {
	var original worker.KeyUseLease
	known := len(raw) > 0 && len(raw) <= 16384 && decodeProviderDeploymentJSON(raw, &original) == nil && !original.Until.IsZero()
	reason := "original_identity_or_state_mismatch"
	switch {
	case now.IsZero():
		reason = "clock_missing"
	case !now.Before(current.Until):
		reason = "current_execution_bound_expired"
	case !known:
		reason = "original_key_record_unavailable"
	case !now.Before(original.Until):
		reason = "original_key_window_expired"
	case current.Until.Before(original.Until):
		reason = "current_execution_bound_shorter"
	}
	remaining := int64(0)
	if known && !now.IsZero() {
		remaining = original.Until.Sub(now).Microseconds()
	}
	log.Printf("[system-backup-description] stage=controller-key-use-transition reason=%s original_key_known=%t original_key_remaining_us=%d", reason, known, remaining)
}
