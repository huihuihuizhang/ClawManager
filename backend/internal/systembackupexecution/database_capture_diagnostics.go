package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"time"

	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
)

func bindOriginalControlWorker(ctx context.Context, tx *sql.Tx, store c.SQLExecutionAuthority, authority d.Authority, request worker.ControlRequest) (*c.ExecutionAuthorityGuard, error) {
	if request.Action == "key-check" && request.Invocation.Request.Database != nil {
		return store.BindObserved(ctx, tx, authority, logOriginalDatabaseBindDiagnostic)
	}
	return store.Bind(ctx, tx, authority)
}

func logOriginalDatabaseBindDiagnostic(v c.ExecutionBindDiagnostic) {
	log.Printf("[system-backup-database] stage=controller-key-check-bind boundary=%s class=%s sql_number=%d sql_state=%s reason=%s", v.Stage(), v.Class(), v.SQLNumber(), v.SQLState(), v.Reason())
}

func logOriginalDatabaseControlRejection(stage string, ctx context.Context, until time.Time) {
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
	log.Printf("[system-backup-database] stage=%s context=%s execution_bound_known=%t execution_remaining_us=%d", stage, state, !until.IsZero(), remaining)
}

// The original key row is ALREADY read under the same original transaction.
// Parse it only after rejection for fixed diagnostic classification. This does
// not authorize a row, adopt current.Until or change advanceKeyUse's result.
func logOriginalDatabaseKeyUseRejection(now time.Time, current worker.KeyUseLease, raw []byte) {
	reason := "key_use_rejected"
	var original worker.KeyUseLease
	known := false
	if len(raw) > 0 && len(raw) <= 16384 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		known = decoder.Decode(&original) == nil && decoder.Decode(new(any)) == io.EOF && !original.Until.IsZero()
	}
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
	keyRemaining := int64(0)
	if known && !now.IsZero() {
		keyRemaining = original.Until.Sub(now).Microseconds()
	}
	currentRemaining := int64(0)
	if !now.IsZero() && !current.Until.IsZero() {
		currentRemaining = current.Until.Sub(now).Microseconds()
	}
	log.Printf("[system-backup-database] stage=controller-key-use-transition reason=%s original_key_known=%t original_key_remaining_us=%d current_execution_remaining_us=%d", reason, known, keyRemaining, currentRemaining)
}
