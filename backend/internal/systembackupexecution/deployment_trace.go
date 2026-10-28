package systembackupexecution

import (
	b "clawreef/internal/systembackup/publicadapter"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	"context"
	"errors"
	"github.com/go-sql-driver/mysql"
	"log"
)

func closedExecutionCode(e error) string {
	if e == nil {
		return "ok"
	}
	var failure *b.Failure
	if errors.As(e, &failure) {
		return failure.Error()
	}
	var sqlErr *mysql.MySQLError
	if errors.As(e, &sqlErr) {
		switch sqlErr.Number {
		case 1044, 1045, 1142, 1143, 1227:
			return "sql-permission"
		case 1213:
			return "sql-deadlock"
		case 1205:
			return "sql-lock-timeout"
		default:
			return "sql-unavailable"
		}
	}
	switch {
	case errors.Is(e, c.ErrClaimLost):
		return "claim-lost"
	case errors.Is(e, c.ErrExecutionAuthority):
		return "authority"
	case errors.Is(e, c.ErrExecutionRecoveryRequired):
		return "recovery-required"
	case errors.Is(e, c.ErrExecutionRecord):
		return "record"
	case errors.Is(e, d.ErrNotReady):
		return "dependency"
	case errors.Is(e, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(e, context.Canceled):
		return "canceled"
	default:
		return "unavailable"
	}
}

type deploymentStoreTrace struct{ c.ExecutionWorkStore }

func (s deploymentStoreTrace) Next(ctx context.Context) (*c.ExecutionWork, error) {
	w, e := s.ExecutionWorkStore.Next(ctx)
	if e != nil {
		log.Printf("[system-backup-public] next-work=%s", closedExecutionCode(e))
	}
	if w != nil {
		log.Printf("[system-backup-public] task=%s step=%s", w.Input.Authority.TaskPublicID, w.Step)
	}
	return w, e
}
func (s deploymentStoreTrace) Record(ctx context.Context, w c.ExecutionWork, out c.ExecutionOutcome) error {
	e := s.ExecutionWorkStore.Record(ctx, w, out)
	log.Printf("[system-backup-public] task=%s step=%s runner=%s record=%s", w.Input.Authority.TaskPublicID, w.Step, closedExecutionCode(out.Err), closedExecutionCode(e))
	return e
}
