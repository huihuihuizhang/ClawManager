package systembackupcontroller

import (
	"errors"
	"fmt"
	"time"
)

// PendingQueueBudget contains only the immutable timestamps needed by the
// D-owned queue alert projection. The caller must select pending rows and
// supply database time; no process-clock reading is performed here.
type PendingQueueBudget struct {
	CreatedAt  time.Time
	DeadlineAt time.Time
}

// MaxPendingQueueDeadlineUtilization returns the maximum elapsed fraction of
// the frozen deadline window. An empty pending group emits zero. A nonpositive
// window is already exhausted and emits one, never a healthy-looking zero.
func MaxPendingQueueDeadlineUtilization(databaseNow time.Time, pending []PendingQueueBudget) (float64, error) {
	if databaseNow.IsZero() {
		return 0, errors.New("missing database time for queue budget")
	}
	maximum := 0.0
	for index, item := range pending {
		if item.CreatedAt.IsZero() || item.DeadlineAt.IsZero() {
			return 0, fmt.Errorf("pending queue budget %d has a missing timestamp", index)
		}
		window := item.DeadlineAt.Sub(item.CreatedAt)
		ratio := 1.0
		if window > 0 {
			elapsed := databaseNow.Sub(item.CreatedAt)
			if elapsed < 0 {
				elapsed = 0
			}
			ratio = float64(elapsed) / float64(window)
		}
		if ratio > maximum {
			maximum = ratio
		}
	}
	return maximum, nil
}
