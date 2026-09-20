package systembackupcontroller

import (
	"testing"
	"time"
)

func TestMaxPendingQueueDeadlineUtilizationUsesFrozenWindows(t *testing.T) {
	created := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	now := created.Add(30 * time.Second)
	budgets := []PendingQueueBudget{
		{CreatedAt: created, DeadlineAt: created.Add(60 * time.Second)},
		{CreatedAt: created.Add(10 * time.Second), DeadlineAt: created.Add(30 * time.Second)},
	}
	ratio, err := MaxPendingQueueDeadlineUtilization(now, budgets)
	if err != nil || ratio != 1 {
		t.Fatalf("max frozen utilization ratio=%v err=%v", ratio, err)
	}
	ratio, err = MaxPendingQueueDeadlineUtilization(created.Add(15*time.Second), budgets[:1])
	if err != nil || ratio != 0.25 {
		t.Fatalf("quarter-window utilization ratio=%v err=%v", ratio, err)
	}
	ratio, err = MaxPendingQueueDeadlineUtilization(created.Add(90*time.Second), budgets[:1])
	if err != nil || ratio != 1.5 {
		t.Fatalf("overdue utilization was clipped: ratio=%v err=%v", ratio, err)
	}
}

func TestMaxPendingQueueDeadlineUtilizationFailClosedBounds(t *testing.T) {
	created := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	for _, budget := range []PendingQueueBudget{
		{CreatedAt: created, DeadlineAt: created},
		{CreatedAt: created, DeadlineAt: created.Add(-time.Second)},
	} {
		ratio, err := MaxPendingQueueDeadlineUtilization(created, []PendingQueueBudget{budget})
		if err != nil || ratio < 1 {
			t.Fatalf("nonpositive frozen window ratio=%v err=%v", ratio, err)
		}
	}
	ratio, err := MaxPendingQueueDeadlineUtilization(created, nil)
	if err != nil || ratio != 0 {
		t.Fatalf("empty pending group ratio=%v err=%v", ratio, err)
	}
	ratio, err = MaxPendingQueueDeadlineUtilization(created.Add(-time.Second), []PendingQueueBudget{{CreatedAt: created, DeadlineAt: created.Add(time.Second)}})
	if err != nil || ratio != 0 {
		t.Fatalf("future creation ratio=%v err=%v", ratio, err)
	}
	if _, err := MaxPendingQueueDeadlineUtilization(time.Time{}, nil); err == nil {
		t.Fatal("missing database time was accepted")
	}
	if _, err := MaxPendingQueueDeadlineUtilization(created, []PendingQueueBudget{{CreatedAt: created}}); err == nil {
		t.Fatal("missing pending-row deadline was accepted")
	}
}
