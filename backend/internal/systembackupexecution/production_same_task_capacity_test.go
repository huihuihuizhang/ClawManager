package systembackupexecution

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	security "clawreef/internal/systembackupsecurity"
)

// Explicit LOCAL capacity input fixture, not physical volume certification or
// a replacement for CollectPinnedRegistrationCapacity. The production consumer
// keeps its original identity/five-second freshness/reservation checks.
func (f *dOriginalSixPartTask) startLocalCapacityInput(parent context.Context, t *testing.T) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	sample := func() error {
		var now time.Time
		if err := f.db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
			return err
		}
		raw, err := json.Marshal(security.CapacityReport{ServerUUID: f.server, Database: f.database, ObservedAt: now, AllocatedBytes: 1 << 20, AvailableBytes: 4 << 30})
		if err != nil {
			return err
		}
		return security.WriteCapacityReport(f.service.Config.CapacityFile, raw)
	}
	if err := sample(); err != nil {
		cancel()
		t.Fatal("local independent capacity input", err)
	}
	done := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				done <- nil
				return
			case <-ticker.C:
				if err := sample(); err != nil {
					if ctx.Err() != nil {
						done <- nil
					} else {
						done <- err
					}
					return
				}
			}
		}
	}()
	return func() {
		cancel()
		if err := <-done; err != nil {
			t.Error("local capacity input sampler", err)
		}
	}
}
