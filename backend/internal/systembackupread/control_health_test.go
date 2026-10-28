package systembackupread

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

func controlHealthFixture() *overviewFixture {
	f := newOverviewFixture()
	now := f.state[14].(time.Time)
	f.health = []driver.Value{"system-backup-control-health.v1", "installation_test", int64(3), int64(4), "controller:pod-uid", int64(8),
		"healthy", "degraded", now.Add(-time.Second), now.Add(29 * time.Second), int64(10)}
	return f
}

func TestControlHealthReadUsesSameAuthoritySnapshotAndCannotBecomePublicOverview(t *testing.T) {
	f := controlHealthFixture()
	result, err := overviewReader(t, f).ReadControlHealth(context.Background())
	if err != nil || result.ControllerHealth() != "healthy" || result.DatabaseHealth() != "degraded" || f.rechecks != 1 || f.commits != 1 {
		t.Fatal("health observation lost its snapshot/authority", result, err)
	}
	if _, err := json.Marshal(result); err == nil {
		t.Fatal("partial D health serialized as a public resource")
	}
}

func TestControlHealthExpiryAndNewEpochStayDistinct(t *testing.T) {
	for _, interval := range []int64{1, 5, 10, 60} {
		t.Run(fmt.Sprintf("interval_%d", interval), func(t *testing.T) {
			ttl := time.Duration(3*interval) * time.Second
			for _, test := range []struct {
				name     string
				age      time.Duration
				sequence int64
				want     string
			}{
				{"fresh", time.Second, 8, "healthy"}, {"just before expiry", ttl - time.Microsecond, 8, "healthy"},
				{"expiry boundary", ttl, 8, "stale"}, {"long expired", time.Hour, 8, "stale"},
				{"new leader without an observation", time.Second, 0, "unknown"},
			} {
				t.Run(test.name, func(t *testing.T) {
					f := controlHealthFixture()
					now := f.state[14].(time.Time)
					f.health[5] = test.sequence
					f.health[10] = interval
					f.health[8] = now.Add(-test.age)
					f.health[9] = now.Add(ttl - test.age)
					if test.sequence == 0 {
						f.health[6], f.health[7] = "unknown", "unknown"
					}
					result, err := overviewReader(t, f).ReadControlHealth(context.Background())
					if err != nil || result.ControllerHealth() != test.want {
						t.Fatal(result, err)
					}
				})
			}
		})
	}
}

func TestControlHealthMissingBadOrUncommittedObservationsReturnNoResult(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*overviewFixture)
	}{
		{"missing", func(f *overviewFixture) { f.health = nil }},
		{"SQL unavailable", func(f *overviewFixture) { f.queryError = controlHealthSQL }},
		{"schema", func(f *overviewFixture) { f.health[0] = "other.v1" }},
		{"installation", func(f *overviewFixture) { f.health[1] = "installation_other" }},
		{"old config", func(f *overviewFixture) { f.health[2] = int64(2) }},
		{"zero epoch", func(f *overviewFixture) { f.health[3] = int64(0) }},
		{"unsafe epoch", func(f *overviewFixture) { f.health[3] = int64(9007199254740992) }},
		{"writer identity", func(f *overviewFixture) { f.health[4] = "" }},
		{"unknown after observation", func(f *overviewFixture) { f.health[6] = "unknown" }},
		{"healthy without observation", func(f *overviewFixture) { f.health[5] = int64(0) }},
		{"future clock", func(f *overviewFixture) { f.health[8] = f.state[14].(time.Time).Add(time.Second) }},
		{"wrong expiry", func(f *overviewFixture) { f.health[9] = f.health[8].(time.Time).Add(time.Hour) }},
		{"expired fixed 30s window with 5s interval", func(f *overviewFixture) {
			now := f.state[14].(time.Time)
			f.health[8], f.health[9], f.health[10] = now.Add(-31*time.Second), now.Add(-time.Second), int64(5)
		}},
		{"invalid interval", func(f *overviewFixture) { f.health[10] = int64(0) }},
		{"revocation", func(f *overviewFixture) { f.recheckErr = ErrDenied }},
		{"commit reply lost", func(f *overviewFixture) { f.commitErr = errors.New("reply lost") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := controlHealthFixture()
			test.change(f)
			result, err := overviewReader(t, f).ReadControlHealth(context.Background())
			if err == nil || result != (ControlHealthSnapshot{}) {
				t.Fatal("unverified health escaped", result, err)
			}
		})
	}
}
