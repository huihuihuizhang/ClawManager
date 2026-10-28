package systembackupsecurity

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// MySQL 8.4 rounds fractional timestamp input to a lower-precision column
// unless TIME_TRUNCATE_FRACTIONAL is enabled. The transport explicitly models
// both SQL expressions, so restoring UTC_TIMESTAMP(6) fails at >= .500000.
// This regression does not claim to execute an actual MySQL server.
func TestConfigBackfillServiceAuditSecondPrecision(t *testing.T) {
	for _, name := range []string{"first-half", "half-second", "second-end", "midnight-end"} {
		t.Run(name, func(t *testing.T) {
			s, m, a, scope, original := maintenanceServiceFixture(t)
			now := m.store.base.now.Truncate(time.Second)
			switch name {
			case "first-half":
				now = now.Add(499999 * time.Microsecond)
			case "half-second":
				now = now.Add(500000 * time.Microsecond)
			case "second-end":
				now = now.Add(999999 * time.Microsecond)
			case "midnight-end":
				now = time.Date(now.Year(), now.Month(), now.Day(), 23, 59, 59, 999999000, time.UTC)
			}
			m.store.base.now = now
			m.auditSQLPrecision = true
			a.until = now.Add(time.Minute)
			a.capacityUntil = now.Add(time.Minute)
			r, err := s.apply(context.Background(), scope.key, scope.canonical, original)
			if err != nil || len(r.bytes()) < 2 {
				t.Fatal("whole-second audit input must not round past receipt", err)
			}
			for _, id := range []int64{11, 12} {
				created := m.store.audits[id][5].(time.Time)
				if !created.Equal(now.Truncate(time.Second)) || created.After(now) {
					t.Fatal("stored audit time differs from published precision")
				}
			}
			if m.commits != 1 || m.fills != 1 || m.auditWrites != 2 || m.store.inserts != 1 {
				t.Fatal("precision repair changed atomic effects")
			}
		})
	}
}

func TestConfigBackfillAuditPrecisionMatchesPublishedSchema(t *testing.T) {
	raw, err := os.ReadFile("../db/migrations/001_init_schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	tables := regexp.MustCompile(`(?ms)^CREATE TABLE IF NOT EXISTS audit_logs \(.*?^\) ENGINE=InnoDB[^;]*;`).FindAllString(string(raw), -1)
	if len(tables) != 1 || !strings.Contains(tables[0], "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,") {
		t.Fatal("published audit timestamp precision changed; explicit review required")
	}
}
