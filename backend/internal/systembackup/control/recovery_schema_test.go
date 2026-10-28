package control

import (
	"context"
	"database/sql/driver"
	"os"
	"strings"
	"testing"
)

func TestRecoveryOperationsUpgradeMatchesFreshSchema(t *testing.T) {
	b, e := os.ReadFile("upgrade-recovery-operations.sql")
	if e != nil {
		t.Fatal(e)
	}
	normalize := func(s string) string { return strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n")) }
	if !strings.Contains(normalize(Schema), normalize(string(b))) {
		t.Fatal("fresh schema and explicit upgrade differ")
	}
}
func TestTerminalGateRejectsUnresolvedRecoveryWork(t *testing.T) {
	task, _, _, _ := redisFixture()
	task.Status = "verifying"
	steps := append(workerCommit(task), sqlStep{contains: "FROM system_backup_tasks", rows: [][]driver.Value{taskRow(task)}}, sqlStep{contains: "system_backup_redis_items", rows: [][]driver.Value{{int64(1)}}, checkArgs: func(args []driver.NamedValue) {
		if len(args) != 11 || args[9].Value != "succeeded" {
			t.Fatal("missing terminal recovery bindings")
		}
	}})
	s, script := scriptStore(t, steps...)
	if _, e := s.Advance(context.Background(), task, "succeeded", ""); e == nil || script.writes != 0 {
		t.Fatal("unresolved recovery marked successful", e)
	}
}
