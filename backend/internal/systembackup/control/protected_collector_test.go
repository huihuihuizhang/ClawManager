package control

import (
	"context"
	"database/sql/driver"
	"testing"

	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/recovery"
)

type protectedFixture struct {
	id                string
	stopped, prepared int
}

func (c *protectedFixture) ID() string                    { return c.id }
func (c *protectedFixture) Prepare(context.Context) error { c.prepared++; return nil }
func (c *protectedFixture) Capture(context.Context) (flow.Part, error) {
	return flow.Part{ID: c.id}, nil
}
func (c *protectedFixture) Stop(context.Context) error { c.stopped++; return nil }
func TestProtectedCollectorsReleaseOnlyTheirOwnConsumerAfterStop(t *testing.T) {
	task, _, rows := guardFixture(t)
	task.Request.Kind = "drill"
	task.Request.Artifact = "sb-source"
	for _, id := range []string{"workspace", "redis"} {
		consumer := recovery.Hash([]byte(id))
		steps := append(guardSteps(task), sqlStep{contains: "AND consumer_id=?", rows: [][]driver.Value{{task.Generation, task.Deadline, false}}, checkArgs: func(a []driver.NamedValue) {
			if a[2].Value != consumer {
				t.Fatal("adopted other consumer")
			}
		}})
		steps = append(steps, guardSteps(task)...)
		steps = append(steps, guardRow(rows[0]), sqlStep{contains: "SELECT generation,released", rows: [][]driver.Value{{task.Generation, false}}}, sqlStep{contains: "AND consumer_id=? AND generation=?", affected: 1, checkArgs: func(a []driver.NamedValue) {
			if a[3].Value != consumer {
				t.Fatal("released other consumer")
			}
		}}, sqlStep{contains: "UPDATE system_backup_recovery_guards", affected: 1})
		steps = append(steps, workerCommit(task)...)
		s, script := scriptStore(t, steps...)
		source := &protectedFixture{id: id}
		c := ProtectedCollector{Guards: RecoveryGuards{s, task}, Artifact: rows[0].ID, Collector: source, StopVerifier: stopLeaseFixture{true}}
		if e := c.Stop(context.Background()); e != nil || source.stopped != 1 || script.commits != 1 {
			t.Fatal(e)
		}
	}
}
func TestProtectedCollectorDoesNotPrepareWithoutRegisteredArtifact(t *testing.T) {
	task, _, _ := guardFixture(t)
	task.Request.Kind = "drill"
	task.Request.Artifact = "sb-source"
	s, _ := scriptStore(t, append(guardSteps(task), sqlStep{contains: "SELECT artifact_json"})...)
	source := &protectedFixture{id: "redis"}
	c := ProtectedCollector{Guards: RecoveryGuards{s, task}, Artifact: "missing", Collector: source, StopVerifier: stopLeaseFixture{true}, TTL: 1000000000}
	if e := c.Prepare(context.Background()); e == nil || source.prepared != 0 {
		t.Fatal("unprotected recovery started", e)
	}
}
