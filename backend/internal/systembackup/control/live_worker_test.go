package control

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
)

func TestLiveWorkerPinsProcessBeforeGrantAndRejectsReplacement(t *testing.T) {
	for _, scenario := range []string{"first", "repeat", "replacement"} {
		t.Run(scenario, func(t *testing.T) {
			task, g, _ := grantFixture()
			p := kube.WorkerProcess{Name: "worker", UID: "pod-one", Node: "node-one", Containers: []string{"containerd://" + strings.Repeat("a", 64)}}
			steps := workerCommit(task)
			steps = append(steps, sqlStep{contains: "FOR UPDATE", rows: [][]driver.Value{taskRow(task)}}, sqlStep{contains: "SELECT " + dbNow, rows: [][]driver.Value{{time.Now().UnixMilli()}}}, sqlStep{contains: "SELECT uid,lifecycle,dispatched", rows: [][]driver.Value{{g.JobUID, "created", true}}}, sqlStep{contains: "SELECT revoked", rows: [][]driver.Value{{false}}})
			read := sqlStep{contains: "SELECT process_json"}
			if scenario != "first" {
				old := p
				if scenario == "replacement" {
					old.UID = "different-pod"
				}
				raw, _ := json.Marshal(old)
				read.rows = [][]driver.Value{{raw}}
			}
			steps = append(steps, read)
			if scenario == "first" {
				steps = append(steps, sqlStep{contains: "INSERT INTO system_backup_worker_processes", affected: 1})
			}
			if scenario != "replacement" {
				steps = append(steps, workerCommit(task)...)
			}
			store, script := scriptStore(t, steps...)
			e := (LiveWorkers{Store: store}).pin(context.Background(), task, g, p)
			if scenario == "replacement" {
				if e != ErrConflict || script.writes != 0 || script.commits != 0 {
					t.Fatal("replacement inherited grant", e)
				}
			} else if e != nil || script.commits != 1 {
				t.Fatal("process identity not durable", e)
			}
		})
	}
}
