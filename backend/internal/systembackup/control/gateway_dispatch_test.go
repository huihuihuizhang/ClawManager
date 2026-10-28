package control

import (
	"context"
	"database/sql/driver"
	"testing"

	"clawreef/internal/systembackup/recovery"
)

func TestGatewaySQLClaimCommitLossNeverAuthorizesSend(t *testing.T) {
	_, p, _, _, _ := acceptanceFixture(t)
	r := recovery.Request{ActionID: "isolated-action", Key: "manifest.json", Size: 2, Payload: []byte(`{}`), SHA256: recovery.Hash([]byte(`{}`)), Deadline: 5000, Generation: 1, Condition: "create-if-absent", Target: p.ArtifactProvider}
	raw, _ := recovery.Marshal(r)
	for _, scenario := range []string{"first", "lost-commit", "existing", "changed-bytes", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			nowValue := int64(1000)
			if scenario == "expired" {
				nowValue = 5000
			}
			steps := []sqlStep{{contains: "SELECT " + dbNow, rows: [][]driver.Value{{nowValue}}}}
			if scenario != "expired" {
				row := []driver.Value{raw, "original-token"}
				if scenario == "changed-bytes" {
					row[0] = []byte(`{}`)
				}
				steps = append(steps, sqlStep{contains: "INSERT INTO system_backup_gateway_dispatch", affected: 1, checkArgs: func(args []driver.NamedValue) {
					if args[2].Value != r.ActionID {
						t.Fatal("action not bound")
					}
					if scenario == "first" || scenario == "lost-commit" {
						row[1] = args[4].Value
					}
				}}, sqlStep{contains: "SELECT request_json,reservation_id", rows: [][]driver.Value{row}})
				if scenario != "changed-bytes" {
					steps = append(steps, sqlStep{contains: "SELECT " + dbNow, rows: [][]driver.Value{{int64(1000)}}})
				}
			}
			s, script := scriptStore(t, steps...)
			script.loseCommit = scenario == "lost-commit"
			first, e := (GatewayDispatch{Store: s}).Reserve(context.Background(), p.Input.Locator, r)
			if first != (scenario == "first") || (e == nil) != (scenario == "first" || scenario == "existing") {
				t.Fatal(first, e)
			}
			if scenario == "expired" && script.writes != 0 {
				t.Fatal("expired claim mutated journal")
			}
		})
	}
}
