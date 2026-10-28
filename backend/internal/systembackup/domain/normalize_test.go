package domain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
)

func table(name string, rows ...Row) Table {
	t := Table{Name: name, Engine: "InnoDB", PrimaryKey: []string{"id"}, Rows: rows}
	if len(rows) > 0 {
		for _, name := range sortedKeys(rows[0]) {
			t.Columns = append(t.Columns, Column{Name: name, Type: "varchar(255)", Nullable: true})
		}
	}
	return t
}
func sortedKeys(r Row) []string {
	var names []string
	for n := range r {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
func fixture() (Snapshot, []Table, Policy) {
	users := table("users", Row{"id": Text("1"), "username": Text("admin"), "password_hash": Text("synthetic-source-hash"), "role": Text("admin"), "is_active": Text("1")}, Row{"id": Text("4"), "username": Text("test-user"), "password_hash": Text("synthetic-user-hash"), "role": Text("user"), "is_active": Text("1")})
	instances := table("instances", Row{"id": Text("7"), "user_id": Text("4"), "type": Text("openclaw"), "runtime_type": Text("gateway"), "instance_mode": Text("lite"), "runtime_variant": Text("linux"), "os_type": Text("linux"), "status": Text("running"), "workspace_path": Text("/source/private"), "access_token": Text("source-token"), "agent_bootstrap_token": Text("source-bootstrap"), "pod_name": Text("source-pod")})
	quotas := table("user_quotas", Row{"id": Text("12"), "user_id": Text("4"), "max_cpu_cores": Text("0.1250000000000000001")})
	desired := table("instance_desired_state", Row{"id": Text("2"), "instance_id": Text("7"), "desired_power_state": Text("running"), "desired_runtime_action": Text("restart")})
	schedules := table("backup_schedules", Row{"id": Text("9"), "instance_id": Text("7"), "cron_expression": Text("0 * * * *"), "is_active": Text("1")})
	quotas.ForeignKeys = []ForeignKey{{"user_id", "users", "id"}}
	instances.ForeignKeys = []ForeignKey{{"user_id", "users", "id"}}
	desired.ForeignKeys = []ForeignKey{{"instance_id", "instances", "id"}}
	schedules.ForeignKeys = []ForeignKey{{"instance_id", "instances", "id"}}
	s := Snapshot{Version: Version, Tables: []Table{users, quotas, instances, desired, schedules}}
	target := append([]Table(nil), s.Tables...)
	target[0].Columns = append(append([]Column(nil), users.Columns...), Column{Name: "auth_provider", Type: "varchar(32)", Default: strptr("local")})
	return s, target, Policy{Placements: map[string]Placement{"7": {Workspace: "/drill/workbuddy/user-4/instance-7", MountPath: "/workspaces", Namespace: "cm-drill-test"}}}
}
func strptr(s string) *string { return &s }
func find(s Snapshot, name string) Table {
	for _, t := range s.Tables {
		if t.Name == name {
			return t
		}
	}
	return Table{}
}

func TestNormalizeKeepsLoginQuotaOwnershipAndStopsWork(t *testing.T) {
	s, target, p := fixture()
	before, _ := Digest(s)
	plan, e := Normalize(context.Background(), s, target, p)
	if e != nil {
		t.Fatal(e)
	}
	if plan.Users != 2 || plan.Instances != 1 {
		t.Fatal("wrong counts")
	}
	admin := find(plan.Data, "users").Rows[0]
	if admin["password_hash"].String() != "synthetic-source-hash" || admin["auth_provider"].String() != "local" {
		t.Fatal("login lost")
	}
	i := find(plan.Data, "instances").Rows[0]
	if i["status"].String() != "stopped" || !i["access_token"].Null || !i["agent_bootstrap_token"].Null || !i["pod_name"].Null || i["user_id"].String() != "4" {
		t.Fatal("instance not inert")
	}
	if find(plan.Data, "instance_desired_state").Rows[0]["desired_power_state"].String() != "stopped" || find(plan.Data, "backup_schedules").Rows[0]["is_active"].String() != "0" {
		t.Fatal("scheduler can replay")
	}
	if find(plan.Data, "user_quotas").Rows[0]["max_cpu_cores"].String() != "0.1250000000000000001" {
		t.Fatal("decimal lost")
	}
	after, _ := Digest(s)
	if before != after {
		t.Fatal("source mutated")
	}
}
func TestNormalizeDoesNotReplayRolloutCheckpointsOrWorkspaceWrites(t *testing.T) {
	source, target, policy := fixture()
	checkpoint := table("runtime_rollout_checkpoints", Row{
		"rollout_id": Text("3"), "state_json": Text(`{"phase":"executing"}`), "updated_at": Text("2026-10-28 00:00:00"),
	})
	checkpoint.PrimaryKey = []string{"rollout_id"}
	intent := table("instance_workspace_write_intents", Row{
		"operation_id": Text(strings.Repeat("a", 32)), "instance_id": Text("7"), "owner_user_id": Text("4"),
		"generation": Text("2"), "action": Text("write"), "created_at": Text("2026-10-28 00:00:00"),
	})
	intent.PrimaryKey = []string{"operation_id"}
	intent.ForeignKeys = []ForeignKey{{"instance_id", "instances", "id"}}
	source.Tables = append(source.Tables, checkpoint, intent)
	target = append(target, checkpoint, intent)
	before, err := Digest(source)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := Normalize(context.Background(), source, target, policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"runtime_rollout_checkpoints", "instance_workspace_write_intents"} {
		if len(find(plan.Data, name).Rows) != 0 || len(find(source, name).Rows) != 1 {
			t.Fatalf("source coordination state replayed or lost: %s", name)
		}
	}
	if after, err := Digest(source); err != nil || after != before {
		t.Fatal("archived source changed")
	}
}

func TestNormalizeFailsClosed(t *testing.T) {
	for _, test := range []string{"orphan", "no-admin", "unknown-field", "missing-target-field", "missing-placement", "windows", "missing-secret-adapter", "new-target-executor"} {
		t.Run(test, func(t *testing.T) {
			s, target, p := fixture()
			switch test {
			case "orphan":
				s.Tables[2].Rows[0]["user_id"] = Text("99")
			case "no-admin":
				s.Tables[0].Rows[0]["role"] = Text("user")
			case "unknown-field":
				s.Tables[2].Columns = append(s.Tables[2].Columns, Column{Name: "auto_execute", Type: "int"})
				s.Tables[2].Rows[0]["auto_execute"] = Text("1")
			case "missing-target-field":
				target[2].Columns = target[2].Columns[1:]
			case "missing-placement":
				p.Placements = nil
			case "windows":
				s.Tables[2].Rows[0]["runtime_variant"] = Text("windows")
			case "missing-secret-adapter":
				s.Tables[2].Columns = append(s.Tables[2].Columns, Column{Name: "environment_overrides_json", Type: "text", Nullable: true})
				s.Tables[2].Rows[0]["environment_overrides_json"] = Text(`{"key":"credential"}`)
				target[2].Columns = s.Tables[2].Columns
			case "new-target-executor":
				target[2].Columns = append(target[2].Columns, Column{Name: "auto_execute", Type: "int", Default: strptr("1")})
			}
			if _, e := Normalize(context.Background(), s, target, p); e == nil {
				t.Fatal("unsafe normalization accepted")
			}
		})
	}
}
func TestCaptureDataRoundTripTypesAndCapacity(t *testing.T) {
	s, _, _ := fixture()
	s.Tables[0].Rows[0]["password_hash"] = Cell{Bytes: []byte{0, 0xff, 0x80, 1}}
	var out strings.Builder
	if e := Encode(&out, s); e != nil {
		t.Fatal(e)
	}
	decoded, e := Decode(strings.NewReader(out.String()), Limits{MaxRows: 20, MaxBytes: 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	a, _ := Digest(s)
	b, _ := Digest(decoded)
	if a != b {
		t.Fatal("not lossless")
	}
	if _, e = Decode(strings.NewReader(out.String()), Limits{MaxRows: 1, MaxBytes: 1 << 20}); !errors.Is(e, ErrCapacity) {
		t.Fatal("row limit")
	}
	if _, e = Decode(strings.NewReader(out.String()+"{}"), Limits{20, 1 << 20}); e == nil {
		t.Fatal("trailing data")
	}
}
func TestNormalizeTwentyTwoLinuxLiteInstances(t *testing.T) {
	s, _, p := fixture()
	s.Tables = s.Tables[:3]
	third := cloneRow(s.Tables[0].Rows[1])
	third["id"] = Text("8")
	third["username"] = Text("third-fixture-user")
	s.Tables[0].Rows = append(s.Tables[0].Rows, third)
	s.Tables[2].Rows = nil
	s.Tables[2].Columns = append(s.Tables[2].Columns, Column{Name: "workbuddy_storage_identity", Type: "varchar(255)", Nullable: true})
	var identities []Row
	p.Placements = map[string]Placement{}
	for typ, count := range map[string]int{"openclaw": 4, "hermes": 3, "opencode": 4, "deepseek-harness": 5, "workbuddy": 6} {
		for j := 0; j < count; j++ {
			id := fmt.Sprint(len(s.Tables[2].Rows) + 1)
			r := cloneRow(fixtureRow())
			r["id"] = Text(id)
			r["type"] = Text(typ)
			r["workbuddy_storage_identity"] = Cell{Null: true}
			if typ == "workbuddy" {
				r["workbuddy_storage_identity"] = Text("storage-" + id)
				identities = append(identities, Row{"id": Text(id), "instance_id": Text(id), "storage_identity": Text("storage-" + id), "linux_uid": Text(fmt.Sprint(4000 + j)), "linux_gid": Text(fmt.Sprint(4000 + j))})
			}
			s.Tables[2].Rows = append(s.Tables[2].Rows, r)
			p.Placements[id] = Placement{Workspace: "/drill/instance-" + id, MountPath: "/workspaces", Namespace: "cm-drill-test"}
		}
	}
	w := table("workbuddy_linux_identities", identities...)
	s.Tables = append(s.Tables, w)
	p.WorkBuddy = &WorkBuddySchema{Version: "synthetic-fixture", SHA256: SchemaDigest(w), Instance: "instance_id", StorageIdentity: "storage_identity", UID: "linux_uid", GID: "linux_gid"}
	plan, e := Normalize(context.Background(), s, s.Tables, p)
	if e != nil || plan.Instances != 22 || plan.Users != 3 {
		t.Fatalf("22-instance fixture: %v", e)
	}
}
func fixtureRow() Row { s, _, _ := fixture(); return s.Tables[2].Rows[0] }

func TestCommandHistoryCannotReplayAndConfigurationChecksumMatches(t *testing.T) {
	s, target, p := fixture()
	commands := table("instance_commands", Row{"id": Text("11"), "instance_id": Text("7"), "status": Text("pending"), "error_message": Cell{Null: true}})
	config := table("instance_config_revisions", Row{"id": Text("5"), "instance_id": Text("7"), "status": Text("published"), "content_json": Text(`{"token":"source-secret"}`), "checksum": Text("sha256:old")})
	s.Tables = append(s.Tables, commands, config)
	target = append(target, commands, config)
	p.Configs = JSONRegistry{"instance_config_revisions.content_json": {{Path: []string{"token"}, Action: "stub", Required: true}}}
	plan, e := Normalize(context.Background(), s, target, p)
	if e != nil {
		t.Fatal(e)
	}
	if find(plan.Data, "instance_commands").Rows[0]["status"].String() != "failed" {
		t.Fatal("command still replayable")
	}
	r := find(plan.Data, "instance_config_revisions").Rows[0]
	sum := sha256.Sum256(r["content_json"].Bytes)
	if r["checksum"].String() != "sha256:"+hex.EncodeToString(sum[:]) || strings.Contains(r["content_json"].String(), "source-secret") {
		t.Fatal("config checksum or stubbing incompatible")
	}
}
