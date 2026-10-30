package domain

import (
	"database/sql"
	"strconv"
)

// TestSQLFixture exposes the existing SQL test driver to external-package
// worker integration tests. It is compiled only by go test, never in a binary.
type TestSQLFixture struct {
	Source, Target *sql.DB
	Policy         Policy
	source, target *memoryDB
}

func NewTestSQLFixture() *TestSQLFixture {
	s, schema, p := fixture()
	source := &memoryDB{tables: copyTables(s.Tables), name: "source", uuid: "fixture-server", grants: "GRANT SELECT ON `source`.* TO 'capture'@'localhost'"}
	target := isolatedTarget(schema)
	return &TestSQLFixture{Source: database(source), Target: database(target), Policy: p, source: source, target: target}
}
func (f *TestSQLFixture) Close() { f.Source.Close(); f.Target.Close() }
func (f *TestSQLFixture) Snapshot() Snapshot {
	return Snapshot{Version: Version, Tables: copyTables(f.target.tables)}
}
func (f *TestSQLFixture) Writes() int             { return f.target.writes }
func (f *TestSQLFixture) Commits() int            { return f.target.commits }
func (f *TestSQLFixture) SourceWrites() int       { return f.source.writes }
func (f *TestSQLFixture) Verifier() *sql.DB       { return database(f.target) }
func (f *TestSQLFixture) SetSourceGrant(s string) { f.source.grants = s }
func (f *TestSQLFixture) SetTargetGrant(s string) { f.target.grants = s }
func (f *TestSQLFixture) Tamper()                 { f.target.tables[0].Rows[0]["password_hash"] = Text("tampered") }

// NewTestTeamsSQLFixture exercises the public SQL worker protocol with nonempty
// C data. Its in-memory SQL driver is NOT a production import profile/schema.
func NewTestTeamsSQLFixture() *TestSQLFixture {
	s, _, p := teamFixture()
	appendFields := func(name string, fields Row) {
		for n := range s.Tables {
			if s.Tables[n].Name == name {
				for key, value := range fields {
					s.Tables[n].Columns = append(s.Tables[n].Columns, Column{Name: key, Type: "text", Nullable: true})
					s.Tables[n].Rows[0][key] = value
				}
			}
		}
	}
	appendFields("teams", Row{"resource_scope": Text("northbound"), "owner": Text("owner-c"), "display_name": Text("保留 owner 名称")})
	appendFields("team_members", Row{"icon_key": Text("crown")})
	appendFields("team_tasks", Row{"payload_json": Text(`{"message":"原始任务"}`), "result_json": Text(`{"partial":"中断前结果"}`)})
	appendFields("team_work_items", Row{"result_json": Text(`{"partial":"二进制产物见目录"}`), "artifact_refs_json": Text(`["/team/results/report.bin"]`)})
	s.Tables = append(s.Tables,
		table("northbound_operations", Row{"operation_id": Text("source-operation"), "user_id": Text("4"), "status": Text("processing"), "lease_owner": Text("source-worker")}),
		table("team_events", Row{"id": Text("26"), "team_id": Text("20"), "member_id": Text("21"), "task_id": Text("22"), "payload_json": Text(`{"text":"完整历史消息"}`), "redis_stream_id": Text("10-3")}),
		table("team_workspace_file_audits", Row{"id": Text("27"), "team_id": Text("20"), "user_id": Text("4"), "relative_path": Text("results/report.bin")}),
		table("custom_team_templates", Row{"id": Text("28"), "user_id": Text("4"), "resource_scope": Text("northbound"), "owner": Text("owner-c"), "name": Text("模板"), "last_operation_id": Text("source-operation"), "spec_json": Text(`{"role":"leader"}`)}),
		table("owner_team_provision_steps", Row{"team_id": Text("20"), "step_key": Text("member"), "operation_id": Text("source-operation"), "status": Text("started")}),
		table("owner_team_admission_locks", Row{"team_id": Text("20")}),
	)
	for n := range s.Tables {
		switch s.Tables[n].Name {
		case "northbound_operations":
			s.Tables[n].PrimaryKey = []string{"operation_id"}
		case "owner_team_provision_steps":
			s.Tables[n].PrimaryKey = []string{"team_id", "step_key"}
		case "owner_team_admission_locks":
			s.Tables[n].PrimaryKey = []string{"team_id"}
		}
	}
	p.Dependencies = map[string]TableAdapter{"northbound_operations": {SchemaSHA256: SchemaDigest(find(s, "northbound_operations")), Columns: map[string]string{"operation_id": "preserve", "user_id": "preserve", "status": "fixed:failed", "lease_owner": "null"}}}
	p.Configs = JSONRegistry{
		"team_tasks.payload_json":            {{Path: []string{"message"}, Action: "preserve"}},
		"team_tasks.result_json":             {{Path: []string{"partial"}, Action: "preserve"}},
		"team_work_items.result_json":        {{Path: []string{"partial"}, Action: "preserve"}},
		"team_work_items.artifact_refs_json": {{Path: []string{"*"}, Action: "preserve"}},
		"team_events.payload_json":           {{Path: []string{"text"}, Action: "preserve"}},
		"custom_team_templates.spec_json":    {{Path: []string{"role"}, Action: "preserve"}},
	}
	// Current and terminal states share the same owner/association/data shape.
	for n := range s.Tables {
		if s.Tables[n].Name == "team_work_items" {
			for _, state := range []string{"cancelled", "skipped", "superseded", "blocked", "awaiting_review", "running", "succeeded"} {
				row := cloneRow(s.Tables[n].Rows[0])
				row["id"] = Text(strconv.Itoa(40 + len(s.Tables[n].Rows)))
				row["status"] = Text(state)
				s.Tables[n].Rows = append(s.Tables[n].Rows, row)
			}
		}
	}
	source := &memoryDB{tables: copyTables(s.Tables), name: "source", uuid: "fixture-server", grants: "GRANT SELECT ON `source`.* TO 'capture'@'localhost'"}
	target := isolatedTarget(s.Tables)
	return &TestSQLFixture{Source: database(source), Target: database(target), Policy: p, source: source, target: target}
}
