package domain

import "database/sql"

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
