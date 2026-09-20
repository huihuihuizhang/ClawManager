package systembackupcontroller

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
)

type grantProbeConnector struct {
	user     string
	role     string
	grants   []string
	connects *atomic.Int32
}

func (c grantProbeConnector) Connect(context.Context) (driver.Conn, error) {
	if c.connects != nil {
		c.connects.Add(1)
	}
	return grantProbeConn{c}, nil
}
func (c grantProbeConnector) Driver() driver.Driver { return grantProbeDriver{} }

type grantProbeDriver struct{}

func (grantProbeDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use connector") }

type grantProbeConn struct{ state grantProbeConnector }

func (grantProbeConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected preparation")
}
func (grantProbeConn) Close() error              { return nil }
func (grantProbeConn) Begin() (driver.Tx, error) { return nil, errors.New("unexpected transaction") }
func (c grantProbeConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if len(args) != 0 {
		return nil, errors.New("unexpected grant query parameters")
	}
	switch query {
	case "SELECT CURRENT_USER()":
		return &grantProbeRows{values: []string{c.state.user}}, nil
	case "SELECT CURRENT_ROLE()":
		return &grantProbeRows{values: []string{c.state.role}}, nil
	case "SHOW GRANTS":
		return &grantProbeRows{values: c.state.grants}, nil
	default:
		return nil, errors.New("unexpected grant query")
	}
}

type grantProbeRows struct {
	values []string
	index  int
}

func (*grantProbeRows) Columns() []string { return []string{"grant"} }
func (*grantProbeRows) Close() error      { return nil }
func (r *grantProbeRows) Next(dest []driver.Value) error {
	if r.index >= len(r.values) {
		return io.EOF
	}
	dest[0] = r.values[r.index]
	r.index++
	return nil
}

func controllerTestGrants() []string {
	grants := []string{"GRANT USAGE ON *.* TO `sbk_controller`@`%`"}
	for table, verbs := range controllerTableGrants {
		grants = append(grants, fmt.Sprintf("GRANT %s ON `clawmanager`.`%s` TO `sbk_controller`@`%%`", strings.Join(verbs, ", "), table))
	}
	return grants
}

func TestControllerGrantMatrixAcceptsOnlyCurrentRuntimePrivileges(t *testing.T) {
	if err := ValidateControllerGrantStatements("clawmanager", controllerTestGrants()); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]string) []string{
		func(grants []string) []string { return grants[:len(grants)-1] },
		func(grants []string) []string {
			return append(grants, "GRANT ALL PRIVILEGES ON *.* TO `sbk_controller`@`%`")
		},
		func(grants []string) []string {
			return append(grants, "GRANT CREATE ON `clawmanager`.`system_backups` TO `sbk_controller`@`%`")
		},
		func(grants []string) []string {
			return append(grants, "GRANT SELECT ON `clawmanager`.* TO `sbk_controller`@`%`")
		},
		func(grants []string) []string {
			return append(grants, "GRANT SELECT ON `clawmanager`.`users` TO `sbk_controller`@`%`")
		},
		func(grants []string) []string {
			return append(grants, "GRANT `admin_role`@`%` TO `sbk_controller`@`%`")
		},
		func(grants []string) []string {
			return append(grants, "GRANT USAGE ON *.* TO `sbk_controller`@`%` WITH GRANT OPTION")
		},
		func(grants []string) []string {
			return append(grants, "GRANT SELECT ON `other_schema`.`system_backups` TO `sbk_controller`@`%`")
		},
	} {
		if err := ValidateControllerGrantStatements("clawmanager", mutate(controllerTestGrants())); err == nil {
			t.Fatal("unsafe or incomplete grant set was accepted")
		}
	}
	if err := ValidateControllerGrantStatements("invalid-name!", controllerTestGrants()); err == nil {
		t.Fatal("invalid schema name was accepted")
	}
}

func TestControllerGrantProbeRejectsActiveRoles(t *testing.T) {
	for _, role := range []string{"NONE", "`admin_role`@`%`"} {
		db := sql.OpenDB(grantProbeConnector{user: "sbk_controller@%", role: role, grants: controllerTestGrants()})
		err := (SQLControllerGrantProbe{DB: db, Schema: "clawmanager", User: "sbk_controller"}).Check(context.Background())
		_ = db.Close()
		if role == "NONE" && err != nil {
			t.Fatalf("safe direct grants rejected: %v", err)
		}
		if role != "NONE" && err == nil {
			t.Fatal("active role was accepted")
		}
	}
}

func TestControllerGrantProbeRejectsProxyOrAnonymousEffectiveUser(t *testing.T) {
	for _, user := range []string{"@%", "clawmanager@%", "sbk_controller_other@%"} {
		db := sql.OpenDB(grantProbeConnector{user: user, role: "NONE", grants: controllerTestGrants()})
		err := (SQLControllerGrantProbe{DB: db, Schema: "clawmanager", User: "sbk_controller"}).Check(context.Background())
		_ = db.Close()
		if err == nil {
			t.Fatalf("mismatched effective database user %q was accepted", user)
		}
	}
}

func TestControllerGrantProbeUsesOneSessionForIdentityRoleAndGrants(t *testing.T) {
	var connects atomic.Int32
	db := sql.OpenDB(grantProbeConnector{
		user: "sbk_controller@127.0.0.1", role: "NONE",
		grants: controllerTestGrants(), connects: &connects,
	})
	defer db.Close()
	db.SetMaxIdleConns(0)
	if err := (SQLControllerGrantProbe{DB: db, Schema: "clawmanager", User: "sbk_controller"}).Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := connects.Load(); got != 1 {
		t.Fatalf("identity, role, and grants used %d connections, want one", got)
	}
}

func TestControllerGrantSQLMatchesAdmissionMatrix(t *testing.T) {
	statements, err := ControllerGrantSQL("clawmanager", "sbk_controller", "%", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(statements) != len(controllerTableGrants) {
		t.Fatalf("grant count = %d, want %d", len(statements), len(controllerTableGrants))
	}
	tables := make([]string, 0, len(controllerTableGrants))
	for table := range controllerTableGrants {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	for index, statement := range statements {
		if !strings.Contains(statement, ".`"+tables[index]+"` TO ") {
			t.Fatalf("grant output is not sorted by table: %q", statement)
		}
		if strings.Contains(statement, "CREATE USER") || strings.Contains(statement, "PASSWORD") {
			t.Fatalf("grant output includes account or password mutation: %q", statement)
		}
		statements[index] = strings.TrimSuffix(statement, ";")
	}
	if err := ValidateControllerGrantStatements("clawmanager", statements); err != nil {
		t.Fatalf("generated grants fail the controller admission matrix: %v", err)
	}
	for _, input := range []struct {
		schema, user, host string
		allowAnyHost       bool
	}{
		{"clawmanager", "sbk_controller", "%", false},
		{"clawmanager", "sbk_controller", "", false},
		{"clawmanager", "clawmanager", "127.0.0.1", false},
		{"clawmanager", "sbk_controller'; DROP USER root; --", "%", true},
		{"clawmanager`; DROP DATABASE mysql; --", "sbk_controller", "%", true},
		{"clawmanager", "sbk_controller", "%.example.com", true},
	} {
		if output, err := ControllerGrantSQL(input.schema, input.user, input.host, input.allowAnyHost); err == nil || output != nil {
			t.Fatalf("unsafe grant arguments accepted: %#v", input)
		}
	}
}
