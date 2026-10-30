package systembackupexecution

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type preflightDriver struct{ model *preflightModel }
type preflightModel struct {
	fault   string
	queries []string
}
type preflightConn struct{ model *preflightModel }

func (d preflightDriver) Open(string) (driver.Conn, error) { return preflightConn{d.model}, nil }
func (c preflightConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare forbidden")
}
func (c preflightConn) Close() error              { return nil }
func (c preflightConn) Begin() (driver.Tx, error) { return nil, errors.New("transaction forbidden") }
func (c preflightConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	c.model.queries = append(c.model.queries, query)
	if !strings.HasPrefix(query, "SELECT ") {
		return nil, errors.New("mutation forbidden")
	}
	if query == "SELECT @@server_uuid,DATABASE()" {
		server := "server"
		if c.model.fault == "server" {
			server = "other"
		}
		return &resultRows{values: []driver.Value{server, "db"}}, nil
	}
	if !strings.HasSuffix(query, " LIMIT 0") {
		return nil, errors.New("data read forbidden")
	}
	if c.model.fault == "schema" && strings.Contains(query, "system_backup_v2_runtime_resources") {
		return nil, errors.New("missing column")
	}
	return &resultRows{}, nil
}

func TestSealPreflightFailsClosedWithoutMutating(t *testing.T) {
	for _, fault := range []string{"", "server", "schema"} {
		t.Run(fault, func(t *testing.T) {
			model := &preflightModel{fault: fault}
			name := fmt.Sprintf("seal-preflight-%s-%p", fault, model)
			sql.Register(name, preflightDriver{model})
			db, err := sql.Open(name, "")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			db.SetMaxOpenConns(1)
			maintenance := SealMaintenance{DB: db, Installation: "installation", ServerUUID: "server", Database: "db"}
			err = maintenance.Preflight(context.Background())
			if (err == nil) != (fault == "") {
				t.Fatalf("fault=%s err=%v", fault, err)
			}
			if len(model.queries) == 0 {
				t.Fatal("no identity check")
			}
			if fault == "server" && len(model.queries) != 1 {
				t.Fatalf("queried schema on wrong server: %v", model.queries)
			}
			if fault == "" && len(model.queries) != 4 {
				t.Fatalf("incomplete schema check: %v", model.queries)
			}
		})
	}
}
