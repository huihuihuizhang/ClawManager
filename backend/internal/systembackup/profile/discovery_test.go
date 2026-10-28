package profile

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/quiesce"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

type inventoryConnector struct {
	t     *testing.T
	users int64
	apps  []control.AppProcess
}

func (c inventoryConnector) Connect(context.Context) (driver.Conn, error) {
	return inventoryConnection{c}, nil
}
func (c inventoryConnector) Driver() driver.Driver { return inventoryDriver{c} }

type inventoryDriver struct{ c inventoryConnector }

func (d inventoryDriver) Open(string) (driver.Conn, error) { return inventoryConnection{d.c}, nil }

type inventoryConnection struct{ c inventoryConnector }

func (c inventoryConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (c inventoryConnection) Close() error { return nil }
func (c inventoryConnection) Begin() (driver.Tx, error) {
	return nil, errors.New("requires explicit readonly transaction")
}
func (c inventoryConnection) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	if !o.ReadOnly || o.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		c.c.t.Fatal("discovery transaction is not readonly snapshot")
	}
	return inventoryTransaction{}, nil
}
func (c inventoryConnection) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.HasPrefix(q, "SELECT process_id,identity_json") {
		var rows [][]driver.Value
		for _, p := range c.c.apps {
			b, _ := json.Marshal(p)
			rows = append(rows, []driver.Value{p.ID, b})
		}
		return &inventoryRows{columns: []string{"id", "identity"}, values: rows}, nil
	}
	if q == "SELECT COUNT(*) FROM users" {
		return &inventoryRows{columns: []string{"count"}, values: [][]driver.Value{{c.c.users}}}, nil
	}
	if strings.HasPrefix(q, "SELECT id,user_id,instance_mode") {
		return &inventoryRows{columns: []string{"id"}}, nil
	}
	c.c.t.Errorf("unexpected discovery SQL %s", q)
	return nil, errors.New("unexpected SQL")
}
func (c inventoryConnection) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.c.t.Fatal("discovery wrote database")
	return nil, errors.New("writes forbidden")
}

type inventoryTransaction struct{}

func (inventoryTransaction) Commit() error {
	return errors.New("discovery must rollback readonly snapshot")
}
func (inventoryTransaction) Rollback() error { return nil }

type inventoryRows struct {
	columns []string
	values  [][]driver.Value
}

func (r *inventoryRows) Columns() []string { return r.columns }
func (r *inventoryRows) Close() error      { return nil }
func (r *inventoryRows) Next(v []driver.Value) error {
	if len(r.values) == 0 {
		return io.EOF
	}
	copy(v, r.values[0])
	r.values = r.values[1:]
	return nil
}

func TestConcreteDiscoveryBuildsDatabasePlanWithoutExternalWrites(t *testing.T) {
	d, task, _ := fixture(t)
	d.Source = sql.OpenDB(inventoryConnector{t: t, users: 1})
	defer d.Source.Close()
	client := fake.NewSimpleClientset(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node", UID: "node-uid", Labels: map[string]string{corev1.LabelOSStable: "linux"}}})
	d.Client = client
	d.Proof = &quiesce.ProofClient{Endpoints: map[string]quiesce.ProofEndpoint{"node": {URL: "https://fixture"}}}
	installAppFixture(t, d)
	task.ProfileRevision = d.Metadata().Revision
	client.ClearActions()
	raw, e := d.Discover(context.Background(), task)
	if e != nil {
		t.Fatal(e)
	}
	var p plan
	if json.Unmarshal(raw, &p) != nil || p.Users != 1 || len(p.Work) != 2 || p.Work[0].Invocation.Request.Operation != "capture-database" || p.Nodes["node"] != "node-uid" {
		t.Fatal("incomplete frozen plan")
	}
	x, e := d.Bind(context.Background(), task, raw)
	if e != nil || len(x.Writers) != 1 || len(x.Capture) != 2 {
		t.Fatal("cannot bind discovered plan", e)
	}
	for _, a := range client.Actions() {
		if a.GetVerb() != "get" && a.GetVerb() != "list" {
			t.Fatal("discovery mutated Kubernetes", a)
		}
	}
	d.Config.Instances = []Instance{{ID: 1}}
	if _, e = d.Discover(context.Background(), task); e == nil {
		t.Fatal("partial/mismatched instance inventory accepted")
	}
}
