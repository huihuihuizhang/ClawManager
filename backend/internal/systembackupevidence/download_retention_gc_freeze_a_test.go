package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"sync/atomic"
	"testing"
	"time"
)

var aFreezeConnectorCalls atomic.Int32

type aFreezeNilMap map[string]string
type aFreezeNilSlice []string
type aFreezeNilFunc func()
type aFreezeNilChan chan struct{}
type aFreezeConnectorDriver struct{}

func (aFreezeConnectorDriver) Open(string) (driver.Conn, error) { return nil, driver.ErrBadConn }
func aFreezeConnect() (driver.Conn, error) {
	aFreezeConnectorCalls.Add(1)
	return nil, driver.ErrBadConn
}
func (aFreezeNilMap) Connect(context.Context) (driver.Conn, error)   { return aFreezeConnect() }
func (aFreezeNilSlice) Connect(context.Context) (driver.Conn, error) { return aFreezeConnect() }
func (aFreezeNilFunc) Connect(context.Context) (driver.Conn, error)  { return aFreezeConnect() }
func (aFreezeNilChan) Connect(context.Context) (driver.Conn, error)  { return aFreezeConnect() }
func (aFreezeNilMap) Driver() driver.Driver                          { return aFreezeConnectorDriver{} }
func (aFreezeNilSlice) Driver() driver.Driver                        { return aFreezeConnectorDriver{} }
func (aFreezeNilFunc) Driver() driver.Driver                         { return aFreezeConnectorDriver{} }
func (aFreezeNilChan) Driver() driver.Driver                         { return aFreezeConnectorDriver{} }

func TestAFreezeTypedNilConnectorBoundary(t *testing.T) {
	for _, tc := range []struct {
		name      string
		connector driver.Connector
		nilValue  bool
	}{
		{"map_nil", aFreezeNilMap(nil), true}, {"slice_nil", aFreezeNilSlice(nil), true},
		{"func_nil", aFreezeNilFunc(nil), true}, {"chan_nil", aFreezeNilChan(nil), true},
		{"map_value", aFreezeNilMap{}, false}, {"slice_value", aFreezeNilSlice{}, false},
		{"func_value", aFreezeNilFunc(func() {}), false}, {"chan_value", aFreezeNilChan(make(chan struct{})), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			aFreezeConnectorCalls.Store(0)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			workCalled := false
			out, err := runDownloadGCFreeze(ctx, downloadGCFreezeConfig{Connector: tc.connector, Server: "server-a", Database: "test_only", Account: "worker@test", WaitSeconds: 1, Admit: func(context.Context, *sql.Conn) error { return nil }}, func(context.Context, *sql.Tx) error { workCalled = true; return nil })
			if err == nil || workCalled || out.Transaction != "not_started" || out.Unlock != "not_acquired" {
				t.Fatal("denied connector reached transaction work")
			}
			if tc.nilValue && aFreezeConnectorCalls.Load() != 0 {
				t.Fatal("typed nil reached connector before admission")
			}
			if !tc.nilValue && aFreezeConnectorCalls.Load() == 0 {
				t.Fatal("non-nil control was rejected before connection")
			}
		})
	}
}
