package systembackupexecution

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
)

// Named close/join protocol model; this does not prove SQL authority or a
// network operation. The native continuation test covers the real held GET.
type publicationCloseConnector struct{ calls *atomic.Int32 }

func (c publicationCloseConnector) Driver() driver.Driver { return publicationCloseDriver{} }
func (c publicationCloseConnector) Connect(context.Context) (driver.Conn, error) {
	return publicationCloseConn{c.calls}, nil
}

type publicationCloseDriver struct{}

func (publicationCloseDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("unexpected Open")
}

type publicationCloseConn struct{ calls *atomic.Int32 }

func (publicationCloseConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected Prepare")
}
func (publicationCloseConn) Close() error              { return nil }
func (publicationCloseConn) Begin() (driver.Tx, error) { return nil, errors.New("unexpected Begin") }
func (c publicationCloseConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.calls.Add(1)
	return driver.RowsAffected(0), nil
}

func TestPublicationContinuationAllClosersJoinAndShareReleaseError(t *testing.T) {
	var calls atomic.Int32
	db := sql.OpenDB(publicationCloseConnector{&calls})
	defer db.Close()
	p := &publicationContinuation{ctx: context.Background(), service: &DeploymentService{publisherVerifierDB: db, Config: DeploymentConfig{InstallationID: "installation_test"}}, claim: c.ClaimToken{Target: c.Target{Kind: c.TargetBackup, PublicID: "sbk_11111111-1111-4111-8111-111111111111"}, Owner: "controller:original", RowVersion: 7}, policy: c.LeasePolicy{ReconcileInterval: time.Second}}
	p.operations.RLock()
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { results <- p.close() }()
	}
	select {
	case err := <-results:
		p.operations.RUnlock()
		t.Fatal("close returned before in-flight operation joined", err)
	case <-time.After(50 * time.Millisecond):
	}
	if !p.closed.Load() || calls.Load() != 0 {
		p.operations.RUnlock()
		t.Fatal("close did not stop admission before joining")
	}
	p.operations.RUnlock()
	first, second := <-results, <-results
	if !errors.Is(first, c.ErrClaimLost) || first != second || calls.Load() != 1 {
		t.Fatal("closers did not share one release/error", first, second, calls.Load())
	}
	if err := p.close(); err != first || calls.Load() != 1 {
		t.Fatal("later close hid error or repeated Release", err, calls.Load())
	}
}
