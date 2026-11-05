package systembackupcontroller

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Real signed original/current Forward files and local key files, using a
// SQL identity/clock transport MODEL. No enabled-only SQL proof or permission
// is fabricated by these controller tests.
type pairSQLConnector struct{ g ExecutionGrant }

func (c pairSQLConnector) Driver() driver.Driver { return pairSQLDriver{} }
func (c pairSQLConnector) Connect(context.Context) (driver.Conn, error) {
	return &pairSQLConn{g: c.g}, nil
}

type pairSQLDriver struct{}

func (pairSQLDriver) Open(string) (driver.Conn, error) { return nil, errors.New("connector only") }

type pairSQLConn struct {
	g    ExecutionGrant
	open bool
}

func (c *pairSQLConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("no prepare") }
func (c *pairSQLConn) Close() error                        { return nil }
func (c *pairSQLConn) Begin() (driver.Tx, error)           { c.open = true; return pairSQLTx{c}, nil }

type pairSQLTx struct{ c *pairSQLConn }

func (t pairSQLTx) Commit() error   { return errors.New("comparison model rolls back") }
func (t pairSQLTx) Rollback() error { t.c.open = false; return nil }
func (c *pairSQLConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	if !c.open {
		return nil, errors.New("closed view")
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	switch q {
	case "SELECT UTC_TIMESTAMP(6),CURRENT_USER(),@@server_uuid,DATABASE()":
		return &claimReceiptRows{values: []driver.Value{now, c.g.DatabaseAccount, c.g.ServerUUID, c.g.Database}}, nil
	case "SELECT UTC_TIMESTAMP(6)":
		return &claimReceiptRows{values: []driver.Value{now}}, nil
	}
	return nil, errors.New("no other SQL/authority in pair checker")
}
func enabledPairFixture(t *testing.T, change func(*ExecutionGrant)) (*PinnedExecutionIdentity, *PinnedExecutionIdentity, *sql.DB) {
	t.Helper()
	_, old, _, _, public, key := pinnedGrantDataFixture(t)
	directory := t.TempDir()
	for _, name := range []string{"record-v1", "capture-v1"} {
		raw := bytes.Repeat([]byte(name[:1]), 32)
		if e := os.WriteFile(filepath.Join(directory, name), raw, 0600); e != nil {
			t.Fatal(e)
		}
		if name == "record-v1" {
			old.RecordKeys[0].SHA256 = recordHash(raw)
		} else {
			old.CaptureKeys[0].SHA256 = recordHash(raw)
		}
	}
	oldRaw := signPinnedGrantData(t, old, key)
	oldFile := filepath.Join(directory, "forward-original.json")
	if e := os.WriteFile(oldFile, oldRaw, 0600); e != nil {
		t.Fatal(e)
	}
	current := old
	current.ConfigVersion = 2
	current.ConfigSHA256 = strings.Repeat("f", 64)
	// Detach original slices before mutating a resigned successor fixture.
	current.Actions = append([]string(nil), old.Actions...)
	current.RecordKeys = append([]ExecutionRecordKey(nil), old.RecordKeys...)
	current.CaptureKeys = append([]ExecutionRecordKey(nil), old.CaptureKeys...)
	if change != nil {
		change(&current)
	}
	raw := signPinnedGrantData(t, current, key)
	path := filepath.Join(directory, "forward-current.json")
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	next, e := NewPinnedExecutionIdentity(path, recordHash(raw), directory, public)
	if e != nil {
		t.Fatal(e)
	}
	prior, e := NewPinnedExecutionIdentity(oldFile, recordHash(oldRaw), directory, public)
	if e != nil {
		t.Fatal(e)
	}
	db := sql.OpenDB(pairSQLConnector{current})
	t.Cleanup(func() { _ = db.Close() })
	return next, prior, db
}
func TestExecutionEnabledOnlyPairUsesOriginalSignaturesKeysAndSameView(t *testing.T) {
	current, original, db := enabledPairFixture(t, nil)
	ctx := context.Background()
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	opened, e := current.OpenOriginalEnabledOnlyPredecessor(original.path, original.digest)
	if e != nil {
		t.Fatal(e)
	}
	if e = current.CheckOriginalEnabledOnlyPredecessorInView(ctx, tx, opened); e != nil {
		t.Fatal(e)
	}
	if e = tx.Rollback(); e != nil {
		t.Fatal(e)
	}
	if e = current.CheckOriginalEnabledOnlyPredecessorInView(ctx, tx, opened); e == nil {
		t.Fatal("closed view accepted")
	}
	if e = os.WriteFile(original.path, []byte("revoked or removed"), 0600); e != nil {
		t.Fatal(e)
	}
	tx, e = db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if current.CheckOriginalEnabledOnlyPredecessorInView(ctx, tx, opened) == nil {
		t.Fatal("original signed source revocation ignored")
	}
}
func TestExecutionEnabledOnlyPairRejectsOtherResignedFields(t *testing.T) {
	cases := []struct {
		name   string
		change func(*ExecutionGrant)
	}{
		{"extended-until", func(g *ExecutionGrant) { g.ExpiresAt = g.ExpiresAt.Add(time.Second) }},
		{"new-not-before", func(g *ExecutionGrant) { g.NotBefore = g.NotBefore.Add(time.Second) }},
		{"new-action", func(g *ExecutionGrant) { g.Actions = append(g.Actions, "recover") }},
		{"new-record-key", func(g *ExecutionGrant) { g.RecordKeys[0].SHA256 = strings.Repeat("1", 64) }},
		{"new-capture-key", func(g *ExecutionGrant) { g.CaptureKeys[0].SHA256 = strings.Repeat("2", 64) }},
		{"new-worker-issuer", func(g *ExecutionGrant) {
			g.WorkerIssuerSHA256 = strings.Repeat("3", 64)
			g.Actions = append(g.Actions, "issue_worker")
		}},
		{"new-profile", func(g *ExecutionGrant) { g.ProfileSHA256 = strings.Repeat("4", 64) }},
		{"new-deployment", func(g *ExecutionGrant) { g.DeploymentConfigSHA256 = strings.Repeat("5", 64) }},
		{"other-owner", func(g *ExecutionGrant) { g.ControllerOwner = "other-owner" }},
		{"other-account", func(g *ExecutionGrant) { g.DatabaseAccount = "backup_controller@other-host" }},
		{"other-version", func(g *ExecutionGrant) { g.ConfigVersion = 3 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			current, old, db := enabledPairFixture(t, tc.change)
			if _, e := current.OpenOriginalEnabledOnlyPredecessor(old.path, old.digest); e == nil {
				t.Fatal("non-tuple signed change accepted")
			}
			tx, e := db.BeginTx(context.Background(), nil)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			if current.CheckOriginalEnabledOnlyPredecessorInView(context.Background(), tx, old) == nil {
				t.Fatal("non-tuple pair reached live use")
			}
		})
	}
}
