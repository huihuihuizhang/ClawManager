package systembackupexecution

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"clawreef/internal/systembackup/staging"
	c "clawreef/internal/systembackupcontroller"
)

// A transparent REAL SQL connection records only the targeted original 104
// commit. The independent administrator reads its committed result before the
// production caller can perform any subsequent filesystem operation.
type aStageCommitBoundary struct {
	mu    sync.Mutex
	kind  string
	seen  int
	after func() error
}

func (b *aStageCommitBoundary) arm(kind string, after func() error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.kind = kind
	b.seen = 0
	b.after = after
}
func (b *aStageCommitBoundary) committed(kind string) error {
	b.mu.Lock()
	if kind == "" || kind != b.kind {
		b.mu.Unlock()
		return nil
	}
	b.seen++
	fn := b.after
	b.mu.Unlock()
	if fn != nil {
		return fn()
	}
	return nil
}

type aStageBoundaryConnector struct {
	driver.Connector
	boundary *aStageCommitBoundary
}

func (cn aStageBoundaryConnector) Connect(ctx context.Context) (driver.Conn, error) {
	v, e := cn.Connector.Connect(ctx)
	if e != nil {
		return nil, e
	}
	return &aStageBoundaryConn{Conn: v, boundary: cn.boundary}, nil
}

type aStageBoundaryConn struct {
	driver.Conn
	boundary *aStageCommitBoundary
	kind     string
}

func (cn *aStageBoundaryConn) Begin() (driver.Tx, error) {
	v, e := cn.Conn.Begin()
	if e != nil {
		return nil, e
	}
	cn.kind = ""
	return aStageBoundaryTx{Tx: v, conn: cn}, nil
}
func (cn *aStageBoundaryConn) BeginTx(ctx context.Context, o driver.TxOptions) (driver.Tx, error) {
	v, e := cn.Conn.(driver.ConnBeginTx).BeginTx(ctx, o)
	if e != nil {
		return nil, e
	}
	cn.kind = ""
	return aStageBoundaryTx{Tx: v, conn: cn}, nil
}
func (cn *aStageBoundaryConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	return cn.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}
func (cn *aStageBoundaryConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	v, e := cn.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
	// MySQL may return ErrSkip for argument-bearing statements, after which
	// database/sql executes the same SQL through Prepare on THIS connection.
	if e == nil || errors.Is(e, driver.ErrSkip) {
		if strings.HasPrefix(q, "INSERT INTO system_backup_v2_staging_resources(") {
			cn.kind = "creating"
		}
		if strings.HasPrefix(q, "UPDATE system_backup_v2_staging_resources SET lifecycle='ready'") {
			cn.kind = "ready"
		}
	}
	return v, e
}

type aStageBoundaryTx struct {
	driver.Tx
	conn *aStageBoundaryConn
}

func (tx aStageBoundaryTx) Commit() error {
	if e := tx.Tx.Commit(); e != nil {
		return e
	}
	return tx.conn.boundary.committed(tx.conn.kind)
}

func aStageLifecycle(t *testing.T, admin *sql.DB, location string) (string, uint64) {
	t.Helper()
	var lifecycle string
	var version uint64
	if e := admin.QueryRow("SELECT lifecycle,row_version FROM system_backup_v2_staging_resources WHERE location_sha256=?", hash([]byte(location))).Scan(&lifecycle, &version); e != nil {
		t.Fatal(e)
	}
	return lifecycle, version
}

func TestAOriginalStagingIntentPrecedesFilesystemAndUnknownACKMySQL(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires owned local MySQL")
	}
	for _, mode := range []string{"fresh", "creating-commit-unknown", "ready-commit-unknown", "directory-complete-before-ready", "old-unmarked-directory", "creating-foreign-directory", "creating-absent", "ready-marker-changed", "wrong-attempt", "wrong-phase", "wrong-task", "wrong-frozen-job", "collector-not-paused"} {
		t.Run(mode, func(t *testing.T) {
			boundary := &aStageCommitBoundary{}
			o, _, admin, _, a, _, _, _, refresh := newConsumerMySQLFixtureOptions(t, &consumerFixtureOptions{WrapControlConnector: func(inner driver.Connector) driver.Connector {
				return aStageBoundaryConnector{Connector: inner, boundary: boundary}
			}})
			// A new controlled root is selected before any effect. The original
			// fixture's C and seal files are retained, never removed or re-adopted.
			parent, e := os.OpenRoot(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			defer parent.Close()
			o.Staging = parent
			ctx := context.Background()
			scope, e := o.stageScope(a)
			if e != nil {
				t.Fatal(e)
			}
			refresh()
			if mode == "wrong-frozen-job" {
				_, _, desc, z := o.input(ctx, a, false)
				if z != nil || len(desc.Parts) != 1 {
					t.Fatal("actual frozen original plan", z)
				}
				bad := desc.Parts[0].Intent
				bad.Generation++
				if _, _, _, z = o.Admit(ctx, a, bad); z == nil {
					t.Fatal("nonmatching frozen Job admitted")
				}
				var count int
				if z = admin.QueryRow("SELECT COUNT(*) FROM system_backup_v2_staging_resources WHERE location_sha256=?", hash([]byte(scope.Location))).Scan(&count); z != nil || count != 0 {
					t.Fatal("nonmatching Job wrote staging intent", count, z)
				}
				if _, z = parent.Lstat(a.TaskPublicID); !errors.Is(z, os.ErrNotExist) {
					t.Fatal("nonmatching Job created directory", z)
				}
				return
			}
			if mode == "collector-not-paused" {
				if _, e = admin.Exec("INSERT INTO system_backup_participants(scope,participant_id,generation,state) VALUES('original-app','actual-unpaused',?,'running')", a.MaintenanceFencingToken); e != nil {
					t.Fatal(e)
				}
				if e = o.ensureStaging(ctx, a); e == nil {
					t.Fatal("unpaused collector admitted")
				}
				var count int
				if e = admin.QueryRow("SELECT COUNT(*) FROM system_backup_v2_staging_resources WHERE location_sha256=?", hash([]byte(scope.Location))).Scan(&count); e != nil || count != 0 {
					t.Fatal("collector rejection wrote intent", count, e)
				}
				return
			}
			if mode == "old-unmarked-directory" {
				if e = parent.Mkdir(a.TaskPublicID, 0700); e != nil {
					t.Fatal(e)
				}
				if e = parent.WriteFile(a.TaskPublicID+"/foreign-data", []byte("preserve"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "fresh" || mode == "creating-commit-unknown" {
				boundary.arm("creating", func() error {
					lifecycle, version := aStageLifecycle(t, admin, scope.Location)
					if lifecycle != "creating" || version != 1 {
						t.Fatalf("pre-FS original intent %s/%d", lifecycle, version)
					}
					for _, name := range []string{a.TaskPublicID, ".controller-stage-owner-keys"} {
						if _, z := parent.Lstat(name); !errors.Is(z, os.ErrNotExist) {
							t.Fatalf("filesystem preceded committed intent %s: %v", name, z)
						}
					}
					if mode == "creating-commit-unknown" {
						return errAPublicationACKLost
					}
					return nil
				})
			}
			if mode == "ready-commit-unknown" {
				boundary.arm("ready", func() error {
					lifecycle, _ := aStageLifecycle(t, admin, scope.Location)
					if lifecycle != "ready" {
						t.Fatal("ready commit did not occur")
					}
					return errAPublicationACKLost
				})
			}
			if mode == "creating-foreign-directory" || mode == "creating-absent" {
				r, key, send, z := o.stageIntent(ctx, a)
				clear(key)
				if z != nil || !send || r.lifecycle != "creating" {
					t.Fatal("original creating intent", send, z)
				}
				if mode == "creating-foreign-directory" {
					if e = parent.Mkdir(a.TaskPublicID, 0700); e != nil {
						t.Fatal(e)
					}
					if e = parent.WriteFile(a.TaskPublicID+"/foreign-data", []byte("preserve"), 0600); e != nil {
						t.Fatal(e)
					}
				}
			}
			if mode == "directory-complete-before-ready" {
				r, key, send, z := o.stageIntent(ctx, a)
				if z != nil || !send {
					clear(key)
					t.Fatal("original creating intent", send, z)
				}
				z = o.createStageDirectory(ctx, a, r, key)
				clear(key)
				if z != nil {
					t.Fatal(z)
				}
				lifecycle, version := aStageLifecycle(t, admin, scope.Location)
				if lifecycle != "creating" || version != 1 {
					t.Fatal("creation should not record its own observation", lifecycle, version)
				}
				if z = o.verifyStageDirectory(r); z != nil {
					t.Fatal("original physical marker was not complete", z)
				}
			}
			e = o.ensureStaging(ctx, a)
			switch mode {
			case "creating-commit-unknown":
				if !errors.Is(e, c.ErrExecutionCommitUnknown) {
					t.Fatal("original commit unknown was not returned", e)
				}
				boundary.arm("", nil)
				if e = o.ensureStaging(ctx, a); e == nil {
					t.Fatal("ambiguous creating intent resent creation")
				}
				if _, e = parent.Lstat(a.TaskPublicID); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("unknown commit created task directory", e)
				}
				lifecycle, version := aStageLifecycle(t, admin, scope.Location)
				if lifecycle != "creating" || version != 1 {
					t.Fatal(lifecycle, version)
				}
				return
			case "creating-absent":
				if e == nil {
					t.Fatal("absent directory was recreated from old intent")
				}
				lifecycle, version := aStageLifecycle(t, admin, scope.Location)
				if lifecycle != "creating" || version != 1 {
					t.Fatal(lifecycle, version)
				}
				return
			case "old-unmarked-directory", "creating-foreign-directory":
				if e == nil {
					t.Fatal("foreign directory adopted")
				}
				lifecycle, _ := aStageLifecycle(t, admin, scope.Location)
				if lifecycle != "ownership_unknown" {
					t.Fatal("present foreign directory did not converge", lifecycle)
				}
				data, z := parent.ReadFile(a.TaskPublicID + "/foreign-data")
				if z != nil || string(data) != "preserve" {
					t.Fatal("unknown directory modified", z)
				}
				if _, z = parent.Lstat(a.TaskPublicID + "/" + originalStageMarkerName); !errors.Is(z, os.ErrNotExist) {
					t.Fatal("foreign directory received marker", z)
				}
				return
			case "ready-commit-unknown":
				if !errors.Is(e, c.ErrExecutionCommitUnknown) {
					t.Fatal("ready ACK not lost", e)
				}
				boundary.arm("", nil)
			default:
				if e != nil {
					t.Fatal("original staging creation", e)
				}
			}
			if mode == "fresh" {
				boundary.mu.Lock()
				seen := boundary.seen
				boundary.mu.Unlock()
				if seen != 1 {
					t.Fatal("did not observe original pre-FS commit", seen)
				}
			}
			lifecycle, version := aStageLifecycle(t, admin, scope.Location)
			if lifecycle != "ready" || version != 2 {
				t.Fatal(lifecycle, version)
			}
			before, z := parent.ReadFile(a.TaskPublicID + "/" + originalStageMarkerName)
			if z != nil {
				t.Fatal(z)
			}
			if mode == "ready-marker-changed" {
				if e = parent.WriteFile(a.TaskPublicID+"/"+originalStageMarkerName, []byte("foreign-marker"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			other := a
			switch mode {
			case "wrong-attempt":
				other.AttemptNo++
			case "wrong-phase":
				other.Phase = "publish"
			case "wrong-task":
				other.TaskPublicID = "sbk_33333333-3333-4333-8333-333333333333"
			}
			e = o.ensureStaging(ctx, other)
			if mode == "ready-marker-changed" {
				if e == nil {
					t.Fatal("changed marker admitted")
				}
				lifecycle, _ = aStageLifecycle(t, admin, scope.Location)
				if lifecycle != "ownership_unknown" {
					t.Fatal(lifecycle)
				}
				return
			}
			if mode == "wrong-attempt" || mode == "wrong-phase" || mode == "wrong-task" {
				if e == nil {
					t.Fatal("cross scope staging authority admitted")
				}
			} else {
				if e != nil {
					t.Fatal("exact original marker readback", e)
				}
			}
			after, z := parent.ReadFile(a.TaskPublicID + "/" + originalStageMarkerName)
			if z != nil || string(after) != string(before) {
				t.Fatal("retry rewrote original marker", z)
			}
			lifecycle, next := aStageLifecycle(t, admin, scope.Location)
			if lifecycle != "ready" || next != version {
				t.Fatal("readback changed original lifecycle", lifecycle, next)
			}
			if mode == "fresh" {
				var keyVersion string
				if z = admin.QueryRow("SELECT owner_marker_key_version FROM system_backup_v2_staging_resources WHERE location_sha256=?", hash([]byte(scope.Location))).Scan(&keyVersion); z != nil {
					t.Fatal(z)
				}
				worker, z := parent.OpenRoot(a.TaskPublicID)
				if z != nil {
					t.Fatal(z)
				}
				file, z := worker.Open("../.controller-stage-owner-keys/" + keyVersion + ".key")
				if file != nil {
					file.Close()
				}
				worker.Close()
				if z == nil {
					t.Fatal("worker exact task root reached controller owner key")
				}
				for _, value := range []string{"sbs_11111111-1111-4111-111111111111", "invalid"} {
					if _, z = admin.Exec("UPDATE system_backup_v2_staging_resources SET public_id=? WHERE location_sha256=?", value, hash([]byte(scope.Location))); z == nil || !strings.Contains(z.Error(), "sbv2_chk_sb_staging_identity") {
						t.Fatal("corrected 132 identity CHECK did not reject malformed UUID", z)
					}
				}
			}
			// The independent key store does not introduce a directory into the
			// original flat seal custody or relax its unknown-entry checks.
			custody, z := staging.OpenSealCustody(parent)
			if z != nil {
				t.Fatal(z)
			}
			defer custody.Close()
			if _, z = staging.InventoryCustody(ctx, custody, staging.CustodyPolicy{Installation: a.InstallationID, MaxBytes: 1 << 20}); z != nil {
				t.Fatal("owner keys broke original seal inventory", z)
			}
		})
	}
}
