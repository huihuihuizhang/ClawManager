package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"
)

// Only SQL transport is modeled. Independent full Manifest vectors and the
// production decoder/GET binding run; no owner authorization is invented.
type downloadPreviewSQL struct {
	*admissionTxDB
	installation driver.Value
	unavailable  bool
	queries      []string
}

func (d *downloadPreviewSQL) Connect(context.Context) (driver.Conn, error) { return d, nil }
func (d *downloadPreviewSQL) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	d.queries = append(d.queries, q)
	if strings.Contains(q, "FROM system_backup_v2_evidence") && (strings.Contains(q, "FOR UPDATE") || strings.Contains(q, "FOR SHARE")) {
		return nil, errors.New("preview attempted L9 lock")
	}
	if q == "SELECT origin_installation_id FROM system_backup_v2_evidence WHERE public_id=?" {
		if d.unavailable {
			return nil, errors.New("PRIVATE missing candidate schema")
		}
		if len(args) != 1 || args[0].Value != d.record.Manifest.Identity.ID {
			return nil, errors.New("wrong evidence selector")
		}
		return admissionTxRow(d.installation), nil
	}
	return d.admissionTxDB.QueryContext(ctx, q, args)
}
func previewFixture(t *testing.T) (*admissionTxFixture, *downloadPreviewSQL, *sql.Tx) {
	t.Helper()
	f := newAdmissionTxFixture(t)
	d := &downloadPreviewSQL{admissionTxDB: f.db, installation: f.initial.Manifest.Identity.Installation}
	db := sql.OpenDB(d)
	t.Cleanup(func() { db.Close() })
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	// Model only the caller's already acquired prefix, not an authorization.
	d.installationLocked = true
	return f, d, tx
}

func TestDownloadPreviewLoadsActualManifestWithoutLateLocks(t *testing.T) {
	f, d, tx := previewFixture(t)
	registry := f.service.registry
	registry.Policy = nil // Preview must not call the legacy policy.
	ownerCalls := 0
	r, err := registry.PreviewDownloadEvidence(context.Background(), tx, f.initial.Manifest.Identity.ID, func(ctx context.Context, borrowed *sql.Tx, i Identity) (time.Time, error) {
		ownerCalls++
		if ctx.Err() != nil || borrowed != tx || i != f.initial.Manifest.Identity || len(d.queries) != 3 {
			t.Fatal("owner callback scope/order", d.queries)
		}
		return f.initial.OwnerDeadline, nil
	})
	if err != nil || ownerCalls != 1 || hash(canonical(r.Manifest)) != hash(canonical(f.initial.Manifest)) || !sameDownloadAdmissionImmutable(r, f.initial) {
		t.Fatal("preview", err)
	}
	bound, err := BindSensitiveDownloadRequest(f.env.actor, r.Manifest, f.request.Header)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := BindSensitiveDownloadRequest(f.env.actor, f.initial.Manifest, f.request.Header)
	if err != nil || bound != expected {
		t.Fatal("preview differed from GET", err)
	}
	if len(d.queries) != 4 || !strings.Contains(d.queries[3], "FROM system_backup_v2_evidence_chunks") || d.commitAttempts != 0 || d.ownerLocked || d.evidenceLocked || d.opKeyLocked || d.inserts != 0 || d.reserved != 0 {
		t.Fatal("preview had admission effects", d.queries)
	}
	for _, q := range d.queries {
		if strings.Contains(q, "FOR UPDATE") || strings.Contains(q, "FOR SHARE") {
			t.Fatal("preview acquired a late lock", q)
		}
	}
}

func TestDownloadPreviewFailsClosedBeforeChunkOrAuthority(t *testing.T) {
	for _, name := range []string{"null-installation", "foreign-installation", "missing-schema", "wrong-server", "owner-denied", "private-owner-error", "deadline-missing", "deadline-non-utc", "manifest-corrupt", "state", "classification", "row-version", "missing-resolver", "nil-context", "nil-tx", "bad-id"} {
		t.Run(name, func(t *testing.T) {
			f, d, tx := previewFixture(t)
			registry := f.service.registry
			ctx := context.Background()
			id := f.initial.Manifest.Identity.ID
			calls := 0
			var owner DownloadPreviewOwner = func(context.Context, *sql.Tx, Identity) (time.Time, error) {
				calls++
				switch name {
				case "owner-denied":
					return time.Time{}, ErrDenied
				case "private-owner-error":
					return time.Time{}, errors.New("PRIVATE owner rows")
				case "deadline-missing":
					return time.Time{}, nil
				case "deadline-non-utc":
					return f.initial.OwnerDeadline.In(time.FixedZone("bad", 3600)), nil
				}
				return f.initial.OwnerDeadline, nil
			}
			switch name {
			case "null-installation":
				d.installation = nil
			case "missing-schema":
				d.unavailable = true
			case "foreign-installation":
				d.installation = "installation_foreign"
			case "wrong-server":
				registry.ServerUUID = "ffffffff-2222-3333-4444-555555555555"
			case "manifest-corrupt":
				d.record.Manifest.ChunkRoot = strings.Repeat("f", 64)
			case "state":
				d.record.State = "gc_claimed"
			case "classification":
				d.record.Manifest.Identity.Classification = "internal"
			case "row-version":
				d.record.RowVersion = 0
			case "missing-resolver":
				owner = nil
			case "nil-context":
				ctx = nil
			case "nil-tx":
				tx = nil
			case "bad-id":
				id = "sev_unknown"
			}
			r, err := registry.PreviewDownloadEvidence(ctx, tx, id, owner)
			if err == nil || r.Manifest.Identity.ID != "" || strings.Contains(err.Error(), "PRIVATE") || d.commitAttempts != 0 || d.inserts != 0 {
				t.Fatal("invalid preview released metadata", err)
			}
			if name == "missing-schema" && err != ErrDownloadAdmissionNotReady {
				t.Fatal("server schema failure blamed on client", err)
			}
			if name == "null-installation" || name == "foreign-installation" || name == "wrong-server" || name == "missing-resolver" || name == "nil-context" || name == "nil-tx" || name == "bad-id" {
				if calls != 0 {
					t.Fatal("owner called before binding validation")
				}
			}
			if strings.Contains(name, "owner") || strings.HasPrefix(name, "deadline-") {
				for _, q := range d.queries {
					if strings.Contains(q, "FROM system_backup_v2_evidence_chunks") {
						t.Fatal("chunks read after owner rejection")
					}
				}
			}
		})
	}
}
