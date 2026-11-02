package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
)

func issueFixture(t *testing.T, f *authorityFixture, ctx context.Context) []byte {
	t.Helper()
	raw, e := f.i.IssueCapture(ctx, f.password, f.enrollment, f.draft, hash(f.draft), f.key, f.files)
	if e != nil {
		t.Fatal("actual authenticated issue/probe", e)
	}
	return raw
}
func TestOwnerAuthorityIssueImportConsumerL2AndRevoke(t *testing.T) {
	f := newAuthorityFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pack := issueFixture(t, f, ctx)
	if f.s.writes != 0 || f.signs.Load() != 1 {
		t.Fatal("issue wrote SQL or skipped actual probe")
	}
	receipt, e := f.i.ImportCapture(ctx, f.password, f.enrollment, pack, hash(pack), f.files)
	if e != nil || receipt.State != "active" || receipt.HeadRevision != 1 || receipt.HeadRowVersion != 1 || receipt.GrantRowVersion != 1 || f.s.writes != 2 || f.signs.Load() != 2 {
		t.Fatal("original signed source import", e, receipt)
	}
	signs := f.signs.Load()
	writes := f.s.writes
	if replay, e := f.i.ImportCapture(ctx, f.password, f.enrollment, pack, hash(pack), f.files); e != nil || !replay.Replayed || f.signs.Load() != signs || f.s.writes != writes {
		t.Fatal("same original import did provider I/O or rewrote rows", e)
	}
	directory := t.TempDir()
	if _, e = f.i.ExportCommitted(ctx, f.password, f.enrollment, pack, hash(pack), directory); e != nil {
		t.Fatal(e)
	}
	pinRaw, e := os.ReadFile(filepath.Join(directory, "owner.pin.json"))
	if e != nil {
		t.Fatal(e)
	}
	var pin owner.TrustPin
	if decodeExact(pinRaw, &pin) != nil || !bytes.Equal(pin.Issuer, f.i.public) {
		t.Fatal("consumer trust did not come from enrolled issuer")
	}
	request, e := readRequest(f.i, f.files)
	if e != nil {
		t.Fatal(e)
	}
	defer request.observer.Close()
	validator, e := owner.NewCaptureSigningValidator(pin, RecordFilesAt(directory), request.observer)
	if e != nil {
		t.Fatal(e)
	}
	// Model a separately connected bootstrap consumer account. This asserts the
	// real kernel's account gate; it does not prove production SQL privileges.
	f.s.auth.account = f.i.plan.Target.DatabaseAccount
	checked, e := validator.Prepare(ctx, f.grant, f.config)
	if e != nil {
		t.Fatal(e)
	}
	prepared, ok := checked.(*owner.PreparedCaptureSigning)
	if !ok {
		t.Fatal("concrete capture owner")
	}
	tx, e := f.i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		t.Fatal(e)
	}
	guard, e := prepared.AuthorizeOriginal(ctx, tx, f.grant, f.config)
	if e != nil || guard.RecheckOriginalIdentity(ctx, tx) != nil || prepared.Recheck(ctx, tx, time.Now().UTC().Truncate(time.Microsecond)) != nil {
		tx.Rollback()
		t.Fatal("imported actual head/grant not consumable at original L2", e)
	}
	if tx.Commit() != nil {
		t.Fatal("consumer original transaction")
	}
	f.s.auth.account = f.i.plan.InstallerDatabaseAccount
	beforeRevoke := f.signs.Load()
	f.resourceDrift.Store(true)
	rev, e := f.i.IssueRevocation(ctx, f.password, f.enrollment, f.key)
	if e != nil {
		t.Fatal(e)
	}
	revoked, e := f.i.ImportRevocation(ctx, f.password, f.enrollment, rev, hash(rev))
	if e != nil || revoked.State != "revoked" || revoked.HeadRevision != 2 || revoked.GrantRowVersion != 2 || f.signs.Load() != beforeRevoke {
		t.Fatal("revoke required provider or failed exact source CAS", e)
	}
	if resolved, e := f.i.Resolve(ctx, f.password, f.enrollment, rev, hash(rev)); e != nil || !resolved.Replayed {
		t.Fatal("original revoke result unresolved", e)
	}
	if _, e = f.i.IssueCapture(ctx, f.password, f.enrollment, f.draft, hash(f.draft), f.key, f.files); e == nil {
		t.Fatal("revoked enrollment reactivated")
	}
	if _, e = f.i.ImportCapture(ctx, f.password, f.enrollment, pack, hash(pack), f.files); e == nil {
		t.Fatal("old active bundle resurrected")
	}
	// Reset only the protocol mock's public metadata to isolate SQL revocation.
	f.resourceDrift.Store(false)
	f.s.auth.account = f.i.plan.Target.DatabaseAccount
	checked, e = validator.Prepare(ctx, f.grant, f.config)
	if e != nil {
		t.Fatal(e)
	}
	prepared = checked.(*owner.PreparedCaptureSigning)
	tx, e = f.i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if _, e = prepared.AuthorizeOriginal(ctx, tx, f.grant, f.config); e == nil {
		t.Fatal("revoked imported source passed original L2")
	}
}

func TestOwnerAuthorityCommitUnknownOnlyResolvesOriginal(t *testing.T) {
	f := newAuthorityFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pack := issueFixture(t, f, ctx)
	f.s.commitLost = true
	if _, e := f.i.ImportCapture(ctx, f.password, f.enrollment, pack, hash(pack), f.files); !errors.Is(e, ErrCommitUnknown) {
		t.Fatal("lost committed response misreported", e)
	}
	signs, writes := f.signs.Load(), f.s.writes
	if r, e := f.i.Resolve(ctx, f.password, f.enrollment, pack, hash(pack)); e != nil || !r.Replayed || f.signs.Load() != signs || f.s.writes != writes {
		t.Fatal("resolve re-signed, re-probed or overwrote source", e)
	}
	if e := SaveFrozenBundle(t.TempDir(), pack); e != nil {
		t.Fatal(e)
	}
}

func TestOwnerAuthorityRejectsWrongSourceBeforeSigningOrWrite(t *testing.T) {
	for _, mode := range []string{"actor", "target", "config", "issuer", "enrollment_pin", "permission", "expired_window"} {
		t.Run(mode, func(t *testing.T) {
			f := newAuthorityFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			r := f.record
			key := f.key
			enrol := f.enrollment
			switch mode {
			case "actor":
				r.Actor.UserID++
			case "target":
				r.Target.NamespaceUID = "foreign-namespace"
			case "config":
				r.ConfigSHA256 = strings.Repeat("f", 64)
			case "issuer":
				_, other, e := ed25519.GenerateKey(rand.Reader)
				if e != nil {
					t.Fatal(e)
				}
				defer clear(other)
				key = other
			case "enrollment_pin":
				enrol.ConfigMapUID = "foreign-enrollment"
			case "permission":
				f.permissionDenied.Store(true)
			case "expired_window":
				r.Until = time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond)
			}
			raw, e := owner.EncodeRecord(r)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = f.i.IssueCapture(ctx, f.password, enrol, raw, hash(raw), key, f.files); e == nil || f.s.writes != 0 || f.signs.Load() != 0 {
				t.Fatal("untrusted request signed or imported", e)
			}
		})
	}
}

func TestOwnerAuthorityFrozenSourceAndResourceDriftRefuseImport(t *testing.T) {
	for _, mode := range []string{"grant_file", "resource", "head_signature", "record_signature", "counter", "other_plan"} {
		t.Run(mode, func(t *testing.T) {
			f := newAuthorityFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			pack := issueFixture(t, f, ctx)
			var b AuthorityBundle
			if decodeExact(pack, &b) != nil {
				t.Fatal("bundle")
			}
			switch mode {
			case "grant_file":
				if os.WriteFile(f.files.GrantFile, []byte("{}"), 0600) != nil {
					t.Fatal("grant mutation")
				}
			case "resource":
				f.resourceDrift.Store(true)
			case "head_signature":
				b.HeadSignature[0] ^= 1
			case "record_signature":
				b.RecordSignature[0] ^= 1
			case "counter":
				b.Expected.HeadRowVersion = 9
			case "other_plan":
				b.PlanSHA256 = strings.Repeat("b", 64)
			}
			pack, e := canonical(b)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = f.i.ImportCapture(ctx, f.password, f.enrollment, pack, hash(pack), f.files); e == nil || f.s.writes != 0 {
				t.Fatal("drift imported a source", e)
			}
		})
	}
}

func TestOwnerAuthorityExportCannotTrustSelfDeclaredBundle(t *testing.T) {
	f := newAuthorityFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pack := issueFixture(t, f, ctx)
	directory := t.TempDir()
	if _, e := f.i.ExportCommitted(ctx, f.password, f.enrollment, pack, hash(pack), directory); e == nil {
		t.Fatal("uncommitted signature created consumer trust")
	}
	entries, e := os.ReadDir(directory)
	if e != nil || len(entries) != 0 {
		t.Fatal("uncommitted exporter left trust files", e)
	}
	if e := SaveFrozenBundle(directory, pack); e != nil {
		t.Fatal(e)
	}
	if CheckNewBundleDirectory(directory) == nil || SaveFrozenBundle(directory, pack) == nil {
		t.Fatal("frozen bundle overwritten or re-sign permitted")
	}
}

func TestOwnerAuthorityExactHeadCASAndAtomicRollback(t *testing.T) {
	t.Run("stale_original_head", func(t *testing.T) {
		f := newAuthorityFixture(t)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		first := issueFixture(t, f, ctx)
		if _, e := f.i.ImportCapture(ctx, f.password, f.enrollment, first, hash(first), f.files); e != nil {
			t.Fatal(e)
		}
		r := f.record
		r.GrantID = "grant-2"
		draft, e := owner.EncodeRecord(r)
		if e != nil {
			t.Fatal(e)
		}
		second, e := f.i.IssueCapture(ctx, f.password, f.enrollment, draft, hash(draft), f.key, f.files)
		if e != nil {
			t.Fatal(e)
		}
		if result, e := f.i.ImportCapture(ctx, f.password, f.enrollment, second, hash(second), f.files); e != nil || result.HeadRevision != 2 || result.HeadRowVersion != 2 || result.GrantRowVersion != 1 {
			t.Fatal("actual source head CAS did not advance", e, result)
		}
		signs, writes := f.signs.Load(), f.s.writes
		if _, e := f.i.ImportCapture(ctx, f.password, f.enrollment, first, hash(first), f.files); e == nil || f.signs.Load() != signs || f.s.writes != writes {
			t.Fatal("stale source bundle rewrote the current owner")
		}
	})
	t.Run("head_and_grant_rollback", func(t *testing.T) {
		f := newAuthorityFixture(t)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		pack := issueFixture(t, f, ctx)
		f.s.failGrantInsert = true
		if _, e := f.i.ImportCapture(ctx, f.password, f.enrollment, pack, hash(pack), f.files); e == nil {
			t.Fatal("failed grant insert reported success")
		}
		if f.s.data.head != nil || len(f.s.data.grants) != 0 || f.s.commits != 0 || f.s.openTx.Load() != 0 {
			t.Fatal("original transaction leaked a partial head/source")
		}
	})
}
