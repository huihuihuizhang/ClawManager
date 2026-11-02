package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	ma "clawreef/internal/systembackupminioauthority"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func importMinioSQLFixture(t *testing.T, ctx context.Context, f *minioSQLLifecycleFixture, raw []byte) MinIOSQLReceipt {
	t.Helper()
	r, e := f.base.i.ImportMinIOSQLAuthority(ctx, f.base.password, f.base.enrollment, f.intent.Pin, raw, hash(raw))
	if e != nil {
		t.Fatal("actual seven-row import", e)
	}
	return r
}
func assertMinioSQLRows(t *testing.T, f *minioSQLLifecycleFixture, state string, version uint64) {
	t.Helper()
	d := f.model.data
	if d.head == nil || d.grant == nil || len(d.refs) != 5 || d.head[7] != state || d.grant[4] != state || counter(d.head[8]) != version || counter(d.grant[5]) != version || f.model.open.Load() != 0 || f.model.captureQueries != 0 {
		t.Fatal("mixed original seven-row state or capture-domain fallback")
	}
	for _, p := range minioSQLPurposes() {
		r := d.refs[string(p)]
		if len(r) != 10 || r[8] != state || counter(r[9]) != version {
			t.Fatal("mixed ref state/version", p)
		}
	}
}

func TestOriginalMinIOSQLSevenRowInstallResolveAndTerminalRevokeComponent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	f := newMinioSQLLifecycleFixture(t)
	raw := f.issue(t, ctx)
	before := cloneMinioSQLData(f.model.data)
	if before.head != nil || f.model.execs != 0 || f.model.captureQueries != 0 {
		t.Fatal("issue mutated SQL or borrowed capture domain")
	}
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e := SaveMinIOSQLBundle(dir, raw); e != nil {
		t.Fatal(e)
	}
	first := importMinioSQLFixture(t, ctx, f, raw)
	assertMinioSQLRows(t, f, "active", 1)
	want := []string{"insert-head", "insert-grant", "insert-artifact_delete", "insert-artifact_read", "insert-artifact_write", "insert-catalog_append", "insert-catalog_read"}
	if !reflect.DeepEqual(f.model.writeOrder, want) || first.State != "active" || first.Replayed || f.model.commits != 1 || f.model.execs != 7 {
		t.Fatal("wrong exact initial seven-row transaction", f.model.writeOrder)
	}
	resolved, e := f.base.i.ResolveMinIOSQLAuthority(ctx, f.base.password, f.base.enrollment, f.intent.Pin, raw, hash(raw))
	if e != nil || !resolved.Replayed || !reflect.DeepEqual(resolved.Comparison, first.Comparison) {
		t.Fatal("independent exact original tuple resolve", e)
	}
	replayed := importMinioSQLFixture(t, ctx, f, raw)
	if !replayed.Replayed || f.model.execs != 7 || f.model.commits != 1 {
		t.Fatal("identical committed import rewrote rows")
	}
	// Loss of the permission-source head must not prevent ORIGINAL SQL revoke.
	// This is not provider health evidence or a new native permission grant.
	if e = f.base.i.kube.CoreV1().ConfigMaps(f.intent.Grant.Target.Namespace).Delete(ctx, f.intent.Grant.PermissionSource.Head.Name, metav1.DeleteOptions{}); e != nil {
		t.Fatal(e)
	}
	revoke, e := f.base.i.IssueMinIOSQLRevocation(ctx, f.base.password, f.base.enrollment, f.intent.Pin, f.base.key)
	if e != nil {
		t.Fatal("revoke must not require permission source health", e)
	}
	original, e := ma.DecodeSQLBundle(raw, ma.Digest(hash(raw)))
	if e != nil {
		t.Fatal(e)
	}
	terminal, e := ma.DecodeSQLBundle(revoke, ma.Digest(hash(revoke)))
	if e != nil || !bytes.Equal(terminal.Grant, original.Grant) || !bytes.Equal(terminal.GrantSignature, original.GrantSignature) || !reflect.DeepEqual(terminal.References, original.References) {
		t.Fatal("revoke re-signed/changed original grant/ref payload", e)
	}
	f.model.writeOrder = nil
	r := importMinioSQLFixture(t, ctx, f, revoke)
	assertMinioSQLRows(t, f, "revoked", 2)
	want = []string{"revoke-head", "revoke-grant", "revoke-artifact_delete", "revoke-artifact_read", "revoke-artifact_write", "revoke-catalog_append", "revoke-catalog_read"}
	if r.State != "revoked" || r.Comparison.HeadRevision != 2 || f.model.commits != 2 || f.model.execs != 14 || !reflect.DeepEqual(f.model.writeOrder, want) {
		t.Fatal("terminal seven-row CAS/order", f.model.writeOrder)
	}
	if _, e = f.base.i.ImportMinIOSQLAuthority(ctx, f.base.password, f.base.enrollment, f.intent.Pin, raw, hash(raw)); e == nil {
		t.Fatal("old active bundle resurrected original authority")
	}
	if _, e = f.base.i.IssueMinIOSQLRevocation(ctx, f.base.password, f.base.enrollment, f.intent.Pin, f.base.key); e == nil {
		t.Fatal("terminal revoked head received a new revision")
	}
	s, e := f.base.i.authenticate(ctx, f.base.password)
	if e != nil {
		t.Fatal(e)
	}
	snapshot, absent, e := minioSQLRead(ctx, s, f.intent.Pin)
	if e != nil || absent {
		t.Fatal(e)
	}
	_, now, e := snapshot.Comparison()
	if e != nil || snapshot.RequireCurrent(now) == nil {
		t.Fatal("revoked actual SQL source authorized current use", e)
	}
}

func TestOriginalMinIOSQLInstallAndRevokeMidBatchRollbackComponent(t *testing.T) {
	for _, operation := range []string{"insert", "revoke"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			f := newMinioSQLLifecycleFixture(t)
			install := f.issue(t, ctx)
			raw := install
			if operation == "revoke" {
				importMinioSQLFixture(t, ctx, f, install)
				var e error
				raw, e = f.base.i.IssueMinIOSQLRevocation(ctx, f.base.password, f.base.enrollment, f.intent.Pin, f.base.key)
				if e != nil {
					t.Fatal(e)
				}
			}
			before := cloneMinioSQLData(f.model.data)
			commits := f.model.commits
			f.model.failOperation, f.model.failPurpose = operation, "artifact_write"
			r, e := f.base.i.ImportMinIOSQLAuthority(ctx, f.base.password, f.base.enrollment, f.intent.Pin, raw, hash(raw))
			if e == nil || r.Version != "" || !reflect.DeepEqual(before, f.model.data) || f.model.commits != commits || f.model.open.Load() != 0 {
				t.Fatal("partial seven-row batch escaped rollback", e)
			}
			f.model.failOperation, f.model.failPurpose = "", ""
			importMinioSQLFixture(t, ctx, f, raw)
			if operation == "insert" {
				assertMinioSQLRows(t, f, "active", 1)
			} else {
				assertMinioSQLRows(t, f, "revoked", 2)
			}
		})
	}
}

func TestOriginalMinIOSQLUnknownCommitIndependentTupleResolveComponent(t *testing.T) {
	for _, operation := range []string{"install", "revoke"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			f := newMinioSQLLifecycleFixture(t)
			active := f.issue(t, ctx)
			raw := active
			if operation == "revoke" {
				importMinioSQLFixture(t, ctx, f, active)
				var e error
				raw, e = f.base.i.IssueMinIOSQLRevocation(ctx, f.base.password, f.base.enrollment, f.intent.Pin, f.base.key)
				if e != nil {
					t.Fatal(e)
				}
			}
			f.model.commitLost = true
			r, e := f.base.i.ImportMinIOSQLAuthority(ctx, f.base.password, f.base.enrollment, f.intent.Pin, raw, hash(raw))
			if !errors.Is(e, ErrCommitUnknown) || r.Version != "" || f.model.open.Load() != 0 {
				t.Fatal("uncertain commit was presented as success", e)
			}
			execs, commits := f.model.execs, f.model.commits
			resolved, e := f.base.i.ResolveMinIOSQLAuthority(ctx, f.base.password, f.base.enrollment, f.intent.Pin, raw, hash(raw))
			if e != nil || !resolved.Replayed || resolved.HeadSHA256 != ma.Digest(hash(mustMinioSQLBundle(t, raw).Head)) || f.model.execs != execs || f.model.commits != commits {
				t.Fatal("original tuple resolve mutated/re-signed source", e)
			}
			if operation == "install" {
				assertMinioSQLRows(t, f, "active", 1)
			} else {
				assertMinioSQLRows(t, f, "revoked", 2)
				if _, e = f.base.i.ResolveMinIOSQLAuthority(ctx, f.base.password, f.base.enrollment, f.intent.Pin, active, hash(active)); e == nil {
					t.Fatal("resolved stale active head after revoke")
				}
			}
			wrong := f.intent.Pin
			wrong.AuthorityID = "foreign-authority"
			if _, e = f.base.i.ResolveMinIOSQLAuthority(ctx, f.base.password, f.base.enrollment, wrong, raw, hash(raw)); e == nil {
				t.Fatal("resolved another original tuple")
			}
			f.model.auth.active = false
			if _, e = f.base.i.ResolveMinIOSQLAuthority(ctx, f.base.password, f.base.enrollment, f.intent.Pin, raw, hash(raw)); e == nil {
				t.Fatal("stored receipt bypassed current original actor revocation")
			}
		})
	}
}

func mustMinioSQLBundle(t *testing.T, raw []byte) ma.SQLBundle {
	t.Helper()
	b, e := ma.DecodeSQLBundle(raw, ma.Digest(hash(raw)))
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestOriginalMinIOSQLRejectsForeignKeyAndRetainsExpiredRevokeWindowsComponent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	f := newMinioSQLLifecycleFixture(t)
	if _, e := f.base.i.IssueMinIOSQLInstall(ctx, f.base.password, f.base.enrollment, f.file, f.sha, make([]byte, ed25519.PrivateKeySize)); e == nil {
		t.Fatal("foreign private key issued scope")
	}
	wrong := f.base.enrollment
	wrong.ConfigMapUID = "foreign-enrollment"
	if _, e := f.base.i.IssueMinIOSQLInstall(ctx, f.base.password, wrong, f.file, f.sha, f.base.key); e == nil {
		t.Fatal("foreign enrollment issued scope")
	}
	raw := f.issue(t, ctx)
	importMinioSQLFixture(t, ctx, f, raw)
	// SQL clock passes original permission Until, while real operator/context
	// remains current. Revoke must keep old bounds, not require a renewed lease.
	f.model.clock = f.intent.Grant.Until.Add(10 * time.Second)
	revoke, e := f.base.i.IssueMinIOSQLRevocation(ctx, f.base.password, f.base.enrollment, f.intent.Pin, f.base.key)
	if e != nil {
		t.Fatal("expired original permission prevented deny-only revoke", e)
	}
	b := mustMinioSQLBundle(t, revoke)
	set, e := ma.VerifySQLRecordSet(f.intent.Pin, b.Grant, b.GrantSignature, b.Head, b.HeadSignature, b.References)
	if e != nil {
		t.Fatal(e)
	}
	g, h, _, e := set.Detached()
	if e != nil || !g.Until.Equal(f.intent.Grant.Until) || !h.Until.Equal(g.Until) || !g.NotBefore.Equal(f.intent.Grant.NotBefore) {
		t.Fatal("revocation renewed original permission window", e)
	}
	importMinioSQLFixture(t, ctx, f, revoke)
	assertMinioSQLRows(t, f, "revoked", 2)
}

func TestOriginalMinIOSQLRejectsOriginalWindowAndPostCommitSourceTailComponent(t *testing.T) {
	for _, scenario := range []string{"window-before-commit", "source-after-commit"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			f := newMinioSQLLifecycleFixture(t)
			raw := f.issue(t, ctx)
			if scenario == "window-before-commit" {
				f.model.expireAfterPurpose = "catalog_read"
				f.model.expireClock = f.intent.Grant.Until.Add(10 * time.Second)
			} else {
				f.model.afterWriteCommit = func() {
					if e := f.base.i.kube.CoreV1().ConfigMaps(f.intent.Grant.Target.Namespace).Delete(ctx, f.intent.Grant.PermissionSource.Head.Name, metav1.DeleteOptions{}); e != nil {
						t.Error(e)
					}
				}
			}
			r, e := f.base.i.ImportMinIOSQLAuthority(ctx, f.base.password, f.base.enrollment, f.intent.Pin, raw, hash(raw))
			if e == nil || r.Version != "" || f.model.open.Load() != 0 {
				t.Fatal("original failed window/source tail became success", e)
			}
			if scenario == "window-before-commit" {
				if errors.Is(e, ErrCommitUnknown) || f.model.commits != 0 || f.model.data.head != nil || len(f.model.data.refs) != 0 {
					t.Fatal("known failed precommit window escaped rollback", e)
				}
			} else {
				if !errors.Is(e, ErrCommitUnknown) || f.model.commits != 1 {
					t.Fatal("failed postcommit source not explicit unknown", e)
				}
				assertMinioSQLRows(t, f, "active", 1)
				// Resolve identifies SQL METADATA only, without claiming the missing
				// Kubernetes/native source or resource readiness has recovered.
				execs := f.model.execs
				resolved, e := f.base.i.ResolveMinIOSQLAuthority(ctx, f.base.password, f.base.enrollment, f.intent.Pin, raw, hash(raw))
				if e != nil || resolved.State != "active" || f.model.execs != execs {
					t.Fatal("exact independent SQL tuple resolution failed or repaired source", e)
				}
			}
		})
	}
}
