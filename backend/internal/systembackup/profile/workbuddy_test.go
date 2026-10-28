package profile

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"clawreef/internal/systembackup/artifact"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/scope"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
)

func identitySnapshotFixture() domain.Snapshot {
	table := func(name, pk, columns string, rows ...domain.Row) domain.Table {
		t := domain.Table{Name: name, Engine: "InnoDB", PrimaryKey: []string{pk}, Rows: rows}
		for _, c := range strings.Fields(columns) {
			t.Columns = append(t.Columns, domain.Column{Name: c, Type: "int"})
		}
		return t
	}
	row := func(values ...string) domain.Row {
		r := domain.Row{}
		for i := 0; i < len(values); i += 2 {
			r[values[i]] = domain.Text(values[i+1])
		}
		return r
	}
	users := table("users", "id", "id username password_hash role is_active", row("id", "4", "username", "admin", "password_hash", "synthetic", "role", "admin", "is_active", "1"))
	instances := table("instances", "id", "id user_id type instance_mode runtime_type runtime_variant os_type", row("id", "7", "user_id", "4", "type", "workbuddy", "instance_mode", "lite", "runtime_type", "gateway", "runtime_variant", "linux", "os_type", "linux"))
	instances.Columns = append(instances.Columns, domain.Column{Name: "workbuddy_storage_identity", Type: "varchar(512)", Nullable: true})
	instances.Rows[0]["workbuddy_storage_identity"] = domain.Cell{Null: true}
	identity := table("workbuddy_linux_identities", "instance_id", "instance_id user_id linux_uid created_at", row("instance_id", "7", "user_id", "4", "linux_uid", "21000", "created_at", "2020-01-01 00:00:00.000000"))
	identity.Columns[3].Type = "datetime(6)"
	identity.UniqueKeys = []domain.UniqueKey{{Name: "linux_uid", Columns: []string{"linux_uid"}}}
	allocator := table("workbuddy_linux_identity_allocator", "id", "id next_uid", row("id", "1", "next_uid", "23000"))
	return domain.Snapshot{Version: domain.Version, Tables: []domain.Table{users, table("user_quotas", "id", "id"), instances, identity, allocator}}
}

func TestWorkBuddyProfileBindsAuthenticatedSQLIdentityAndRejectsDrift(t *testing.T) {
	ctx := context.Background()
	s := identitySnapshotFixture()
	w := work{PartID: "instance-7", Invocation: worker.Invocation{Request: worker.Request{RuntimePolicy: &worker.RuntimePolicy{Runtime: scope.Runtime{Type: "workbuddy"}}}}}
	if e := bindWorkBuddyIdentity(s, &w); e != nil {
		t.Fatal(e)
	}
	if w.Invocation.Request.WorkBuddyIdentity.UID != 21000 {
		t.Fatal("not bound to SQL")
	}
	root, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	d := &Driver{Config: Config{WorkBuddy: domain.WorkBuddyUIDSchema()}, Keys: artifact.SecretKeys{"wrap": make([]byte, 32)}}
	binding := staging.Binding{BackupID: "fixture", Attempt: "1", Path: "database", CaptureContextHash: strings.Repeat("a", 64), EnvelopeID: "key"}
	key := make([]byte, 32)
	wrapped, e := d.Keys.Wrap(ctx, binding, "wrap", key)
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := staging.SealFile(ctx, root, "database.enc", key, binding, func(out io.Writer) error {
		return staging.Compress(out, func(out io.Writer) error { return domain.Encode(out, s) })
	})
	if e != nil {
		t.Fatal(e)
	}
	b := artifact.Bundle{Parts: []artifact.Part{{ID: "database", Binding: binding, Key: wrapped, Receipt: receipt}}}
	p := plan{Work: []work{w}}
	if e = d.validateWorkBuddyCapture(ctx, root, b, p); e != nil {
		t.Fatal(e)
	}
	// Independent target derivation uses the authenticated archive, no source DB.
	decoded, e := d.databaseSnapshot(ctx, root, b)
	if e != nil {
		t.Fatal(e)
	}
	target := w
	target.Invocation.Request.WorkBuddyIdentity = nil
	if e = bindWorkBuddyIdentity(decoded, &target); e != nil || !jsonEqual(target.Invocation.Request.WorkBuddyIdentity, w.Invocation.Request.WorkBuddyIdentity) {
		t.Fatal("target identity derivation failed", e)
	}
	p.Work[0].Invocation.Request.WorkBuddyIdentity.UID++
	if d.validateWorkBuddyCapture(ctx, root, b, p) == nil {
		t.Fatal("source identity drift accepted")
	}
	p.Work[0].Invocation.Request.WorkBuddyIdentity = nil
	if d.validateWorkBuddyCapture(ctx, root, b, p) == nil {
		t.Fatal("missing frozen identity accepted")
	}
	b.Parts[0].Binding.EnvelopeID = "tampered"
	if _, e = d.databaseSnapshot(ctx, root, b); e == nil {
		t.Fatal("unauthenticated SQL accepted")
	}
}

func TestWorkBuddyUIDContractIsPinnedInProfile(t *testing.T) {
	d, _, _ := fixture(t)
	old := d.contract().PolicySHA256
	d.Config.WorkBuddy = domain.WorkBuddyUIDSchema()
	if d.contract().PolicySHA256 == old {
		t.Fatal("UID contract not signed")
	}
	if e := d.Config.Validate(); e != nil {
		t.Fatal(e)
	}
	d.Config.WorkBuddy.AllocatorSHA256 = strings.Repeat("0", 64)
	if d.Config.Validate() == nil {
		t.Fatal("arbitrary allocator contract accepted")
	}
}
