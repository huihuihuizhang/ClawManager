package domain

// These fixtures reproduce schema and relationship SHAPES observed read-only
// on 2026-10-26. All row IDs, UIDs, timestamps and account data are synthetic.
// These preserve the legacy rejection boundary. The versioned UID adapter's
// positive/negative import tests live in workbuddy_uid_test.go.
import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"clawreef/internal/systembackup/staging"
)

func observedWorkBuddyFixture(retired bool) (Snapshot, []Table, Policy) {
	s, target, p := fixture()
	instances := &s.Tables[2]
	instances.Columns = append(instances.Columns, Column{Name: "workbuddy_storage_identity", Type: "varchar(512)", Nullable: true})
	instances.Rows[0]["type"] = Text("workbuddy")
	instances.Rows[0]["workbuddy_storage_identity"] = Cell{Null: true}
	identity := Table{Name: "workbuddy_linux_identities", Engine: "InnoDB", PrimaryKey: []string{"instance_id"}, Columns: []Column{{Name: "instance_id", Type: "int"}, {Name: "user_id", Type: "int"}, {Name: "linux_uid", Type: "int"}, {Name: "created_at", Type: "datetime(6)"}}, Rows: []Row{{"instance_id": Text("7"), "user_id": Text("4"), "linux_uid": Text("21000"), "created_at": Text("2020-01-01 00:00:00.000000")}}}
	identity.UniqueKeys = []UniqueKey{{Name: "linux_uid", Columns: []string{"linux_uid"}}}
	if retired {
		identity.Rows = append(identity.Rows, Row{"instance_id": Text("987"), "user_id": Text("4"), "linux_uid": Text("21001"), "created_at": Text("2020-01-01 00:00:01.000000")})
	}
	allocator := Table{Name: "workbuddy_linux_identity_allocator", Engine: "InnoDB", PrimaryKey: []string{"id"}, Columns: []Column{{Name: "id", Type: "int"}, {Name: "next_uid", Type: "int"}}, Rows: []Row{{"id": Text("1"), "next_uid": Text("21010")}}}
	s.Tables = append(s.Tables, identity, allocator)
	target[2] = *instances
	target = append(target, identity, allocator)
	return s, target, p
}

func TestObservedWorkBuddyShapeCapturePreservesHistoricalIdentityAndAllocator(t *testing.T) {
	s, _, _ := observedWorkBuddyFixture(true)
	state := &memoryDB{tables: copyTables(s.Tables)}
	db := database(state)
	captured, e := Capture(context.Background(), db, Limits{100, 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	if state.writes != 0 || state.readOnlyBegins == 0 {
		t.Fatal("capture was not read-only")
	}
	db.Close()
	key := bytes.Repeat([]byte{37}, 32)
	binding := staging.Binding{BackupID: "synthetic-workbuddy-observed", Attempt: "1", Path: "mysql/domain", CaptureContextHash: string(bytes.Repeat([]byte{'a'}, 64)), EnvelopeID: "fixture-key"}
	var sealed, plain bytes.Buffer
	if e = staging.Seal(context.Background(), &sealed, key, binding, func(w io.Writer) error { return Encode(w, captured) }); e != nil {
		t.Fatal(e)
	}
	if e = staging.Open(context.Background(), &sealed, &plain, key, binding, 1<<20); e != nil {
		t.Fatal(e)
	}
	recovered, e := Decode(&plain, Limits{100, 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	identities := find(recovered, "workbuddy_linux_identities")
	if len(identities.Rows) != 2 || find(recovered, "workbuddy_linux_identity_allocator").Rows[0]["next_uid"].String() != "21010" {
		t.Fatal("capture lost historical identities or allocator high-water mark")
	}
	if !find(recovered, "instances").Rows[0]["workbuddy_storage_identity"].Null {
		t.Fatal("capture fabricated a storage identity")
	}
	before, _ := Digest(captured)
	after, _ := Digest(recovered)
	if before != after {
		t.Fatal("encrypted round trip changed source data")
	}
}

func TestObservedWorkBuddyShapeCannotUseUnprovenAdapterOrWriteBootstrap(t *testing.T) {
	for _, retired := range []bool{false, true} {
		s, target, p := observedWorkBuddyFixture(retired)
		identity := find(s, "workbuddy_linux_identities")
		// Even binding the real column fingerprint does not make the old
		// separate-GID/storage-column contract compatible with this source.
		p.WorkBuddy = &WorkBuddySchema{Version: "synthetic-observed-shape", SHA256: SchemaDigest(identity), Instance: "instance_id", UID: "linux_uid", GID: "linux_gid", StorageIdentity: "storage_identity"}
		state := isolatedTarget(target)
		db := database(state)
		before, _ := Digest(Snapshot{Version: Version, Tables: state.tables})
		_, e := RestoreDrill(context.Background(), db, targetProof(), s, p)
		db.Close()
		want := ErrSchema
		if retired {
			want = ErrData
		}
		if !errors.Is(e, want) {
			t.Fatalf("retired=%v: want %v, got %v", retired, want, e)
		}
		after, _ := Digest(Snapshot{Version: Version, Tables: state.tables})
		if state.writes != 0 || state.commits != 0 || before != after {
			t.Fatal("unproven identity adapter changed bootstrap target")
		}
	}
}
