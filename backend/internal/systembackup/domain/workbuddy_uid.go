package domain

import "strconv"

// WorkBuddyUIDV1 is the explicitly selected schema observed on 2026-10-26.
// It preserves historical reservations; it never reclaims UIDs or fabricates a
// storage identity. GID equals UID as enforced by this Linux Lite launcher.
const WorkBuddyUIDV1 = "workbuddy-linux-uid.v1"
const workBuddyIdentities = "workbuddy_linux_identities"
const workBuddyAllocator = "workbuddy_linux_identity_allocator"

func workBuddyUIDTables() (Table, Table) {
	i := Table{Name: workBuddyIdentities, Engine: "InnoDB", PrimaryKey: []string{"instance_id"}, Columns: []Column{{Name: "instance_id", Type: "int"}, {Name: "user_id", Type: "int"}, {Name: "linux_uid", Type: "int"}, {Name: "created_at", Type: "datetime(6)"}}, UniqueKeys: []UniqueKey{{Name: "linux_uid", Columns: []string{"linux_uid"}}}}
	a := Table{Name: workBuddyAllocator, Engine: "InnoDB", PrimaryKey: []string{"id"}, Columns: []Column{{Name: "id", Type: "int"}, {Name: "next_uid", Type: "int"}}}
	return i, a
}

// WorkBuddyUIDSchema returns a pinned contract, not a fingerprint of arbitrary
// incoming metadata. Both source and target must match these exact structures.
func WorkBuddyUIDSchema() *WorkBuddySchema {
	i, a := workBuddyUIDTables()
	return &WorkBuddySchema{Version: WorkBuddyUIDV1, SHA256: SchemaDigest(i), Instance: "instance_id", UID: "linux_uid", Layout: WorkBuddyUIDV1, AllocatorSHA256: SchemaDigest(a)}
}
func (w *WorkBuddySchema) uidLayout() bool { return w != nil && w.Layout == WorkBuddyUIDV1 }
func (w *WorkBuddySchema) validUIDContract() bool {
	if !w.uidLayout() {
		return false
	}
	expected := WorkBuddyUIDSchema()
	return *w == *expected
}
func workBuddyTable(s Snapshot, name string) (Table, bool) {
	for _, t := range s.Tables {
		if t.Name == name {
			return t, true
		}
	}
	return Table{}, false
}
func boundedID(c Cell, min, max uint64) (uint64, bool) {
	if c.Null {
		return 0, false
	}
	v, e := strconv.ParseUint(c.String(), 10, 32)
	return v, e == nil && v >= min && v <= max && strconv.FormatUint(v, 10) == c.String()
}

func validateWorkBuddyUID(s Snapshot, w *WorkBuddySchema) error {
	if !w.validUIDContract() {
		return ErrSchema
	}
	ident, ok := workBuddyTable(s, workBuddyIdentities)
	if !ok || SchemaDigest(ident) != w.SHA256 {
		return ErrSchema
	}
	allocator, ok := workBuddyTable(s, workBuddyAllocator)
	if !ok || SchemaDigest(allocator) != w.AllocatorSHA256 {
		return ErrSchema
	}
	instances := map[string]Row{}
	live := map[string]bool{}
	for _, t := range s.Tables {
		if t.Name == "instances" {
			for _, r := range t.Rows {
				instances[r["id"].String()] = r
				if r["type"].String() == "workbuddy" {
					// Only the observed Linux Lite identity contract is enabled here.
					if r["instance_mode"].String() != "lite" || r["runtime_type"].String() != "gateway" || r["runtime_variant"].String() != "linux" {
						return ErrSchema
					}
					storage, exists := r["workbuddy_storage_identity"]
					if !exists || !storage.Null || len(storage.Bytes) != 0 {
						return ErrSchema
					}
					live[r["id"].String()] = false
				}
			}
		}
	}
	seenID, seenUID := map[string]bool{}, map[uint64]bool{}
	var maximum uint64
	for _, r := range ident.Rows {
		if _, ok := boundedID(r["instance_id"], 1, 2147483647); !ok {
			return ErrData
		}
		if _, ok := boundedID(r["user_id"], 1, 2147483647); !ok {
			return ErrData
		}
		uid, ok := boundedID(r["linux_uid"], 10000, 65533)
		if !ok || seenUID[uid] || seenID[r["instance_id"].String()] {
			return ErrData
		}
		id := r["instance_id"].String()
		if inst, exists := instances[id]; exists {
			if inst["type"].String() != "workbuddy" || inst["user_id"].String() != r["user_id"].String() {
				return ErrData
			}
			live[id] = true
		}
		// No live instance: preserve reservation and historical owner verbatim,
		// even if that user is gone. This exception never applies to other tables.
		seenID[id] = true
		seenUID[uid] = true
		if uid > maximum {
			maximum = uid
		}
	}
	for _, found := range live {
		if !found {
			return ErrData
		}
	}
	if len(allocator.Rows) != 1 || allocator.Rows[0]["id"].String() != "1" {
		return ErrData
	}
	next, ok := boundedID(allocator.Rows[0]["next_uid"], 10000, 65534)
	if !ok || next <= maximum {
		return ErrData
	}
	// 65534 represents exhaustion, not a UID to allocate. Never wrap or reset.
	return nil
}

func validateWorkBuddyUIDTarget(target map[string]Table, w *WorkBuddySchema) error {
	if !w.validUIDContract() {
		return ErrSchema
	}
	i, ok := target[workBuddyIdentities]
	if !ok || SchemaDigest(i) != w.SHA256 {
		return ErrSchema
	}
	a, ok := target[workBuddyAllocator]
	if !ok || SchemaDigest(a) != w.AllocatorSHA256 {
		return ErrSchema
	}
	return nil
}
