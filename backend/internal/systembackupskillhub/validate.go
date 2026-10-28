package systembackupskillhub

import (
	"context"
	"reflect"
)

// ValidateRows validates local row identity, referential closure and semantic
// cross-table ownership. It does not authenticate a dump, test DB collation,
// check object bytes or prove workspace recoverability.
func ValidateRows(ctx context.Context, r Rows) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	byTable := map[string]map[int]reflect.Value{}
	for _, t := range tables(r) {
		idx := map[int]reflect.Value{}
		for i := 0; i < t.rows.Len(); i++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			row := t.rows.Index(i)
			id, _ := intField(row.FieldByName("ID"))
			if !validID(id) || idx[id].IsValid() {
				return invalid(ErrRows, t.name, "id")
			}
			idx[id] = row
		}
		byTable[t.name] = idx
	}
	for _, t := range tables(r) {
		for i := 0; i < t.rows.Len(); i++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			row := t.rows.Index(i)
			for _, ref := range t.refs {
				id, present := intField(row.FieldByName(ref.field))
				if !present {
					continue
				}
				if !validID(id) {
					return invalid(ErrRows, t.name, ref.field)
				}
				if idx, owned := byTable[ref.table]; owned && !idx[id].IsValid() {
					return invalid(ErrRows, t.name, ref.field)
				}
			}
		}
	}
	// These are byte-exact source uniqueness checks. MySQL collation and seeded
	// target occupancy must additionally be checked by the isolated SQL writer.
	unique := map[string]map[any]bool{}
	add := func(table, field string, key any) error {
		index := table + "." + field
		if unique[index] == nil {
			unique[index] = map[any]bool{}
		}
		if unique[index][key] {
			return invalid(ErrRows, table, field)
		}
		unique[index][key] = true
		return nil
	}
	skillBlobs := map[[2]int]bool{}
	for _, v := range r.Versions {
		if v.VersionNo <= 0 {
			return invalid(ErrRows, "skill_versions", "version_no")
		}
		if err := add("skill_versions", "version_no", [2]int{v.SkillID, v.VersionNo}); err != nil {
			return err
		}
		if err := add("skill_versions", "blob_id", [2]int{v.SkillID, v.BlobID}); err != nil {
			return err
		}
		skillBlobs[[2]int{v.SkillID, v.BlobID}] = true
	}
	for _, s := range r.Skills {
		if err := add("skills", "skill_key", struct {
			user int
			key  string
		}{s.UserID, s.SkillKey}); err != nil {
			return err
		}
		if s.CurrentVersionID != nil && int(byTable["skill_versions"][*s.CurrentVersionID].FieldByName("SkillID").Int()) != s.ID {
			return invalid(ErrRows, "skills", "current_version_id")
		}
		if s.LastScanResultID != nil {
			blob := int(byTable["skill_scan_results"][*s.LastScanResultID].FieldByName("BlobID").Int())
			if !skillBlobs[[2]int{s.ID, blob}] {
				return invalid(ErrRows, "skills", "last_scan_result_id")
			}
		}
	}
	for _, b := range r.Blobs {
		if b.SizeBytes < 0 {
			return invalid(ErrRows, "skill_blobs", "size_bytes")
		}
		if err := add("skill_blobs", "content_hash", b.ContentHash); err != nil {
			return err
		}
		if b.LastScanResultID != nil && int(byTable["skill_scan_results"][*b.LastScanResultID].FieldByName("BlobID").Int()) != b.ID {
			return invalid(ErrRows, "skill_blobs", "last_scan_result_id")
		}
	}
	for _, b := range r.Bindings {
		if err := add("instance_skills", "skill_id", [2]int{b.InstanceID, b.SkillID}); err != nil {
			return err
		}
		if b.SkillVersionID != nil && int(byTable["skill_versions"][*b.SkillVersionID].FieldByName("SkillID").Int()) != b.SkillID {
			return invalid(ErrRows, "instance_skills", "skill_version_id")
		}
	}
	for _, j := range r.Jobs {
		switch j.Status {
		case "pending", "running", "succeeded", "failed", "cancelled":
		default:
			return invalid(ErrRows, "skill_package_materialize_jobs", "status")
		}
		if err := add("skill_package_materialize_jobs", "idempotency_key", j.IdempotencyKey); err != nil {
			return err
		}
	}
	for _, t := range r.Tags {
		if err := add("skill_hub_tags", "tag_key", t.TagKey); err != nil {
			return err
		}
	}
	for _, a := range r.Assignments {
		if err := add("skill_hub_tag_assignments", "tag_id", [2]int{a.SkillID, a.TagID}); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func validateMapping(ctx context.Context, r Rows, m RestoreMapping) error {
	views := tables(r)
	if len(m.IDs) != len(views)+2 {
		return ErrMapping
	}
	for _, name := range []string{"users", "instances"} {
		if _, ok := m.IDs[name]; !ok {
			return invalid(ErrMapping, name, "id")
		}
	}
	for name, ids := range m.IDs {
		seen := map[int]bool{}
		for source, target := range ids {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !validID(source) || !validID(target) || seen[target] {
				return invalid(ErrMapping, knownTable(name), "id")
			}
			seen[target] = true
		}
	}
	for _, t := range views {
		ids, ok := m.IDs[t.name]
		if !ok || len(ids) != t.rows.Len() {
			return invalid(ErrMapping, t.name, "id")
		}
		for i := 0; i < t.rows.Len(); i++ {
			row := t.rows.Index(i)
			id, _ := intField(row.FieldByName("ID"))
			if !validID(ids[id]) {
				return invalid(ErrMapping, t.name, "id")
			}
			for _, ref := range t.refs {
				id, present := intField(row.FieldByName(ref.field))
				if present && !validID(m.IDs[ref.table][id]) {
					return invalid(ErrMapping, t.name, ref.field)
				}
			}
		}
	}
	objects := map[string]bool{}
	for _, b := range r.Blobs {
		if b.ObjectKey != "" {
			objects[b.ObjectKey] = true
		}
	}
	if len(objects) != len(m.ObjectKeys) {
		return invalid(ErrMapping, "skill_blobs", "object_key")
	}
	targetKeys := map[string]bool{}
	for key := range objects {
		target, ok := m.ObjectKeys[key]
		if !ok || !validObjectKey(target) || targetKeys[target] {
			return invalid(ErrMapping, "skill_blobs", "object_key")
		}
		targetKeys[target] = true
	}
	if len(m.BindingPaths) != len(r.Bindings) {
		return invalid(ErrMapping, "instance_skills", "workspace_dir")
	}
	for _, b := range r.Bindings {
		paths, ok := m.BindingPaths[b.ID]
		if !ok || !sameOptionalPath(b.InstallPath, paths.InstallPath) || !sameOptionalPath(b.WorkspaceDir, paths.WorkspaceDir) {
			return invalid(ErrMapping, "instance_skills", "workspace_dir")
		}
	}
	if len(m.JobWorkspaceDirs) != len(r.Jobs) {
		return invalid(ErrMapping, "skill_package_materialize_jobs", "workspace_dir")
	}
	for _, j := range r.Jobs {
		target, ok := m.JobWorkspaceDirs[j.ID]
		if !ok || (j.WorkspaceDir == "") != (target == "") || !safeRelative(target, true) {
			return invalid(ErrMapping, "skill_package_materialize_jobs", "workspace_dir")
		}
	}
	return ctx.Err()
}

func knownTable(name string) string {
	for _, t := range tables(Rows{}) {
		if name == t.name {
			return name
		}
	}
	if name == "users" || name == "instances" {
		return name
	}
	return "unknown_table"
}
