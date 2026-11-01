package domain

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"time"

	sh "clawreef/internal/systembackupskillhub"
)

// skillRows bridges the existing raw SQL archive to B's existing eight-table
// validator. Reflection only decodes explicitly allowlisted columns; it never
// creates a backup format or grants authority to newly added model fields.
// The raw cells (including NULL timestamps and json:"-" fields) remain the
// source of target writes, so the model projection cannot lose archive bytes.
func skillRows(ctx context.Context, s Snapshot, complete bool) (sh.Rows, bool, error) {
	var out sh.Rows
	targets := map[string]any{
		"skills": &out.Skills, "skill_blobs": &out.Blobs, "skill_versions": &out.Versions,
		"instance_skills": &out.Bindings, "skill_scan_results": &out.Scans,
		"skill_package_materialize_jobs": &out.Jobs, "skill_hub_tags": &out.Tags,
		"skill_hub_tag_assignments": &out.Assignments,
	}
	seen, nonempty := map[string]bool{}, false
	for _, table := range s.Tables {
		if err := ctx.Err(); err != nil {
			return sh.Rows{}, false, err
		}
		ptr, owned := targets[table.Name]
		if !owned {
			continue
		}
		seen[table.Name] = true
		allowed := map[string]bool{}
		for _, c := range strings.Fields(dependencyColumns[table.Name]) {
			allowed[c] = true
		}
		dst := reflect.ValueOf(ptr).Elem()
		for _, row := range table.Rows {
			if err := ctx.Err(); err != nil {
				return sh.Rows{}, false, err
			}
			nonempty = true
			v := reflect.New(dst.Type().Elem()).Elem()
			for n := 0; n < v.NumField(); n++ {
				name := strings.Split(v.Type().Field(n).Tag.Get("db"), ",")[0]
				cell, ok := row[name]
				if !allowed[name] || !ok {
					return sh.Rows{}, false, ErrSchema
				}
				if err := skillCell(v.Field(n), cell); err != nil {
					return sh.Rows{}, false, err
				}
			}
			dst.Set(reflect.Append(dst, v))
		}
	}
	if complete && nonempty && len(seen) != len(targets) {
		return sh.Rows{}, false, ErrSchema
	}
	return out, nonempty, nil
}

func skillCell(v reflect.Value, cell Cell) error {
	if cell.Null {
		if v.Kind() == reflect.Pointer || v.Type() == reflect.TypeOf(time.Time{}) {
			return nil
		}
		return ErrData
	}
	if v.Kind() == reflect.Pointer {
		v.Set(reflect.New(v.Type().Elem()))
		v = v.Elem()
	}
	if v.Type() == reflect.TypeOf(time.Time{}) {
		for _, layout := range []string{"2006-01-02 15:04:05.999999", time.RFC3339Nano} {
			if at, err := time.Parse(layout, cell.String()); err == nil {
				v.Set(reflect.ValueOf(at))
				return nil
			}
		}
		return ErrData
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString(cell.String())
	case reflect.Int, reflect.Int64:
		n, err := strconv.ParseInt(cell.String(), 10, v.Type().Bits())
		if err != nil {
			return ErrData
		}
		v.SetInt(n)
	case reflect.Bool:
		if cell.String() != "0" && cell.String() != "1" {
			return ErrData
		}
		v.SetBool(cell.String() == "1")
	default:
		return ErrSchema
	}
	return nil
}

func validateSkillRestore(ctx context.Context, s Snapshot, mapping *sh.RestoreMapping) error {
	rows, nonempty, err := skillRows(ctx, s, true)
	if err != nil {
		return err
	}
	if !nonempty && mapping == nil {
		return nil
	}
	if mapping == nil {
		return ErrNormalization
	}
	// The common raw SQL restore preserves IDs in every domain. B's remapping
	// API is reused, but an ID-changing map cannot be mixed with that contract.
	for _, ids := range mapping.IDs {
		for source, target := range ids {
			if err := ctx.Err(); err != nil {
				return err
			}
			if source != target {
				return ErrData
			}
		}
	}
	for _, name := range []string{"users", "instances"} {
		actual := map[int]bool{}
		for _, table := range s.Tables {
			if table.Name == name {
				for _, row := range table.Rows {
					id, err := strconv.Atoi(row["id"].String())
					if err != nil {
						return ErrData
					}
					actual[id] = true
				}
			}
		}
		for id := range mapping.IDs[name] {
			if !actual[id] {
				return ErrData
			}
		}
	}
	if _, err := sh.PrepareRestoreRows(ctx, rows, *mapping); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrData
	}
	return nil
}

func normalizeSkill(table string, r Row, mapping *sh.RestoreMapping) error {
	if _, owned := skillCaptureColumns[table]; !owned {
		return nil
	}
	if mapping == nil {
		return ErrNormalization
	}
	id, err := strconv.Atoi(r["id"].String())
	if err != nil {
		return ErrData
	}
	switch table {
	case "skill_blobs":
		if key := r["object_key"].String(); key != "" {
			r["object_key"] = Text(mapping.ObjectKeys[key])
		}
	case "instance_skills":
		p := mapping.BindingPaths[id]
		for name, value := range map[string]*string{"install_path": p.InstallPath, "workspace_dir": p.WorkspaceDir} {
			if value == nil {
				r[name] = Cell{Null: true}
			} else {
				r[name] = Text(*value)
			}
		}
	case "skill_package_materialize_jobs":
		r["workspace_dir"] = Text(mapping.JobWorkspaceDirs[id])
		if r["status"].String() == "pending" || r["status"].String() == "running" {
			r["status"] = Text("cancelled")
		}
	}
	return nil
}

// VerifySkillQuarantine checks semantic closure independently of encrypted
// expected bytes. Paths remain relative to the separately verified target
// mounts; checking this SQL projection does not attest those files/objects.
func VerifySkillQuarantine(s Snapshot) error {
	return VerifySkillQuarantineContext(context.Background(), s)
}

// VerifySkillQuarantineContext inherits the task cancellation/deadline through
// both raw-cell projection and the owner module's relationship validation.
func VerifySkillQuarantineContext(ctx context.Context, s Snapshot) error {
	rows, nonempty, err := skillRows(ctx, s, false)
	if err != nil || !nonempty {
		return err
	}
	m := sh.RestoreMapping{IDs: map[string]map[int]int{}, ObjectKeys: map[string]string{}, BindingPaths: map[int]sh.BindingPaths{}, JobWorkspaceDirs: map[int]string{}}
	for _, table := range s.Tables {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, owned := skillCaptureColumns[table.Name]
		if !owned && table.Name != "users" && table.Name != "instances" {
			continue
		}
		m.IDs[table.Name] = map[int]int{}
		for _, row := range table.Rows {
			id, err := strconv.Atoi(row["id"].String())
			if err != nil {
				return ErrData
			}
			m.IDs[table.Name][id] = id
			if table.Name == "instances" && row["status"].String() != "stopped" {
				return ErrNormalization
			}
		}
	}
	// Empty tables can be omitted from the normalized write plan, but must have
	// appeared in the original source. Fill only their empty mapping here.
	for name := range skillCaptureColumns {
		if m.IDs[name] == nil {
			m.IDs[name] = map[int]int{}
		}
	}
	for _, b := range rows.Blobs {
		if b.ObjectKey != "" {
			m.ObjectKeys[b.ObjectKey] = b.ObjectKey
		}
	}
	for _, b := range rows.Bindings {
		m.BindingPaths[b.ID] = sh.BindingPaths{InstallPath: b.InstallPath, WorkspaceDir: b.WorkspaceDir}
	}
	for _, j := range rows.Jobs {
		if j.Status != "succeeded" && j.Status != "failed" && j.Status != "cancelled" {
			return ErrNormalization
		}
		m.JobWorkspaceDirs[j.ID] = j.WorkspaceDir
	}
	if _, err := sh.PrepareRestoreRows(ctx, rows, m); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrData
	}
	return nil
}
