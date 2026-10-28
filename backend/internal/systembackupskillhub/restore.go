package systembackupskillhub

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"time"
)

// PrepareRestoreRows is a pure candidate transformation, not the Runner's
// Normalizer or an SQL writer. All-or-nothing: no rows are returned on error.
// Caller must supply complete authenticated source/mappings, and validate the
// isolated target and current write authority again at SQL commit time.
func PrepareRestoreRows(ctx context.Context, source Rows, mapping RestoreMapping) (Rows, error) {
	var empty Rows
	if err := ValidateRows(ctx, source); err != nil {
		return empty, err
	}
	if err := validateMapping(ctx, source, mapping); err != nil {
		return empty, err
	}
	out := cloneRows(source)
	for _, t := range tables(out) {
		for i := 0; i < t.rows.Len(); i++ {
			if err := ctx.Err(); err != nil {
				return empty, err
			}
			row := t.rows.Index(i)
			id, _ := intField(row.FieldByName("ID"))
			setID(row.FieldByName("ID"), mapping.IDs[t.name][id])
			for _, ref := range t.refs {
				field := row.FieldByName(ref.field)
				id, present := intField(field)
				if present {
					setID(field, mapping.IDs[ref.table][id])
				}
			}
		}
	}
	for i := range out.Blobs {
		if key := source.Blobs[i].ObjectKey; key != "" {
			out.Blobs[i].ObjectKey = mapping.ObjectKeys[key]
		}
	}
	for i := range out.Bindings {
		p := mapping.BindingPaths[source.Bindings[i].ID]
		out.Bindings[i].InstallPath = cloneString(p.InstallPath)
		out.Bindings[i].WorkspaceDir = cloneString(p.WorkspaceDir)
	}
	for i := range out.Jobs {
		out.Jobs[i].WorkspaceDir = mapping.JobWorkspaceDirs[source.Jobs[i].ID]
		switch out.Jobs[i].Status {
		case "pending", "running":
			out.Jobs[i].Status = "cancelled"
		}
	}
	for _, t := range tables(out) {
		sort.Slice(t.rows.Interface(), func(i, j int) bool {
			return t.rows.Index(i).FieldByName("ID").Int() < t.rows.Index(j).FieldByName("ID").Int()
		})
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return out, nil
}
func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	out := *value
	return &out
}

func dbColumn(tag string) string { return strings.Split(tag, ",")[0] }
func equalField(a, b reflect.Value) bool {
	if a.Kind() == reflect.Pointer {
		if a.IsNil() || b.IsNil() {
			return a.IsNil() && b.IsNil()
		}
		a, b = a.Elem(), b.Elem()
	}
	if a.Type() == reflect.TypeOf(time.Time{}) {
		return a.Interface().(time.Time).Equal(b.Interface().(time.Time))
	}
	return reflect.DeepEqual(a.Interface(), b.Interface())
}

// CompareRestoredRows independently compares a read-only target snapshot with
// source rows and the common mapping. It does not call PrepareRestoreRows or
// trust its output as the expected snapshot. Order is irrelevant; duplicates,
// extra/missing rows, raw fields (including json:"-"), nulls and history matter.
// A nil error is a local comparison, not a public verifier/acceptance result.
func CompareRestoredRows(ctx context.Context, source Rows, mapping RestoreMapping, target Rows) error {
	if err := ValidateRows(ctx, source); err != nil {
		return err
	}
	if err := validateMapping(ctx, source, mapping); err != nil {
		return err
	}
	if err := ValidateRows(ctx, target); err != nil {
		return err
	}
	targets := tables(target)
	for ti, t := range tables(source) {
		actual := targets[ti]
		if t.rows.Len() != actual.rows.Len() {
			return invalid(ErrMismatch, t.name, "row_count")
		}
		byID := map[int]reflect.Value{}
		for i := 0; i < actual.rows.Len(); i++ {
			r := actual.rows.Index(i)
			byID[int(r.FieldByName("ID").Int())] = r
		}
		for i := 0; i < t.rows.Len(); i++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			row := t.rows.Index(i)
			id := int(row.FieldByName("ID").Int())
			got, ok := byID[mapping.IDs[t.name][id]]
			if !ok {
				return invalid(ErrMismatch, t.name, "id")
			}
			for f := 0; f < row.NumField(); f++ {
				field := row.Type().Field(f)
				a, b := row.Field(f), got.Field(f)
				if field.Name == "ID" {
					continue
				}
				refTable := ""
				for _, ref := range t.refs {
					if ref.field == field.Name {
						refTable = ref.table
						break
					}
				}
				equal := false
				if refTable != "" {
					sid, sp := intField(a)
					tid, tp := intField(b)
					equal = sp == tp && (!sp || mapping.IDs[refTable][sid] == tid)
				} else {
					switch {
					case t.name == "skill_blobs" && field.Name == "ObjectKey":
						expected := a.String()
						if expected != "" {
							expected = mapping.ObjectKeys[expected]
						}
						equal = expected == b.String()
					case t.name == "instance_skills" && field.Name == "InstallPath":
						equal = reflect.DeepEqual(mapping.BindingPaths[id].InstallPath, b.Interface())
					case t.name == "instance_skills" && field.Name == "WorkspaceDir":
						equal = reflect.DeepEqual(mapping.BindingPaths[id].WorkspaceDir, b.Interface())
					case t.name == "skill_package_materialize_jobs" && field.Name == "WorkspaceDir":
						equal = mapping.JobWorkspaceDirs[id] == b.String()
					case t.name == "skill_package_materialize_jobs" && field.Name == "Status":
						expected := a.String()
						if expected == "pending" || expected == "running" {
							expected = "cancelled"
						}
						equal = expected == b.String()
					default:
						equal = equalField(a, b)
					}
				}
				if !equal {
					return invalid(ErrMismatch, t.name, dbColumn(field.Tag.Get("db")))
				}
			}
		}
	}
	return ctx.Err()
}
