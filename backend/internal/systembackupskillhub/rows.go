// Package systembackupskillhub prepares Skill Hub restore candidates and checks
// supplied snapshots. Its SQL restorer requires explicit write authority and
// fencing; its verifier reads an independently authorized target. B must
// authenticate complete snapshots/mappings and isolate the restore target.
// These helpers grant no service, publisher or task-state authority.
package systembackupskillhub

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"clawreef/internal/models"
)

// Rows contains all eight tables, including history, removed bindings and
// empty tables. Do not JSON-marshal business models as a backup format:
// ManifestJSON and FindingsJSON deliberately have json:"-" tags.
type Rows struct {
	Skills      []models.Skill
	Blobs       []models.SkillBlob
	Versions    []models.SkillVersion
	Bindings    []models.InstanceSkill
	Scans       []models.SkillScanResult
	Jobs        []models.SkillPackageMaterializeJob
	Tags        []models.SkillHubTag
	Assignments []models.SkillHubTagAssignment
}

type BindingPaths struct {
	InstallPath  *string
	WorkspaceDir *string
}

// RestoreMapping is supplied by the common restore coordinator, not derived
// by this module. IDs has exactly the eight owned tables plus users/instances.
// Owned maps are exact and injective. External maps may include unrelated IDs.
// Paths are explicit per source row, including nil/empty paths.
// Object keys are logical keys within an independently isolated provider root.
type RestoreMapping struct {
	IDs              map[string]map[int]int
	ObjectKeys       map[string]string
	BindingPaths     map[int]BindingPaths
	JobWorkspaceDirs map[int]string
}

var (
	ErrRows     = errors.New("skill hub rows invalid")
	ErrMapping  = errors.New("skill hub restore mapping invalid")
	ErrMismatch = errors.New("skill hub restored rows mismatch")
)

// Errors intentionally expose only static table/field names, never row values,
// IDs, object keys, workspace paths, manifests or scanner findings.
func invalid(kind error, table, field string) error {
	return fmt.Errorf("%w: %s.%s", kind, table, field)
}

type reference struct{ field, table string }
type tableView struct {
	name string
	rows reflect.Value
	refs []reference
}

func tables(r Rows) []tableView {
	return []tableView{
		{"skills", reflect.ValueOf(r.Skills), []reference{{"UserID", "users"}, {"PublishedBy", "users"}, {"CurrentVersionID", "skill_versions"}, {"LastScanResultID", "skill_scan_results"}}},
		{"skill_blobs", reflect.ValueOf(r.Blobs), []reference{{"LastScanResultID", "skill_scan_results"}}},
		{"skill_versions", reflect.ValueOf(r.Versions), []reference{{"SkillID", "skills"}, {"BlobID", "skill_blobs"}}},
		{"instance_skills", reflect.ValueOf(r.Bindings), []reference{{"InstanceID", "instances"}, {"SkillID", "skills"}, {"SkillVersionID", "skill_versions"}}},
		{"skill_scan_results", reflect.ValueOf(r.Scans), []reference{{"BlobID", "skill_blobs"}}},
		{"skill_package_materialize_jobs", reflect.ValueOf(r.Jobs), []reference{{"InstanceID", "instances"}, {"SkillID", "skills"}, {"BlobID", "skill_blobs"}}},
		{"skill_hub_tags", reflect.ValueOf(r.Tags), nil},
		{"skill_hub_tag_assignments", reflect.ValueOf(r.Assignments), []reference{{"SkillID", "skills"}, {"TagID", "skill_hub_tags"}}},
	}
}

func validID(id int) bool { return id > 0 && id <= math.MaxInt32 }
func intField(v reflect.Value) (int, bool) {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return 0, false
		}
		v = v.Elem()
	}
	return int(v.Int()), true
}
func setID(v reflect.Value, id int) {
	if v.Kind() == reflect.Pointer {
		p := reflect.New(v.Type().Elem())
		p.Elem().SetInt(int64(id))
		v.Set(p)
	} else {
		v.SetInt(int64(id))
	}
}

// cloneRows copies every model value, including fields excluded from JSON.
// These closed model types contain only scalars, time.Time and scalar/time
// pointers. Tests pin that shape and all db fields against the policy file.
func cloneRows(in Rows) Rows {
	out := in
	dst := reflect.ValueOf(&out).Elem()
	for i, t := range tables(in) {
		copySlice := reflect.MakeSlice(t.rows.Type(), t.rows.Len(), t.rows.Len())
		reflect.Copy(copySlice, t.rows)
		for j := 0; j < copySlice.Len(); j++ {
			row := copySlice.Index(j)
			for k := 0; k < row.NumField(); k++ {
				f := row.Field(k)
				if f.Kind() == reflect.Pointer && !f.IsNil() {
					p := reflect.New(f.Type().Elem())
					p.Elem().Set(f.Elem())
					f.Set(p)
				}
			}
		}
		dst.Field(i).Set(copySlice)
	}
	return out
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return ErrRows
	}
	return ctx.Err()
}

func safeRelative(value string, empty bool) bool {
	if value == "" {
		return empty
	}
	if !utf8.ValidString(value) || value == "." || path.Clean(value) != value || strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\\:") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." || part == "." || part == "" {
			return false
		}
	}
	return strings.IndexFunc(value, unicode.IsControl) < 0
}

func sameOptionalPath(source, target *string) bool {
	if source == nil || target == nil {
		return source == nil && target == nil
	}
	// Preserve SQL NULL vs empty string and do not invent content locations.
	return (*source == "") == (*target == "") && safeRelative(*target, true)
}
