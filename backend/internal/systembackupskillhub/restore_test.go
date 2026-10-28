package systembackupskillhub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"clawreef/internal/models"
)

func ptr[T any](v T) *T { return &v }
func fixture() (Rows, RestoreMapping) {
	at := time.Date(2026, 10, 22, 4, 5, 6, 123000000, time.UTC)
	r := Rows{
		Skills: []models.Skill{
			{ID: 10, UserID: 1, SkillKey: "demo", Name: "private name", Description: ptr("private description"), CurrentVersionID: ptr(101), SourceType: "uploaded", Status: "active", Visibility: "private", RiskLevel: "low", LastScanResultID: ptr(10001), LastScannedAt: &at},
			{ID: 20, UserID: 2, SkillKey: "public", Name: "public name", CurrentVersionID: ptr(200), Visibility: "public", PublishedBy: ptr(1), PublishedAt: &at, SourceType: "uploaded", Status: "active", RiskLevel: "low", LastScanResultID: ptr(10000)},
			{ID: 30, UserID: 1, SkillKey: "new", Name: "unpackaged", CurrentVersionID: ptr(300), Visibility: "private", Status: "active"},
		},
		Blobs: []models.SkillBlob{
			{ID: 1000, ContentHash: "business-md5-shared", ArchiveHash: "legacy-hash", ObjectKey: "shared/demo.zip", FileName: "demo.zip", MediaType: "application/zip", SizeBytes: 5, ScanStatus: "completed", RiskLevel: "low", LastScanResultID: ptr(10000), LastScannedAt: &at},
			{ID: 1001, ContentHash: "business-md5-v2", ArchiveHash: "archive-hash-v2", ObjectKey: "archive/v2.zip", SizeBytes: 7, ScanStatus: "completed", RiskLevel: "low", LastScanResultID: ptr(10001)},
			{ID: 1002, ContentHash: "unpackaged-hash", ObjectKey: "", ScanStatus: "pending"},
		},
		Versions: []models.SkillVersion{
			{ID: 100, SkillID: 10, BlobID: 1000, VersionNo: 1, ManifestJSON: ptr("{\"private\":\"manifest-v1\"}"), SourceType: "uploaded"},
			{ID: 101, SkillID: 10, BlobID: 1001, VersionNo: 2, ManifestJSON: ptr("{\"private\":\"manifest-v2\"}"), SourceType: "uploaded"},
			{ID: 200, SkillID: 20, BlobID: 1000, VersionNo: 1, ManifestJSON: ptr(""), SourceType: "uploaded"},
			{ID: 300, SkillID: 30, BlobID: 1002, VersionNo: 1, SourceType: "discovered"},
		},
		Bindings: []models.InstanceSkill{
			{ID: 500, InstanceID: 7, SkillID: 10, SkillVersionID: ptr(100), InstallPath: ptr("/source/private/demo"), WorkspaceDir: ptr("skills/demo"), ObservedHash: ptr("legitimate-user-edit"), Status: "active", LastSeenAt: &at},
			{ID: 501, InstanceID: 8, SkillID: 20, WorkspaceDir: ptr(""), Status: "removed", RemovedAt: &at},
			{ID: 502, InstanceID: 7, SkillID: 30, SkillVersionID: ptr(300), WorkspaceDir: ptr("skills/new"), ObservedHash: ptr("unpackaged-hash"), Status: "active"},
		},
		Scans: []models.SkillScanResult{
			{ID: 10000, BlobID: 1000, Engine: "scanner", RiskLevel: "low", Status: "completed", Summary: ptr("private finding"), FindingsJSON: ptr("{\"finding\":\"private\"}"), ScannedAt: &at},
			{ID: 10001, BlobID: 1001, Engine: "scanner", RiskLevel: "low", Status: "completed", FindingsJSON: ptr(""), ScannedAt: &at},
		},
		Tags:        []models.SkillHubTag{{ID: 40, TagKey: "featured", Name: "Featured", Description: ptr("admin only"), SortOrder: 2, AdminOnly: true}, {ID: 41, TagKey: "coding", Name: "Coding", SortOrder: 1}},
		Assignments: []models.SkillHubTagAssignment{{ID: 60, SkillID: 20, TagID: 40}, {ID: 61, SkillID: 10, TagID: 41}},
	}
	for i, status := range []string{"pending", "running", "succeeded", "failed", "cancelled"} {
		r.Jobs = append(r.Jobs, models.SkillPackageMaterializeJob{ID: 900 + i, InstanceID: 7, SkillID: 30, BlobID: 1002, WorkspaceDir: "skills/new", ContentHash: "unpackaged-hash", Status: status, AttemptCount: 2, MaxAttempts: 5, LastError: ptr("private historical error"), IdempotencyKey: "job-" + status, TriggerSource: "sync", StartedAt: &at})
	}
	for _, table := range tables(r) {
		for i := 0; i < table.rows.Len(); i++ {
			for _, name := range []string{"CreatedAt", "UpdatedAt"} {
				f := table.rows.Index(i).FieldByName(name)
				if f.IsValid() {
					f.Set(reflect.ValueOf(at))
				}
			}
		}
	}
	m := RestoreMapping{
		IDs: map[string]map[int]int{
			"skills": {10: 110, 20: 120, 30: 130}, "skill_blobs": {1000: 2000, 1001: 2001, 1002: 2002},
			"skill_versions": {100: 1100, 101: 1101, 200: 1200, 300: 1300}, "instance_skills": {500: 1500, 501: 1501, 502: 1502},
			"skill_scan_results": {10000: 20000, 10001: 20001}, "skill_package_materialize_jobs": {900: 1900, 901: 1901, 902: 1902, 903: 1903, 904: 1904},
			"skill_hub_tags": {40: 140, 41: 141}, "skill_hub_tag_assignments": {60: 160, 61: 161},
			"users": {1: 11, 2: 12}, "instances": {7: 17, 8: 18},
		},
		ObjectKeys:       map[string]string{"shared/demo.zip": "restored/shared.zip", "archive/v2.zip": "restored/v2.zip"},
		BindingPaths:     map[int]BindingPaths{500: {InstallPath: ptr("home/skills/demo"), WorkspaceDir: ptr("restored/skills/demo")}, 501: {WorkspaceDir: ptr("")}, 502: {WorkspaceDir: ptr("restored/skills/new")}},
		JobWorkspaceDirs: map[int]string{900: "restored/skills/new", 901: "restored/skills/new", 902: "restored/skills/new", 903: "restored/skills/new", 904: "restored/skills/new"},
	}
	return r, m
}

// Deliberately spell out target IDs and special fields independently of the
// production mapping loops. Shared blobs, old versions and nulls remain.
func goldenRows(source Rows) Rows {
	r := cloneRows(source)
	r.Skills[0].ID = 110
	r.Skills[0].UserID = 11
	r.Skills[0].CurrentVersionID = ptr(1101)
	r.Skills[0].LastScanResultID = ptr(20001)
	r.Skills[1].ID = 120
	r.Skills[1].UserID = 12
	r.Skills[1].CurrentVersionID = ptr(1200)
	r.Skills[1].PublishedBy = ptr(11)
	r.Skills[1].LastScanResultID = ptr(20000)
	r.Skills[2].ID = 130
	r.Skills[2].UserID = 11
	r.Skills[2].CurrentVersionID = ptr(1300)
	r.Blobs[0].ID = 2000
	r.Blobs[0].ObjectKey = "restored/shared.zip"
	r.Blobs[0].LastScanResultID = ptr(20000)
	r.Blobs[1].ID = 2001
	r.Blobs[1].ObjectKey = "restored/v2.zip"
	r.Blobs[1].LastScanResultID = ptr(20001)
	r.Blobs[2].ID = 2002
	r.Versions[0].ID = 1100
	r.Versions[0].SkillID = 110
	r.Versions[0].BlobID = 2000
	r.Versions[1].ID = 1101
	r.Versions[1].SkillID = 110
	r.Versions[1].BlobID = 2001
	r.Versions[2].ID = 1200
	r.Versions[2].SkillID = 120
	r.Versions[2].BlobID = 2000
	r.Versions[3].ID = 1300
	r.Versions[3].SkillID = 130
	r.Versions[3].BlobID = 2002
	r.Bindings[0].ID = 1500
	r.Bindings[0].InstanceID = 17
	r.Bindings[0].SkillID = 110
	r.Bindings[0].SkillVersionID = ptr(1100)
	r.Bindings[0].InstallPath = ptr("home/skills/demo")
	r.Bindings[0].WorkspaceDir = ptr("restored/skills/demo")
	r.Bindings[1].ID = 1501
	r.Bindings[1].InstanceID = 18
	r.Bindings[1].SkillID = 120
	r.Bindings[2].ID = 1502
	r.Bindings[2].InstanceID = 17
	r.Bindings[2].SkillID = 130
	r.Bindings[2].SkillVersionID = ptr(1300)
	r.Bindings[2].WorkspaceDir = ptr("restored/skills/new")
	r.Scans[0].ID = 20000
	r.Scans[0].BlobID = 2000
	r.Scans[1].ID = 20001
	r.Scans[1].BlobID = 2001
	for i := range r.Jobs {
		r.Jobs[i].ID = 1900 + i
		r.Jobs[i].InstanceID = 17
		r.Jobs[i].SkillID = 130
		r.Jobs[i].BlobID = 2002
		r.Jobs[i].WorkspaceDir = "restored/skills/new"
	}
	r.Jobs[0].Status = "cancelled"
	r.Jobs[1].Status = "cancelled"
	r.Tags[0].ID = 140
	r.Tags[1].ID = 141
	r.Assignments[0].ID = 160
	r.Assignments[0].SkillID = 120
	r.Assignments[0].TagID = 140
	r.Assignments[1].ID = 161
	r.Assignments[1].SkillID = 110
	r.Assignments[1].TagID = 141
	return r
}

func TestRestoreRowOrderIsIndependent(t *testing.T) {
	source, mapping := fixture()
	expected := goldenRows(source)
	for _, table := range tables(source) {
		swap := reflect.Swapper(table.rows.Interface())
		for i, j := 0, table.rows.Len()-1; i < j; i, j = i+1, j-1 {
			swap(i, j)
		}
	}
	got, err := PrepareRestoreRows(context.Background(), source, mapping)
	if err != nil || !reflect.DeepEqual(got, expected) {
		t.Fatalf("source order affected candidates: %v", err)
	}
	for _, table := range tables(expected) {
		swap := reflect.Swapper(table.rows.Interface())
		for i, j := 0, table.rows.Len()-1; i < j; i, j = i+1, j-1 {
			swap(i, j)
		}
	}
	if err := CompareRestoredRows(context.Background(), source, mapping, expected); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareRestoreRowsGolden(t *testing.T) {
	source, m := fixture()
	actual, err := PrepareRestoreRows(context.Background(), source, m)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, goldenRows(source)) {
		t.Fatal("candidate differs from independently specified rows")
	}
	if err := CompareRestoredRows(context.Background(), source, m, goldenRows(source)); err != nil {
		t.Fatal(err)
	}
	// A real SQL read can use a different location for the same UTC instant.
	actual.Skills[0].CreatedAt = actual.Skills[0].CreatedAt.In(time.FixedZone("offset", 8*3600))
	slices.Reverse(actual.Skills)
	if err := CompareRestoredRows(context.Background(), source, m, actual); err != nil {
		t.Fatal(err)
	}
}
func TestPrepareRestoreRowsDoesNotAliasInputs(t *testing.T) {
	source, m := fixture()
	actual, err := PrepareRestoreRows(context.Background(), source, m)
	if err != nil {
		t.Fatal(err)
	}
	*actual.Skills[0].Description = "changed"
	*actual.Versions[0].ManifestJSON = "changed"
	*actual.Scans[0].FindingsJSON = "changed"
	*actual.Bindings[0].InstallPath = "changed"
	*actual.Jobs[0].StartedAt = time.Time{}
	if *source.Skills[0].Description != "private description" || *source.Versions[0].ManifestJSON != "{\"private\":\"manifest-v1\"}" || *source.Scans[0].FindingsJSON != "{\"finding\":\"private\"}" || *m.BindingPaths[500].InstallPath != "home/skills/demo" || source.Jobs[0].StartedAt.IsZero() {
		t.Fatal("candidate aliases source or mappings")
	}
	if source.Jobs[0].Status != "pending" {
		t.Fatal("mutated source status")
	}
}
func TestRestoreRejectsInvalidSourcesWithoutPartialRows(t *testing.T) {
	cases := map[string]func(*Rows){
		"duplicate id":             func(r *Rows) { r.Skills = append(r.Skills, r.Skills[0]) },
		"zero id":                  func(r *Rows) { r.Blobs[0].ID = 0 },
		"missing blob":             func(r *Rows) { r.Blobs = r.Blobs[1:] },
		"missing user id":          func(r *Rows) { r.Skills[0].UserID = 0 },
		"foreign current version":  func(r *Rows) { r.Skills[0].CurrentVersionID = ptr(200) },
		"foreign binding version":  func(r *Rows) { r.Bindings[0].SkillVersionID = ptr(200) },
		"foreign blob scan":        func(r *Rows) { r.Blobs[0].LastScanResultID = ptr(10001) },
		"foreign skill scan":       func(r *Rows) { r.Skills[2].LastScanResultID = ptr(10000) },
		"dangling tag":             func(r *Rows) { r.Assignments[0].TagID = 999 },
		"duplicate association":    func(r *Rows) { a := r.Assignments[0]; a.ID = 62; r.Assignments = append(r.Assignments, a) },
		"duplicate version number": func(r *Rows) { r.Versions[1].VersionNo = 1 },
		"duplicate version blob":   func(r *Rows) { r.Versions[1].BlobID = 1000 },
		"duplicate user skill key": func(r *Rows) { r.Skills[2].SkillKey = "demo" },
		"duplicate blob hash":      func(r *Rows) { r.Blobs[1].ContentHash = r.Blobs[0].ContentHash },
		"duplicate tag key":        func(r *Rows) { r.Tags[1].TagKey = r.Tags[0].TagKey },
		"duplicate idempotency":    func(r *Rows) { r.Jobs[1].IdempotencyKey = r.Jobs[0].IdempotencyKey },
		"unknown job state":        func(r *Rows) { r.Jobs[0].Status = "queued" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			source, m := fixture()
			mutate(&source)
			got, err := PrepareRestoreRows(context.Background(), source, m)
			if !errors.Is(err, ErrRows) || !reflect.DeepEqual(got, Rows{}) {
				t.Fatalf("returned partial rows or wrong error: %v", err)
			}
		})
	}
}
func TestRestoreRejectsIncompleteOrUnsafeMapping(t *testing.T) {
	cases := map[string]func(*RestoreMapping){
		"missing table":      func(m *RestoreMapping) { delete(m.IDs, "skill_blobs") },
		"unknown table":      func(m *RestoreMapping) { m.IDs["private-table"] = map[int]int{} },
		"missing reference":  func(m *RestoreMapping) { delete(m.IDs["users"], 1) },
		"merge users":        func(m *RestoreMapping) { m.IDs["users"][2] = 11 },
		"merge blobs":        func(m *RestoreMapping) { m.IDs["skill_blobs"][1001] = 2000 },
		"extra owned id":     func(m *RestoreMapping) { m.IDs["skills"][99] = 199 },
		"zero target":        func(m *RestoreMapping) { m.IDs["skills"][10] = 0 },
		"missing object":     func(m *RestoreMapping) { delete(m.ObjectKeys, "shared/demo.zip") },
		"extra object":       func(m *RestoreMapping) { m.ObjectKeys["unreferenced"] = "x" },
		"merge objects":      func(m *RestoreMapping) { m.ObjectKeys["archive/v2.zip"] = "restored/shared.zip" },
		"object escape":      func(m *RestoreMapping) { m.ObjectKeys["shared/demo.zip"] = "../private" },
		"blank object":       func(m *RestoreMapping) { m.ObjectKeys["shared/demo.zip"] = " " },
		"windows path":       func(m *RestoreMapping) { m.JobWorkspaceDirs[900] = "C:\\secret" },
		"absolute workspace": func(m *RestoreMapping) { m.JobWorkspaceDirs[900] = "/private" },
		"workspace escape":   func(m *RestoreMapping) { m.JobWorkspaceDirs[900] = "a/../private" },
		"null becomes string": func(m *RestoreMapping) {
			m.BindingPaths[501] = BindingPaths{InstallPath: ptr("x"), WorkspaceDir: ptr("")}
		},
		"empty becomes null": func(m *RestoreMapping) { m.BindingPaths[501] = BindingPaths{} },
		"missing binding":    func(m *RestoreMapping) { delete(m.BindingPaths, 500) },
		"missing job path":   func(m *RestoreMapping) { delete(m.JobWorkspaceDirs, 900) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			source, m := fixture()
			mutate(&m)
			got, err := PrepareRestoreRows(context.Background(), source, m)
			if !errors.Is(err, ErrMapping) || !reflect.DeepEqual(got, Rows{}) {
				t.Fatalf("partial rows or wrong error: %v", err)
			}
		})
	}
}
func TestVerifierDetectsTargetDrift(t *testing.T) {
	cases := map[string]func(*Rows){
		"private became public":   func(r *Rows) { r.Skills[0].Visibility = "public" },
		"owner changed":           func(r *Rows) { r.Skills[0].UserID = 12 },
		"publisher changed":       func(r *Rows) { r.Skills[1].PublishedBy = ptr(12) },
		"admin tag relaxed":       func(r *Rows) { r.Tags[0].AdminOnly = false },
		"assignment changed":      func(r *Rows) { r.Assignments[0].TagID = 141 },
		"old version lost":        func(r *Rows) { r.Versions = r.Versions[1:] },
		"manifest lost":           func(r *Rows) { r.Versions[0].ManifestJSON = nil },
		"findings lost":           func(r *Rows) { r.Scans[0].FindingsJSON = nil },
		"empty becomes null":      func(r *Rows) { r.Versions[2].ManifestJSON = nil },
		"workspace overwritten":   func(r *Rows) { r.Bindings[0].ObservedHash = ptr("business-md5-shared") },
		"removed binding revived": func(r *Rows) { r.Bindings[1].Status = "active" },
		"job replayed":            func(r *Rows) { r.Jobs[0].Status = "pending" },
		"history rewritten":       func(r *Rows) { r.Jobs[2].FinishedAt = ptr(time.Now()) },
		"attempt count reset":     func(r *Rows) { r.Jobs[0].AttemptCount = 0 },
		"object key fallback":     func(r *Rows) { r.Blobs[0].ObjectKey = "shared/demo.zip" },
		"archive hash replaced":   func(r *Rows) { r.Blobs[0].ArchiveHash = strings.Repeat("f", 64) },
		"extra tag":               func(r *Rows) { r.Tags = append(r.Tags, models.SkillHubTag{ID: 999, TagKey: "extra"}) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			source, m := fixture()
			target := goldenRows(source)
			mutate(&target)
			if err := CompareRestoredRows(context.Background(), source, m, target); err == nil {
				t.Fatal("accepted target drift")
			}
		})
	}
}
func TestRestoreCancellationAndEmptyTables(t *testing.T) {
	source, m := fixture()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := PrepareRestoreRows(ctx, source, m); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := CompareRestoredRows(ctx, source, m, goldenRows(source)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	empty := Rows{}
	mapping := RestoreMapping{IDs: map[string]map[int]int{"users": {}, "instances": {}}}
	for _, table := range tables(empty) {
		mapping.IDs[table.name] = map[int]int{}
	}
	got, err := PrepareRestoreRows(context.Background(), empty, mapping)
	if err != nil {
		t.Fatal(err)
	}
	if err := CompareRestoredRows(context.Background(), empty, mapping, got); err != nil {
		t.Fatal(err)
	}
}
func TestRestoreErrorsDoNotExposePrivateValues(t *testing.T) {
	source, m := fixture()
	source.Skills[0].Name = "SECRET-NAME"
	m.ObjectKeys["shared/demo.zip"] = "../SECRET-KEY"
	_, err := PrepareRestoreRows(context.Background(), source, m)
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("unredacted error: %v", err)
	}
	source, m = fixture()
	target := goldenRows(source)
	target.Scans[0].FindingsJSON = ptr("SECRET-FINDING")
	err = CompareRestoredRows(context.Background(), source, m, target)
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("unredacted error: %v", err)
	}
}
func TestRestoreModelPolicyCoverage(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "system-backup", "v12", "c-skill-hub-object-policies.json"))
	if err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Policies []struct {
			Name       string
			Fields     []string
			References map[string]string
		}
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		t.Fatal(err)
	}
	if len(policy.Policies) != 8 {
		t.Fatal("policy table count changed")
	}
	count := 0
	for _, table := range tables(Rows{}) {
		model := table.rows.Type().Elem()
		fields := []string{}
		refs := map[string]string{}
		for _, ref := range table.refs {
			f, _ := model.FieldByName(ref.field)
			refs[dbColumn(f.Tag.Get("db"))] = ref.table
		}
		for i := 0; i < model.NumField(); i++ {
			field := model.Field(i)
			fields = append(fields, dbColumn(field.Tag.Get("db")))
			typ := field.Type
			if typ.Kind() == reflect.Pointer {
				typ = typ.Elem()
			}
			if typ != reflect.TypeOf(time.Time{}) && typ.Kind() != reflect.Int && typ.Kind() != reflect.Int64 && typ.Kind() != reflect.String && typ.Kind() != reflect.Bool {
				t.Fatalf("clone must support new field shape: %s.%s", table.name, field.Name)
			}
		}
		found := false
		for _, p := range policy.Policies {
			if p.Name == table.name {
				found = true
				slices.Sort(fields)
				slices.Sort(p.Fields)
				if !reflect.DeepEqual(fields, p.Fields) || !reflect.DeepEqual(refs, p.References) {
					t.Fatalf("model/reference coverage drift: %s", table.name)
				}
			}
		}
		if !found {
			t.Fatalf("unregistered table: %s", table.name)
		}
		count += len(fields)
	}
	if count != 88 {
		t.Fatalf("review field policies, got %d fields", count)
	}
}
func TestRestoreTenThousandSkills(t *testing.T) {
	r := Rows{}
	m := RestoreMapping{IDs: map[string]map[int]int{"users": {1: 2}, "instances": {}}}
	for _, table := range tables(r) {
		m.IDs[table.name] = map[int]int{}
	}
	for i := 1; i <= 10000; i++ {
		r.Skills = append(r.Skills, models.Skill{ID: i, UserID: 1, SkillKey: fmt.Sprint(i), CurrentVersionID: ptr(i), Visibility: "private"})
		r.Blobs = append(r.Blobs, models.SkillBlob{ID: i, ContentHash: fmt.Sprint(i), ObjectKey: fmt.Sprintf("source/%d", i)})
		r.Versions = append(r.Versions, models.SkillVersion{ID: i, SkillID: i, BlobID: i, VersionNo: 1})
		for _, table := range []string{"skills", "skill_blobs", "skill_versions"} {
			m.IDs[table][i] = i + 10000
		}
	}
	m.ObjectKeys = map[string]string{}
	for _, b := range r.Blobs {
		m.ObjectKeys[b.ObjectKey] = "target/" + b.ObjectKey
	}
	result, err := PrepareRestoreRows(context.Background(), r, m)
	if err != nil {
		t.Fatal(err)
	}
	if err := CompareRestoredRows(context.Background(), r, m, result); err != nil {
		t.Fatal(err)
	}
}
