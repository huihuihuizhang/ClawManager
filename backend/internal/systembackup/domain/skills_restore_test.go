package domain

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"clawreef/internal/models"
	sh "clawreef/internal/systembackupskillhub"
)

func skillPtr[T any](v T) *T { return &v }

// All eight tables are nonempty; raw model fields deliberately include the
// json:"-" manifest/findings and current schema's scan updated_at column.
func businessRestoreFixture() (Snapshot, []Table, Policy) {
	s, _, p := teamFixture()
	data := map[string]any{
		"skills":                         []models.Skill{{ID: 11, UserID: 4, SkillKey: "demo", Name: "技能", CurrentVersionID: skillPtr(13), Status: "active", Visibility: "private", LastScanResultID: skillPtr(15)}},
		"skill_blobs":                    []models.SkillBlob{{ID: 12, ContentHash: "content", ArchiveHash: "archive", ObjectKey: "source/demo.tgz", SizeBytes: 4, LastScanResultID: skillPtr(15)}},
		"skill_versions":                 []models.SkillVersion{{ID: 13, SkillID: 11, BlobID: 12, VersionNo: 1, ManifestJSON: skillPtr(`{"name":"demo"}`)}},
		"instance_skills":                []models.InstanceSkill{{ID: 14, InstanceID: 7, SkillID: 11, SkillVersionID: skillPtr(13), InstallPath: skillPtr("/source/skills/demo"), WorkspaceDir: skillPtr("skills/demo"), ObservedHash: skillPtr("edited-files"), Status: "active"}},
		"skill_scan_results":             []models.SkillScanResult{{ID: 15, BlobID: 12, Status: "completed", FindingsJSON: skillPtr(`{"finding":"保留"}`)}},
		"skill_package_materialize_jobs": []models.SkillPackageMaterializeJob{{ID: 16, InstanceID: 7, SkillID: 11, BlobID: 12, WorkspaceDir: "skills/demo", ContentHash: "edited-files", Status: "running", AttemptCount: 2, MaxAttempts: 5, IdempotencyKey: "source-history"}},
		"skill_hub_tags":                 []models.SkillHubTag{{ID: 17, TagKey: "tag", Name: "标签", AdminOnly: true}},
		"skill_hub_tag_assignments":      []models.SkillHubTagAssignment{{ID: 18, SkillID: 11, TagID: 17}},
	}
	m := &sh.RestoreMapping{IDs: map[string]map[int]int{"users": {1: 1, 4: 4}, "instances": {7: 7}}, ObjectKeys: map[string]string{"source/demo.tgz": "restored/demo.tgz"}, BindingPaths: map[int]sh.BindingPaths{14: {InstallPath: skillPtr("skills/demo"), WorkspaceDir: skillPtr("skills/demo")}}, JobWorkspaceDirs: map[int]string{16: "skills/demo"}}
	for _, name := range sh.CaptureTableNames() {
		value := reflect.ValueOf(data[name])
		var rows []Row
		for i := 0; i < value.Len(); i++ {
			r := Row{}
			v := value.Index(i)
			for j := 0; j < v.NumField(); j++ {
				field := v.Field(j)
				column := strings.Split(v.Type().Field(j).Tag.Get("db"), ",")[0]
				if field.Kind() == reflect.Pointer {
					if field.IsNil() {
						r[column] = Cell{Null: true}
						continue
					}
					field = field.Elem()
				}
				switch {
				case field.Type() == reflect.TypeOf(time.Time{}):
					r[column] = Text("2026-10-30 01:02:03.123456")
				case field.Kind() == reflect.String:
					r[column] = Text(field.String())
				case field.Kind() == reflect.Bool:
					r[column] = Text("0")
					if field.Bool() {
						r[column] = Text("1")
					}
				default:
					r[column] = Text(strconv.FormatInt(field.Int(), 10))
				}
			}
			rows = append(rows, r)
		}
		t := table(name, rows...)
		// Use the actual migration dependency direction; current-version/scan
		// links are logical keys, not SQL FKs, and must not cause false cycles.
		refs := map[string][]ForeignKey{
			"skills":                         {{"user_id", "users", "id"}},
			"skill_versions":                 {{"skill_id", "skills", "id"}, {"blob_id", "skill_blobs", "id"}},
			"instance_skills":                {{"instance_id", "instances", "id"}, {"skill_id", "skills", "id"}, {"skill_version_id", "skill_versions", "id"}},
			"skill_scan_results":             {{"blob_id", "skill_blobs", "id"}},
			"skill_package_materialize_jobs": {{"instance_id", "instances", "id"}, {"skill_id", "skills", "id"}, {"blob_id", "skill_blobs", "id"}},
			"skill_hub_tag_assignments":      {{"skill_id", "skills", "id"}, {"tag_id", "skill_hub_tags", "id"}},
		}
		t.ForeignKeys = refs[name]
		s.Tables = append(s.Tables, t)
		m.IDs[name] = map[int]int{}
		for _, row := range rows {
			id, _ := strconv.Atoi(row["id"].String())
			m.IDs[name][id] = id
		}
	}
	// An originally stopped source is not started by normalization or restore.
	find(s, "instances").Rows[0]["status"] = Text("stopped")
	p.Skills = m
	p.Configs = JSONRegistry{"skill_versions.manifest_json": {{Path: []string{"name"}, Action: "preserve"}}}
	return s, copyTables(s.Tables), p
}

func TestNonemptyBusinessRestoreKeepsEightSkillTablesAndRelations(t *testing.T) {
	s, schema, p := businessRestoreFixture()
	before, _ := Digest(s)
	state := isolatedTarget(schema)
	writer := database(state)
	defer writer.Close()
	plan, err := RestoreDrill(context.Background(), writer, targetProof(), s, p)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range sh.CaptureTableNames() {
		if len(find(plan.Data, name).Rows) != 1 {
			t.Fatal("lost table", name)
		}
	}
	if find(plan.Data, "instance_skills").Rows[0]["status"].String() != "active" || find(plan.Data, "instance_skills").Rows[0]["install_path"].String() != "skills/demo" || find(plan.Data, "skill_package_materialize_jobs").Rows[0]["status"].String() != "cancelled" {
		t.Fatal("installation/history mapping")
	}
	if find(plan.Data, "skills").Rows[0]["last_scan_result_id"].String() != "15" || find(plan.Data, "skill_scan_results").Rows[0]["findings_json"].String() != `{"finding":"保留"}` || find(plan.Data, "skill_blobs").Rows[0]["object_key"].String() != "restored/demo.tgz" {
		t.Fatal("skill content lost")
	}
	reader := database(state)
	defer reader.Close()
	if err := VerifyDrill(context.Background(), reader, targetProof(), plan); err != nil {
		t.Fatal(err)
	}
	if after, _ := Digest(s); before != after {
		t.Fatal("source changed")
	}
	if find(plan.Data, "instances").Rows[0]["status"].String() != "stopped" {
		t.Fatal("stopped instance activated")
	}
	// Independent comparison rejects content tampering, not merely row counts.
	find(Snapshot{Tables: state.tables}, "skill_scan_results").Rows[0]["findings_json"] = Text("tampered")
	if VerifyDrill(context.Background(), reader, targetProof(), plan) == nil {
		t.Fatal("tampering passed")
	}
}

func TestBusinessRestoreRejectsMissingMappingAndSemanticDrift(t *testing.T) {
	for _, mode := range []string{"missing-map", "source-path", "changed-id", "missing-table", "wrong-current-version", "wrong-scan", "unknown-column", "dangling-tag", "extra-object"} {
		t.Run(mode, func(t *testing.T) {
			s, schema, p := businessRestoreFixture()
			switch mode {
			case "missing-map":
				p.Skills = nil
			case "source-path":
				p.Skills.BindingPaths[14] = sh.BindingPaths{InstallPath: skillPtr("/source/skills/demo"), WorkspaceDir: skillPtr("skills/demo")}
			case "changed-id":
				p.Skills.IDs["skills"][11] = 99
			case "missing-table":
				for i, x := range s.Tables {
					if x.Name == "skill_hub_tags" {
						s.Tables = append(s.Tables[:i], s.Tables[i+1:]...)
						break
					}
				}
			case "wrong-current-version":
				find(s, "skills").Rows[0]["current_version_id"] = Text("99")
			case "wrong-scan":
				find(s, "skill_blobs").Rows[0]["last_scan_result_id"] = Text("99")
			case "unknown-column":
				for i := range s.Tables {
					if s.Tables[i].Name == "skills" {
						s.Tables[i].Columns = append(s.Tables[i].Columns, Column{Name: "new_execution_field", Type: "text", Nullable: true})
						s.Tables[i].Rows[0]["new_execution_field"] = Text("active")
					}
				}
			case "dangling-tag":
				find(s, "skill_hub_tag_assignments").Rows[0]["tag_id"] = Text("99")
			case "extra-object":
				p.Skills.ObjectKeys["unknown"] = "other"
			}
			if _, err := Normalize(context.Background(), s, schema, p); err == nil {
				t.Fatal("invalid restore accepted")
			}
		})
	}
}

func TestRestoreDistinguishesDefaultExpressionsFromGeneratedColumns(t *testing.T) {
	for _, extra := range []string{"DEFAULT_GENERATED", "DEFAULT_GENERATED on update CURRENT_TIMESTAMP", "VIRTUAL GENERATED", "STORED GENERATED"} {
		s, schema, p := businessRestoreFixture()
		for i := range schema {
			if schema[i].Name == "skill_scan_results" {
				for j := range schema[i].Columns {
					if schema[i].Columns[j].Name == "updated_at" {
						schema[i].Columns[j].Extra = extra
					}
				}
			}
		}
		_, err := Normalize(context.Background(), s, schema, p)
		if strings.HasPrefix(extra, "DEFAULT_GENERATED") && err != nil {
			t.Fatal("ordinary timestamp rejected", err)
		}
		if !strings.HasPrefix(extra, "DEFAULT_GENERATED") && err == nil {
			t.Fatal("generated column accepted")
		}
	}
}

func TestSkillRestoreValidationInheritsTaskCancellation(t *testing.T) {
	s, _, p := businessRestoreFixture()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := validateSkillRestore(ctx, s, p.Skills); !errors.Is(err, context.Canceled) {
		t.Fatal("normalizer lost cancellation", err)
	}
	if err := VerifySkillQuarantineContext(ctx, s); !errors.Is(err, context.Canceled) {
		t.Fatal("verifier lost cancellation", err)
	}
}

func TestNonemptyBusinessRestoreRollsBackOnFailureOrCancellation(t *testing.T) {
	for _, mode := range []string{"insert", "evidence", "cancel", "isolation"} {
		t.Run(mode, func(t *testing.T) {
			s, schema, p := businessRestoreFixture()
			sourceBefore, _ := Digest(s)
			state := isolatedTarget(schema)
			before, _ := Digest(Snapshot{Tables: state.tables})
			writer := database(state)
			defer writer.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			proof := targetProof()
			if mode == "insert" {
				state.failInsert = "skill_versions"
			}
			evidence := func(context.Context, RestorePlan) error {
				switch mode {
				case "evidence":
					return errors.New("fixture evidence failure")
				case "cancel":
					cancel()
				case "isolation":
					proof.CheckIsolation = func(context.Context) error { return ErrIsolation }
				}
				return nil
			}
			// Capture proof through a stable closure to model authority revocation.
			check := proof.CheckIsolation
			valid := true
			proof.CheckIsolation = func(c context.Context) error {
				if !valid {
					return ErrIsolation
				}
				return check(c)
			}
			if mode == "isolation" {
				evidence = func(context.Context, RestorePlan) error { valid = false; return nil }
			}
			if _, err := RestoreDrillWithEvidence(ctx, writer, proof, s, p, evidence); err == nil {
				t.Fatal("failure accepted")
			}
			if state.commits != 0 {
				t.Fatal("failed transaction committed")
			}
			if after, _ := Digest(Snapshot{Tables: state.tables}); before != after {
				t.Fatal("target rollback lost data")
			}
			if after, _ := Digest(s); sourceBefore != after {
				t.Fatal("failure changed source")
			}
		})
	}
}
