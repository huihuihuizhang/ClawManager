package domain_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"

	"clawreef/internal/models"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	sh "clawreef/internal/systembackupskillhub"
)

func TestPublicWorkerNonemptyBusinessRestoreWithFrozenMapping(t *testing.T) {
	f := newWorkerFixture(t)
	f.sql.Close()
	f.sql = domain.NewTestBusinessSQLFixture()
	t.Cleanup(f.sql.Close)
	d := *f.restore.Database
	d.Placements, d.TeamPlacements = f.sql.Policy.Placements, f.sql.Policy.TeamPlacements
	d.Configs = f.sql.Policy.Configs.(domain.JSONRegistry)
	d.SkillsRestore = f.sql.Policy.Skills
	f.restore.Database = &d
	captured, err := worker.RunDatabase(context.Background(), f.capture, worker.DatabaseEnvironment{Database: f.sql.Source, Staging: f.store, Key: f.key, Check: allowWorker})
	if err != nil || f.sql.SourceWrites() != 0 || captured.Rows < 20 {
		t.Fatal("nonempty capture", err)
	}
	f.restore.Receipt = captured.Receipt
	f.sql.Source.Close()
	checks := 0
	restored, err := f.restoreData(func(_ context.Context, _ string, r worker.Request) error {
		checks++
		if r.Database.SkillsRestore.ObjectKeys["source/demo.tgz"] != "restored/demo.tgz" {
			t.Fatal("callback mutation crossed checks")
		}
		r.Database.SkillsRestore.ObjectKeys["source/demo.tgz"] = "attacker/key"
		*r.Database.SkillsRestore.BindingPaths[14].InstallPath = "attacker/path"
		// Mutating the original caller after entry must not change frozen work.
		d.SkillsRestore.ObjectKeys["source/demo.tgz"] = "caller/changed"
		return nil
	})
	if err != nil || !restored.Quarantined || restored.Verified || checks < 4 {
		t.Fatal("restore protocol", err)
	}
	for _, table := range f.sql.Snapshot().Tables {
		for _, row := range table.Rows {
			if table.Name == "skill_blobs" && row["object_key"].String() != "restored/demo.tgz" {
				t.Fatal("unfrozen object mapping")
			}
			if table.Name == "instance_skills" && row["install_path"].String() != "skills/demo" {
				t.Fatal("unfrozen installation mapping")
			}
		}
	}
	f.sql.Target.Close() // writer has ended before separate SELECT-only handle
	v := f.restore
	v.Operation, v.Binding, v.Receipt = "verify-database", d.EvidenceBinding, restored.Evidence
	vd := d
	vd.Placements, vd.TeamPlacements, vd.Configs, vd.SkillsRestore, vd.EvidenceName = nil, nil, nil, nil, ""
	v.Database = &vd
	reader := f.sql.Verifier()
	defer reader.Close()
	before := f.sql.Writes()
	verified, err := worker.RunDatabase(context.Background(), v, worker.DatabaseEnvironment{Database: reader, Staging: f.evidence, Key: f.key, Check: allowWorker})
	if err != nil || !verified.Verified || f.sql.Writes() != before {
		t.Fatal("independent verification", err)
	}
	verifyBusinessFilesAndObjects(t, f)
}

type versionFixtureReader func(context.Context, string, string) (sh.ObjectVersion, error)

func (r versionFixtureReader) OpenVersion(ctx context.Context, key, version string) (sh.ObjectVersion, error) {
	return r(ctx, key, version)
}

// Same SQL object/workspace mappings are consumed by existing object and
// workspace readers. This is component evidence, not a production object
// provider upload, mounted permission proof or a published six-part restore.
func verifyBusinessFilesAndObjects(t *testing.T, f *workerFixture) {
	t.Helper()
	ctx := context.Background()
	var objectKey, install, workspace string
	for _, table := range f.sql.Snapshot().Tables {
		for _, row := range table.Rows {
			switch table.Name {
			case "skill_blobs":
				objectKey = row["object_key"].String()
			case "instance_skills":
				install = row["install_path"].String()
				workspace = row["workspace_dir"].String()
			}
		}
	}
	if install != workspace || workspace != "skills/demo" {
		t.Fatal("SQL/workspace mapping disagrees")
	}
	packaged := []byte{0, 255, 1, 2}
	entry := sh.FrozenObject{Key: "source/demo.tgz", VersionID: "source-v1", Size: 4}
	metadata := sh.ObjectMetadata{ContentType: "application/gzip"}
	sourceAvailable := true
	source := versionFixtureReader(func(_ context.Context, key, version string) (sh.ObjectVersion, error) {
		if !sourceAvailable || key != entry.Key || version != entry.VersionID {
			return sh.ObjectVersion{}, errors.New("source unavailable")
		}
		return sh.ObjectVersion{Body: io.NopCloser(bytes.NewReader(packaged)), Size: 4, VersionID: version, Properties: &sh.ObjectProperties{Metadata: metadata, ETag: "named-source-etag", LastModified: "2026-10-30T01:02:03Z"}}, nil
	})
	var digest sh.ObjectDigest
	binding := f.capture.Binding
	binding.Path = "skill-object/12"
	receipt, err := staging.SealFile(ctx, f.store, "skill-object.enc", f.key, binding, func(w io.Writer) error {
		var err error
		digest, err = sh.CopyFrozenObject(ctx, source, w, entry, 64)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	sourceAvailable = false
	sealed, err := staging.OpenFile(ctx, f.store, receipt)
	if err != nil {
		t.Fatal(err)
	}
	defer sealed.Close()
	var restored bytes.Buffer
	if err = staging.Open(ctx, sealed, &restored, f.key, binding, 64); err != nil {
		t.Fatal(err)
	}
	limits := sh.ObjectCaptureLimits{MaxObjects: 1, MaxObjectBytes: 64, MaxTotalBytes: 64, MaxIndexBytes: 4096}
	objectPlan, err := sh.PrepareObjectRestore(ctx, []models.SkillBlob{{ID: 12, ObjectKey: entry.Key, SizeBytes: 4}}, map[string]string{entry.Key: objectKey}, []sh.FrozenObject{entry}, []sh.CapturedObject{{Object: entry, Digest: digest}}, map[string]sh.RestoredObjectLocation{entry.Key: {Key: objectKey, VersionID: "target-v1"}}, limits)
	if err != nil {
		t.Fatal(err)
	}
	targetReader := versionFixtureReader(func(_ context.Context, key, version string) (sh.ObjectVersion, error) {
		if key != objectKey || version != "target-v1" {
			return sh.ObjectVersion{}, errors.New("target version denied")
		}
		return sh.ObjectVersion{Body: io.NopCloser(bytes.NewReader(restored.Bytes())), Size: int64(restored.Len()), VersionID: version, Properties: &sh.ObjectProperties{Metadata: metadata}}, nil
	})
	if err = sh.VerifyObjectRestorePlan(ctx, targetReader, objectPlan, limits); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err = root.MkdirAll(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	edited := []byte("# locally edited skill\n保留实例中的修改\n")
	if err = root.WriteFile(workspace+"/SKILL.md", edited, 0600); err != nil {
		t.Fatal(err)
	}
	if err = root.WriteFile("runtime.json", []byte(`{"enabled":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	r := f.capture
	r.Operation = "capture-workspace"
	r.Database = nil
	r.ArtifactName = "skill-workspace.enc"
	r.Binding.Path = "workspace/7"
	r.MaxFiles = 100
	r.MaxFileBytes = 1 << 20
	captured, err := worker.Run(ctx, r, worker.Environment{Workspace: root, Staging: f.store, Key: f.key, Check: allowWorker})
	if err != nil {
		t.Fatal(err)
	}
	root.Close()
	targetPath := t.TempDir()
	target, err := os.OpenRoot(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	r.Operation = "restore-workspace"
	r.ArtifactName = ""
	r.Receipt = captured.Receipt
	r.PolicyVersion = "fixture-runtime-disabled"
	r.Files = []worker.FileRule{{Path: "runtime.json", Required: true, Fields: []domain.JSONRule{{Path: []string{"enabled"}, Action: "disable", Required: true}}}}
	_, err = worker.Run(ctx, r, worker.Environment{Workspace: target, Staging: f.store, Key: f.key, Check: allowWorker})
	target.Close()
	if err != nil {
		t.Fatal(err)
	}
	readback, err := os.OpenRoot(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	defer readback.Close()
	actual, err := readback.ReadFile(install + "/SKILL.md")
	if err != nil || !bytes.Equal(actual, edited) || bytes.Equal(actual, packaged) {
		t.Fatal("workspace edits substituted with packaged object")
	}
	runtime, err := readback.ReadFile("runtime.json")
	if err != nil || !bytes.Contains(runtime, []byte(`"enabled":false`)) {
		t.Fatal("runtime config activated")
	}
}
