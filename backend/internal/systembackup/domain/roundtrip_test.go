package domain

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/workspace"
)

// A full domain-level offline drill: capture -> encrypted bytes -> disconnect
// source -> recover into separate DB and directory -> independent read-only
// verification. All identities, credentials and files are fabricated fixtures.
func TestIsolatedDomainBackupRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	fixtureData, targetSchema, policy := fixture()
	sourceState := &memoryDB{tables: copyTables(fixtureData.Tables)}
	source := database(sourceState)
	captured, e := Capture(ctx, source, Limits{100, 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	key := bytes.Repeat([]byte{31}, 32)
	binding := staging.Binding{BackupID: "fixture", Attempt: "1", Path: "mysql/domain", CaptureContextHash: string(bytes.Repeat([]byte{'a'}, 64)), EnvelopeID: "isolated-memory-key"}
	var dbArtifact bytes.Buffer
	if e = staging.Seal(ctx, &dbArtifact, key, binding, func(w io.Writer) error { return Encode(w, captured) }); e != nil {
		t.Fatal(e)
	}
	root, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	for name, data := range map[string]string{"session-history.json": `{"messages":["synthetic conversation"]}`, "tasks.json": `{"enabled":true,"prompt":"preserve task"}`, "model.json": `{"token":"source-synthetic-secret","model":"test"}`, "SKILL.md": "fixture skill"} {
		if e = root.WriteFile(name, []byte(data), 0600); e != nil {
			t.Fatal(e)
		}
	}
	wb := binding
	wb.Path = "workspace/7"
	var fileArtifact bytes.Buffer
	if e = staging.Seal(ctx, &fileArtifact, key, wb, func(w io.Writer) error {
		_, e := workspace.Archive(ctx, root, w, workspace.Limits{MaxFiles: 100, MaxBytes: 1 << 20})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(dbArtifact.Bytes(), []byte("synthetic-source-hash")) || bytes.Contains(fileArtifact.Bytes(), []byte("source-synthetic-secret")) {
		t.Fatal("plaintext staging")
	}
	source.Close()
	root.Close() // recovery below has no source handles
	var dbPlain bytes.Buffer
	if e = staging.Open(ctx, &dbArtifact, &dbPlain, key, binding, 1<<20); e != nil {
		t.Fatal(e)
	}
	decoded, e := Decode(&dbPlain, Limits{100, 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	targetState := isolatedTarget(targetSchema)
	writer := database(targetState)
	plan, e := RestoreDrill(ctx, writer, targetProof(), decoded, policy)
	if e != nil {
		t.Fatal(e)
	}
	writer.Close()
	targetRoot, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer targetRoot.Close()
	var workspacePlain bytes.Buffer
	if e = staging.Open(ctx, &fileArtifact, &workspacePlain, key, wb, 1<<20); e != nil {
		t.Fatal(e)
	}
	if _, e = workspace.Restore(ctx, targetRoot, &workspacePlain, workspace.Limits{MaxFiles: 100, MaxBytes: 1 << 20}, false); e != nil {
		t.Fatal(e)
	}
	registry := JSONRegistry{"fixture.tasks": {{Path: []string{"enabled"}, Action: "disable", Required: true}, {Path: []string{"prompt"}, Action: "preserve", Required: true}}, "fixture.model": {{Path: []string{"token"}, Action: "stub", Required: true}, {Path: []string{"model"}, Action: "preserve", Required: true}}}
	for file, field := range map[string]string{"tasks.json": "fixture.tasks", "model.json": "fixture.model"} {
		raw, e := targetRoot.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		safe, e := registry.NormalizeJSON(ctx, field, Cell{Bytes: raw})
		if e != nil {
			t.Fatal(e)
		}
		if e = targetRoot.WriteFile(file, safe.Bytes, 0600); e != nil {
			t.Fatal(e)
		}
	}
	verifier := database(targetState)
	defer verifier.Close()
	if e = VerifyDrill(ctx, verifier, targetProof(), plan); e != nil {
		t.Fatal(e)
	}
	model, _ := targetRoot.ReadFile("model.json")
	tasks, _ := targetRoot.ReadFile("tasks.json")
	sessions, _ := targetRoot.ReadFile("session-history.json")
	if bytes.Contains(model, []byte("source-synthetic-secret")) || !bytes.Contains(tasks, []byte(`"enabled":false`)) || !bytes.Contains(sessions, []byte("synthetic conversation")) {
		t.Fatal("restore normalization or history mismatch")
	}
}
