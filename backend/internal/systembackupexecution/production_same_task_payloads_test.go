package systembackupexecution

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/scope"
	sh "clawreef/internal/systembackupskillhub"
)

// Actual owned files/version bodies are created BEFORE HTTP admission and its
// source snapshot. MD5 is the original Skill content identity; encrypted stream
// integrity continues to use the original AEAD/SHA256 checks independently.
func (f *dOriginalSixPartTask) createOriginalPayloads(t *testing.T) {
	t.Helper()
	f.objectBodies = map[string][]byte{}
	f.workspaceDirectories = map[string]string{}
	packaged := map[string][]byte{"SKILL.md": []byte("# packaged original\n"), "src/main.py": []byte("print('packaged original')\n"), ".private": []byte("original packaged hidden bytes")}
	unpackaged := map[string][]byte{"SKILL.md": []byte("# demo\n"), "src/main.py": []byte("print('demo')\n"), ".private": []byte("original workspace hidden bytes")}
	f.packageContentMD5, f.unpackagedContentMD5 = originalFixtureSkillMD5(packaged), originalFixtureSkillMD5(unpackaged)
	if f.unpackagedContentMD5 != "7c876ed8f2fc9206f8cc0914cb0a24f0" || f.packageContentMD5 == f.unpackagedContentMD5 {
		t.Fatal("original independently checked Skill MD5 fixture")
	}
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	names := make([]string, 0, len(packaged))
	for name := range packaged {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(0600)
		header.SetModTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
		entry, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(packaged[name]); err != nil {
			t.Fatal(err)
		}
	}
	if writer.Close() != nil {
		t.Fatal("original versioned Skill archive")
	}
	f.objectBodies["original.zip"] = append([]byte{}, archive.Bytes()...)
	f.objectBodies["unreferenced.zip"] = []byte("original unreferenced object\n")
	for name, files := range map[string]map[string][]byte{
		"instance_7_workspace": {"config.json": []byte(`{"enabled":true}`), "sessions/original.json": []byte(`{"original_history":true}`)},
		"instance_9_workspace": {"config.json": []byte(`{"enabled":true}`), "sessions/stopped.json": []byte(`{"original_stopped_history":true}`)},
		"team_20_workspace":    {"artifacts/original-result.json": []byte(`{"original_team_result":true}`)},
	} {
		root := filepath.Join(f.directory, "original-workspaces", name)
		f.workspaceDirectories[name] = root
		for relative, raw := range files {
			file := filepath.Join(root, filepath.FromSlash(relative))
			if os.MkdirAll(filepath.Dir(file), 0700) != nil || os.WriteFile(file, raw, 0600) != nil {
				t.Fatal("original nonempty workspace file")
			}
		}
	}
	skillRoot, err := sh.WorkspaceSkillRoot(scope.Runtime{Type: "openclaw", Mode: "pro", Backend: "desktop", Variant: "linux", OS: "linux"}, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"demo", "previous"} {
		for name, raw := range unpackaged {
			file := filepath.Join(f.workspaceDirectories["instance_7_workspace"], filepath.FromSlash(path.Join(skillRoot, directory, name)))
			if os.MkdirAll(filepath.Dir(file), 0700) != nil || os.WriteFile(file, raw, 0600) != nil {
				t.Fatal("original unpackaged Skill workspace")
			}
		}
	}
	for _, raw := range unpackaged {
		f.unpackagedBytes += len(raw)
	}
}

// Independent fixture builder matches the documented original service framing,
// including directories; dot files remain in the archive but outside legacy
// content MD5. The golden unpackaged value is checked above before seeding SQL.
func originalFixtureSkillMD5(files map[string][]byte) string {
	kinds := map[string]bool{}
	for name := range files {
		hidden := false
		for _, segment := range strings.Split(name, "/") {
			hidden = hidden || strings.HasPrefix(segment, ".")
		}
		if hidden {
			continue
		}
		kinds[name] = true
		for directory := path.Dir(name); directory != "."; directory = path.Dir(directory) {
			kinds[directory] = false
		}
	}
	names := make([]string, 0, len(kinds))
	for name := range kinds {
		names = append(names, name)
	}
	sort.Strings(names)
	digest := md5.New()
	for _, name := range names {
		io.WriteString(digest, name+"\n")
		if !kinds[name] {
			io.WriteString(digest, "dir\n")
			continue
		}
		io.WriteString(digest, "file\n")
		digest.Write(files[name])
		io.WriteString(digest, "\n")
	}
	return hex.EncodeToString(digest.Sum(nil))
}
