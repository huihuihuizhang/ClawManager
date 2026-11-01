package systembackupskillhub

import (
	"archive/tar"
	"bytes"
	"context"
	"strings"
	"testing"

	"clawreef/internal/systembackup/scope"
)

// Original golden Skill MD5 plus unrelated workspace content. This tests the
// new count API against complete archive policy; it supplies no SQL authority.
func TestWorkspaceCountsRequireWholeVerifiedArchive(t *testing.T) {
	spec := WorkspaceCaptureSpec{Version: WorkspaceCaptureVersion, InventorySHA256: strings.Repeat("a", 64), MountID: "workspace", InstanceID: 7, Runtime: scope.Runtime{Type: "hermes", Mode: "lite", Backend: "gateway", Variant: "linux", OS: "linux"}, SkillRoot: "home/.hermes/skills", Requirements: []WorkspaceCaptureRequirement{{BlobID: 12, InstanceID: 7, BindingID: 14, WorkspaceDirectory: "demo", ContentMD5: "7c876ed8f2fc9206f8cc0914cb0a24f0"}}, MaxFiles: 100, MaxBytes: 4 << 20, MaxProofBytes: 1 << 20}
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	entries := []struct{ name, body string }{{spec.SkillRoot + "/demo/SKILL.md", "# demo\n"}, {spec.SkillRoot + "/demo/src/main.py", "print('demo')\n"}, {"home/notes.txt", "unrelated workspace content\n"}}
	var wantBytes int64
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: tar.TypeReg, Size: int64(len(e.body)), Mode: 0600}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
		wantBytes += int64(len(e.body))
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"current", "truncated-content", "nonzero-suffix", "wrong-md5", "file-capacity", "byte-capacity", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			input := bytes.Clone(archive.Bytes())
			current := spec
			current.Requirements = append([]WorkspaceCaptureRequirement(nil), spec.Requirements...)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "truncated-content":
				input = input[:512+len(entries[0].body)-1]
			case "nonzero-suffix":
				input = append(input, '!')
			case "wrong-md5":
				current.Requirements[0].ContentMD5 = strings.Repeat("0", 32)
			case "file-capacity":
				current.MaxFiles = 2
			case "byte-capacity":
				current.MaxBytes = wantBytes - 1
			case "canceled":
				cancel()
			}
			got, err := VerifyWorkspaceCaptureWithCounts(ctx, bytes.NewReader(input), current)
			if mode != "current" {
				if err == nil || got != (WorkspaceCaptureCounts{}) {
					t.Fatalf("incomplete archive yielded counts: %s %v %+v", mode, err, got)
				}
				return
			}
			if err != nil || got.Entries != 3 || got.Bytes != wantBytes {
				t.Fatalf("full workspace count/Skill MD5 mismatch: %v %+v want bytes=%d", err, got, wantBytes)
			}
		})
	}
}
