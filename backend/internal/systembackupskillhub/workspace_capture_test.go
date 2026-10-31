package systembackupskillhub

import (
	"archive/tar"
	"bytes"
	"context"
	"strings"
	"testing"

	"clawreef/internal/systembackup/scope"
)

func TestWorkspaceProofBoundsPaddingAndDirectoryIndex(t *testing.T) {
	spec := WorkspaceCaptureSpec{Version: WorkspaceCaptureVersion, InventorySHA256: strings.Repeat("a", 64), MountID: "workspace", InstanceID: 7, Runtime: scope.Runtime{Type: "hermes", Mode: "lite", Backend: "gateway", Variant: "linux", OS: "linux"}, SkillRoot: "home/.hermes/skills", Requirements: []WorkspaceCaptureRequirement{{BlobID: 12, InstanceID: 7, BindingID: 14, WorkspaceDirectory: "demo", ContentMD5: "7c876ed8f2fc9206f8cc0914cb0a24f0"}}, MaxFiles: 100, MaxBytes: 4 << 20, MaxProofBytes: 1 << 20}
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for name, body := range map[string]string{"SKILL.md": "# demo\n", "src/main.py": "print('demo')\n"} {
		if err := tw.WriteHeader(&tar.Header{Name: spec.SkillRoot + "/demo/" + name, Typeflag: tar.TypeReg, Size: int64(len(body)), Mode: 0600}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	tw.Close()
	if err := VerifyWorkspaceCapture(context.Background(), bytes.NewReader(raw.Bytes()), spec); err != nil {
		t.Fatal("bounded original golden archive", err)
	}
	extended := append(bytes.Clone(raw.Bytes()), make([]byte, 3<<20)...)
	reader := bytes.NewReader(extended)
	if err := VerifyWorkspaceCapture(context.Background(), reader, spec); err == nil || reader.Len() == 0 {
		t.Fatal("unbounded zero suffix was fully consumed or accepted", err, reader.Len())
	}
	_, err := workspaceContentMD5(context.Background(), map[string][]byte{strings.Repeat("a/", 10000) + "file": nil}, 4096)
	if err == nil {
		t.Fatal("adversarial directory-index expansion was unbounded")
	}
}
