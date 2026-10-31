package systembackupexecution

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path"
	"strings"
	"testing"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/scope"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	"clawreef/internal/systembackup/workspace"
	sh "clawreef/internal/systembackupskillhub"
	w "clawreef/internal/systembackupwire"
)

func TestFormalObserverVerifiesSkillMD5InActualWholeWorkspaceArchive(t *testing.T) {
	for _, mode := range []string{"hermes-lite", "hermes-pro", "openclaw-nested", "opencode-project", "missing-manifest", "wrong-md5", "wrong-original-root", "invalid-root-scope", "capacity"} {
		t.Run(mode, func(t *testing.T) {
			source, custody, sealScope, inv, candidate, keys := formalObserverFixture(t, func(root *os.Root, i *worker.Invocation) {
				runtime := scope.Runtime{Type: "hermes", Mode: "lite", Backend: "gateway", Variant: "linux", OS: "linux"}
				directory, project := "demo", ""
				switch mode {
				case "hermes-pro":
					runtime.Mode, runtime.Backend = "pro", "desktop"
				case "openclaw-nested":
					runtime.Type = "openclaw"
					directory = "category/demo"
				case "opencode-project":
					runtime.Type, runtime.Mode, runtime.Backend = "opencode", "pro", "desktop"
					project = "workspace/nested/project"
				}
				skillRoot, err := sh.WorkspaceSkillRoot(runtime, project)
				if err != nil {
					t.Fatal(err)
				}
				i.Request.RuntimePolicy = &worker.RuntimePolicy{Version: "original-runtime-r1", Image: "worker@sha256:" + strings.Repeat("a", 64), Runtime: runtime, Files: []worker.FileRule{{Path: "history.json", Required: true, Fields: []domain.JSONRule{{Path: []string{"fixture"}, Action: "preserve"}}}}}
				i.Request.SkillWorkspace = &sh.WorkspaceCaptureSpec{Version: sh.WorkspaceCaptureVersion, InventorySHA256: strings.Repeat("e", 64), InstanceID: 7, MountID: "workspace", Runtime: runtime, OpenCodeProject: project, SkillRoot: skillRoot, Requirements: []sh.WorkspaceCaptureRequirement{{BlobID: 12, InstanceID: 7, BindingID: 14, WorkspaceDirectory: directory, ContentMD5: "7c876ed8f2fc9206f8cc0914cb0a24f0"}}, MaxFiles: 100, MaxBytes: 2 << 20, MaxProofBytes: 1 << 20}
				actualRoot := skillRoot
				if mode == "wrong-original-root" {
					actualRoot = "skills"
				}
				actualRoot = path.Join(actualRoot, directory)
				if err := root.MkdirAll(path.Join(actualRoot, "src"), 0700); err != nil {
					t.Fatal(err)
				}
				for name, raw := range map[string]string{"SKILL.md": "# demo\n", "src/main.py": "print('demo')\n", ".private": "private hidden bytes retained"} {
					if name == "SKILL.md" && mode == "missing-manifest" {
						continue
					}
					if err := root.WriteFile(path.Join(actualRoot, name), []byte(raw), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "wrong-md5" {
					i.Request.SkillWorkspace.Requirements[0].ContentMD5 = strings.Repeat("0", 32)
				}
				if mode == "invalid-root-scope" {
					i.Request.SkillWorkspace.SkillRoot = "skills"
				}
				if mode == "capacity" {
					i.Request.SkillWorkspace.MaxProofBytes = 2
				}
			})
			observed, err := observeOriginalFormalCandidate(context.Background(), source, custody, staging.CustodyPolicy{Installation: sealScope.Installation, MaxBytes: 16 << 20}, sealScope, inv, candidate, keys)
			valid := mode == "hermes-lite" || mode == "hermes-pro" || mode == "openclaw-nested" || mode == "opencode-project"
			if !valid {
				if err == nil || observed.Reference() != "" {
					t.Fatal("invalid source bytes/MD5/root yielded original seal", mode, err)
				}
				return
			}
			if err != nil || observed.Reference() == "" || keys.calls != 1 {
				t.Fatal("actual independent semantic observer", mode, err, keys.calls)
			}
			// Independent parse of the very same C candidate verifies that legacy MD5
			// filtering did not remove hidden data from the full workspace artifact.
			encrypted, _ := source.ReadFile(candidate.Ciphertext.Name)
			envelope, _ := source.ReadFile(candidate.Envelope.Name)
			spec := w.StreamSpec{Request: inv.ProviderKey.Request, Path: inv.Request.ArtifactName, MaxPlaintextBytes: inv.Request.MaxCompressedBytes, MaxFrames: inv.FormalCapture.MaxFrames}
			hidden := false
			_, err = w.InspectWrappedStream(context.Background(), spec, envelope, bytes.NewReader(encrypted), keys, func(src io.Reader) error {
				z, err := gzip.NewReader(src)
				if err != nil {
					return err
				}
				defer z.Close()
				tr := tar.NewReader(z)
				for {
					h, err := tr.Next()
					if err == io.EOF {
						break
					}
					if err != nil {
						return err
					}
					raw, err := io.ReadAll(tr)
					if err != nil {
						return err
					}
					if path.Base(h.Name) == ".private" && string(raw) == "private hidden bytes retained" {
						hidden = true
					}
				}
				_, err = io.Copy(io.Discard, z)
				return err
			})
			if err != nil || !hidden {
				t.Fatal("MD5 filter lost original hidden archive data", err)
			}
		})
	}
}

func TestFormalSkillObserverRejectsValidAEADWithUnsafeArchiveHeaders(t *testing.T) {
	for _, mode := range []string{"safe-relative-link", "absolute-link", "character-device", "hard-link", "setuid", "unknown-pax"} {
		t.Run(mode, func(t *testing.T) {
			var original *os.Root
			source, custody, sealScope, inv, candidate, keys := formalObserverFixture(t, func(root *os.Root, i *worker.Invocation) {
				original = root
				runtime := scope.Runtime{Type: "hermes", Mode: "lite", Backend: "gateway", Variant: "linux", OS: "linux"}
				i.Request.RuntimePolicy = &worker.RuntimePolicy{Version: "original-r1", Image: "worker@sha256:" + strings.Repeat("a", 64), Runtime: runtime, Files: []worker.FileRule{{Path: "history.json", Fields: []domain.JSONRule{{Path: []string{"fixture"}, Action: "preserve"}}}}}
				i.Request.SkillWorkspace = &sh.WorkspaceCaptureSpec{Version: sh.WorkspaceCaptureVersion, InventorySHA256: strings.Repeat("e", 64), InstanceID: 7, MountID: "workspace", Runtime: runtime, SkillRoot: "home/.hermes/skills", Requirements: []sh.WorkspaceCaptureRequirement{{BlobID: 12, InstanceID: 7, BindingID: 14, WorkspaceDirectory: "demo", ContentMD5: "7c876ed8f2fc9206f8cc0914cb0a24f0"}}, MaxFiles: 100, MaxBytes: 2 << 20, MaxProofBytes: 1 << 20}
				if err := root.MkdirAll("home/.hermes/skills/demo/src", 0700); err != nil {
					t.Fatal(err)
				}
				for name, body := range map[string]string{"SKILL.md": "# demo\n", "src/main.py": "print('demo')\n"} {
					if err := root.WriteFile("home/.hermes/skills/demo/"+name, []byte(body), 0600); err != nil {
						t.Fatal(err)
					}
				}
			})
			source, candidate = forgeSkillArchiveCandidate(t, original, inv, candidate, keys, mode)
			observed, err := observeOriginalFormalCandidate(context.Background(), source, custody, staging.CustodyPolicy{Installation: sealScope.Installation, MaxBytes: 16 << 20}, sealScope, inv, candidate, keys)
			if mode == "safe-relative-link" {
				if err != nil || observed.Reference() == "" {
					t.Fatal("safe original link rejected", err)
				}
				return
			}
			if err == nil || observed.Reference() != "" || keys.calls != 1 {
				t.Fatal("valid AEAD/MD5 laundered an unsafe whole archive", mode, err, keys.calls)
			}
			files, _, err := staging.OpenFormalObserved(context.Background(), custody, sealScope, candidate.Ciphertext, candidate.Envelope)
			files.Close()
			if err == nil {
				t.Fatal("unsafe archive became usable original custody")
			}
		})
	}
}

func forgeSkillArchiveCandidate(t *testing.T, original *os.Root, inv worker.Invocation, candidate worker.FormalCaptureResult, keys *candidateContentUnwrapper, mode string) (*os.Root, worker.FormalCaptureResult) {
	t.Helper()
	var ordinary, forged bytes.Buffer
	if _, err := workspace.Archive(context.Background(), original, &ordinary, workspace.Limits{MaxFiles: 100, MaxBytes: 2 << 20}); err != nil {
		t.Fatal(err)
	}
	tr, tw := tar.NewReader(&ordinary), tar.NewWriter(&forged)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil || tw.WriteHeader(h) != nil {
			t.Fatal("original tar fixture", err)
		}
		if _, err = io.Copy(tw, tr); err != nil {
			t.Fatal(err)
		}
	}
	extra := &tar.Header{Name: "shortcut", Typeflag: tar.TypeSymlink, Linkname: "home/.hermes/skills/demo/SKILL.md", Mode: 0777, Format: tar.FormatPAX}
	switch mode {
	case "absolute-link":
		extra.Linkname = "/etc/passwd"
	case "character-device":
		extra.Typeflag = tar.TypeChar
		extra.Linkname = ""
		extra.Mode = 0600
	case "hard-link":
		extra.Typeflag = tar.TypeLink
	case "setuid":
		extra.Typeflag = tar.TypeReg
		extra.Linkname = ""
		extra.Mode = 04755
	case "unknown-pax":
		extra.Typeflag = tar.TypeReg
		extra.Linkname = ""
		extra.Mode = 0600
		extra.PAXRecords = map[string]string{"SCHILY.xattr.security.capability": "untrusted"}
	}
	if err := tw.WriteHeader(extra); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	spec := w.StreamSpec{Request: inv.ProviderKey.Request, Path: inv.Request.ArtifactName, MaxPlaintextBytes: inv.Request.MaxCompressedBytes, MaxFrames: inv.FormalCapture.MaxFrames}
	var ciphertext bytes.Buffer
	seal, err := w.EncryptStream(context.Background(), spec, keys.key, &ciphertext, func(dst io.Writer) error {
		return staging.Compress(dst, func(z io.Writer) error { _, err := z.Write(forged.Bytes()); return err })
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := seal.EnvelopeJSON(w.WrappedKey{Request: spec.Request, Algorithm: "provider-native", Ciphertext: []byte("explicit forged-worker fixture")})
	if err != nil {
		t.Fatal(err)
	}
	forgedSource, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { forgedSource.Close() })
	source := forgedSource
	receipt := func(name string, raw []byte) staging.Receipt {
		sum := sha256.Sum256(raw)
		if err := source.WriteFile(name, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return staging.Receipt{Name: name, Size: int64(len(raw)), SHA256: hex.EncodeToString(sum[:])}
	}
	candidate.Ciphertext = receipt(inv.Request.ArtifactName, ciphertext.Bytes())
	candidate.Envelope = receipt(inv.FormalCapture.EnvelopeName, envelope)
	candidate.Files++
	return source, candidate
}
