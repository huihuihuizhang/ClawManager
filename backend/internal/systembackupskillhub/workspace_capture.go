package systembackupskillhub

import (
	"archive/tar"
	"context"
	"crypto/md5"
	"encoding/hex"
	"io"
	"path"
	"sort"
	"strings"

	"clawreef/internal/systembackup/scope"
	"clawreef/internal/systembackup/workspace"
)

const WorkspaceCaptureVersion = "skill-hub-original-workspace-capture.v1"

// SkillRoot is relative to the ORIGINAL full workspace mount. WorkspaceDir in
// each requirement remains the original DB value relative to this SkillRoot.
// These are frozen plan data; the controller must bind Runtime, InstanceID and
// the exact original mount independently before accepting this scope.
type WorkspaceCaptureSpec struct {
	Version, InventorySHA256, MountID string
	InstanceID                        int
	Runtime                           scope.Runtime
	WorkspaceLayout                   workspace.Layout
	OpenCodeProject                   string
	SkillRoot                         string
	Requirements                      []WorkspaceCaptureRequirement
	MaxFiles, MaxBytes, MaxProofBytes int64
}

// Root selection mirrors services.runtimeSkillInstallRoot. OpenCodeProject is
// the resolved, authenticated /config-relative project, never ambient settings.
func WorkspaceSkillRoot(runtime scope.Runtime, project string) (string, error) {
	planned, err := scope.PlanRuntime(runtime)
	if err != nil {
		return "", ErrWorkspaceProof
	}
	if project != "" && (planned.Type != "opencode" || planned.Mode != "pro") {
		return "", ErrWorkspaceProof
	}
	if planned.Mode == "lite" {
		switch planned.Type {
		case "hermes":
			return "home/.hermes/skills", nil
		case "deepseek-harness":
			return "home/.dsh/skills", nil
		case "opencode":
			return "home/.config/opencode/skills", nil
		}
	}
	if planned.Mode == "pro" {
		switch planned.Type {
		case "hermes":
			return ".hermes/skills", nil
		case "deepseek-harness":
			return ".dsh/skills", nil
		case "opencode":
			if project == "" {
				project = "workspace"
			}
			if !captureRelative(project) || (project != "workspace" && !strings.HasPrefix(project, "workspace/")) {
				return "", ErrWorkspaceProof
			}
			return project + "/.opencode/skills", nil
		}
	}
	return "home/.openclaw/workspace/skills", nil
}

func (s WorkspaceCaptureSpec) Validate() error {
	root, err := WorkspaceSkillRoot(s.Runtime, s.OpenCodeProject)
	planned, planErr := scope.PlanRuntime(s.Runtime)
	if planErr != nil || !s.WorkspaceLayout.Known() || ((s.WorkspaceLayout == workspace.WorkBuddyWineV1 || s.WorkspaceLayout == workspace.WorkBuddyInstanceWineV1) && (planned.Type != "workbuddy" || planned.Mode != "lite")) || (s.WorkspaceLayout == workspace.DeepSeekHarnessV1 && planned.Type != "deepseek-harness") {
		return ErrWorkspaceProof
	}
	if err != nil || s.Version != WorkspaceCaptureVersion || !validSHA256(s.InventorySHA256) || s.InstanceID <= 0 || s.MountID == "" || len(s.MountID) > 64 || !captureRelative(s.MountID) || s.SkillRoot != root || len(s.Requirements) < 1 || len(s.Requirements) > 10000 || s.MaxFiles < 1 || s.MaxFiles > 1000000 || s.MaxBytes < 1 || s.MaxBytes > 1<<40 || s.MaxProofBytes < 1 || s.MaxProofBytes > 32<<20 {
		return ErrWorkspaceProof
	}
	seen := map[string]bool{}
	for _, r := range s.Requirements {
		directory := r.WorkspaceDirectory
		// Original service accepts at most two non-hidden path segments.
		if r.InstanceID != s.InstanceID || r.BlobID <= 0 || r.BindingID < 0 || r.JobID < 0 || (r.BindingID <= 0) == (r.JobID <= 0) || !captureMD5(r.ContentMD5) || r.ContentMD5 != strings.ToLower(r.ContentMD5) || !captureRelative(directory) || len(strings.Split(directory, "/")) > 2 || strings.Contains(directory, "..") || captureHidden(directory) {
			return ErrWorkspaceProof
		}
		identity := directory + "\x00" + r.ContentMD5
		if seen[identity] {
			continue
		}
		seen[identity] = true
	}
	return nil
}

func captureRelative(name string) bool {
	return name != "" && name != "." && name != ".." && !path.IsAbs(name) && path.Clean(name) == name && !strings.HasPrefix(name, "../") && !strings.ContainsAny(name, "\\\x00\r\n:")
}
func captureHidden(name string) bool {
	for _, segment := range strings.Split(name, "/") {
		if strings.HasPrefix(segment, ".") {
			return true
		}
	}
	return false
}

// VerifyWorkspaceCapture consumes the actual FULL workspace tar. It stores
// only finite, nonhidden regular Skill file bytes, never reads the source a
// second time, and never rewrites/restores the archive. Empty dirs, dotfiles
// and symlinks remain in the full archive but match original service MD5 rules.
// Success discharges only these exact requirements, not cross-part coverage,
// task consistency or immutable publication. Any failure returns no proof.
func VerifyWorkspaceCapture(ctx context.Context, src io.Reader, s WorkspaceCaptureSpec) error {
	if ctx == nil || ctx.Err() != nil || src == nil || s.Validate() != nil {
		return ErrWorkspaceProof
	}
	reader := &workspaceCaptureReader{ctx: ctx, reader: src}
	tr := tar.NewReader(reader)
	archivePolicy, err := workspace.NewCapturedArchiveValidator(s.WorkspaceLayout)
	if err != nil {
		return ErrWorkspaceProof
	}
	files := map[string]map[string][]byte{}
	for _, r := range s.Requirements {
		files[s.SkillRoot+"/"+r.WorkspaceDirectory] = map[string][]byte{}
	}
	defer func() {
		for _, entries := range files {
			for _, raw := range entries {
				clear(raw)
			}
		}
	}()
	seen := map[string]bool{}
	var count, total, proofBytes int64
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil || ctx.Err() != nil {
			return ErrWorkspaceProof
		}
		name := header.Name
		if archivePolicy.Observe(header) != nil {
			return ErrWorkspaceProof
		}
		if name != "." && (path.IsAbs(name) || path.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") || strings.ContainsAny(name, "\\\x00\r\n")) {
			return ErrWorkspaceProof
		}
		if seen[name] || header.Size < 0 || header.Size > s.MaxBytes-total {
			return ErrWorkspaceProof
		}
		seen[name] = true
		count++
		total += header.Size
		if count > s.MaxFiles {
			return ErrCapacity
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			if header.Size != 0 {
				return ErrWorkspaceProof
			}
			continue
		}
		var matching []struct{ root, relative string }
		for root := range files {
			if strings.HasPrefix(name, root+"/") {
				rel := strings.TrimPrefix(name, root+"/")
				if !captureHidden(rel) {
					if !captureRelative(rel) || strings.TrimSpace(rel) != rel || len(rel) > 4096 || len(strings.Split(rel, "/")) > 128 {
						return ErrWorkspaceProof
					}
					matching = append(matching, struct{ root, relative string }{root, rel})
				}
			}
		}
		if len(matching) == 0 {
			if _, err := io.Copy(io.Discard, tr); err != nil {
				return ErrWorkspaceProof
			}
			continue
		}
		// Overlapping requirements do not multiply body memory; all references
		// share this bounded buffer, which is zeroed before leaving the reader.
		cost := header.Size + int64(len(name)) + 256*int64(len(matching))
		if cost < header.Size || cost > s.MaxProofBytes-proofBytes {
			return ErrCapacity
		}
		raw, err := io.ReadAll(io.LimitReader(tr, header.Size+1))
		if err != nil || int64(len(raw)) != header.Size {
			clear(raw)
			return ErrWorkspaceProof
		}
		proofBytes += cost
		for _, match := range matching {
			if _, exists := files[match.root][match.relative]; exists {
				clear(raw)
				return ErrWorkspaceProof
			}
			files[match.root][match.relative] = raw
		}
	}
	// A tar EOF is not source EOF. Consume only zero padding; a concatenated
	// archive or nonzero suffix cannot hide additional workspace entries.
	var padding [4096]byte
	var paddingBytes int64
	for {
		n, err := reader.Read(padding[:])
		paddingBytes += int64(n)
		if paddingBytes > 1<<20 {
			return ErrCapacity
		}
		for _, b := range padding[:n] {
			if b != 0 {
				return ErrWorkspaceProof
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return ErrWorkspaceProof
		}
	}
	digests := map[string]string{}
	for _, r := range s.Requirements {
		root := s.SkillRoot + "/" + r.WorkspaceDirectory
		entries := files[root]
		if _, ok := entries["SKILL.md"]; !ok || len(entries) == 0 {
			return ErrWorkspaceProof
		}
		if digests[root] == "" {
			digest, err := workspaceContentMD5(ctx, entries, s.MaxProofBytes)
			if err != nil {
				return err
			}
			digests[root] = digest
		}
		if digests[root] != r.ContentMD5 {
			return ErrWorkspaceProof
		}
	}
	if archivePolicy.Finish() != nil {
		return ErrWorkspaceProof
	}
	return ctx.Err()
}

func workspaceContentMD5(ctx context.Context, files map[string][]byte, maxIndexBytes int64) (string, error) {
	kinds := map[string]bool{}
	var indexBytes int64
	add := func(name string, file bool) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, exists := kinds[name]; exists {
			return nil
		}
		cost := int64(len(name)) + 128
		if cost > maxIndexBytes-indexBytes {
			return ErrCapacity
		}
		indexBytes += cost
		kinds[name] = file
		return nil
	}
	for name := range files {
		if err := add(name, true); err != nil {
			return "", err
		}
		for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
			if err := add(dir, false); err != nil {
				return "", err
			}
		}
	}
	names := make([]string, 0, len(kinds))
	for name := range kinds {
		names = append(names, name)
	}
	sort.Strings(names)
	digest := md5.New() // Original Skill content identity; AEAD/SHA256 remain separate.
	for _, name := range names {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		io.WriteString(digest, name+"\n")
		if !kinds[name] {
			io.WriteString(digest, "dir\n")
			continue
		}
		io.WriteString(digest, "file\n")
		digest.Write(files[name])
		io.WriteString(digest, "\n")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

type workspaceCaptureReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *workspaceCaptureReader) Read(p []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, r.ctx.Err()
	}
	n, err := r.reader.Read(p)
	if r.ctx.Err() != nil {
		return 0, r.ctx.Err()
	}
	return n, err
}
