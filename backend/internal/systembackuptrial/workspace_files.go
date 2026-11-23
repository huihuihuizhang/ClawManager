package systembackuptrial

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf8"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/workspace"
)

const maxWorkspaceArchive = 32 << 20

var workspaceFileLimits = workspace.Limits{MaxFiles: 10000, MaxBytes: maxWorkspaceArchive}
var errWorkspaceFiles = errors.New("trial workspace archive invalid or unavailable")

type workspaceSelection struct {
	UserID      int    `json:"user_id"`
	InstanceID  int    `json:"instance_id"`
	RelativeDir string `json:"relative_dir"`
}

type workspaceFileReceipt struct {
	Entries int64  `json:"entries"`
	Bytes   int64  `json:"file_bytes"`
	SHA256  string `json:"archive_sha256"`
}

type workspaceManifest struct {
	workspaceSelection
	Runtime      string `json:"runtime"`
	ArchiveBytes int    `json:"archive_bytes"`
	workspaceFileReceipt
}

func selectedRuntime(snapshot domain.Snapshot, selection workspaceSelection) string {
	if selection.UserID <= 0 || selection.InstanceID <= 0 || !validWorkspaceSelection(selection.RelativeDir) {
		return ""
	}
	userID, instanceID := strconv.Itoa(selection.UserID), strconv.Itoa(selection.InstanceID)
	for _, table := range snapshot.Tables {
		if table.Name != "instances" {
			continue
		}
		for _, row := range table.Rows {
			if row["id"].String() != instanceID || row["user_id"].String() != userID ||
				row["instance_mode"].String() != "lite" || row["runtime_type"].String() != "gateway" {
				continue
			}
			switch name := row["type"].String(); name {
			case "hermes", "openclaw", "opencode", "deepseek-harness":
				return name
			}
		}
	}
	return ""
}

func validWorkspaceSelection(name string) bool {
	if name == "" || name == "home" || len(name) > 240 || !utf8.ValidString(name) ||
		path.IsAbs(name) || path.Clean(name) != name || strings.ContainsAny(name, "\\:\x00\r\n") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || strings.HasPrefix(part, ".") {
			return false
		}
	}
	return true
}

func (m workspaceManifest) location() string {
	return fmt.Sprintf("%s/user-%d/instance-%d/%s", m.Runtime, m.UserID, m.InstanceID, m.RelativeDir)
}

// Mount roots belong to the isolated deployment. Every component beneath that
// root must be a directory at that exact location, including the instance root.
func openWorkspaceDirectory(root *os.Root, relative string) (*os.Root, error) {
	if relative == "." {
		return root.OpenRoot(".")
	}
	for _, dir := range strings.Split(relative, "/") {
		if dir == "" || dir == "." || dir == ".." {
			return nil, errWorkspaceFiles
		}
	}
	for current := relative; current != "."; current = path.Dir(current) {
		info, err := root.Lstat(current)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			return nil, errWorkspaceFiles
		}
	}
	return root.OpenRoot(relative)
}

type workspaceArchiveBuffer struct{ bytes.Buffer }

func (b *workspaceArchiveBuffer) Write(p []byte) (int, error) {
	if len(p) > maxWorkspaceArchive-b.Len() {
		return 0, errWorkspaceFiles
	}
	return b.Buffer.Write(p)
}

func (s *Service) captureWorkspaceFiles(ctx context.Context, snapshot domain.Snapshot) ([]byte, *workspaceManifest, error) {
	file, source := s.value("WORKSPACE_FILES_SELECTION_FILE"), s.value("WORKSPACE_FILES_SOURCE_ROOT")
	if file == "" && source == "" {
		return nil, nil, nil
	}
	if !filepath.IsAbs(source) || filepath.Clean(source) != source || filepath.Dir(source) == source {
		return nil, nil, errWorkspaceFiles
	}
	selectionJSON, err := readSetting(file, 4096)
	var selection workspaceSelection
	if err != nil || json.Unmarshal(selectionJSON, &selection) != nil {
		return nil, nil, errWorkspaceFiles
	}
	m := workspaceManifest{workspaceSelection: selection, Runtime: selectedRuntime(snapshot, selection)}
	if m.Runtime == "" {
		return nil, nil, errWorkspaceFiles
	}
	mount, err := os.OpenRoot(source)
	if err != nil {
		return nil, nil, errWorkspaceFiles
	}
	defer mount.Close()
	root, err := openWorkspaceDirectory(mount, m.location())
	if err != nil {
		return nil, nil, errWorkspaceFiles
	}
	defer root.Close()
	var archive workspaceArchiveBuffer
	if _, err := workspace.Archive(ctx, root, &archive, workspaceFileLimits); err != nil {
		clear(archive.Bytes())
		return nil, nil, errWorkspaceFiles
	}
	receipt, err := describeWorkspaceFiles(archive.Bytes())
	if err != nil {
		clear(archive.Bytes())
		return nil, nil, err
	}
	m.ArchiveBytes, m.workspaceFileReceipt = archive.Len(), receipt
	return archive.Bytes(), &m, nil
}

func describeWorkspaceFiles(data []byte) (workspaceFileReceipt, error) {
	if len(data) == 0 || len(data) > maxWorkspaceArchive {
		return workspaceFileReceipt{}, errWorkspaceFiles
	}
	validator, err := workspace.NewCapturedArchiveValidator("")
	if err != nil {
		return workspaceFileReceipt{}, errWorkspaceFiles
	}
	var receipt workspaceFileReceipt
	rest := bytes.NewReader(data)
	tr := tar.NewReader(rest)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil || validator.Observe(header) != nil ||
			(header.Typeflag != tar.TypeDir && header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) ||
			(receipt.Entries == 0 && header.Name != ".") {
			return workspaceFileReceipt{}, errWorkspaceFiles
		}
		receipt.Entries++
		if receipt.Entries > workspaceFileLimits.MaxFiles || header.Size > workspaceFileLimits.MaxBytes-receipt.Bytes {
			return workspaceFileReceipt{}, errWorkspaceFiles
		}
		receipt.Bytes += header.Size
	}
	if rest.Len() != 0 || receipt.Entries < 1 || validator.Finish() != nil {
		return workspaceFileReceipt{}, errWorkspaceFiles
	}
	digest := sha256.Sum256(data)
	receipt.SHA256 = hex.EncodeToString(digest[:])
	return receipt, nil
}

func (s *Service) openWorkspaceTarget() (*os.Root, error) {
	root := s.value("WORKSPACE_FILES_TARGET_ROOT")
	if runtime.GOOS != "linux" || !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Dir(root) == root {
		return nil, errWorkspaceFiles
	}
	target, err := os.OpenRoot(root)
	if err != nil {
		return nil, errWorkspaceFiles
	}
	return target, nil
}

func verifyWorkspaceFiles(ctx context.Context, mount *os.Root, m workspaceManifest, archive []byte) error {
	root, err := openWorkspaceDirectory(mount, m.location())
	if err != nil {
		return err
	}
	defer root.Close()
	return verifyWorkspaceArchive(ctx, root, m, archive)
}

func verifyWorkspaceArchive(ctx context.Context, root *os.Root, m workspaceManifest, archive []byte) error {
	report, err := workspace.Verify(ctx, root, bytes.NewReader(archive), workspaceFileLimits, true)
	if err != nil || report.Files != m.Entries || report.Bytes != m.Bytes {
		return errWorkspaceFiles
	}
	return nil
}

func checkWorkspaceDestination(ctx context.Context, mount *os.Root, m workspaceManifest, archive []byte) error {
	if err := verifyWorkspaceFiles(ctx, mount, m, archive); !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	parent, err := openWorkspaceDirectory(mount, path.Dir(m.location()))
	if err != nil {
		return errWorkspaceFiles
	}
	defer parent.Close()
	return checkWorkspacePublish(parent)
}

func checkWorkspacePublish(parent *os.Root) (err error) {
	name := ".trial-files-probe-" + newID()
	if err := parent.Mkdir(name, 0700); err != nil {
		return fmt.Errorf("%w: create workspace publication probe: %v", errWorkspaceFiles, err)
	}
	defer func() {
		if cleanup := parent.RemoveAll(name); cleanup != nil {
			err = errors.Join(err, fmt.Errorf("%w: clean workspace publication probe: %v", errWorkspaceFiles, cleanup))
		}
	}()
	probe, err := parent.OpenRoot(name)
	if err != nil {
		return fmt.Errorf("%w: open workspace publication probe: %v", errWorkspaceFiles, err)
	}
	defer probe.Close()
	if err := probe.Mkdir("staged", 0700); err != nil {
		return fmt.Errorf("%w: stage workspace publication probe: %v", errWorkspaceFiles, err)
	}
	if err := publishWorkspaceFiles(probe, "staged", "published"); err != nil {
		return fmt.Errorf("%w: workspace publication probe: %v", errWorkspaceFiles, err)
	}
	return nil
}

func restoreWorkspaceFiles(ctx context.Context, mount *os.Root, m workspaceManifest, archive []byte) error {
	if err := verifyWorkspaceFiles(ctx, mount, m, archive); !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	parent, leaf := path.Split(m.location())
	root, err := openWorkspaceDirectory(mount, strings.TrimSuffix(parent, "/"))
	if err != nil {
		return errWorkspaceFiles
	}
	defer root.Close()
	staging := ".trial-files-" + newID()
	if err := root.Mkdir(staging, 0700); err != nil {
		return errWorkspaceFiles
	}
	defer root.RemoveAll(staging)
	stage, err := root.OpenRoot(staging)
	if err != nil {
		return errWorkspaceFiles
	}
	defer stage.Close()
	if _, err := workspace.Restore(ctx, stage, bytes.NewReader(archive), workspaceFileLimits, true); err != nil {
		return fmt.Errorf("%w: extract staged files: %v", errWorkspaceFiles, err)
	}
	if err := verifyWorkspaceArchive(ctx, stage, m, archive); err != nil {
		return fmt.Errorf("%w: staged file readback differs", errWorkspaceFiles)
	}
	if err := syncWorkspaceStage(ctx, stage); err != nil {
		return fmt.Errorf("%w: sync staged files: %v", errWorkspaceFiles, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := publishWorkspaceFiles(root, staging, leaf); errors.Is(err, fs.ErrExist) {
		// A concurrent or interrupted restore may already have published. Only
		// the independently verified, identical directory can complete this run.
		if err := verifyWorkspaceFiles(ctx, mount, m, archive); err != nil {
			return errWorkspaceFiles
		}
	} else if err != nil {
		return fmt.Errorf("%w: publish staged directory: %v", errWorkspaceFiles, err)
	}
	return nil
}

func syncWorkspaceStage(ctx context.Context, stage *os.Root) error {
	return fs.WalkDir(stage.FS(), ".", func(name string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		file, err := stage.Open(name)
		if err != nil {
			return err
		}
		return errors.Join(file.Sync(), file.Close())
	})
}
