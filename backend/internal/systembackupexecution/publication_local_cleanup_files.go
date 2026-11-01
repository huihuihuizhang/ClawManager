package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"clawreef/internal/systembackup/staging"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
)

// DATA selected from independently authenticated original captured records.
// This cannot authorize removal; the production caller holds the current SQL
// claim and original deleting ledger row around the precise filesystem action.
type publicationLocalSeal struct {
	Intent staging.SealIntent
	Name   string
}

type publicationLocalFile struct {
	Path, SHA256 string
	Bytes        int64
	Directory    bool
	Modified     time.Time
	identity     os.FileInfo
}

type publicationLocalFiles struct {
	parent, task, custody   *os.Root
	stage                   originalStageResource
	taskIdentity            os.FileInfo
	taskFiles, flatFiles    []publicationLocalFile
	seals                   []publicationLocalSeal
	taskSHA256, sealsSHA256 string
}

func (p *publicationLocalFiles) close() {
	if p == nil {
		return
	}
	if p.task != nil {
		_ = p.task.Close()
		p.task = nil
	}
	if p.custody != nil {
		_ = p.custody.Close()
		p.custody = nil
	}
}

// No recursive RemoveAll, symlink traversal or path outside an os.Root is used.
// A bounded complete inventory is frozen before the original dispatch commits.
func publicationLocalInventory(ctx context.Context, root *os.Root) ([]publicationLocalFile, error) {
	out := []publicationLocalFile{}
	var total int64
	var walk func(string, int) error
	walk = func(directory string, depth int) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if depth > 32 {
			return c.ErrExecutionRecord
		}
		file, err := root.Open(directory)
		if err != nil {
			return err
		}
		entries, readErr := file.ReadDir(10001)
		closeErr := file.Close()
		if readErr != nil && readErr != io.EOF || closeErr != nil || len(entries) > 10000 {
			return c.ErrExecutionRecord
		}
		for _, entry := range entries {
			if len(out) >= 10000 || entry.Name() == "." || entry.Name() == ".." || filepath.Base(entry.Name()) != entry.Name() {
				return c.ErrExecutionRecord
			}
			name := entry.Name()
			if directory != "." {
				name = filepath.Join(directory, name)
			}
			info, err := root.Lstat(name)
			if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() && !info.Mode().IsRegular() {
				return c.ErrExecutionRecord
			}
			item := publicationLocalFile{Path: name, Bytes: info.Size(), Directory: info.IsDir(), Modified: info.ModTime(), identity: info}
			if info.IsDir() {
				if err = walk(name, depth+1); err != nil {
					return err
				}
			} else {
				if info.Size() < 0 || info.Size() > 1<<40-total {
					return c.ErrExecutionRecord
				}
				total += info.Size()
				if item.SHA256, err = publicationLocalFileHash(ctx, root, name, info); err != nil {
					return err
				}
			}
			if len(out) >= 10000 {
				return c.ErrExecutionRecord
			}
			out = append(out, item)
		}
		return nil
	}
	if err := walk(".", 0); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func publicationLocalFileHash(ctx context.Context, root *os.Root, name string, original os.FileInfo) (string, error) {
	file, err := root.Open(name)
	if err != nil {
		return "", err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || original == nil || !os.SameFile(original, before) || !before.Mode().IsRegular() || before.Size() != original.Size() || !before.ModTime().Equal(original.ModTime()) {
		return "", c.ErrExecutionRecord
	}
	digest := sha256.New()
	buffer := make([]byte, 64<<10)
	var n int64
	for {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		read, err := file.Read(buffer)
		if read > 0 {
			_, _ = digest.Write(buffer[:read])
			n += int64(read)
			if n > original.Size() {
				return "", c.ErrExecutionRecord
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || n != before.Size() || after.Size() != n || !after.ModTime().Equal(before.ModTime()) {
		return "", c.ErrExecutionRecord
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func publicationLocalSealsHash(seals []publicationLocalSeal) (string, error) {
	if len(seals) == 0 || len(seals) > 128 {
		return "", c.ErrExecutionRecord
	}
	last := ""
	for _, seal := range seals {
		ref, err := staging.SealReferenceForIntent(seal.Intent)
		if err != nil || ref != "controller-staging-seal.v1/"+seal.Name || seal.Name <= last {
			return "", c.ErrExecutionRecord
		}
		last = seal.Name
	}
	raw, err := ce.Canonical(seals)
	if err != nil {
		return "", err
	}
	return hash(raw), nil
}

func openPublicationLocalCustody(parent *os.Root) (*os.Root, error) {
	if parent == nil {
		return nil, c.ErrExecutionAuthority
	}
	info, err := parent.Lstat(".controller-seals")
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, c.ErrExecutionRecord
	}
	root, err := parent.OpenRoot(".controller-seals")
	if err != nil {
		return nil, err
	}
	actual, err := root.Stat(".")
	if err != nil || !os.SameFile(info, actual) {
		_ = root.Close()
		return nil, c.ErrExecutionRecord
	}
	// Query-only reopen cannot create a missing custody directory or lock file.
	lock, err := root.Lstat(".custody.lock")
	if err != nil || !lock.Mode().IsRegular() || lock.Mode()&os.ModeSymlink != 0 {
		_ = root.Close()
		return nil, c.ErrExecutionRecord
	}
	return root, nil
}

func publicationLocalCustodyCurrent(parent, custody *os.Root) bool {
	if parent == nil || custody == nil {
		return false
	}
	entry, err := parent.Lstat(".controller-seals")
	if err != nil || !entry.IsDir() || entry.Mode()&os.ModeSymlink != 0 {
		return false
	}
	opened, err := custody.Stat(".")
	return err == nil && opened.IsDir() && os.SameFile(entry, opened)
}

func preparePublicationLocalFiles(ctx context.Context, owner *PublicJobOwner, stage originalStageResource, seals []publicationLocalSeal) (*publicationLocalFiles, error) {
	if ctx == nil || ctx.Err() != nil || owner == nil || owner.Staging == nil || stage.owner.Location != filepath.Join(owner.Staging.Name(), stage.owner.Task) || filepath.Base(stage.owner.Task) != stage.owner.Task || owner.verifyStageDirectory(stage) != nil {
		return nil, c.ErrExecutionAuthority
	}
	sealSHA, err := publicationLocalSealsHash(seals)
	if err != nil {
		return nil, err
	}
	for _, seal := range seals {
		if seal.Intent.Scope.Installation != stage.owner.Installation || seal.Intent.Scope.Task != stage.owner.Task || seal.Intent.Scope.Attempt != stage.owner.Attempt || seal.Intent.Scope.ConfigVersion != stage.owner.ConfigVersion || seal.Intent.Scope.ConfigSHA256 != stage.owner.ConfigSHA256 {
			return nil, c.ErrExecutionRecord
		}
	}
	p := &publicationLocalFiles{parent: owner.Staging, stage: stage, seals: seals, sealsSHA256: sealSHA}
	ok := false
	defer func() {
		if !ok {
			p.close()
		}
	}()
	if p.taskIdentity, err = owner.Staging.Lstat(stage.owner.Task); err != nil || !p.taskIdentity.IsDir() || p.taskIdentity.Mode()&os.ModeSymlink != 0 {
		return nil, c.ErrExecutionRecord
	}
	if p.task, err = owner.Staging.OpenRoot(stage.owner.Task); err != nil {
		return nil, err
	}
	actual, err := p.task.Stat(".")
	if err != nil || !os.SameFile(p.taskIdentity, actual) {
		return nil, c.ErrExecutionRecord
	}
	if p.taskFiles, err = publicationLocalInventory(ctx, p.task); err != nil {
		return nil, err
	}
	raw, err := ce.Canonical(p.taskFiles)
	if err != nil {
		return nil, err
	}
	p.taskSHA256 = hash(raw)
	if p.custody, err = openPublicationLocalCustody(owner.Staging); err != nil {
		return nil, err
	}
	if err = staging.WithCustodyLock(ctx, p.custody, func() error { return p.freezeFlatFiles(ctx) }); err != nil {
		return nil, err
	}
	ok = true
	return p, nil
}

func (p *publicationLocalFiles) freezeFlatFiles(ctx context.Context) error {
	if !publicationLocalCustodyCurrent(p.parent, p.custody) {
		return c.ErrExecutionRecord
	}
	directory, err := p.custody.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(10001)
	closeErr := directory.Close()
	if readErr != nil && readErr != io.EOF || closeErr != nil || len(entries) > 10000 {
		return c.ErrExecutionRecord
	}
	// Inventory all names/metadata, but never hash another task's ciphertext.
	all := make([]publicationLocalFile, 0, len(entries))
	byName := map[string]publicationLocalFile{}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		info, err := p.custody.Lstat(entry.Name())
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 {
			return c.ErrExecutionRecord
		}
		item := publicationLocalFile{Path: entry.Name(), Bytes: info.Size(), Modified: info.ModTime(), identity: info}
		all = append(all, item)
		byName[item.Path] = item
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Path < all[j].Path })
	expected := map[string]publicationLocalSeal{}
	ownedJobs, ownedInvocations := map[string]bool{}, map[string]bool{}
	for _, seal := range p.seals {
		expected[seal.Name] = seal
		ownedJobs[seal.Intent.Scope.JobUID], ownedInvocations[seal.Intent.Scope.InvocationSHA256] = true, true
	}
	seen := map[string]bool{}
	foreignChecked := map[string]bool{}
	for _, item := range all {
		if item.Path == ".custody.lock" || item.Path == ".custody-policy.json" {
			continue
		}
		name, intent := strings.CutSuffix(item.Path, ".intent.json")
		if !intent {
			name = item.Path
		}
		if !strings.HasPrefix(name, "seal-") || !strings.HasSuffix(name, ".enc") || !formalCandidateDigest(strings.TrimSuffix(strings.TrimPrefix(name, "seal-"), ".enc")) {
			return c.ErrExecutionRecord
		}
		seal, wanted := expected[name]
		if !wanted {
			// A paired canonical small intent proves foreign attribution. An
			// unpaired object/intent or partial cannot silently hide our payload.
			if !foreignChecked[name] {
				objectFile, hasObject := byName[name]
				intentFile, hasIntent := byName[name+".intent.json"]
				if !hasObject || !hasIntent || intentFile.Bytes < 1 || intentFile.Bytes > 8192 {
					return c.ErrExecutionRecord
				}
				raw, err := readStageFile(p.custody, name+".intent.json", 8192)
				var other staging.SealIntent
				if err != nil || json.Unmarshal(raw, &other) != nil {
					return c.ErrExecutionRecord
				}
				canonical, _ := json.Marshal(other)
				ref, err := staging.SealReferenceForIntent(other)
				if err != nil || !bytes.Equal(raw, canonical) || ref != "controller-staging-seal.v1/"+name || other.Scope.Installation != p.stage.owner.Installation || other.Scope.Task == p.stage.owner.Task || ownedJobs[other.Scope.JobUID] || ownedInvocations[other.Scope.InvocationSHA256] || objectFile.Bytes != other.Original.Size {
					return c.ErrExecutionRecord
				}
				foreignChecked[name] = true
			}
			continue
		}
		if seen[item.Path] {
			return c.ErrExecutionRecord
		}
		seen[item.Path] = true
		item.SHA256, err = publicationLocalFileHash(ctx, p.custody, item.Path, item.identity)
		if err != nil {
			return err
		}
		if intent {
			raw, _ := json.Marshal(seal.Intent)
			if item.SHA256 != hash(raw) || item.Bytes != int64(len(raw)) {
				return c.ErrExecutionRecord
			}
		} else if item.Bytes != seal.Intent.Original.Size || item.SHA256 != seal.Intent.Original.SHA256 {
			return c.ErrExecutionRecord
		}
		p.flatFiles = append(p.flatFiles, item)
	}
	if len(p.flatFiles) != 2*len(p.seals) {
		return c.ErrExecutionRecord
	}
	return nil
}

func removePublicationLocalFile(ctx context.Context, root *os.Root, item publicationLocalFile) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	info, err := root.Lstat(item.Path)
	if err != nil || item.identity == nil || !os.SameFile(item.identity, info) || info.IsDir() != item.Directory || info.Mode()&os.ModeSymlink != 0 {
		return c.ErrExecutionRecord
	}
	if !item.Directory {
		if !info.Mode().IsRegular() || info.Size() != item.Bytes || !info.ModTime().Equal(item.Modified) {
			return c.ErrExecutionRecord
		}
		// The exact inode was hashed under the shared custody lock. Windows
		// read-only ciphertext needs this precise chmod before its own removal.
		if err = root.Chmod(item.Path, 0600); err != nil {
			return err
		}
	}
	return root.Remove(item.Path)
}

func (p *publicationLocalFiles) removeLocked(ctx context.Context, authorize func(func() error) error) error {
	if p == nil || p.task == nil || p.custody == nil || p.parent == nil || authorize == nil {
		return c.ErrExecutionAuthority
	}
	if !publicationLocalCustodyCurrent(p.parent, p.custody) {
		return c.ErrExecutionRecord
	}
	parentIdentity, err := p.parent.Lstat(p.stage.owner.Task)
	if err != nil || !os.SameFile(parentIdentity, p.taskIdentity) {
		return c.ErrExecutionRecord
	}
	// Repeat the complete inventories before removing anything. Concurrent
	// writes, replacement inodes and extra files all fail closed.
	again, err := publicationLocalInventory(ctx, p.task)
	if err != nil {
		return err
	}
	raw, _ := ce.Canonical(again)
	if hash(raw) != p.taskSHA256 {
		return c.ErrExecutionRecord
	}
	for index, item := range again {
		if index >= len(p.taskFiles) || !os.SameFile(item.identity, p.taskFiles[index].identity) {
			return c.ErrExecutionRecord
		}
	}
	old := p.flatFiles
	p.flatFiles = nil
	if err = p.freezeFlatFiles(ctx); err != nil {
		p.flatFiles = old
		return err
	}
	for index, item := range p.flatFiles {
		if index >= len(old) || !os.SameFile(item.identity, old[index].identity) {
			return c.ErrExecutionRecord
		}
	}
	return authorize(func() error {
		if !publicationLocalCustodyCurrent(p.parent, p.custody) {
			return c.ErrExecutionRecord
		}
		parentIdentity, err := p.parent.Lstat(p.stage.owner.Task)
		if err != nil || !os.SameFile(parentIdentity, p.taskIdentity) {
			return c.ErrExecutionRecord
		}
		for _, item := range p.flatFiles {
			if err = removePublicationLocalFile(ctx, p.custody, item); err != nil {
				return err
			}
		}
		if err = staging.SyncDirectory(p.custody); err != nil {
			return err
		}
		// Remove children before parents and preserve the HMAC marker until last.
		sort.SliceStable(again, func(i, j int) bool {
			if again[i].Path == originalStageMarkerName {
				return false
			}
			if again[j].Path == originalStageMarkerName {
				return true
			}
			return len(again[i].Path) > len(again[j].Path)
		})
		for _, item := range again {
			if err = removePublicationLocalFile(ctx, p.task, item); err != nil {
				return err
			}
		}
		if err = staging.SyncDirectory(p.task); err != nil {
			return err
		}
		if err = p.task.Close(); err != nil {
			return err
		}
		p.task = nil
		info, err := p.parent.Lstat(p.stage.owner.Task)
		if err != nil || !os.SameFile(info, p.taskIdentity) {
			return c.ErrExecutionRecord
		}
		if err = p.parent.Remove(p.stage.owner.Task); err != nil {
			return err
		}
		return staging.SyncDirectory(p.parent)
	})
}

func publicationLocalPathAbsent(err error) bool {
	path, ok := err.(*os.PathError)
	return ok && os.IsNotExist(path.Err)
}

// Only exact previously frozen names are queried. A surviving file, unknown
// result or replacement task directory never becomes permission to remove it.
func publicationLocalFilesAbsent(parent, custody *os.Root, task string, seals []publicationLocalSeal) bool {
	if parent == nil || custody == nil || task == "" || filepath.Base(task) != task || !publicationLocalCustodyCurrent(parent, custody) {
		return false
	}
	if _, err := parent.Lstat(task); !publicationLocalPathAbsent(err) {
		return false
	}
	if _, err := publicationLocalSealsHash(seals); err != nil {
		return false
	}
	for _, seal := range seals {
		for _, name := range []string{seal.Name, seal.Name + ".intent.json"} {
			if _, err := custody.Lstat(name); !publicationLocalPathAbsent(err) {
				return false
			}
		}
	}
	return publicationLocalCustodyCurrent(parent, custody)
}
