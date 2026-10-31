package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"clawreef/internal/systembackup/staging"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	security "clawreef/internal/systembackupsecurity"
	"github.com/google/uuid"
)

const originalStageMarkerName = ".system-backup-owner.json"

// This is the controlled local directory, not an observation of a Kubernetes
// PVC's UID. A PVC and its stop/unmount proof retain their own resource ledger.
type originalStageOwner struct {
	Schema, Installation, Task, Phase, PhaseUID, Resource, Location string
	Attempt, ConfigVersion                                          uint64
	ConfigSHA256, KeyVersion                                        string
}
type originalStageResource struct {
	owner          originalStageOwner
	mac, lifecycle string
	version        uint64
}

func (o *PublicJobOwner) stageScope(a d.Authority) (originalStageOwner, error) {
	if o == nil || o.Staging == nil || a.TaskType != "backup" || a.Phase != "capture" || a.AttemptNo == 0 || a.ConfigVersion == 0 || !formalCandidateDigest(a.ConfigSHA256) || !strings.HasPrefix(a.TaskPublicID, "sbk_") {
		return originalStageOwner{}, c.ErrExecutionRecord
	}
	if _, err := uuid.Parse(strings.TrimPrefix(a.TaskPublicID, "sbk_")); err != nil || len(a.TaskPublicID) != 40 {
		return originalStageOwner{}, c.ErrExecutionRecord
	}
	root := o.Staging.Name()
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return originalStageOwner{}, c.ErrExecutionRecord
	}
	s := originalStageOwner{Schema: "system-backup-original-stage-owner.v1", Installation: a.InstallationID, Task: a.TaskPublicID, Phase: a.Phase, Attempt: a.AttemptNo, ConfigVersion: a.ConfigVersion, ConfigSHA256: a.ConfigSHA256, Location: filepath.Join(root, a.TaskPublicID)}
	if len(s.Location) > 1024 {
		return originalStageOwner{}, c.ErrExecutionRecord
	}
	raw, _ := json.Marshal(s)
	s.PhaseUID = "capture-" + hash(raw)
	return s, nil
}

func stageMAC(s originalStageOwner, key []byte) string {
	raw, _ := json.Marshal(s)
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(raw)
	return hex.EncodeToString(m.Sum(nil))
}

// The original 104 creating intent is committed before ANY new directory or
// key file. A commit error grants no send. The fresh in-memory key is never a
// payload DEK or a signing key; its durable private custody is outside workers'
// exact task subPath. It is retained while its original ledger row exists.
func (o *PublicJobOwner) stageIntent(ctx context.Context, a d.Authority) (originalStageResource, []byte, bool, error) {
	s, err := o.stageScope(a)
	if err != nil {
		return originalStageResource{}, nil, false, err
	}
	tx, err := o.Gate.Authority.DB.BeginTx(ctx, nil)
	if err != nil {
		return originalStageResource{}, nil, false, err
	}
	defer tx.Rollback()
	g, err := o.Gate.Authority.Bind(ctx, tx, a)
	if err != nil {
		return originalStageResource{}, nil, false, err
	}
	r := originalStageResource{owner: s}
	var installation, task, phase, phaseUID, kind, location, keyVersion string
	var attempt uint64
	err = tx.QueryRowContext(ctx, "SELECT public_id,origin_installation_id,backup_public_id,attempt_no,phase,phase_uid,resource_type,planned_locator,owner_marker_hmac,owner_marker_key_version,lifecycle,row_version FROM system_backup_v2_staging_resources WHERE origin_installation_id=? AND location_sha256=? FOR UPDATE", a.InstallationID, hash([]byte(s.Location))).Scan(&r.owner.Resource, &installation, &task, &attempt, &phase, &phaseUID, &kind, &location, &r.mac, &keyVersion, &r.lifecycle, &r.version)
	if err == nil {
		if installation != s.Installation || task != s.Task || attempt != s.Attempt || phase != s.Phase || phaseUID != s.PhaseUID || kind != "hostpath" || location != s.Location || !formalCandidateDigest(r.mac) || keyVersion == "" || (r.lifecycle != "creating" && r.lifecycle != "ready") {
			return originalStageResource{}, nil, false, c.ErrExecutionRecord
		}
		if _, err := uuid.Parse(keyVersion); err != nil {
			return originalStageResource{}, nil, false, c.ErrExecutionRecord
		}
		if !strings.HasPrefix(r.owner.Resource, "sbs_") {
			return originalStageResource{}, nil, false, c.ErrExecutionRecord
		}
		if _, err := uuid.Parse(strings.TrimPrefix(r.owner.Resource, "sbs_")); err != nil {
			return originalStageResource{}, nil, false, c.ErrExecutionRecord
		}
		r.owner.KeyVersion = keyVersion
		if err = g.Recheck(ctx, tx); err != nil {
			return originalStageResource{}, nil, false, err
		}
		if err = tx.Commit(); err != nil {
			return originalStageResource{}, nil, false, c.ErrExecutionCommitUnknown
		}
		return r, nil, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return originalStageResource{}, nil, false, err
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return originalStageResource{}, nil, false, err
	}
	ok := false
	defer func() {
		if !ok {
			clear(key)
		}
	}()
	r.owner.Resource = "sbs_" + uuid.NewString()
	r.owner.KeyVersion = uuid.NewString()
	r.mac = stageMAC(r.owner, key)
	r.lifecycle = "creating"
	r.version = 1
	var capacity int64
	if err = tx.QueryRowContext(ctx, "SELECT control_metadata_capacity_bytes FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=?", a.InstallationID, a.ConfigVersion).Scan(&capacity); err != nil {
		return originalStageResource{}, nil, false, err
	}
	raw, _ := json.Marshal(r.owner)
	if err = (security.RegistrationCapacity{ReportFile: o.Gate.Records.CapacityReportFile}).Reserve(ctx, tx, capacity, len(raw)+1024); err != nil {
		return originalStageResource{}, nil, false, err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO system_backup_v2_staging_resources(public_id,origin_installation_id,backup_public_id,attempt_no,phase,phase_uid,resource_type,planned_locator,location_sha256,owner_marker_hmac,owner_marker_key_version) VALUES (?,?,?,?,?,?,'hostpath',?,?,?,?)", r.owner.Resource, a.InstallationID, a.TaskPublicID, a.AttemptNo, a.Phase, r.owner.PhaseUID, r.owner.Location, hash([]byte(r.owner.Location)), r.mac, r.owner.KeyVersion)
	if err != nil {
		return originalStageResource{}, nil, false, err
	}
	if err = g.Recheck(ctx, tx); err != nil {
		return originalStageResource{}, nil, false, err
	}
	if err = tx.Commit(); err != nil {
		return originalStageResource{}, nil, false, c.ErrExecutionCommitUnknown
	}
	ok = true
	return r, key, true, nil
}

// Separate from flat seal custody: never change that inventory's accepted ABI.
// Workers mount only their task subPath, not this controller-owned sibling.
func stageKeyRoot(parent *os.Root, create bool) (*os.Root, error) {
	const name = ".controller-stage-owner-keys"
	if create {
		if err := parent.Mkdir(name, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	info, err := parent.Lstat(name)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, c.ErrExecutionRecord
	}
	if create {
		if err = staging.SyncDirectory(parent); err != nil {
			return nil, err
		}
	}
	return parent.OpenRoot(name)
}

// A fixed local key budget complements the original SQL capacity reservation.
// No unknown file/directory is ignored and no referenced key is garbage-collected.
func writeStageOwnerKey(ctx context.Context, root *os.Root, name string, key []byte) error {
	return staging.WithCustodyLock(ctx, root, func() error {
		dir, err := root.Open(".")
		if err != nil {
			return err
		}
		defer dir.Close()
		entries, err := dir.ReadDir(10002)
		if err != nil && err != io.EOF {
			return err
		}
		count := 0
		for _, entry := range entries {
			info, e := root.Lstat(entry.Name())
			if e != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return c.ErrExecutionRecord
			}
			if entry.Name() == ".custody.lock" {
				continue
			}
			id, ok := strings.CutSuffix(entry.Name(), ".key")
			if !ok || info.Size() != 32 {
				return c.ErrExecutionRecord
			}
			if _, e = uuid.Parse(id); e != nil {
				return c.ErrExecutionRecord
			}
			count++
		}
		if count >= 10000 || len(entries) >= 10002 {
			return staging.ErrCapacity
		}
		return writeStageExclusive(root, name, key)
	})
}

func readStageFile(root *os.Root, name string, limit int64) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > limit {
		return nil, c.ErrExecutionRecord
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return nil, c.ErrExecutionRecord
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, c.ErrExecutionRecord
	}
	return raw, nil
}
func writeStageExclusive(root *os.Root, name string, raw []byte) error {
	f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return staging.SyncDirectory(root)
}
func stageMarkerBytes(r originalStageResource) []byte {
	raw, _ := json.Marshal(struct {
		Owner originalStageOwner
		HMAC  string
	}{r.owner, r.mac})
	return raw
}

func (o *PublicJobOwner) verifyStageDirectory(r originalStageResource) error {
	info, err := o.Staging.Lstat(r.owner.Task)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return c.ErrExecutionRecord
	}
	keys, err := stageKeyRoot(o.Staging, false)
	if err != nil {
		return err
	}
	defer keys.Close()
	key, err := readStageFile(keys, r.owner.KeyVersion+".key", 32)
	if err != nil {
		return err
	}
	defer clear(key)
	if len(key) != 32 || !hmac.Equal([]byte(stageMAC(r.owner, key)), []byte(r.mac)) {
		return c.ErrExecutionRecord
	}
	root, err := o.Staging.OpenRoot(r.owner.Task)
	if err != nil {
		return err
	}
	defer root.Close()
	expected := stageMarkerBytes(r)
	raw, err := readStageFile(root, originalStageMarkerName, int64(len(expected)))
	if err != nil || !bytes.Equal(raw, expected) {
		return c.ErrExecutionRecord
	}
	return nil
}

func (o *PublicJobOwner) recordStageLifecycle(ctx context.Context, a d.Authority, r originalStageResource, unknown bool) error {
	tx, err := o.Gate.Authority.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	g, err := o.Gate.Authority.Bind(ctx, tx, a)
	if err != nil {
		return err
	}
	query := "UPDATE system_backup_v2_staging_resources SET lifecycle='ready',observed_name=?,observed_uid=?,row_version=row_version+1 WHERE public_id=? AND origin_installation_id=? AND backup_public_id=? AND attempt_no=? AND phase=? AND phase_uid=? AND owner_marker_hmac=? AND owner_marker_key_version=? AND row_version=? AND lifecycle='creating'"
	args := []any{a.TaskPublicID, r.owner.Resource, r.owner.Resource, a.InstallationID, a.TaskPublicID, a.AttemptNo, a.Phase, r.owner.PhaseUID, r.mac, r.owner.KeyVersion, r.version}
	if unknown {
		query = "UPDATE system_backup_v2_staging_resources SET lifecycle='ownership_unknown',cleanup_result='failed',last_failure_code='ownership_unknown',row_version=row_version+1 WHERE public_id=? AND origin_installation_id=? AND backup_public_id=? AND attempt_no=? AND phase=? AND phase_uid=? AND owner_marker_hmac=? AND owner_marker_key_version=? AND row_version=? AND lifecycle IN ('creating','ready')"
		args = args[2:]
	}
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return c.ErrExecutionRecord
	}
	if err = g.Recheck(ctx, tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return c.ErrExecutionCommitUnknown
	}
	return nil
}

func (o *PublicJobOwner) ensureStaging(ctx context.Context, a d.Authority) error {
	if err := o.Gate.ValidateCollectors(ctx, a); err != nil {
		return err
	}
	r, key, create, err := o.stageIntent(ctx, a)
	if err != nil {
		return err
	}
	defer clear(key)
	if create {
		if err = o.createStageDirectory(ctx, a, r, key); err != nil {
			return err
		}
	}
	// Existing creating rows authorize only exact marker readback, never a second
	// Mkdir or marker write. Missing keys/markers and foreign directories stay
	// untouched. A ready record whose marker changed becomes ownership_unknown.
	if err = o.verifyStageDirectory(r); err != nil {
		_, presenceErr := o.Staging.Lstat(a.TaskPublicID)
		if r.lifecycle == "ready" || presenceErr == nil {
			if e := o.recordStageLifecycle(ctx, a, r, true); e != nil {
				return e
			}
		}
		return err
	}
	if err = o.Gate.ValidateCollectors(ctx, a); err != nil {
		return err
	}
	if r.lifecycle == "creating" {
		return o.recordStageLifecycle(ctx, a, r, false)
	}
	return nil
}

// Only the caller holding the acknowledged fresh creating intent's key may
// send creation. Restart paths have no key and can only verify exact readback.
func (o *PublicJobOwner) createStageDirectory(ctx context.Context, a d.Authority, r originalStageResource, key []byte) error {
	s, err := o.stageScope(a)
	if err != nil {
		return err
	}
	s.Resource = r.owner.Resource
	s.KeyVersion = r.owner.KeyVersion
	if s != r.owner || r.lifecycle != "creating" || len(key) != 32 || !hmac.Equal([]byte(stageMAC(s, key)), []byte(r.mac)) {
		return c.ErrExecutionRecord
	}
	if err = o.Gate.ValidateCollectors(ctx, a); err != nil {
		return err
	}
	keys, err := stageKeyRoot(o.Staging, true)
	if err != nil {
		return err
	}
	err = writeStageOwnerKey(ctx, keys, r.owner.KeyVersion+".key", key)
	keys.Close()
	if err != nil {
		return err
	}
	if err = o.Gate.ValidateCollectors(ctx, a); err != nil {
		return err
	}
	if err = o.Staging.Mkdir(a.TaskPublicID, 0700); err != nil {
		if errors.Is(err, os.ErrExist) {
			if e := o.recordStageLifecycle(ctx, a, r, true); e != nil {
				return e
			}
			return c.ErrExecutionRecord
		}
		return err
	}
	root, err := o.Staging.OpenRoot(a.TaskPublicID)
	if err != nil {
		return err
	}
	err = writeStageExclusive(root, originalStageMarkerName, stageMarkerBytes(r))
	root.Close()
	if err != nil {
		return err
	}
	return staging.SyncDirectory(o.Staging)
}
