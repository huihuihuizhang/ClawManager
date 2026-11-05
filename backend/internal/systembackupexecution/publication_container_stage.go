package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"time"

	"clawreef/internal/systembackup/staging"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

// Derived publication files stay INSIDE the actual owned original 104 local
// resource. No publish-phase hostpath row, capture Authority or Job is invented.
// Only individual file subPaths will be mounted into the upload-only Job.
type publicationContainerPlan struct {
	Version                                          string `json:"schema_version"`
	Installation, Backup                             string
	Attempt, ConfigVersion                           uint64
	ConfigSHA256, CaptureSHA256, CertificateSHA256   string
	CaptureResultSHA256, CaptureContextSHA256        string
	ParentResource, ParentKeyVersion, ParentOwnerMAC string
	ParentRowVersion                                 uint64
	Directory                                        string
}

type publicationContainerDirectory struct {
	root *os.Root
	plan publicationContainerPlan
}

func (d *publicationContainerDirectory) Close() {
	if d != nil && d.root != nil {
		d.root.Close()
		d.root = nil
	}
}

func publicationContainerPlanID(installation, backup string, attempt uint64) string {
	raw, _ := ce.Canonical([]any{"original-publication-container-files.v1", installation, backup, attempt})
	return "sev_pub_containers_" + hash(raw)
}

func containerDirectoryMarker(plan publicationContainerPlan, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, c.ErrExecutionRecord
	}
	raw, err := ce.Canonical(plan)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("system-backup-original-publication-container-directory.v1\x00"))
	mac.Write(raw)
	return ce.Canonical(struct{ Version, PlanSHA256, MAC string }{"system-backup-publication-directory-owner.v1", hash(raw), hex.EncodeToString(mac.Sum(nil))})
}

func (s *DeploymentService) publicationStageForContainers(ctx context.Context, guard *publicationContainerGuard, capture publicationVerifiedCapture) (publicationCertificateSQLFacts, error) {
	var zero publicationCertificateSQLFacts
	if guard == nil || guard.service != s || !capture.checked() || guard.current(ctx, true) != nil {
		return zero, c.ErrExecutionAuthority
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: false, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, err
	}
	bound, err := guard.access.Bind(ctx, tx)
	var original publicationCertificateSQLFacts
	if err == nil {
		original, err = s.readPublicationCertificateFactsTx(ctx, tx, bound.Facts(), capture, nil)
	}
	if err == nil {
		err = bound.RecheckTx(ctx, tx)
	}
	if rollbackErr := tx.Rollback(); err == nil {
		err = rollbackErr
	}
	if err != nil {
		return zero, err
	}
	if s.Runtime.Owner.verifyStageDirectory(original.stage) != nil || guard.current(ctx, true) != nil {
		return zero, c.ErrExecutionAuthority
	}
	// Native key/marker reads are outside SQL; authenticate the same original
	// row again afterwards, without changing its lifecycle or source facts.
	final, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: false, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, err
	}
	defer final.Rollback()
	bound, err = guard.access.Bind(ctx, final)
	if err != nil {
		return zero, err
	}
	again, err := s.readPublicationCertificateFactsTx(ctx, final, bound.Facts(), capture, nil)
	if err != nil || !samePublicationContainerStage(again, original) || bound.RecheckTx(ctx, final) != nil {
		return zero, c.ErrExecutionRecord
	}
	return original, nil
}

// Explicit current-claim renewal may change the backup row version. The actual
// current token is independently checked by Bind/readPublicationCertificateFacts;
// it cannot alter the original capture completion or actual 104 ownership row.
func samePublicationContainerStage(a, b publicationCertificateSQLFacts) bool {
	return a.stage == b.stage && a.locationHash == b.locationHash && a.completed.Equal(b.completed) && a.ttl == b.ttl
}

func (s *DeploymentService) ensurePublicationContainerDirectory(ctx context.Context, claim *c.ClaimToken, attempt uint64, policy c.LeasePolicy, capture publicationVerifiedCapture) (*publicationContainerDirectory, error) {
	return s.ensurePublicationContainerDirectoryMode(ctx, claim, attempt, policy, capture, false)
}

func (s *DeploymentService) ensurePublicationContainerDirectoryMode(ctx context.Context, claim *c.ClaimToken, attempt uint64, policy c.LeasePolicy, capture publicationVerifiedCapture, freshPreparation bool) (*publicationContainerDirectory, error) {
	if s == nil || claim == nil || !capture.checked() || attempt != capture.Input.CaptureAttemptNo || claim.Target.PublicID != capture.Input.TaskPublicID {
		return nil, c.ErrExecutionAuthority
	}
	guard := &publicationContainerGuard{service: s, claim: claim, attempt: attempt, policy: policy, freshPreparation: freshPreparation}
	if err := guard.current(ctx, true); err != nil {
		return nil, err
	}
	certificate, known, err := s.loadOriginalPublicationCaptureCertificate(ctx, *claim, attempt, capture)
	if err != nil || !known || !certificate.checked(capture, time.Now()) {
		return nil, c.ErrExecutionRecord
	}
	original, err := s.publicationStageForContainers(ctx, guard, capture)
	if err != nil {
		return nil, err
	}
	plan := publicationContainerPlan{Version: "system-backup-original-publication-container-plan.v1", Installation: capture.Input.InstallationID, Backup: capture.Input.TaskPublicID, Attempt: attempt, ConfigVersion: capture.Input.ConfigVersion, ConfigSHA256: capture.Input.ConfigSHA256, CaptureSHA256: capture.receipt.sha256, CertificateSHA256: certificate.sha256, ParentResource: original.stage.owner.Resource, ParentKeyVersion: original.stage.owner.KeyVersion, ParentOwnerMAC: original.stage.mac}
	plan.CaptureResultSHA256, plan.CaptureContextSHA256 = capture.CaptureResultSHA256, capture.CaptureContextSHA256
	plan.ParentRowVersion = original.stage.version
	definition, err := ce.Canonical(plan)
	if err != nil {
		return nil, err
	}
	plan.Directory = "publication-" + hash(definition)
	if err = s.freezePublicationContainerPlan(ctx, guard, capture, original, plan); err != nil {
		return nil, err
	}
	if err = guard.current(ctx, true); err != nil {
		return nil, err
	}
	keys, err := stageKeyRoot(s.Runtime.Owner.Staging, false)
	if err != nil {
		return nil, err
	}
	key, err := readStageFile(keys, plan.ParentKeyVersion+".key", 32)
	keys.Close()
	if err != nil {
		return nil, err
	}
	defer clear(key)
	if len(key) != 32 || !hmac.Equal([]byte(stageMAC(original.stage.owner, key)), []byte(plan.ParentOwnerMAC)) {
		return nil, c.ErrExecutionRecord
	}
	marker, err := containerDirectoryMarker(plan, key)
	if err != nil {
		return nil, err
	}
	if s.Runtime.Owner.verifyStageDirectory(original.stage) != nil || guard.current(ctx, true) != nil {
		return nil, c.ErrExecutionAuthority
	}
	info, err := s.Runtime.Owner.Staging.Lstat(plan.Backup)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, c.ErrExecutionRecord
	}
	parent, err := s.Runtime.Owner.Staging.OpenRoot(plan.Backup)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	actual, err := parent.Stat(".")
	if err != nil || !os.SameFile(info, actual) {
		return nil, c.ErrExecutionRecord
	}
	created := false
	if err = parent.Mkdir(plan.Directory, 0700); err == nil {
		created = true
	} else if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	entry, err := parent.Lstat(plan.Directory)
	if err != nil || !entry.IsDir() || entry.Mode()&os.ModeSymlink != 0 {
		return nil, c.ErrExecutionRecord
	}
	root, err := parent.OpenRoot(plan.Directory)
	if err != nil {
		return nil, err
	}
	good := false
	defer func() {
		if !good {
			root.Close()
		}
	}()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(entry, opened) {
		return nil, c.ErrExecutionRecord
	}
	const markerName = ".system-backup-publication-owner.json"
	if created {
		if err = writeStageExclusive(root, markerName, marker); err != nil {
			return nil, err
		}
		if err = staging.SyncDirectory(parent); err != nil {
			return nil, err
		}
	} else {
		// An unmarked pre-existing directory is never repaired or adopted.
		actual, err := readStageFile(root, markerName, int64(len(marker)))
		if err != nil || !bytes.Equal(actual, marker) {
			return nil, c.ErrExecutionRecord
		}
	}
	if err = guard.current(ctx, true); err != nil {
		return nil, err
	}
	if _, err = s.publicationStageForContainers(ctx, guard, capture); err != nil {
		return nil, err
	}
	good = true
	return &publicationContainerDirectory{root: root, plan: plan}, nil
}

func (s *DeploymentService) freezePublicationContainerPlan(ctx context.Context, guard *publicationContainerGuard, capture publicationVerifiedCapture, original publicationCertificateSQLFacts, plan publicationContainerPlan) error {
	if guard == nil || guard.current(ctx, true) != nil {
		return c.ErrExecutionAuthority
	}
	body, err := ce.Canonical(plan)
	if err != nil || len(body) > 8192 {
		return c.ErrExecutionRecord
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	bound, err := guard.access.Bind(ctx, tx)
	if err != nil {
		return err
	}
	current, err := s.readPublicationCertificateFactsTx(ctx, tx, bound.Facts(), capture, nil)
	if err != nil || !samePublicationContainerStage(current, original) {
		return c.ErrExecutionRecord
	}
	if _, err = readPublicationLimitsTx(ctx, tx, bound); err != nil {
		return err
	}
	id := publicationContainerPlanID(plan.Installation, plan.Backup, plan.Attempt)
	old, err := loadPublicationMetadata(ctx, tx, plan.Backup, id)
	if err == nil {
		if !bytes.Equal(old, body) {
			return c.ErrExecutionRecord
		}
		return bound.RecheckTx(ctx, tx)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err = publicationPreparationOpenTx(ctx, tx, plan.Installation, plan.Backup); err != nil {
		return err
	}
	var capacity, retention int64
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT control_metadata_capacity_bytes,evidence_retention_seconds,UTC_TIMESTAMP(6) FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=? FOR SHARE`, plan.Installation, plan.ConfigVersion, plan.ConfigSHA256).Scan(&capacity, &retention, &now) != nil || retention < 60 || retention > 10*365*86400 || !now.Add(time.Duration(retention)*time.Second).After(bound.Facts().TaskDeadline) {
		return c.ErrExecutionAuthority
	}
	if err = (security.RegistrationCapacity{ReportFile: s.Config.CapacityFile}).Reserve(ctx, tx, capacity, len(body)); err != nil {
		return err
	}
	if err = registerPublicationMetadata(ctx, tx, plan.Installation, plan.Backup, id, body, now.Add(time.Duration(retention)*time.Second)); err != nil {
		return err
	}
	if err = bound.RecheckTx(ctx, tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return c.ErrExecutionCommitUnknown
	}
	return nil
}
