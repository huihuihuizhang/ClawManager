package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"

	"clawreef/internal/systembackup/kube"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

func isPublicationContainerObject(path string) bool {
	for _, part := range publicationRequestedParts {
		if path == "parts/"+part+"/container.enc" {
			return true
		}
	}
	return false
}

// Read only already committed original plan/file facts. This does not create
// files, renew a grant, claim that a manifest is complete or dispatch a Job.
func (s *DeploymentService) loadPublicationContainerJobInputs(ctx context.Context, claim c.ClaimToken, attempt uint64, objects map[string]PublicationUploadInput) ([]kube.PublishInputFile, error) {
	if s == nil || s.Runtime == nil || s.Runtime.Owner == nil || s.Runtime.Owner.Staging == nil {
		return nil, c.ErrExecutionAuthority
	}
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, err
	}
	bound, err := access.Bind(ctx, tx)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	facts := bound.Facts()
	if facts.Status != "validating" && facts.Status != "publishing" {
		tx.Rollback()
		return nil, c.ErrExecutionAuthority
	}
	plan, files, original, err := readPublicationContainerJobInputsTx(ctx, tx, bound, s)
	if rollbackErr := tx.Rollback(); err == nil {
		err = rollbackErr
	}
	if err != nil {
		return nil, err
	}
	if s.Runtime.Owner.verifyStageDirectory(original) != nil || access.Check(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	if err = verifyPublicationContainerDirectoryForJob(s, plan, original); err != nil {
		return nil, err
	}
	// The same immutable SQL descriptor/104 row is checked after native marker
	// and key reads. Only exact per-file metadata reaches the Job constructor.
	final, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, err
	}
	defer final.Rollback()
	current, err := access.Bind(ctx, final)
	if err != nil {
		return nil, err
	}
	again, againFiles, againStage, err := readPublicationContainerJobInputsTx(ctx, final, current, s)
	firstRaw, _ := ce.Canonical(files)
	againRaw, _ := ce.Canonical(againFiles)
	if err != nil || again != plan || againStage != original || !bytes.Equal(firstRaw, againRaw) || current.RecheckTx(ctx, final) != nil {
		return nil, c.ErrExecutionRecord
	}
	inputs := make([]kube.PublishInputFile, 0, len(files.Files))
	for _, file := range files.Files {
		object, ok := objects[file.Path]
		if !ok || object.SHA256 != file.Receipt.SHA256 || object.Bytes != file.Receipt.Size {
			return nil, c.ErrExecutionRecord
		}
		inputs = append(inputs, kube.PublishInputFile{Path: file.Path, SubPath: file.SubPath})
		delete(objects, file.Path)
	}
	return inputs, nil
}

func verifyPublicationContainerDirectoryForJob(s *DeploymentService, plan publicationContainerPlan, stage originalStageResource) error {
	if s == nil || s.Runtime == nil || s.Runtime.Owner == nil || stage.owner.Resource != plan.ParentResource || stage.owner.KeyVersion != plan.ParentKeyVersion || stage.mac != plan.ParentOwnerMAC || stage.version != plan.ParentRowVersion {
		return c.ErrExecutionAuthority
	}
	parentRoot := s.Runtime.Owner.Staging
	keys, err := stageKeyRoot(parentRoot, false)
	if err != nil {
		return err
	}
	key, err := readStageFile(keys, plan.ParentKeyVersion+".key", 32)
	keys.Close()
	if err != nil {
		return err
	}
	defer clear(key)
	marker, err := containerDirectoryMarker(plan, key)
	if err != nil {
		return err
	}
	before, err := parentRoot.Lstat(plan.Backup)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return c.ErrExecutionRecord
	}
	parent, err := parentRoot.OpenRoot(plan.Backup)
	if err != nil {
		return err
	}
	defer parent.Close()
	actual, err := parent.Stat(".")
	if err != nil || !os.SameFile(before, actual) {
		return c.ErrExecutionRecord
	}
	before, err = parent.Lstat(plan.Directory)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return c.ErrExecutionRecord
	}
	root, err := parent.OpenRoot(plan.Directory)
	if err != nil {
		return err
	}
	defer root.Close()
	actual, err = root.Stat(".")
	if err != nil || !os.SameFile(before, actual) {
		return c.ErrExecutionRecord
	}
	raw, err := readStageFile(root, ".system-backup-publication-owner.json", int64(len(marker)))
	if err != nil || !bytes.Equal(raw, marker) {
		return c.ErrExecutionRecord
	}
	return nil
}

func readPublicationContainerJobInputsTx(ctx context.Context, tx *sql.Tx, guard *security.SQLPublisherCaptureGuard, s *DeploymentService) (publicationContainerPlan, publicationContainerFileSet, originalStageResource, error) {
	var plan publicationContainerPlan
	var files publicationContainerFileSet
	var stage originalStageResource
	bad := func() (publicationContainerPlan, publicationContainerFileSet, originalStageResource, error) {
		return publicationContainerPlan{}, publicationContainerFileSet{}, originalStageResource{}, c.ErrExecutionRecord
	}
	facts := guard.Facts()
	id := publicationContainerPlanID(facts.InstallationID, facts.BackupPublicID, facts.CaptureAttemptNo)
	raw, err := loadPublicationMetadata(ctx, tx, facts.BackupPublicID, id)
	if err != nil || decodeProviderDeploymentJSON(raw, &plan) != nil {
		return bad()
	}
	canonical, err := ce.Canonical(plan)
	if err != nil || !bytes.Equal(raw, canonical) || plan.Version != "system-backup-original-publication-container-plan.v1" || plan.Installation != facts.InstallationID || plan.Backup != facts.BackupPublicID || plan.Attempt != facts.CaptureAttemptNo || plan.ConfigVersion != facts.ConfigVersion || plan.ConfigSHA256 != facts.ConfigSHA256 || plan.CaptureResultSHA256 != facts.CaptureResultSHA256 || !formalCandidateDigest(plan.CaptureSHA256) || !formalCandidateDigest(plan.CertificateSHA256) || !formalCandidateDigest(plan.CaptureContextSHA256) || plan.ParentResource == "" || plan.ParentKeyVersion == "" || plan.ParentRowVersion < 1 || !formalCandidateDigest(plan.ParentOwnerMAC) {
		return bad()
	}
	definition := plan
	definition.Directory = ""
	definitionRaw, err := ce.Canonical(definition)
	if err != nil || plan.Directory != "publication-"+hash(definitionRaw) {
		return bad()
	}
	raw, err = loadPublicationMetadata(ctx, tx, facts.BackupPublicID, id+"_files")
	if err != nil || decodeProviderDeploymentJSON(raw, &files) != nil {
		return bad()
	}
	canonical, err = ce.Canonical(files)
	if err != nil || !bytes.Equal(raw, canonical) || validatePublicationContainerFileSet(plan, files) != nil {
		return bad()
	}
	limits, err := readPublicationLimitsTx(ctx, tx, guard)
	if err != nil {
		return publicationContainerPlan{}, publicationContainerFileSet{}, originalStageResource{}, err
	}
	var total int64
	for _, file := range files.Files {
		if file.Receipt.Size > limits.MaxArtifactBytes-total {
			return bad()
		}
		total += file.Receipt.Size
	}
	location := filepath.Join(s.Runtime.Owner.Staging.Name(), plan.Backup)
	owner := originalStageOwner{Schema: "system-backup-original-stage-owner.v1", Installation: plan.Installation, Task: plan.Backup, Phase: "capture", Attempt: plan.Attempt, ConfigVersion: plan.ConfigVersion, ConfigSHA256: plan.ConfigSHA256, Location: location}
	base, _ := json.Marshal(owner)
	owner.PhaseUID = "capture-" + hash(base)
	owner.Resource = plan.ParentResource
	owner.KeyVersion = plan.ParentKeyVersion
	stage = originalStageResource{owner: owner, mac: plan.ParentOwnerMAC, lifecycle: "ready", version: plan.ParentRowVersion}
	var phase, uid, kind, locator, locationSHA, mac, keyVersion, lifecycle, observedName, observedUID string
	var rowVersion uint64
	if tx.QueryRowContext(ctx, `SELECT phase,phase_uid,resource_type,planned_locator,location_sha256,owner_marker_hmac,owner_marker_key_version,lifecycle,row_version,observed_name,observed_uid FROM system_backup_v2_staging_resources WHERE public_id=? AND origin_installation_id=? AND backup_public_id=? AND attempt_no=? FOR SHARE`, plan.ParentResource, plan.Installation, plan.Backup, plan.Attempt).Scan(&phase, &uid, &kind, &locator, &locationSHA, &mac, &keyVersion, &lifecycle, &rowVersion, &observedName, &observedUID) != nil || phase != "capture" || uid != owner.PhaseUID || kind != "hostpath" || locator != location || locationSHA != hash([]byte(location)) || mac != stage.mac || keyVersion != owner.KeyVersion || lifecycle != "ready" || rowVersion != stage.version || observedName != plan.Backup || observedUID != plan.ParentResource {
		return bad()
	}
	if guard.RecheckTx(ctx, tx) != nil {
		return bad()
	}
	return plan, files, stage, nil
}

func validatePublicationContainerFileSet(plan publicationContainerPlan, files publicationContainerFileSet) error {
	raw, err := ce.Canonical(plan)
	if err != nil || files.Version != "system-backup-original-publication-container-files.v1" || files.PlanSHA256 != hash(raw) || len(files.Files) != len(publicationRequestedParts) {
		return c.ErrExecutionRecord
	}
	for index, file := range files.Files {
		part := publicationRequestedParts[index]
		name := "container-" + part + ".enc"
		if file.Part != part || file.Path != "parts/"+part+"/container.enc" || file.SubPath != plan.Backup+"/"+plan.Directory+"/"+name || file.Receipt.Name != name || file.Receipt.Size < 1 || !formalCandidateDigest(file.Receipt.SHA256) {
			return c.ErrExecutionRecord
		}
	}
	return nil
}
