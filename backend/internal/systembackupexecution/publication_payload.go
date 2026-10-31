package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

// Immutable original evidence metadata for a binary object, not a second task
// or mutable publication ledger. Original 102 remains unchanged and handles
// only its four JSON commit actions. An acknowledged intent insert permits
// exactly one conditional PUT. Every later encounter is observation-only.
type publicationPayloadIntent struct {
	Version                                   string `json:"schema_version"`
	Installation, Backup                      string
	Attempt                                   uint64
	Part, InvocationSHA256, Path, Key, SHA256 string
	Size                                      int64
	Deadline                                  time.Time
}

type publicationPayloadObservation struct {
	Version                                   string `json:"schema_version"`
	IntentSHA256, ObjectVersion, ObjectSHA256 string
	Size                                      int64
}

// Only the independent full-body reader constructs this inert observation.
// It is not task authority; the current original guard is still mandatory.
type publicationPayloadReadReceipt struct {
	target                             PublicationTargetMaterials
	intentSHA256, key, version, sha256 string
	size                               int64
}

func (object nativePublicationObject) checkedPayloadRead(target PublicationTargetMaterials, intent publicationPayloadIntent) bool {
	raw, err := ce.Canonical(intent)
	r := object.payloadRead
	return err == nil && r != nil && r.target == target && r.intentSHA256 == hash(raw) && r.key == object.Key && r.version == object.Version && r.sha256 == object.SHA256 && r.size == object.Size && object.Key == intent.Key && object.Size == intent.Size && object.SHA256 == intent.SHA256 && object.Version != "" && object.Version != "null"
}

func publicationPartPaths(part string, index uint32, invocation string) (string, string) {
	if part == ce.Part {
		return ce.CipherPath, ce.EnvelopePath
	}
	if part == ce.ProofPart {
		return ce.ProofCipherPath, "control/evidence-proofs.envelope.json"
	}
	root := "parts/" + strconv.FormatUint(uint64(index), 10) + "/" + invocation
	return root + ".enc", root + ".envelope.json"
}

func (s *DeploymentService) publicationPayloadVersion(ctx context.Context, claim c.ClaimToken, attempt uint64, intent publicationPayloadIntent) (string, error) {
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil {
		return "", err
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	guard, err := access.Bind(ctx, tx)
	if err != nil {
		return "", err
	}
	raw, err := loadPublicationMetadata(ctx, tx, intent.Backup, intent.id()+"_observed")
	if errors.Is(err, sql.ErrNoRows) {
		return "", guard.RecheckTx(ctx, tx)
	}
	if err != nil {
		return "", err
	}
	var observed publicationPayloadObservation
	intentRaw, _ := ce.Canonical(intent)
	if decodeProviderDeploymentJSON(raw, &observed) != nil || observed.Version != "system-backup-original-binary-observation.v1" || observed.IntentSHA256 != hash(intentRaw) || observed.Size != intent.Size || observed.ObjectSHA256 != intent.SHA256 || observed.ObjectVersion == "" || observed.ObjectVersion == "null" || len(observed.ObjectVersion) > 256 || guard.RecheckTx(ctx, tx) != nil {
		return "", c.ErrExecutionRecord
	}
	return observed.ObjectVersion, nil
}

func (p publicationPayloadIntent) id() string {
	raw, _ := ce.Canonical([]any{"original-publication-binary-intent.v1", p.Installation, p.Backup, p.Attempt, p.Path})
	return "sev_pub_upload_" + hash(raw)
}

func loadPublicationMetadata(ctx context.Context, tx *sql.Tx, backup, id string) ([]byte, error) {
	var body []byte
	var checksum string
	var size int64
	if err := tx.QueryRowContext(ctx, `SELECT inline_payload,content_checksum,content_size_bytes FROM system_backup_v2_evidence WHERE public_id=? AND owner_target_type='backup' AND owner_target_public_id=? AND evidence_type='diagnostic' AND storage_state='inline' AND observed_health='healthy' AND evidence_failure_code='none' AND encryption='none' AND media_type='application/json' AND redaction_classification='internal' AND expires_at>UTC_TIMESTAMP(6) FOR SHARE`, id, backup).Scan(&body, &checksum, &size); err != nil {
		return nil, err
	}
	if len(body) == 0 || len(body) > 8192 || int64(len(body)) != size || hash(body) != checksum {
		return nil, c.ErrExecutionRecord
	}
	return body, nil
}

func registerPublicationMetadata(ctx context.Context, tx *sql.Tx, installation, backup, id string, body []byte, until time.Time) error {
	if len(body) == 0 || len(body) > 8192 {
		return c.ErrExecutionRecord
	}
	old, err := loadPublicationMetadata(ctx, tx, backup, id)
	if err == nil {
		if !bytes.Equal(old, body) {
			return errPublicationConflict
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var hasOrigin int
	if tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='system_backup_v2_evidence' AND COLUMN_NAME='origin_installation_id'").Scan(&hasOrigin) != nil {
		return c.ErrExecutionRecord
	}
	columns, values := "", ""
	args := []any{}
	if hasOrigin == 1 {
		columns = "origin_installation_id,"
		values = "?,"
		args = append(args, installation)
	}
	args = append(args, id, backup, body, hash(body), len(body), until.UTC().Truncate(time.Microsecond))
	_, err = tx.ExecContext(ctx, "INSERT INTO system_backup_v2_evidence("+columns+"public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at) VALUES("+values+"?,'backup',?,'diagnostic','inline',?,?,?,'application/json','none','internal','healthy',?)", args...)
	if err != nil {
		return err
	}
	read, err := loadPublicationMetadata(ctx, tx, backup, id)
	if err != nil || !bytes.Equal(read, body) {
		return c.ErrExecutionRecord
	}
	return nil
}

func (s *DeploymentService) beginPublicationPayload(ctx context.Context, claim c.ClaimToken, attempt uint64, target PublicationTargetMaterials, proposed publicationPayloadIntent) (publicationPayloadIntent, bool, error) {
	var zero publicationPayloadIntent
	if proposed.Version != "system-backup-original-binary-upload.v1" || proposed.Installation != s.Config.InstallationID || proposed.Backup != claim.Target.PublicID || proposed.Attempt != attempt || proposed.Size < 1 || proposed.Size > 8<<30 || !formalCandidateDigest(proposed.SHA256) || !formalCandidateDigest(proposed.InvocationSHA256) || !safePublicationKey(proposed.Path) || proposed.Key != target.Root+proposed.Backup+"/"+strconv.FormatUint(attempt, 10)+"/"+proposed.Path {
		return zero, false, c.ErrExecutionRecord
	}
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil {
		return zero, false, c.ErrExecutionAuthority
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, false, err
	}
	defer tx.Rollback()
	// Serialize first dispatch on the original root row, not an evidence gap
	// lock or an in-process flag. No network occurs inside this transaction.
	var status string
	var version uint64
	if tx.QueryRowContext(ctx, `SELECT status,row_version FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? FOR UPDATE`, proposed.Installation, proposed.Backup).Scan(&status, &version) != nil || version != claim.RowVersion {
		return zero, false, c.ErrClaimLost
	}
	guard, err := access.Bind(ctx, tx)
	if err != nil || s.checkPublicationTargetTx(ctx, tx, guard.Facts(), target) != nil {
		return zero, false, c.ErrExecutionAuthority
	}
	old, err := loadPublicationMetadata(ctx, tx, proposed.Backup, proposed.id())
	if err == nil {
		var original publicationPayloadIntent
		if decodeProviderDeploymentJSON(old, &original) != nil {
			return zero, false, c.ErrExecutionRecord
		}
		comparison := proposed
		comparison.Deadline = original.Deadline
		raw, _ := ce.Canonical(comparison)
		if !bytes.Equal(raw, old) || original.Deadline.IsZero() || original.Deadline.After(guard.Facts().TaskDeadline) || guard.RecheckTx(ctx, tx) != nil {
			return zero, false, errPublicationConflict
		}
		return original, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return zero, false, err
	}
	// Later publication/unknown phases may observe an existing original binary
	// intent, but can never introduce another binary send identity.
	if status != "validating" {
		return zero, false, c.ErrExecutionAuthority
	}
	proposed.Deadline = access.ValidUntil().UTC().Truncate(time.Microsecond)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(proposed.Deadline) {
		proposed.Deadline = deadline.UTC().Truncate(time.Microsecond)
	}
	var capacity, retention int64
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT control_metadata_capacity_bytes,evidence_retention_seconds,UTC_TIMESTAMP(6) FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR SHARE`, proposed.Installation, guard.Facts().ConfigVersion).Scan(&capacity, &retention, &now) != nil || retention < 60 || retention > 10*365*86400 {
		return zero, false, c.ErrExecutionAuthority
	}
	if !now.Add(time.Duration(retention) * time.Second).After(guard.Facts().TaskDeadline) {
		return zero, false, c.ErrExecutionAuthority
	}
	body, err := ce.Canonical(proposed)
	if err != nil || (security.RegistrationCapacity{ReportFile: s.Config.CapacityFile}).ReserveExecutionPayload(ctx, tx, capacity, len(body)) != nil {
		return zero, false, c.ErrExecutionAuthority
	}
	if err = registerPublicationMetadata(ctx, tx, proposed.Installation, proposed.Backup, proposed.id(), body, now.Add(time.Duration(retention)*time.Second)); err != nil {
		return zero, false, err
	}
	if guard.RecheckTx(ctx, tx) != nil {
		return zero, false, c.ErrClaimLost
	}
	if tx.Commit() != nil || ctx.Err() != nil {
		return zero, false, c.ErrExecutionCommitUnknown
	}
	return proposed, true, nil
}

// Complete EOF read with the independent read principal; HEAD/PUT headers do
// not authorize a receipt. A nonempty immutable version pins this exact body.
func readPublicationPayload(ctx context.Context, store *nativePublicationS3, intent publicationPayloadIntent, version string, until time.Time) (nativePublicationObject, error) {
	return readPublicationPayloadTo(ctx, store, intent, version, until, io.Discard)
}

func readPublicationPayloadTo(ctx context.Context, store *nativePublicationS3, intent publicationPayloadIntent, version string, until time.Time, destination io.Writer) (nativePublicationObject, error) {
	object, err := store.stat(ctx, intent.Key, version, until)
	if err != nil {
		return nativePublicationObject{}, err
	}
	if object.Size != intent.Size {
		return nativePublicationObject{}, errPublicationConflict
	}
	reader, err := store.open(ctx, object, until)
	if err != nil {
		return nativePublicationObject{}, err
	}
	digest := sha256.New()
	n, readErr := io.Copy(io.MultiWriter(digest, destination), io.LimitReader(reader, intent.Size+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || n != intent.Size {
		return nativePublicationObject{}, errPublicationUnavailable
	}
	object.SHA256 = hex.EncodeToString(digest.Sum(nil))
	if object.SHA256 != intent.SHA256 {
		return nativePublicationObject{}, errPublicationConflict
	}
	raw, err := ce.Canonical(intent)
	if err != nil {
		return nativePublicationObject{}, c.ErrExecutionRecord
	}
	object.payloadRead = &publicationPayloadReadReceipt{target: store.config, intentSHA256: hash(raw), key: object.Key, version: object.Version, sha256: object.SHA256, size: object.Size}
	return object, nil
}

// Transfer only the already independently verified ORIGINAL C descriptors.
// This does not issue Generate/rewrap, publish a marker or claim acceptance.
func (s *DeploymentService) publishOriginalPayload(ctx context.Context, claim c.ClaimToken, attempt uint64, store *nativePublicationS3, part *publicationCaptureFiles, path string, envelope bool) (nativePublicationObject, error) {
	if part == nil || part.check(ctx) != nil || store == nil || store.config.InstallationID != s.Config.InstallationID || !part.domainVerified && len(part.controlPlain) == 0 {
		return nativePublicationObject{}, c.ErrExecutionAuthority
	}
	source := part.files.Ciphertext
	size, checksum := part.candidate.Ciphertext.Size, part.candidate.Ciphertext.SHA256
	if envelope {
		source = part.files.Envelope
		size = part.candidate.Envelope.Size
		checksum = part.candidate.Envelope.SHA256
	}
	invSHA, _ := part.record.Invocation.Hash()
	cipherPath, envelopePath := publicationPartPaths(part.record.Invocation.Request.Binding.Path, part.record.Invocation.Request.Binding.PartIndex, invSHA)
	expected := cipherPath
	if envelope {
		expected = envelopePath
	}
	if path != expected || part.record.Input.TaskPublicID != claim.Target.PublicID || part.record.Input.CaptureAttemptNo != attempt {
		return nativePublicationObject{}, c.ErrExecutionRecord
	}
	intent, send, err := s.beginPublicationPayload(ctx, claim, attempt, store.config, publicationPayloadIntent{Version: "system-backup-original-binary-upload.v1", Installation: s.Config.InstallationID, Backup: claim.Target.PublicID, Attempt: attempt, Part: part.record.Invocation.Request.Binding.Path, InvocationSHA256: invSHA, Path: path, Key: store.config.Root + claim.Target.PublicID + "/" + strconv.FormatUint(attempt, 10) + "/" + path, SHA256: checksum, Size: size})
	if err != nil {
		return nativePublicationObject{}, err
	}
	version, err := s.publicationPayloadVersion(ctx, claim, attempt, intent)
	if err != nil {
		return nativePublicationObject{}, err
	}
	if send {
		if part.check(ctx) != nil || !time.Now().Before(intent.Deadline) {
			return nativePublicationObject{}, c.ErrExecutionAuthority
		}
		if _, err = source.Seek(0, io.SeekStart); err != nil {
			return nativePublicationObject{}, err
		}
		localSHA := sha256.New()
		localBytes, localErr := io.Copy(localSHA, io.LimitReader(source, size+1))
		if localErr != nil || localBytes != size || hex.EncodeToString(localSHA.Sum(nil)) != checksum || part.check(ctx) != nil {
			return nativePublicationObject{}, c.ErrExecutionRecord
		}
		if _, err = source.Seek(0, io.SeekStart); err != nil {
			return nativePublicationObject{}, err
		}
		put, putErr := store.create(ctx, intent.Key, source, size, checksum, intent.Deadline)
		if putErr == nil {
			version = put.Version
		}
		// Even an unknown PUT can be resolved only by complete independent
		// observation. No error/absence here authorizes a second conditional PUT.
	}
	if part.check(ctx) != nil {
		return nativePublicationObject{}, c.ErrExecutionAuthority
	}
	object, err := readPublicationPayload(ctx, store, intent, version, part.until)
	if err != nil {
		return nativePublicationObject{}, err
	}
	if part.check(ctx) != nil {
		return nativePublicationObject{}, c.ErrExecutionAuthority
	}
	return s.recordPublicationPayloadObservation(ctx, claim, attempt, store, intent, object)
}

func (s *DeploymentService) recordPublicationPayloadObservation(ctx context.Context, claim c.ClaimToken, attempt uint64, store *nativePublicationS3, intent publicationPayloadIntent, object nativePublicationObject) (nativePublicationObject, error) {
	if store == nil || !object.checkedPayloadRead(store.config, intent) {
		return nativePublicationObject{}, c.ErrExecutionRecord
	}
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil {
		return nativePublicationObject{}, c.ErrExecutionAuthority
	}
	currentStore, err := s.publicationStore(ctx)
	if err != nil {
		return nativePublicationObject{}, err
	}
	currentStore.Close()
	if currentStore.config != store.config {
		return nativePublicationObject{}, c.ErrExecutionAuthority
	}
	if _, err = currentStore.credential(false); err != nil {
		return nativePublicationObject{}, c.ErrExecutionAuthority
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nativePublicationObject{}, err
	}
	defer tx.Rollback()
	var currentVersion uint64
	if tx.QueryRowContext(ctx, `SELECT row_version FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? FOR UPDATE`, s.Config.InstallationID, claim.Target.PublicID).Scan(&currentVersion) != nil || currentVersion != claim.RowVersion {
		return nativePublicationObject{}, c.ErrClaimLost
	}
	guard, err := access.Bind(ctx, tx)
	if err != nil || s.checkPublicationTargetTx(ctx, tx, guard.Facts(), store.config) != nil {
		return nativePublicationObject{}, c.ErrExecutionAuthority
	}
	stored, err := loadPublicationMetadata(ctx, tx, intent.Backup, intent.id())
	expectedBody, _ := ce.Canonical(intent)
	if err != nil || !bytes.Equal(stored, expectedBody) || guard.RecheckTx(ctx, tx) != nil {
		return nativePublicationObject{}, c.ErrExecutionRecord
	}
	observation := publicationPayloadObservation{Version: "system-backup-original-binary-observation.v1", IntentSHA256: hash(expectedBody), ObjectVersion: object.Version, ObjectSHA256: object.SHA256, Size: object.Size}
	body, err := ce.Canonical(observation)
	if err != nil {
		return nativePublicationObject{}, err
	}
	old, oldErr := loadPublicationMetadata(ctx, tx, intent.Backup, intent.id()+"_observed")
	if oldErr == nil {
		if !bytes.Equal(old, body) {
			return nativePublicationObject{}, errPublicationConflict
		}
	} else {
		if !errors.Is(oldErr, sql.ErrNoRows) {
			return nativePublicationObject{}, oldErr
		}
		var capacity, retention int64
		var now time.Time
		if tx.QueryRowContext(ctx, `SELECT control_metadata_capacity_bytes,evidence_retention_seconds,UTC_TIMESTAMP(6) FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR SHARE`, s.Config.InstallationID, guard.Facts().ConfigVersion).Scan(&capacity, &retention, &now) != nil || retention < 60 || retention > 10*365*86400 || (security.RegistrationCapacity{ReportFile: s.Config.CapacityFile}).ReserveExecutionPayload(ctx, tx, capacity, len(body)) != nil {
			return nativePublicationObject{}, c.ErrExecutionAuthority
		}
		if !now.Add(time.Duration(retention) * time.Second).After(guard.Facts().TaskDeadline) {
			return nativePublicationObject{}, c.ErrExecutionAuthority
		}
		if err = registerPublicationMetadata(ctx, tx, s.Config.InstallationID, intent.Backup, intent.id()+"_observed", body, now.Add(time.Duration(retention)*time.Second)); err != nil {
			return nativePublicationObject{}, err
		}
	}
	if guard.RecheckTx(ctx, tx) != nil {
		return nativePublicationObject{}, c.ErrClaimLost
	}
	if tx.Commit() != nil || ctx.Err() != nil {
		return nativePublicationObject{}, c.ErrExecutionCommitUnknown
	}
	return object, nil
}
