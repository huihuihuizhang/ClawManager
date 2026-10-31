package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/google/uuid"
)

// These are the ORIGINAL 102 journal fields. There is no second publication
// task/ledger and no in-memory "sent" flag that can authorize a replay.
type publicationJournalAction struct {
	ID, Kind, ActionKey, LogicalSHA, Key, PayloadSHA, State string
	Payload                                                 []byte
	Size                                                    int64
	Generation, Version                                     uint64
	Deadline                                                time.Time
	ObjectVersion                                           sql.NullString
	ObjectSHA                                               sql.NullString
}

type publicationJSONIntent struct {
	Kind, Key string
	Payload   []byte
	Deadline  time.Time
}

func (p publicationJSONIntent) validate(target PublicationTargetMaterials) error {
	suffix := map[string]string{"manifest_put": "manifest.json", "marker_put": "_COMMITTED", "acceptance_put": "_ACCEPTANCE", "catalog_registration_append": ""}
	end, ok := suffix[p.Kind]
	if !ok || !safePublicationKey(p.Key) || !strings.HasPrefix(p.Key, target.Root) || end != "" && !strings.HasSuffix(p.Key, "/"+end) || len(p.Payload) == 0 || len(p.Payload) > 262144 || p.Deadline.IsZero() {
		return errPublicationUnavailable
	}
	canonical, err := jsoncanonicalizer.Transform(p.Payload)
	if err != nil || !bytes.Equal(canonical, p.Payload) {
		return errPublicationUnavailable
	}
	return nil
}

func publicationActionKey(backup string, attempt uint64, kind string) string {
	return "backup:" + backup + ":" + strconv.FormatUint(attempt, 10) + ":" + kind
}

func publicationLogicalHash(installation, backup string, attempt uint64, p publicationJSONIntent) string {
	raw, _ := json.Marshal(struct {
		Version, Installation, Backup string
		Attempt                       uint64
		Kind, Key, SHA                string
		Size                          int
		Generation                    uint64
		Deadline                      string
	}{"system-backup-native-publication-intent.v1", installation, backup, attempt, p.Kind, p.Key, hash(p.Payload), len(p.Payload), 1, p.Deadline.UTC().Format(time.RFC3339Nano)})
	return hash(raw)
}

func (d *DeploymentService) publicationAccess(ctx context.Context, claim c.ClaimToken, attempt uint64) (*security.SQLPublisherCaptureAuthority, error) {
	if d == nil || d.publisherVerifierFactory == nil || d.publisherVerifierDB == nil || claim.Target.Kind != c.TargetBackup || claim.Owner != d.PublisherOwner || d.checkPublisherVerifierBinding(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	return d.publisherVerifierFactory.CaptureAccess(ctx, security.PublisherCaptureScope{BackupPublicID: claim.Target.PublicID, Claim: security.SQLSigningClaim{ControllerOwner: claim.Owner, RowVersion: claim.RowVersion}, CaptureAttemptNo: attempt})
}

func scanPublicationAction(row interface{ Scan(...any) error }) (publicationJournalAction, error) {
	var a publicationJournalAction
	err := row.Scan(&a.ID, &a.Kind, &a.ActionKey, &a.LogicalSHA, &a.Key, &a.Payload, &a.PayloadSHA, &a.Size, &a.Generation, &a.Deadline, &a.State, &a.Version, &a.ObjectVersion, &a.ObjectSHA)
	if err != nil {
		return publicationJournalAction{}, err
	}
	if len(a.Payload) == 0 || len(a.Payload) > 262144 || int64(len(a.Payload)) != a.Size || hash(a.Payload) != a.PayloadSHA || a.Generation != 1 || a.Version == 0 || !formalCandidateDigest(a.LogicalSHA) {
		return publicationJournalAction{}, errPublicationUnavailable
	}
	return a, nil
}

const publicationActionColumns = "public_id,action_type,action_key,logical_action_hash,final_key,canonical_payload_bytes,payload_sha256,content_length,dispatch_generation,dispatch_deadline,state,row_version,observed_version,observed_checksum"

// beginPublicationAction closes cancellation and freezes the exact native
// request in the SAME task transaction. A commit error authorizes no send.
// Existing rows ALWAYS return send=false, including request_sent with count 0.
func (d *DeploymentService) beginPublicationAction(ctx context.Context, claim c.ClaimToken, attempt uint64, target PublicationTargetMaterials, intent publicationJSONIntent) (publicationJournalAction, bool, error) {
	var zero publicationJournalAction
	intent.Deadline = intent.Deadline.UTC().Truncate(time.Microsecond)
	if intent.validate(target) != nil || target.InstallationID != d.Config.InstallationID {
		return zero, false, errPublicationUnavailable
	}
	access, err := d.publicationAccess(ctx, claim, attempt)
	if err != nil {
		return zero, false, err
	}
	tx, err := d.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, false, errPublicationUnavailable
	}
	defer tx.Rollback()
	var status string
	var originalVersion uint64
	if tx.QueryRowContext(ctx, "SELECT status,row_version FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? FOR UPDATE", d.Config.InstallationID, claim.Target.PublicID).Scan(&status, &originalVersion) != nil || originalVersion != claim.RowVersion {
		return zero, false, c.ErrClaimLost
	}
	guard, err := access.Bind(ctx, tx)
	if err != nil {
		return zero, false, err
	}
	if err = d.checkPublicationTargetTx(ctx, tx, guard.Facts(), target); err != nil {
		return zero, false, err
	}
	actionKey := publicationActionKey(claim.Target.PublicID, attempt, intent.Kind)
	previous, err := scanPublicationAction(tx.QueryRowContext(ctx, "SELECT "+publicationActionColumns+" FROM system_backup_v2_external_actions WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND action_type=? AND action_key=? FOR UPDATE", d.Config.InstallationID, claim.Target.PublicID, intent.Kind, actionKey))
	if err == nil {
		// The persisted original deadline is never refreshed on recovery. Its
		// request must still match byte-for-byte; it alone controls observation.
		if previous.Key != intent.Key || !bytes.Equal(previous.Payload, intent.Payload) || guard.RecheckTx(ctx, tx) != nil {
			return zero, false, errPublicationConflict
		}
		if tx.Rollback() != nil {
			return zero, false, errPublicationUnavailable
		}
		return previous, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) || status == "finalization_unknown" || status != "validating" && status != "publishing" {
		return zero, false, errPublicationUnavailable
	}
	if intent.Deadline.After(access.ValidUntil()) || !time.Now().Before(intent.Deadline) {
		return zero, false, errPublicationUnavailable
	}
	var capacity int64
	if tx.QueryRowContext(ctx, "SELECT control_metadata_capacity_bytes FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR SHARE", d.Config.InstallationID, guard.Facts().ConfigVersion).Scan(&capacity) != nil || (security.RegistrationCapacity{ReportFile: d.Config.CapacityFile}).ReserveExecutionPayload(ctx, tx, capacity, len(intent.Payload)) != nil {
		return zero, false, errPublicationUnavailable
	}
	id := "sxa_" + uuid.NewString()
	logical := publicationLogicalHash(d.Config.InstallationID, claim.Target.PublicID, attempt, intent)
	if _, err = tx.ExecContext(ctx, `INSERT INTO system_backup_v2_external_actions(public_id,origin_installation_id,target_type,target_public_id,action_type,logical_action_hash,action_key,canonical_payload_bytes,payload_sha256,content_length,final_key,dispatch_generation,dispatch_deadline,state,send_attempt_count) VALUES(?,?,'backup',?,?,?,?,?,?,?,?,1,?,'request_sent',1)`, id, d.Config.InstallationID, claim.Target.PublicID, intent.Kind, logical, actionKey, intent.Payload, hash(intent.Payload), len(intent.Payload), intent.Key, intent.Deadline); err != nil {
		return zero, false, errPublicationUnavailable
	}
	if guard.RecheckTx(ctx, tx) != nil {
		return zero, false, c.ErrClaimLost
	}
	result, err := tx.ExecContext(ctx, `UPDATE system_backup_v2_backups SET status='publishing',can_cancel=FALSE,commit_started_at=COALESCE(commit_started_at,UTC_TIMESTAMP(6)),finalization_action_public_id=?,attention_reason='none' WHERE origin_installation_id=? AND public_id=? AND controller_owner=? AND row_version=? AND controller_lease_expires_at>UTC_TIMESTAMP(6) AND deadline_at>UTC_TIMESTAMP(6) AND status IN ('validating','publishing')`, id, d.Config.InstallationID, claim.Target.PublicID, claim.Owner, claim.RowVersion)
	if err != nil || publicationOneRow(result) != nil {
		return zero, false, c.ErrClaimLost
	}
	action := publicationJournalAction{ID: id, Kind: intent.Kind, ActionKey: actionKey, LogicalSHA: logical, Key: intent.Key, Payload: bytes.Clone(intent.Payload), PayloadSHA: hash(intent.Payload), Size: int64(len(intent.Payload)), Generation: 1, Version: 1, Deadline: intent.Deadline, State: "request_sent"}
	if tx.Commit() != nil || ctx.Err() != nil {
		return zero, false, c.ErrExecutionCommitUnknown
	}
	return action, true, nil
}

func publicationOneRow(result sql.Result) error {
	if result == nil {
		return c.ErrClaimLost
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return c.ErrClaimLost
	}
	return nil
}

// bind all transport coordinates to the ORIGINAL frozen task config. A file
// pin is only a mapping; it cannot substitute identity/ref versions from a
// newer config, another installation, or a public request.
func (d *DeploymentService) checkPublicationTargetTx(ctx context.Context, tx *sql.Tx, facts security.PublisherCaptureFacts, target PublicationTargetMaterials) error {
	if target.validate() != nil || target.InstallationID != facts.InstallationID {
		return c.ErrExecutionAuthority
	}
	var write, writeVersion, read, readVersion, ca, caVersion string
	if tx.QueryRowContext(ctx, `SELECT artifact_write_identity_hash,artifact_write_ref_version,artifact_read_identity_hash,artifact_read_ref_version,artifact_ca_identity_hash,artifact_ca_ref_version FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=? FOR SHARE`, facts.InstallationID, facts.ConfigVersion, facts.ConfigSHA256).Scan(&write, &writeVersion, &read, &readVersion, &ca, &caVersion) != nil || write != target.WriteIdentityHash || writeVersion != target.WriteRefVersion || read != target.ReadIdentityHash || readVersion != target.ReadRefVersion || ca != target.CAIdentityHash || caVersion != target.CARefVersion {
		return c.ErrExecutionAuthority
	}
	return nil
}

// Observe only the ORIGINAL key and version. A complete independently read
// body, including its EOF, is mandatory. PUT headers, ETags, a 404 or caller
// supplied bytes never constitute a publication receipt.
func readPublicationJSON(ctx context.Context, store *nativePublicationS3, action publicationJournalAction, deadline time.Time) (nativePublicationObject, []byte, error) {
	version := ""
	if action.ObjectVersion.Valid {
		version = action.ObjectVersion.String
	}
	object, err := store.stat(ctx, action.Key, version, deadline)
	if err != nil {
		return nativePublicationObject{}, nil, err
	}
	if object.Size > 262144 {
		return object, nil, errPublicationConflict
	}
	reader, err := store.open(ctx, object, deadline)
	if err != nil {
		return nativePublicationObject{}, nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(reader, object.Size+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || int64(len(raw)) != object.Size {
		return nativePublicationObject{}, nil, errPublicationUnavailable
	}
	object.SHA256 = hash(raw)
	if object.Size != action.Size || object.SHA256 != action.PayloadSHA || !bytes.Equal(raw, action.Payload) {
		return object, nil, errPublicationConflict
	}
	return object, raw, nil
}

// recordPublicationObservation performs no provider I/O. It rereads the exact
// original action under the CURRENT acquired claim after network completion.
// Unknown does not become absence, failure, cancellation or a new write.
func (d *DeploymentService) recordPublicationObservation(ctx context.Context, claim c.ClaimToken, attempt uint64, action publicationJournalAction, object nativePublicationObject, observationErr error) error {
	access, err := d.publicationAccess(ctx, claim, attempt)
	if err != nil {
		return err
	}
	tx, err := d.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return errPublicationUnavailable
	}
	defer tx.Rollback()
	var status string
	if tx.QueryRowContext(ctx, "SELECT status FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? FOR UPDATE", d.Config.InstallationID, claim.Target.PublicID).Scan(&status) != nil {
		return c.ErrClaimLost
	}
	guard, err := access.Bind(ctx, tx)
	if err != nil {
		return err
	}
	current, err := scanPublicationAction(tx.QueryRowContext(ctx, "SELECT "+publicationActionColumns+" FROM system_backup_v2_external_actions WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND public_id=? FOR UPDATE", d.Config.InstallationID, claim.Target.PublicID, action.ID))
	if err != nil || current.Version != action.Version || current.LogicalSHA != action.LogicalSHA || current.Key != action.Key || !bytes.Equal(current.Payload, action.Payload) {
		return errPublicationUnavailable
	}
	state := "provider_unreachable"
	var version, checksum any
	if observationErr == nil {
		state = "confirmed_present"
		version = object.Version
		checksum = object.SHA256
	} else if errors.Is(observationErr, errPublicationConflict) && object.Version != "" && formalCandidateDigest(object.SHA256) && object.SHA256 != action.PayloadSHA {
		state = "conflict"
		version = object.Version
		checksum = object.SHA256
	}
	if current.State == "confirmed_present" || current.State == "conflict" {
		return errPublicationUnavailable
	}
	if guard.RecheckTx(ctx, tx) != nil {
		return c.ErrClaimLost
	}
	result, err := tx.ExecContext(ctx, `UPDATE system_backup_v2_external_actions SET state=?,observe_attempt_count=observe_attempt_count+1,last_checked_at=UTC_TIMESTAMP(6),observed_version=?,observed_checksum=?,row_version=row_version+1 WHERE public_id=? AND origin_installation_id=? AND row_version=? AND state IN ('request_sent','provider_unreachable')`, state, version, checksum, action.ID, d.Config.InstallationID, action.Version)
	if err != nil || publicationOneRow(result) != nil {
		return errPublicationUnavailable
	}
	taskStatus, attention := "finalization_unknown", "external_result_unknown"
	if state == "confirmed_present" {
		taskStatus, attention = "publishing", "none"
	}
	if state == "conflict" {
		category := "artifact_conflict"
		if action.Kind == "catalog_registration_append" {
			category = "catalog_conflict"
		}
		result, err = tx.ExecContext(ctx, `UPDATE system_backup_v2_backups SET status='failed',attention_reason='none',can_cancel=FALSE,failure_category=?,failure_message='Immutable publication object conflicts with the original request.',finished_at=UTC_TIMESTAMP(6),retryable=FALSE,acceptance_eligible=FALSE,eligibility_reason_codes='task_not_succeeded',artifact_usable=FALSE,artifact_unusable_reason=IF(artifact_state='committed','verification_inconclusive',artifact_unusable_reason),controller_owner=NULL,controller_lease_expires_at=NULL,next_reconcile_at=NULL,row_version=row_version+1 WHERE origin_installation_id=? AND public_id=? AND controller_owner=? AND row_version=? AND controller_lease_expires_at>UTC_TIMESTAMP(6) AND deadline_at>UTC_TIMESTAMP(6) AND status IN ('publishing','finalization_unknown')`, category, d.Config.InstallationID, claim.Target.PublicID, claim.Owner, claim.RowVersion)
		if err != nil || publicationOneRow(result) != nil {
			return c.ErrClaimLost
		}
		if tx.Commit() != nil {
			return c.ErrExecutionCommitUnknown
		}
		return errPublicationConflict
	}
	result, err = tx.ExecContext(ctx, `UPDATE system_backup_v2_backups SET status=?,attention_reason=?,can_cancel=FALSE WHERE origin_installation_id=? AND public_id=? AND controller_owner=? AND row_version=? AND controller_lease_expires_at>UTC_TIMESTAMP(6) AND deadline_at>UTC_TIMESTAMP(6) AND status IN ('publishing','finalization_unknown')`, taskStatus, attention, d.Config.InstallationID, claim.Target.PublicID, claim.Owner, claim.RowVersion)
	if err != nil || result == nil {
		return c.ErrClaimLost
	}
	changed, countErr := result.RowsAffected()
	// The real MySQL driver reports changed rows. A publishing->publishing
	// receipt is a legitimate no-op; prove its STILL-live locked guard instead
	// of enabling clientFoundRows or mistaking zero for a lost claim.
	if countErr != nil || changed > 1 || changed == 0 && guard.RecheckTx(ctx, tx) != nil {
		return c.ErrClaimLost
	}
	if tx.Commit() != nil {
		return c.ErrExecutionCommitUnknown
	}
	return observationErr
}

func (d *DeploymentService) publishOriginalJSON(ctx context.Context, claim c.ClaimToken, attempt uint64, store *nativePublicationS3, intent publicationJSONIntent) (nativePublicationObject, error) {
	action, send, err := d.beginPublicationAction(ctx, claim, attempt, store.config, intent)
	if err != nil {
		return nativePublicationObject{}, err
	}
	if send {
		// Exact original current authority is checked AFTER the journal commit.
		// A denied check leaves request_sent for query-only reconciliation.
		access, e := d.publicationAccess(ctx, claim, attempt)
		if e != nil || access.Check(ctx) != nil {
			return nativePublicationObject{}, c.ErrExecutionAuthority
		}
		_, _ = store.createJSON(ctx, action.Key, bytes.NewReader(action.Payload), action.Size, action.PayloadSHA, action.Deadline)
	}
	access, err := d.publicationAccess(ctx, claim, attempt)
	if err != nil {
		return nativePublicationObject{}, err
	}
	object, _, observationErr := readPublicationJSON(ctx, store, action, access.ValidUntil())
	// Final network I/O may have renewed the real claim or revoked original
	// material. This SAME access object must still be valid before any receipt.
	if access.Check(ctx) != nil || d.checkPublisherVerifierBinding(ctx) != nil || d.publicationBinding() != nil {
		return nativePublicationObject{}, c.ErrExecutionAuthority
	}
	currentStore, checkErr := d.publicationStore(ctx)
	if checkErr != nil {
		return nativePublicationObject{}, c.ErrExecutionAuthority
	}
	currentStore.Close()
	if action.State == "confirmed_present" {
		if observationErr != nil || object.Version != action.ObjectVersion.String || object.SHA256 != action.ObjectSHA.String {
			return nativePublicationObject{}, errPublicationUnavailable
		}
		return d.publicationReceipt(ctx, claim, attempt, store.config, action, object)
	}
	if err = d.recordPublicationObservation(ctx, claim, attempt, action, object, observationErr); err != nil {
		return nativePublicationObject{}, err
	}
	return d.publicationReceipt(ctx, claim, attempt, store.config, action, object)
}
