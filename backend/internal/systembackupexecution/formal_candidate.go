package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"strconv"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	security "clawreef/internal/systembackupsecurity"
)

// FormalCandidateRecord is an authenticated original worker report, not a seal
// observation or publication proof. An independent observer must authenticate
// the exact C stream/envelope bytes before it can produce a ModuleResult.
type FormalCandidateRecord struct {
	Version                                             string       `json:"schema_version"`
	Authority                                           d.Authority  `json:"authority"`
	Job                                                 d.JobBinding `json:"job"`
	Pod                                                 BoundPod     `json:"pod"`
	InvocationSHA256, KeyUseNonce, ExecutionGrantSHA256 string
	Candidate                                           worker.FormalCaptureResult `json:"candidate"`
}

func (o *PublicJobOwner) candidateJournalReady(ctx context.Context) error {
	rows, err := o.Gate.Authority.DB.QueryContext(ctx, "SELECT candidate_cipher,candidate_key_ref,candidate_sha256 FROM system_backup_v2_runtime_resources WHERE 1=0")
	if err != nil {
		return err
	}
	return rows.Close()
}

func formalCandidateBinding(a d.Authority, j d.JobBinding, digest string) staging.Binding {
	return staging.Binding{BackupID: a.TaskPublicID, Attempt: strconv.FormatUint(a.AttemptNo, 10), Path: a.InstallationID + "/" + a.Phase + "/formal-candidate/" + j.Namespace + "/" + j.Name + "/" + j.UID + "/" + j.JobUnitKey, CaptureContextHash: a.ConfigSHA256, EnvelopeID: digest}
}

func (o *PublicJobOwner) sealFormalCandidate(ctx context.Context, a d.Authority, j d.JobBinding, pod BoundPod, req worker.ControlRequest) (string, string, []byte, error) {
	if req.Action != "candidate" || req.Invocation.ProviderKey == nil || !worker.ValidateControl(req) {
		return "", "", nil, c.ErrExecutionRecord
	}
	r := FormalCandidateRecord{Version: "public-formal-candidate-record.v1", Authority: a, Job: j, Pod: pod, InvocationSHA256: req.InvocationSHA256, KeyUseNonce: req.Point, ExecutionGrantSHA256: o.Identity.GrantSHA256(), Candidate: *req.Candidate}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > 16384 {
		return "", "", nil, c.ErrExecutionRecord
	}
	defer clear(raw)
	ref, key, err := o.Identity.Resolve(ctx, a, "")
	defer clear(key)
	if err != nil || ref == "" || len(ref) > 256 || len(key) != 32 {
		return "", "", nil, c.ErrExecutionAuthority
	}
	digest := hash(raw)
	var sealed bytes.Buffer
	if staging.Seal(ctx, &sealed, key, formalCandidateBinding(a, j, digest), func(w io.Writer) error { _, err := w.Write(raw); return err }) != nil {
		return "", "", nil, c.ErrExecutionRecord
	}
	return ref, digest, sealed.Bytes(), nil
}

// Called under the SAME authority/Job row lock as keyUseTx. Only a finished
// original key window may enter here. Replay compares the original digest;
// no result evidence, sealed observation, completed relay or task state changes.
func (o *PublicJobOwner) saveFormalCandidateTx(ctx context.Context, tx *sql.Tx, a d.Authority, j d.JobBinding, ref, digest string, sealed []byte) error {
	if ref == "" || len(ref) > 256 || !formalCandidateDigest(digest) || len(sealed) < 2 || len(sealed) > 32768 {
		return c.ErrExecutionRecord
	}
	var previous sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT candidate_sha256 FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND attempt_no=? AND phase=? AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND observed_uid=? AND revoked=FALSE AND lifecycle='ready' AND stopped_at IS NULL FOR UPDATE`, a.TaskPublicID, a.AttemptNo, a.Phase, j.Namespace, j.Name, j.UID).Scan(&previous); err != nil {
		return err
	}
	if previous.Valid {
		if previous.String != digest {
			return c.ErrExecutionRecord
		}
		return nil
	}
	var capacity int64
	if tx.QueryRowContext(ctx, `SELECT control_metadata_capacity_bytes FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=?`, a.InstallationID, a.ConfigVersion).Scan(&capacity) != nil {
		return c.ErrExecutionRecord
	}
	if err := (security.RegistrationCapacity{ReportFile: o.Gate.Records.CapacityReportFile}).ReserveExecutionPayload(ctx, tx, capacity, len(sealed)); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE system_backup_v2_runtime_resources SET candidate_cipher=?,candidate_key_ref=?,candidate_sha256=?,row_version=row_version+1 WHERE task_public_id=? AND attempt_no=? AND phase=? AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND observed_uid=? AND candidate_sha256 IS NULL AND revoked=FALSE AND stopped_at IS NULL`, sealed, ref, digest, a.TaskPublicID, a.AttemptNo, a.Phase, j.Namespace, j.Name, j.UID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return c.ErrExecutionRecord
	}
	return nil
}

func formalCandidateDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// ReadFormalCandidate opens only the recorded original ciphertext. Recovery
// may inspect it after the forward window, but receives no new source/KEK grant.
// Current worker files and stdout are never a fallback for a missing record.
func (o *PublicJobOwner) ReadFormalCandidate(ctx context.Context, a d.Authority, j d.JobBinding, recovery bool) (FormalCandidateRecord, error) {
	var zero FormalCandidateRecord
	if o == nil || !o.ready() {
		return zero, d.ErrNotReady
	}
	check := func() error {
		if recovery {
			return o.Gate.Recovery.Check(ctx, a)
		}
		return o.Gate.Check(ctx, a)
	}
	if err := check(); err != nil {
		return zero, err
	}
	var ref, digest string
	var sealed []byte
	if err := o.Gate.Authority.DB.QueryRowContext(ctx, `SELECT candidate_key_ref,candidate_sha256,candidate_cipher FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND attempt_no=? AND phase=? AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND observed_uid=?`, a.TaskPublicID, a.AttemptNo, a.Phase, j.Namespace, j.Name, j.UID).Scan(&ref, &digest, &sealed); err != nil {
		return zero, err
	}
	if !formalCandidateDigest(digest) || len(sealed) > 32768 {
		return zero, c.ErrExecutionRecord
	}
	keys := deploymentRecordKeys{o}
	actual, key, err := keys.Resolve(ctx, a, ref)
	defer clear(key)
	if err != nil || actual != ref || len(key) != 32 {
		return zero, c.ErrExecutionAuthority
	}
	record, err := openFormalCandidate(ctx, a, j, digest, sealed, key)
	if err != nil {
		return zero, err
	}
	_, _, desc, err := o.input(ctx, a, recovery)
	if err != nil {
		return zero, err
	}
	if validateFormalCandidatePlan(record, desc) != nil {
		return zero, c.ErrExecutionRecord
	}
	if err = check(); err != nil {
		return zero, err
	}
	return record, nil
}

func openFormalCandidate(ctx context.Context, a d.Authority, j d.JobBinding, digest string, sealed, key []byte) (FormalCandidateRecord, error) {
	var zero FormalCandidateRecord
	var plain bytes.Buffer
	defer func() { clear(plain.Bytes()) }()
	if staging.Open(ctx, bytes.NewReader(sealed), &plain, key, formalCandidateBinding(a, j, digest), 16384) != nil || hash(plain.Bytes()) != digest {
		return zero, c.ErrExecutionRecord
	}
	var record FormalCandidateRecord
	decoder := json.NewDecoder(bytes.NewReader(plain.Bytes()))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil || decoder.Decode(new(any)) != io.EOF || record.Version != "public-formal-candidate-record.v1" || record.Job != j || record.Authority.InstallationID != a.InstallationID || record.Authority.TaskPublicID != a.TaskPublicID || record.Authority.AttemptNo != a.AttemptNo || record.Authority.Phase != a.Phase || record.Authority.ConfigVersion != a.ConfigVersion || record.Authority.ConfigSHA256 != a.ConfigSHA256 || record.InvocationSHA256 != record.Candidate.InvocationSHA256 {
		return zero, c.ErrExecutionRecord
	}
	return record, nil
}

func validateFormalCandidatePlan(record FormalCandidateRecord, desc b.Discovery) error {
	if record.Pod.Namespace != record.Job.Namespace || record.Pod.UID == "" || record.Pod.Name == "" || record.Pod.ServiceAccountUID == "" || !formalCandidateDigest(record.ExecutionGrantSHA256) || len(record.KeyUseNonce) != 32 || record.Authority.TaskType != "backup" {
		return c.ErrExecutionRecord
	}
	for _, part := range desc.Parts {
		if part.Intent.JobUnitKey != record.Job.JobUnitKey {
			continue
		}
		var i worker.Invocation
		if part.Intent.Namespace != record.Job.Namespace || part.Intent.Name != record.Job.Name || part.Intent.Generation != record.Job.Generation || part.InvocationSHA256 != record.InvocationSHA256 || hash(part.InvocationJSON) != record.InvocationSHA256 || json.Unmarshal(part.InvocationJSON, &i) != nil || !worker.ValidateFormalCaptureResult(i, &record.Candidate) {
			return c.ErrExecutionRecord
		}
		return nil
	}
	return c.ErrExecutionRecord
}
