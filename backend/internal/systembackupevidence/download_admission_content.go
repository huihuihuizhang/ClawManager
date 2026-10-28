package systembackupevidence

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"time"

	"clawreef/internal/systembackupsecurity"
)

const DownloadAdmissionReceiptSchema = "system-backup-evidence-download-admission.v1"
const MaxDownloadAdmissionContentBytes = 8192

var downloadAdmissionKey = regexp.MustCompile(`^[A-Za-z0-9._:-]{16,128}$`)

// DownloadAdmissionReceiptFacts are independently locked database facts. This
// codec grants no authority and does not prove a commit, a claim CAS or nonce
// consumption. Digests are bindings, never transferable download capabilities.
type DownloadAdmissionReceiptFacts struct {
	Installation, OperationID, EvidenceID         string
	SubjectSHA256, SessionSHA256, RequestHash     string
	ClaimSHA256, ManifestSHA256                   string
	EvidenceRowVersion, IntentAuditID, Start, End int64
	RangePresent                                  bool
	ClaimExpiresAt, AdmittedAt                    time.Time
}

func downloadAdmissionContentTime(t time.Time) bool {
	_, offset := t.Zone()
	return !t.IsZero() && offset == 0 && t.Year() >= 1970 && t.Year() <= 9999 && t.Nanosecond()%1000 == 0
}

func downloadAdmissionFormatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// All names and strings in this profile are closed ASCII, and integers are
// bounded below 2^53. The package's restricted JCS encoder therefore suffices.
func CanonicalDownloadAdmissionReceipt(f DownloadAdmissionReceiptFacts) ([]byte, error) {
	if !installationPattern.MatchString(f.Installation) || !downloadAdmissionOperationID.MatchString(f.OperationID) || !idPattern.MatchString(f.EvidenceID) ||
		!digestPattern.MatchString(f.SubjectSHA256) || !digestPattern.MatchString(f.SessionSHA256) || !digestPattern.MatchString(f.RequestHash) ||
		!digestPattern.MatchString(f.ClaimSHA256) || !digestPattern.MatchString(f.ManifestSHA256) ||
		f.EvidenceRowVersion < 1 || f.EvidenceRowVersion > 9007199254740991 || f.IntentAuditID < 1 || f.IntentAuditID > 2147483647 ||
		f.Start < 0 || f.End < f.Start || f.End >= MaxContent || f.End-f.Start+1 > MaxResponse || !f.RangePresent && f.Start != 0 ||
		!downloadAdmissionContentTime(f.AdmittedAt) || !downloadAdmissionContentTime(f.ClaimExpiresAt) || !f.AdmittedAt.Before(f.ClaimExpiresAt) {
		return nil, ErrInvalid
	}
	raw := canonical(map[string]any{
		"schema_version": DownloadAdmissionReceiptSchema, "operation_public_id": f.OperationID,
		"origin_installation_id": f.Installation, "evidence_id": f.EvidenceID, "evidence_row_version": f.EvidenceRowVersion,
		"subject_sha256": f.SubjectSHA256, "session_sha256": f.SessionSHA256, "request_hash": f.RequestHash,
		"claim_sha256": f.ClaimSHA256, "claim_expires_at": downloadAdmissionFormatTime(f.ClaimExpiresAt), "manifest_sha256": f.ManifestSHA256,
		"range_present": f.RangePresent, "range_start": f.Start, "range_end": f.End,
		"admitted_at": downloadAdmissionFormatTime(f.AdmittedAt), "intent_audit_id": f.IntentAuditID,
	})
	if len(raw) < 2 || len(raw) > MaxDownloadAdmissionContentBytes {
		return nil, ErrInvalid
	}
	return raw, nil
}

// DownloadAdmissionOperationFacts describe the complete public Operation,
// separately from the private receipt. A successful admission is synchronous:
// all four lifecycle timestamps equal the final SQL UTC, and both results are
// null. HTTPStatus 200 describes admission, not the GET's binary 200/206 body.
type DownloadAdmissionOperationFacts struct {
	Installation, OperationID, EvidenceID, IdempotencyKey, RequestHash string
	ActorID, RowVersion                                                int64
	AdmittedAt, DeadlineAt                                             time.Time
}

func CanonicalDownloadAdmissionOperation(f DownloadAdmissionOperationFacts) ([]byte, error) {
	if !installationPattern.MatchString(f.Installation) || !downloadAdmissionOperationID.MatchString(f.OperationID) || !idPattern.MatchString(f.EvidenceID) ||
		!downloadAdmissionKey.MatchString(f.IdempotencyKey) || !digestPattern.MatchString(f.RequestHash) || f.ActorID < 1 || f.ActorID > 2147483647 ||
		f.RowVersion < 1 || f.RowVersion > 9007199254740991 || !downloadAdmissionContentTime(f.AdmittedAt) ||
		!downloadAdmissionContentTime(f.DeadlineAt) || !f.AdmittedAt.Before(f.DeadlineAt) {
		return nil, ErrInvalid
	}
	timestamp := downloadAdmissionFormatTime(f.AdmittedAt)
	raw := canonical(map[string]any{
		"schema_version": "system-backup-operation.v1", "public_id": f.OperationID, "origin_installation_id": f.Installation,
		"operation_type": "evidence_download_admission", "target_type": "evidence", "target_public_id": f.EvidenceID,
		"actor_type": "admin", "actor_id": strconv.FormatInt(f.ActorID, 10), "endpoint": systembackupsecurity.SensitiveDownloadEndpoint,
		"idempotency_key": f.IdempotencyKey, "request_hash": f.RequestHash, "status": "succeeded",
		"result_resource_public_id": nil, "result_config_version": nil, "retryable": false, "failure_category": "none",
		"failure_message": nil, "http_status": 200, "row_version": f.RowVersion, "deadline_at": downloadAdmissionFormatTime(f.DeadlineAt),
		"started_at": timestamp, "finished_at": timestamp, "created_at": timestamp, "updated_at": timestamp,
	})
	if len(raw) < 2 || len(raw) > MaxDownloadAdmissionContentBytes {
		return nil, ErrInvalid
	}
	return raw, nil
}

// DecodeCanonicalDownloadAdmissionReceipt validates representation only.
// Re-encoding and exact byte comparison reject duplicate/unknown/missing keys,
// null substitutions, whitespace, alternate numbers and noncanonical dates.
// Never use values decoded from the receipt as the independent SQL expectations.
func DecodeCanonicalDownloadAdmissionReceipt(raw []byte) (DownloadAdmissionReceiptFacts, error) {
	bad := func() (DownloadAdmissionReceiptFacts, error) { return DownloadAdmissionReceiptFacts{}, ErrInvalid }
	if len(raw) < 2 || len(raw) > MaxDownloadAdmissionContentBytes {
		return bad()
	}
	var dto struct {
		Installation string `json:"origin_installation_id"`
		OperationID  string `json:"operation_public_id"`
		EvidenceID   string `json:"evidence_id"`
		Subject      string `json:"subject_sha256"`
		Session      string `json:"session_sha256"`
		Request      string `json:"request_hash"`
		Claim        string `json:"claim_sha256"`
		Manifest     string `json:"manifest_sha256"`
		Version      int64  `json:"evidence_row_version"`
		Audit        int64  `json:"intent_audit_id"`
		Start        int64  `json:"range_start"`
		End          int64  `json:"range_end"`
		Present      bool   `json:"range_present"`
		Expires      string `json:"claim_expires_at"`
		Admitted     string `json:"admitted_at"`
	}
	if json.Unmarshal(raw, &dto) != nil {
		return bad()
	}
	expires, e1 := time.Parse(time.RFC3339Nano, dto.Expires)
	admitted, e2 := time.Parse(time.RFC3339Nano, dto.Admitted)
	if e1 != nil || e2 != nil {
		return bad()
	}
	f := DownloadAdmissionReceiptFacts{dto.Installation, dto.OperationID, dto.EvidenceID, dto.Subject, dto.Session, dto.Request, dto.Claim, dto.Manifest, dto.Version, dto.Audit, dto.Start, dto.End, dto.Present, expires, admitted}
	expected, err := CanonicalDownloadAdmissionReceipt(f)
	if err != nil || !bytes.Equal(raw, expected) {
		return bad()
	}
	return f, nil
}

// VerifyDownloadAdmissionContent binds two independently stored byte strings to
// their own length/digest columns AND independently locked receipt/operation
// facts. A self-consistent replacement of bytes and checksum must still fail.
// This function cannot replace SQL joins, final guards or a confirmed commit.
func VerifyDownloadAdmissionContent(receipt, operation []byte, receiptSHA, operationSHA string, receiptSize, operationSize int64, r DownloadAdmissionReceiptFacts, o DownloadAdmissionOperationFacts) error {
	if !digestPattern.MatchString(receiptSHA) || !digestPattern.MatchString(operationSHA) || receiptSize != int64(len(receipt)) || operationSize != int64(len(operation)) ||
		receiptSize < 2 || receiptSize > MaxDownloadAdmissionContentBytes || operationSize < 2 || operationSize > MaxDownloadAdmissionContentBytes ||
		hash(receipt) != receiptSHA || hash(operation) != operationSHA || r.Installation != o.Installation || r.OperationID != o.OperationID ||
		r.EvidenceID != o.EvidenceID || r.RequestHash != o.RequestHash || !r.AdmittedAt.Equal(o.AdmittedAt) || o.DeadlineAt.After(r.ClaimExpiresAt) ||
		r.SubjectSHA256 != hash([]byte("user:"+strconv.FormatInt(o.ActorID, 10))) {
		return ErrIntegrity
	}
	wantReceipt, e1 := CanonicalDownloadAdmissionReceipt(r)
	wantOperation, e2 := CanonicalDownloadAdmissionOperation(o)
	if e1 != nil || e2 != nil || !bytes.Equal(receipt, wantReceipt) || !bytes.Equal(operation, wantOperation) {
		return ErrIntegrity
	}
	return nil
}
