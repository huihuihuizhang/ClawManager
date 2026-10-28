package systembackupevidence

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func downloadContentFixture() (DownloadAdmissionReceiptFacts, DownloadAdmissionOperationFacts) {
	now := time.Date(2026, 10, 16, 7, 0, 0, 123456000, time.UTC)
	r := DownloadAdmissionReceiptFacts{
		Installation: "installation_test", OperationID: "sop_11111111-2222-4333-8444-555555555555", EvidenceID: "sev_11111111-2222-4333-8444-555555555555",
		SubjectSHA256: hash([]byte("user:42")), SessionSHA256: strings.Repeat("a", 64), RequestHash: strings.Repeat("b", 64),
		ClaimSHA256: strings.Repeat("c", 64), ManifestSHA256: strings.Repeat("d", 64), EvidenceRowVersion: 7, IntentAuditID: 123,
		Start: 0, End: 8191, ClaimExpiresAt: now.Add(time.Minute), AdmittedAt: now,
	}
	o := DownloadAdmissionOperationFacts{
		Installation: r.Installation, OperationID: r.OperationID, EvidenceID: r.EvidenceID, IdempotencyKey: "download-key-0001", RequestHash: r.RequestHash,
		ActorID: 42, RowVersion: 1, AdmittedAt: now, DeadlineAt: now.Add(30 * time.Second),
	}
	return r, o
}

func TestDownloadAdmissionContentClosedContract(t *testing.T) {
	r, o := downloadContentFixture()
	raw, err := CanonicalDownloadAdmissionReceipt(r)
	if err != nil {
		t.Fatal(err)
	}
	op, err := CanonicalDownloadAdmissionOperation(o)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCanonicalDownloadAdmissionReceipt(raw)
	if err != nil || decoded != r {
		t.Fatalf("roundtrip: %v", err)
	}
	var private, public map[string]any
	if json.Unmarshal(raw, &private) != nil || json.Unmarshal(op, &public) != nil {
		t.Fatal("invalid JSON")
	}
	if len(private) != 16 || len(public) != 24 {
		t.Fatalf("closed fields: %d/%d", len(private), len(public))
	}
	for key, want := range map[string]any{"schema_version": "system-backup-operation.v1", "operation_type": "evidence_download_admission", "target_type": "evidence", "target_public_id": r.EvidenceID, "actor_type": "admin", "actor_id": "42", "endpoint": "getSystemBackupEvidence", "status": "succeeded", "retryable": false, "failure_category": "none", "failure_message": nil, "result_resource_public_id": nil, "result_config_version": nil, "http_status": float64(200), "row_version": float64(1)} {
		if public[key] != want {
			t.Fatalf("public %s: got %v, want %v", key, public[key], want)
		}
	}
	for _, key := range []string{"created_at", "started_at", "finished_at", "updated_at"} {
		if public[key] != "2026-10-16T07:00:00.123456Z" {
			t.Fatalf("synchronous timestamp %s", key)
		}
	}
	if private["schema_version"] != "system-backup-evidence-download-admission.v1" || private["intent_audit_id"] != float64(123) || private["claim_expires_at"] != "2026-10-16T07:01:00.123456Z" {
		t.Fatal("receipt contract")
	}
	for _, forbidden := range []string{"claim_sha256", "session_sha256", "subject_sha256", "intent_audit_id", "evidence_row_version"} {
		if _, ok := public[forbidden]; ok {
			t.Fatalf("private %s exposed", forbidden)
		}
	}
	if err := VerifyDownloadAdmissionContent(raw, op, hash(raw), hash(op), int64(len(raw)), int64(len(op)), r, o); err != nil {
		t.Fatal(err)
	}
	// Caller buffers are not retained by the pure codecs.
	raw[0] = '!'
	again, _ := CanonicalDownloadAdmissionReceipt(r)
	if again[0] != '{' {
		t.Fatal("mutable alias")
	}
}

func TestDownloadAdmissionReceiptRejectsNoncanonicalWire(t *testing.T) {
	r, _ := downloadContentFixture()
	raw, _ := CanonicalDownloadAdmissionReceipt(r)
	cases := map[string][]byte{
		"padding":             append(append([]byte{}, raw...), '\n'),
		"oversized":           bytes.Repeat([]byte(" "), MaxDownloadAdmissionContentBytes+1),
		"duplicate":           bytes.Replace(raw, []byte(`"intent_audit_id":123`), []byte(`"intent_audit_id":124,"intent_audit_id":123`), 1),
		"numeric_exponent":    bytes.Replace(raw, []byte(`"intent_audit_id":123`), []byte(`"intent_audit_id":1.23e2`), 1),
		"null_false":          bytes.Replace(raw, []byte(`"range_present":false`), []byte(`"range_present":null`), 1),
		"null_zero":           bytes.Replace(raw, []byte(`"range_start":0`), []byte(`"range_start":null`), 1),
		"noncanonical_date":   bytes.Replace(raw, []byte(`2026-10-16T07:00:00.123456Z`), []byte(`2026-10-16T07:00:00.1234560Z`), 1),
		"utc_offset_spelling": bytes.Replace(raw, []byte(`2026-10-16T07:00:00.123456Z`), []byte(`2026-10-16T07:00:00.123456+00:00`), 1),
		"wrong_schema":        bytes.Replace(raw, []byte(DownloadAdmissionReceiptSchema), []byte("system-backup-operation.v1"), 1),
		"trailing_object":     append(append([]byte{}, raw...), []byte("{}")...),
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	for key := range object {
		copy := make(map[string]json.RawMessage)
		for k, v := range object {
			if k != key {
				copy[k] = v
			}
		}
		cases["missing_"+key], _ = json.Marshal(copy)
	}
	for _, forbidden := range []string{"raw_claim", "raw_nonce", "proof", "bearer", "provider_locator", "plaintext_evidence", "secret_material"} {
		copy := make(map[string]json.RawMessage)
		for k, v := range object {
			copy[k] = v
		}
		copy[forbidden] = json.RawMessage(`"never-persist-this"`)
		cases["forbidden_"+forbidden], _ = json.Marshal(copy)
	}
	for name, invalid := range cases {
		t.Run(name, func(t *testing.T) {
			if got, err := DecodeCanonicalDownloadAdmissionReceipt(invalid); err == nil || got != (DownloadAdmissionReceiptFacts{}) {
				t.Fatal("invalid wire yielded facts")
			}
		})
	}
}

func TestDownloadAdmissionContentRejectsInvalidFacts(t *testing.T) {
	r, o := downloadContentFixture()
	mutations := map[string]func(*DownloadAdmissionReceiptFacts){
		"installation":    func(f *DownloadAdmissionReceiptFacts) { f.Installation = "installation_<>" },
		"operation":       func(f *DownloadAdmissionReceiptFacts) { f.OperationID = f.EvidenceID },
		"target":          func(f *DownloadAdmissionReceiptFacts) { f.EvidenceID = f.OperationID },
		"subject":         func(f *DownloadAdmissionReceiptFacts) { f.SubjectSHA256 = "user:42" },
		"session":         func(f *DownloadAdmissionReceiptFacts) { f.SessionSHA256 = "session" },
		"request":         func(f *DownloadAdmissionReceiptFacts) { f.RequestHash = "" },
		"claim":           func(f *DownloadAdmissionReceiptFacts) { f.ClaimSHA256 = "aev_" + strings.Repeat("c", 32) },
		"manifest":        func(f *DownloadAdmissionReceiptFacts) { f.ManifestSHA256 = strings.Repeat("D", 64) },
		"zero_version":    func(f *DownloadAdmissionReceiptFacts) { f.EvidenceRowVersion = 0 },
		"unsafe_version":  func(f *DownloadAdmissionReceiptFacts) { f.EvidenceRowVersion = 9007199254740992 },
		"zero_audit":      func(f *DownloadAdmissionReceiptFacts) { f.IntentAuditID = 0 },
		"audit_overflow":  func(f *DownloadAdmissionReceiptFacts) { f.IntentAuditID = 2147483648 },
		"negative_range":  func(f *DownloadAdmissionReceiptFacts) { f.Start = -1 },
		"reversed_range":  func(f *DownloadAdmissionReceiptFacts) { f.End = -1 },
		"oversized_range": func(f *DownloadAdmissionReceiptFacts) { f.End = MaxResponse },
		"past_content_limit": func(f *DownloadAdmissionReceiptFacts) {
			f.Start = MaxContent
			f.End = MaxContent
			f.RangePresent = true
		},
		"implicit_partial_start": func(f *DownloadAdmissionReceiptFacts) { f.Start = 1 },
		"expired_claim":          func(f *DownloadAdmissionReceiptFacts) { f.ClaimExpiresAt = f.AdmittedAt },
		"zero_time":              func(f *DownloadAdmissionReceiptFacts) { f.AdmittedAt = time.Time{} },
		"submicrosecond":         func(f *DownloadAdmissionReceiptFacts) { f.AdmittedAt = f.AdmittedAt.Add(time.Nanosecond) },
		"non_utc":                func(f *DownloadAdmissionReceiptFacts) { f.AdmittedAt = f.AdmittedAt.In(time.FixedZone("offset", 3600)) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			f := r
			mutate(&f)
			if raw, err := CanonicalDownloadAdmissionReceipt(f); err == nil || raw != nil {
				t.Fatal("invalid facts encoded")
			}
		})
	}
	for name, mutate := range map[string]func(*DownloadAdmissionOperationFacts){
		"bad_key":        func(f *DownloadAdmissionOperationFacts) { f.IdempotencyKey = strings.Repeat("!", 16) },
		"short_key":      func(f *DownloadAdmissionOperationFacts) { f.IdempotencyKey = "short" },
		"actor_overflow": func(f *DownloadAdmissionOperationFacts) { f.ActorID = 2147483648 },
		"zero_actor":     func(f *DownloadAdmissionOperationFacts) { f.ActorID = 0 },
		"row_overflow":   func(f *DownloadAdmissionOperationFacts) { f.RowVersion = 9007199254740992 },
		"expired":        func(f *DownloadAdmissionOperationFacts) { f.DeadlineAt = f.AdmittedAt },
		"nanosecond":     func(f *DownloadAdmissionOperationFacts) { f.DeadlineAt = f.DeadlineAt.Add(time.Nanosecond) },
	} {
		t.Run("operation_"+name, func(t *testing.T) {
			f := o
			mutate(&f)
			if raw, err := CanonicalDownloadAdmissionOperation(f); err == nil || raw != nil {
				t.Fatal("invalid operation encoded")
			}
		})
	}
}

func TestDownloadAdmissionContentIndependentBindings(t *testing.T) {
	r, o := downloadContentFixture()
	receipt, _ := CanonicalDownloadAdmissionReceipt(r)
	operation, _ := CanonicalDownloadAdmissionOperation(o)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(receipt, &fields); err != nil {
		t.Fatal(err)
	}
	for key, replacement := range map[string]string{
		"origin_installation_id": `"installation_other"`, "operation_public_id": `"sop_99999999-2222-4333-8444-555555555555"`,
		"evidence_id": `"sev_99999999-2222-4333-8444-555555555555"`, "evidence_row_version": "8", "intent_audit_id": "124",
		"subject_sha256": `"` + strings.Repeat("e", 64) + `"`, "session_sha256": `"` + strings.Repeat("e", 64) + `"`, "request_hash": `"` + strings.Repeat("e", 64) + `"`,
		"claim_sha256": `"` + strings.Repeat("e", 64) + `"`, "manifest_sha256": `"` + strings.Repeat("e", 64) + `"`, "range_present": "true", "range_start": "1", "range_end": "8190",
		"admitted_at": `"2026-10-16T07:00:01.123456Z"`, "claim_expires_at": `"2026-10-16T07:02:00.123456Z"`,
	} {
		t.Run("receipt_"+key, func(t *testing.T) {
			copy := make(map[string]json.RawMessage)
			for k, v := range fields {
				copy[k] = v
			}
			copy[key] = json.RawMessage(replacement)
			changed, _ := json.Marshal(copy)
			if err := VerifyDownloadAdmissionContent(changed, operation, hash(changed), hash(operation), int64(len(changed)), int64(len(operation)), r, o); err != ErrIntegrity {
				t.Fatal("self-consistent replacement accepted")
			}
		})
	}
	for _, mutate := range []func(*DownloadAdmissionOperationFacts){
		func(f *DownloadAdmissionOperationFacts) { f.ActorID++ }, func(f *DownloadAdmissionOperationFacts) { f.Installation = "installation_other" },
		func(f *DownloadAdmissionOperationFacts) { f.EvidenceID = "sev_99999999-2222-4333-8444-555555555555" }, func(f *DownloadAdmissionOperationFacts) { f.IdempotencyKey = "download-key-0002" },
		func(f *DownloadAdmissionOperationFacts) { f.RequestHash = strings.Repeat("e", 64) }, func(f *DownloadAdmissionOperationFacts) { f.RowVersion++ },
		func(f *DownloadAdmissionOperationFacts) { f.AdmittedAt = f.AdmittedAt.Add(time.Second) }, func(f *DownloadAdmissionOperationFacts) { f.DeadlineAt = f.DeadlineAt.Add(time.Second) },
	} {
		f := o
		mutate(&f)
		changed, err := CanonicalDownloadAdmissionOperation(f)
		if err != nil {
			t.Fatal(err)
		}
		if VerifyDownloadAdmissionContent(receipt, changed, hash(receipt), hash(changed), int64(len(receipt)), int64(len(changed)), r, o) != ErrIntegrity {
			t.Fatal("modified operation accepted")
		}
	}
	if VerifyDownloadAdmissionContent(receipt, operation, hash(receipt), hash(operation), int64(len(receipt))+1, int64(len(operation)), r, o) != ErrIntegrity {
		t.Fatal("wrong length")
	}
	if VerifyDownloadAdmissionContent(receipt, operation, strings.Repeat("0", 64), hash(operation), int64(len(receipt)), int64(len(operation)), r, o) != ErrIntegrity {
		t.Fatal("wrong digest")
	}
	badDeadline := o
	badDeadline.DeadlineAt = r.ClaimExpiresAt.Add(time.Second)
	badOperation, _ := CanonicalDownloadAdmissionOperation(badDeadline)
	if VerifyDownloadAdmissionContent(receipt, badOperation, hash(receipt), hash(badOperation), int64(len(receipt)), int64(len(badOperation)), r, badDeadline) != ErrIntegrity {
		t.Fatal("deadline exceeds original claim")
	}
}
