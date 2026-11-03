package services

import (
	"bytes"
	"encoding/json"
	"net/http"
	"unicode/utf8"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// DecodeRuntimeBackupWireObservation validates DATA from the existing
// isolated-backup.v1 wire and retains the EXACT received response bytes. It
// does not authenticate transport, prove current physical stop, hold a writer
// reservation, establish a task/maintenance grant, or authorize recovery.
// D must bind the real authenticated Agent endpoint and original request,
// current live state, durable journal, mount/participant fence and its absolute
// hold deadline. B's independently keyed node observation is a separate proof.
//
// No expiry is inferred from ConfirmedAt: v1 has no wire expiry/auto-thaw.
// The original owner's deadline and current-state checks remain mandatory.
func DecodeRuntimeBackupWireObservation(expected RuntimeBackupRequest, action string, status int, raw []byte) (RuntimeBackupObservation, error) {
	var zero RuntimeBackupObservation
	if !expected.Valid() || len(raw) == 0 || len(raw) > 64<<10 || !utf8.Valid(raw) {
		return zero, ErrRuntimeStopReceiptMismatch
	}
	if _, err := jsoncanonicalizer.Transform(raw); err != nil {
		return zero, ErrRuntimeStopReceiptMismatch
	}
	switch action {
	case "stop", "state", "resume", "complete":
	default:
		return zero, ErrRuntimeStopReceiptMismatch
	}
	if status == http.StatusAccepted {
		if action != "state" && action != "resume" {
			return zero, ErrRuntimeStopReceiptMismatch
		}
		fields, err := runtimeBackupWireObject(raw, []string{"state"}, nil)
		var pending string
		if err != nil || json.Unmarshal(fields["state"], &pending) != nil || pending != "resuming" {
			return zero, ErrRuntimeStopReceiptMismatch
		}
		return RuntimeBackupObservation{Pending: true, Raw: bytes.Clone(raw)}, nil
	}
	if status != http.StatusOK {
		return zero, ErrRuntimeStopUnconfirmed
	}
	fields, err := runtimeBackupWireObject(raw, []string{"request", "state", "confirmation_scope", "confirmed_at"}, []string{"pid"})
	if err != nil {
		return zero, ErrRuntimeStopReceiptMismatch
	}
	requestKeys := []string{"protocol", "namespace", "pod_uid", "agent_epoch", "operation_id", "runtime_type", "instance_id", "user_id", "generation", "gateway_id", "gateway_port", "expected_pid", "resume_generation", "restart_sha256"}
	if _, err := runtimeBackupWireObject(fields["request"], requestKeys, nil); err != nil {
		return zero, ErrRuntimeStopReceiptMismatch
	}
	var receipt RuntimeBackupReceipt
	if decodeRuntimeBackup(raw, &receipt) != nil || !ValidateRuntimeBackupReceipt(expected, receipt) || action == "stop" && receipt.State != "stopped" || (action == "resume" || action == "complete") && receipt.State != "resumed" {
		return zero, ErrRuntimeStopReceiptMismatch
	}
	return RuntimeBackupObservation{Receipt: receipt, Raw: bytes.Clone(raw)}, nil
}

// The existing native encoder emits exact lowercase field names. Reject case
// aliases as well as unknown/missing/null fields; Go's permissive field-name
// matching must not turn ambiguous external JSON into a differently bound row.
func runtimeBackupWireObject(raw []byte, required, optional []string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, ErrRuntimeStopReceiptMismatch
	}
	allowed := map[string]bool{}
	for _, key := range required {
		allowed[key] = true
		value := fields[key]
		if len(value) == 0 || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, ErrRuntimeStopReceiptMismatch
		}
	}
	for _, key := range optional {
		allowed[key] = true
	}
	for key, value := range fields {
		if !allowed[key] || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, ErrRuntimeStopReceiptMismatch
		}
	}
	return fields, nil
}
