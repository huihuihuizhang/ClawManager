package services

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// DATA-only wire compatibility/rejection tests. No Agent, physical stop,
// maintenance/task authorization, clock freshness or reservation is faked.
func backupWireData(t *testing.T, state string) (RuntimeBackupRequest, []byte) {
	t.Helper()
	req := backupClientTestRequest()
	pid := 0
	if state == "resumed" {
		pid = 456
	}
	raw, e := json.Marshal(RuntimeBackupReceipt{Request: req, State: state, Scope: RuntimeBackupStopScope, PID: pid, ConfirmedAt: time.Unix(1700000000, 1234).UTC()})
	if e != nil {
		t.Fatal(e)
	}
	return req, append(raw, '\n')
}
func TestRuntimeBackupRawWirePreservesExactBytesAndOperationBinding(t *testing.T) {
	for _, state := range []string{"stopped", "resumed"} {
		req, raw := backupWireData(t, state)
		action := "stop"
		if state == "resumed" {
			action = "complete"
		}
		o, e := DecodeRuntimeBackupWireObservation(req, action, http.StatusOK, raw)
		if e != nil || o.Pending || o.Receipt.State != state || !bytes.Equal(o.Raw, raw) {
			t.Fatal("native raw receipt compatibility", state, e)
		}
		before := bytes.Clone(o.Raw)
		raw[0] = ' '
		if !bytes.Equal(o.Raw, before) {
			t.Fatal("returned raw receipt aliases input")
		}
		// Timestamp deliberately is old: this parser must not invent a receipt
		// TTL. Original owner deadline/current live state remain separate checks.
		if o.Receipt.ConfirmedAt.Year() != 2023 {
			t.Fatal("receipt time was rewritten")
		}
	}
}
func TestRuntimeBackupRawWireRejectsAmbiguousOrForeignReceipt(t *testing.T) {
	req, raw := backupWireData(t, "stopped")
	for _, which := range []string{"duplicate", "case_alias", "foreign_operation", "wrong_state", "unknown_field", "null_pid", "trailing", "too_large", "invalid_utf8", "http_error", "bad_action"} {
		t.Run(which, func(t *testing.T) {
			body := bytes.Clone(raw)
			status := http.StatusOK
			action := "state"
			switch which {
			case "duplicate":
				body = bytes.Replace(body, []byte(`"state":"stopped"`), []byte(`"state":"stopped","state":"stopped"`), 1)
			case "case_alias":
				body = bytes.Replace(body, []byte(`"operation_id"`), []byte(`"Operation_ID"`), 1)
			case "foreign_operation":
				body = bytes.Replace(body, []byte(req.OperationID), []byte(strings.Repeat("d", 32)), 1)
			case "wrong_state":
				body = bytes.Replace(body, []byte(`"state":"stopped"`), []byte(`"state":"resumed"`), 1)
			case "unknown_field":
				body = append(bytes.TrimSuffix(bytes.TrimSpace(body), []byte("}")), []byte(`,"approved":true}`)...)
			case "null_pid":
				body = append(bytes.TrimSuffix(bytes.TrimSpace(body), []byte("}")), []byte(`,"pid":null}`)...)
			case "trailing":
				body = append(body, []byte(`{}`)...)
			case "too_large":
				body = append(bytes.Repeat([]byte(" "), 64<<10), body...)
			case "invalid_utf8":
				body = append(body, 255)
			case "http_error":
				status = http.StatusConflict
			case "bad_action":
				action = "approve"
			}
			if _, e := DecodeRuntimeBackupWireObservation(req, action, status, body); e == nil {
				t.Fatal("ambiguous/foreign response accepted", which)
			}
		})
	}
}
func TestRuntimeBackupRawWirePendingNeverBecomesStopOrCompletion(t *testing.T) {
	req := backupClientTestRequest()
	raw := []byte("{\"state\":\"resuming\"}\n")
	for _, action := range []string{"resume", "state"} {
		o, e := DecodeRuntimeBackupWireObservation(req, action, http.StatusAccepted, raw)
		if e != nil || !o.Pending || o.Receipt.State != "" || !bytes.Equal(o.Raw, raw) {
			t.Fatal("pending response changed", action, e)
		}
	}
	for _, action := range []string{"stop", "complete"} {
		if _, e := DecodeRuntimeBackupWireObservation(req, action, http.StatusAccepted, raw); e == nil {
			t.Fatal("pending admitted as stop/completion", action)
		}
	}
	if _, e := DecodeRuntimeBackupWireObservation(req, "state", http.StatusAccepted, []byte(`{"state":"resuming","stopped":true}`)); e == nil {
		t.Fatal("extra pending approval accepted")
	}
}
