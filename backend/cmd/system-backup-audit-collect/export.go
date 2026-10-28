package main

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func publicScalar(key string, raw json.RawMessage) bool {
	if key == "resource_id" {
		return string(raw) == "null"
	}
	if key == "range_present" {
		return string(raw) == "false"
	}
	for _, number := range []string{"id", "operation_id", "intent_audit_id", "result_audit_id", "user_id", "evidence_row_version", "size_bytes", "bytes_written", "range_start", "range_end", "nonce_count"} {
		if key == number {
			n, e := strconv.ParseUint(string(raw), 10, 64)
			return e == nil && n <= 9007199254740991 && regexp.MustCompile(`^(0|[1-9][0-9]*)$`).Match(raw)
		}
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	if strings.HasSuffix(key, "sha256") || key == "request_hash" {
		return hashPattern.MatchString(value)
	}
	switch key {
	case "public_id", "operation_public_id":
		return strings.HasPrefix(value, "sop_") && uuidPattern.MatchString(strings.TrimPrefix(value, "sop_"))
	case "evidence_id":
		return strings.HasPrefix(value, "sev_") && uuidPattern.MatchString(strings.TrimPrefix(value, "sev_"))
	case "installation_id", "origin_installation_id":
		return regexp.MustCompile(`^installation_[A-Za-z0-9._:-]{1,115}$`).MatchString(value)
	case "actor_id":
		return regexp.MustCompile(`^[1-9][0-9]{0,15}$`).MatchString(value)
	case "idempotency_key":
		return regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`).MatchString(value)
	case "operation_type":
		return value == "evidence_download_admission"
	case "endpoint":
		return value == "getSystemBackupEvidence"
	case "status":
		return value == "succeeded"
	case "action":
		return value == "system_backup.evidence_download.intent" || value == "system_backup.evidence_download.result"
	case "resource_type":
		return value == "system_backup"
	case "schema_version":
		return value == "system-backup-evidence-download-admission.v1" || value == "system-backup-evidence-download-intent.v1" || value == "system-backup-evidence-download-result.v1"
	case "outcome":
		return value == "local_write_complete"
	case "claim_expires_at", "admitted_at", "intent_at", "result_at", "retain_until":
		_, e := time.Parse(time.RFC3339Nano, value)
		return e == nil
	}
	return false
}

// Reject unknown audit body members before any database bytes leave the process.
// Full link, canonical digest, nonce and HTTP binding checks stay in the existing
// Node reviewer. A collected envelope never means the audit has passed review.
func checkExport(raw []byte, r request) error {
	top, err := object(raw, "server_uuid", "database", "operation", "admission", "intent", "result", "result_link", "nonce_count")
	if err != nil {
		return rejected
	}
	var server, database string
	if json.Unmarshal(top["server_uuid"], &server) != nil || json.Unmarshal(top["database"], &database) != nil || server != r.ServerUUID || database != r.Database {
		return rejected
	}
	if !publicScalar("nonce_count", top["nonce_count"]) {
		return rejected
	}
	shapes := map[string][]string{
		"operation":   {"id", "public_id", "installation_id", "actor_id", "operation_type", "endpoint", "status", "idempotency_key", "request_hash", "evidence_id"},
		"admission":   {"operation_id", "operation_public_id", "installation_id", "evidence_id", "intent_audit_id", "size_bytes", "sha256", "body"},
		"intent":      {"id", "user_id", "action", "resource_type", "resource_id", "body"},
		"result":      {"id", "user_id", "action", "resource_type", "resource_id", "body"},
		"result_link": {"operation_id", "operation_public_id", "installation_id", "evidence_id", "intent_audit_id", "result_audit_id", "size_bytes", "sha256"},
	}
	bodies := map[string][]string{
		"admission": {"schema_version", "operation_public_id", "origin_installation_id", "evidence_id", "evidence_row_version", "subject_sha256", "session_sha256", "request_hash", "claim_sha256", "claim_expires_at", "manifest_sha256", "range_present", "range_start", "range_end", "admitted_at", "intent_audit_id"},
		"intent":    {"schema_version", "operation_public_id", "origin_installation_id", "evidence_id", "evidence_row_version", "request_hash", "manifest_sha256", "claim_sha256", "range_present", "range_start", "range_end", "intent_at"},
		"result":    {"schema_version", "operation_public_id", "origin_installation_id", "intent_audit_id", "evidence_id", "evidence_row_version", "claim_sha256", "request_hash", "range_start", "range_end", "range_present", "outcome", "bytes_written", "result_at", "retain_until"},
	}
	for name, keys := range shapes {
		// resource_id is deliberately nullable. All other selected members are not.
		fields, e := object(top[name], keys...)
		if e != nil {
			return rejected
		}
		if (name == "intent" || name == "result") && string(fields["resource_id"]) != "null" {
			return rejected
		}
		for key, value := range fields {
			if key != "body" && !publicScalar(key, value) {
				return rejected
			}
		}
		if name == "operation" {
			var id string
			if json.Unmarshal(fields["public_id"], &id) != nil || id != r.OperationID {
				return rejected
			}
		}
		if bodyKeys, ok := bodies[name]; ok {
			body, e := object(fields["body"], bodyKeys...)
			if e != nil {
				return rejected
			}
			for key, value := range body {
				if !publicScalar(key, value) {
					return rejected
				}
			}
		}
	}
	return nil
}
