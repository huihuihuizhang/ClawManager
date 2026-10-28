package systembackupapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"unicode/utf8"

	read "clawreef/internal/systembackupread"
)

// NewTaskRequestContract supplies the v12 create business-body decoder. It does
// no I/O and grants no admission: resource identities and readiness still belong
// to TaskAdmission in the caller's authorized transaction.
func NewTaskRequestContract() TaskRequestContract { return taskRequestContract{} }

type taskRequestContract struct{}
type canonicalTaskRequest struct{ data []byte }

func (r canonicalTaskRequest) CanonicalJSON() []byte { return append([]byte(nil), r.data...) }

var requestPartOrder = [...]string{"mysql", "redis", "object_storage", "workspace", "deployment_resources", "secret_bundle"}

func (taskRequestContract) Decode(ctx context.Context, kind read.TaskKind, endpoint string, raw json.RawMessage) (NormalizedTaskRequest, error) {
	if nilDependency(ctx) || ctx.Err() != nil {
		return nil, &Error{"not_ready"}
	}
	_, expected, prefix := taskRoute(kind)
	if expected == "" || endpoint != expected || len(raw) < 2 || len(raw) > maxTaskBody || !utf8.Valid(raw) {
		return nil, &Error{"validation_failed"}
	}
	fields, err := createRequestFields(raw)
	if err != nil {
		return nil, err
	}
	var normalized map[string]any
	switch kind {
	case read.BackupTask:
		normalized, err = decodeBackupRequest(fields)
	case read.PreflightTask:
		normalized, err = decodePreflightRequest(fields)
	default:
		return nil, &Error{"validation_failed"}
	}
	if err != nil {
		return nil, err
	}
	// This writer cannot yet persist/validate a new-task retry relationship.
	// Validate its kind first, then refuse rather than silently drop the field.
	if retry, present := fields["retry_of_public_id"]; present && !bytes.Equal(bytes.TrimSpace(retry), []byte("null")) {
		var id string
		if json.Unmarshal(retry, &id) != nil || len(id) != 40 || id[:4] != prefix || !uuid.MatchString(id[4:]) {
			return nil, &Error{"validation_failed"}
		}
		return nil, &Error{"not_ready"}
	}
	normalized["retry_of_public_id"] = nil
	if kind == read.PreflightTask && normalized["source_artifact_type"] == "catalog_import" {
		// The ID grammar exists, but the canonical catalog reader/admission
		// contract has not been delivered. Never substitute a backup lookup.
		return nil, &Error{"not_ready"}
	}
	// Exact JCS subset: all keys and values have been restricted to printable
	// ASCII without escapes, or arrays of those strings, plus null. Go's sorted
	// map keys and compact JSON match JCS for this subset. No arbitrary Unicode,
	// numbers, nested objects or HTML-sensitive strings reach this encoder.
	canonical, err := json.Marshal(normalized)
	if err != nil || ctx.Err() != nil {
		return nil, &Error{"not_ready"}
	}
	return canonicalTaskRequest{data: canonical}, nil
}

// Decode top-level keys before values so escaped duplicate keys and casing
// aliases cannot be hidden by encoding/json's map/struct last-value behavior.
func createRequestFields(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, &Error{"validation_failed"}
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		tok, err := d.Token()
		if err != nil {
			return nil, &Error{"validation_failed"}
		}
		key, ok := tok.(string)
		if _, exists := fields[key]; !ok || exists {
			return nil, &Error{"validation_failed"}
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, &Error{"validation_failed"}
		}
		fields[key] = value
	}
	if tok, err = d.Token(); err != nil || tok != json.Delim('}') {
		return nil, &Error{"validation_failed"}
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, &Error{"validation_failed"}
	}
	return fields, nil
}

func requestString(fields map[string]json.RawMessage, key, fallback string) (string, bool) {
	raw, present := fields[key]
	if !present {
		return fallback, fallback != ""
	}
	var value string
	if json.Unmarshal(raw, &value) != nil || value == "" {
		return "", false
	}
	return value, true
}

func requestKeys(fields map[string]json.RawMessage, allowed ...string) bool {
	for key := range fields {
		if key == "retry_of_public_id" {
			continue
		}
		found := false
		for _, candidate := range allowed {
			found = found || key == candidate
		}
		if !found {
			return false
		}
	}
	return true
}

func decodeBackupRequest(fields map[string]json.RawMessage) (map[string]any, error) {
	purpose, ok := requestString(fields, "task_purpose", "acceptance")
	var parts []string
	if !requestKeys(fields, "task_purpose", "requested_parts") || !ok || !writerEnum(purpose, "acceptance", "functional_test") ||
		json.Unmarshal(fields["requested_parts"], &parts) != nil || len(parts) == 0 || len(parts) > len(requestPartOrder) {
		return nil, &Error{"validation_failed"}
	}
	seen := make(map[string]bool, len(parts))
	for _, part := range parts {
		if seen[part] || !writerEnum(part, requestPartOrder[:]...) {
			return nil, &Error{"validation_failed"}
		}
		seen[part] = true
	}
	if purpose == "acceptance" && len(seen) != len(requestPartOrder) {
		return nil, &Error{"validation_failed"}
	}
	sorted := make([]string, 0, len(parts))
	for _, part := range requestPartOrder {
		if seen[part] {
			sorted = append(sorted, part)
		}
	}
	return map[string]any{"requested_parts": sorted, "task_purpose": purpose}, nil
}

func decodePreflightRequest(fields map[string]json.RawMessage) (map[string]any, error) {
	if !requestKeys(fields, "source_artifact_type", "source_public_id", "target_profile", "restore_target_config_ref", "preflight_mode") {
		return nil, &Error{"validation_failed"}
	}
	values := make(map[string]any, 5)
	for _, key := range []string{"source_artifact_type", "source_public_id", "target_profile", "restore_target_config_ref", "preflight_mode"} {
		fallback := ""
		if key == "preflight_mode" {
			fallback = "production_readonly"
		}
		value, ok := requestString(fields, key, fallback)
		if !ok {
			return nil, &Error{"validation_failed"}
		}
		values[key] = value
	}
	source, id := values["source_artifact_type"].(string), values["source_public_id"].(string)
	if !writerEnum(source, "backup", "catalog_import") || len(id) != 40 || !uuid.MatchString(id[4:]) ||
		(source == "backup" && id[:4] != "sbk_") || (source == "catalog_import" && id[:4] != "sci_") ||
		!writerEnum(values["target_profile"].(string), "cluster", "single-node") ||
		!writerEnum(values["preflight_mode"].(string), "production_readonly", "functional_test") ||
		!taskWriterValue.MatchString(values["restore_target_config_ref"].(string)) {
		return nil, &Error{"validation_failed"}
	}
	return values, nil
}
