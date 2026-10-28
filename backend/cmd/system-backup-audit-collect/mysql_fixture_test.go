package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/go-sql-driver/mysql"
)

// Shared with the tagged probe so default offline tests check the actual inputs.
//
//go:embed testdata/audit.json
var mysqlAuditFixture []byte

//go:embed testdata/mysql.sql
var mysqlAuditSchema string

type mysqlFixtureStep struct {
	stage string
	query string
	args  []any
}

// This fixture is deliberately limited to one CREATE TABLE per noncomment line.
// It is not an SQL parser; reject unsupported layouts instead of splitting SQL
// or comments blindly at semicolons.
func mysqlFixtureSchemaSteps(schema string) ([]mysqlFixtureStep, error) {
	want := map[string]bool{"system_backup_v2_operations": false, "system_backup_v2_download_admission_receipts": false,
		"audit_logs": false, "system_backup_v2_download_result_receipts": false, "system_backup_v2_strong_auth_nonces": false}
	pattern := regexp.MustCompile(`^CREATE TABLE ([a-z][a-z0-9_]*) \([^;]+\);$`)
	var steps []mysqlFixtureStep
	for _, line := range strings.Split(schema, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-- ") {
			continue
		}
		match := pattern.FindStringSubmatch(line)
		if match == nil {
			return nil, errors.New("unsupported isolated schema fixture layout")
		}
		seen, known := want[match[1]]
		if !known || seen {
			return nil, errors.New("unexpected isolated fixture table")
		}
		want[match[1]] = true
		steps = append(steps, mysqlFixtureStep{stage: fmt.Sprintf("schema_%d", len(steps)+1), query: strings.TrimSuffix(line, ";")})
	}
	if len(steps) != len(want) {
		return nil, errors.New("incomplete isolated schema fixture")
	}
	return steps, nil
}

func mysqlFixtureSeedSteps(raw []byte) ([]mysqlFixtureStep, error) {
	var fixture map[string]map[string]any
	// The top-level fixture also has scalar metadata, so select the five objects
	// explicitly instead of decoding unrelated members as object maps.
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil {
		return nil, errors.New("invalid isolated row fixture")
	}
	fixture = make(map[string]map[string]any)
	for _, name := range []string{"operation", "admission", "intent", "result", "result_link"} {
		var part map[string]any
		if json.Unmarshal(top[name], &part) != nil || part == nil {
			return nil, errors.New("incomplete isolated row fixture")
		}
		fixture[name] = part
	}
	body := func(name string) (string, error) {
		part, ok := fixture[name]["body"].(map[string]any)
		if !ok {
			return "", errors.New("invalid isolated audit body fixture")
		}
		value, err := json.Marshal(part)
		return string(value), err
	}
	o, a, i, r, l := fixture["operation"], fixture["admission"], fixture["intent"], fixture["result"], fixture["result_link"]
	ab, err := body("admission")
	if err != nil {
		return nil, err
	}
	ib, err := body("intent")
	if err != nil {
		return nil, err
	}
	rb, err := body("result")
	if err != nil {
		return nil, err
	}
	claims := a["body"].(map[string]any)
	return []mysqlFixtureStep{
		{"seed_operation", "INSERT INTO system_backup_v2_operations (id,public_id,origin_installation_id,actor_id,operation_type,endpoint,status,idempotency_key,request_hash,target_public_id) VALUES (?,?,?,?,?,?,?,?,?,?)", []any{o["id"], o["public_id"], o["installation_id"], o["actor_id"], o["operation_type"], o["endpoint"], o["status"], o["idempotency_key"], o["request_hash"], o["evidence_id"]}},
		{"seed_admission", "INSERT INTO system_backup_v2_download_admission_receipts (operation_id,operation_public_id,origin_installation_id,evidence_public_id,intent_audit_id,receipt_size_bytes,receipt_sha256,receipt_canonical_json) VALUES (?,?,?,?,?,?,?,?)", []any{a["operation_id"], a["operation_public_id"], a["installation_id"], a["evidence_id"], a["intent_audit_id"], a["size_bytes"], a["sha256"], ab}},
		{"seed_intent", "INSERT INTO audit_logs (id,user_id,action,resource_type,resource_id,details) VALUES (?,?,?,?,?,?)", []any{i["id"], i["user_id"], i["action"], i["resource_type"], nil, ib}},
		{"seed_result", "INSERT INTO audit_logs (id,user_id,action,resource_type,resource_id,details) VALUES (?,?,?,?,?,?)", []any{r["id"], r["user_id"], r["action"], r["resource_type"], nil, rb}},
		{"seed_result_link", "INSERT INTO system_backup_v2_download_result_receipts (operation_id,operation_public_id,origin_installation_id,evidence_public_id,intent_audit_id,result_audit_id,result_size_bytes,result_sha256) VALUES (?,?,?,?,?,?,?,?)", []any{l["operation_id"], l["operation_public_id"], l["installation_id"], l["evidence_id"], l["intent_audit_id"], l["result_audit_id"], l["size_bytes"], l["sha256"]}},
		{"seed_nonce", "INSERT INTO system_backup_v2_strong_auth_nonces (operation_id,audit_log_id,origin_installation_id,endpoint,idempotency_key,request_hash,subject_sha256,session_sha256) VALUES (?,?,?,?,?,?,?,?)", []any{o["id"], i["id"], o["installation_id"], o["endpoint"], o["idempotency_key"], o["request_hash"], claims["subject_sha256"], claims["session_sha256"]}},
	}, nil
}

// SQL errors can contain the statement, credentials or audit body. Publish only
// a fixed stage and structured numeric error metadata, never err.Error().
func mysqlFixtureFailure(stage string, err error) string {
	if !regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`).MatchString(stage) {
		stage = "unknown"
	}
	class, code, state := "unclassified", uint16(0), "unknown"
	var sqlError *mysql.MySQLError
	switch {
	case errors.As(err, &sqlError) && sqlError != nil:
		class, code = "mysql", sqlError.Number
		if candidate := string(sqlError.SQLState[:]); regexp.MustCompile(`^[A-Z0-9]{5}$`).MatchString(candidate) {
			state = candidate
		}
	case errors.Is(err, context.DeadlineExceeded):
		class = "deadline"
	case errors.Is(err, context.Canceled):
		class = "canceled"
	}
	return fmt.Sprintf("isolated SQL fixture step failed stage=%s class=%s code=%d sqlstate=%s", stage, class, code, state)
}
