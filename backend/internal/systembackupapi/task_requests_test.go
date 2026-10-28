package systembackupapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	read "clawreef/internal/systembackupread"
)

const completeBackupRequest = `{"requested_parts":["mysql","redis","object_storage","workspace","deployment_resources","secret_bundle"]}`
const localPreflightRequest = `{"source_artifact_type":"backup","source_public_id":"sbk_00000000-0000-4000-8000-000000000001","target_profile":"cluster","restore_target_config_ref":"target_v1"}`

func decodeRequest(t *testing.T, kind read.TaskKind, body string) NormalizedTaskRequest {
	t.Helper()
	_, endpoint, _ := taskRoute(kind)
	r, err := NewTaskRequestContract().Decode(context.Background(), kind, endpoint, json.RawMessage(body))
	if err != nil {
		t.Fatalf("request rejected: %v", err)
	}
	return r
}

func TestTaskRequestsBackupCanonicalIdentity(t *testing.T) {
	want := `{"requested_parts":["mysql","redis","object_storage","workspace","deployment_resources","secret_bundle"],"retry_of_public_id":null,"task_purpose":"acceptance"}`
	for _, raw := range []string{completeBackupRequest,
		` { "retry_of_public_id":null, "task_purpose":"acceptance", "requested_parts":["secret_bundle","deployment_resources","workspace","object_storage","redis","mysql"] } `,
		`{"requested_parts":["mysql","redis","object_storage","workspace","deployment_resources","secret_bundle"],"task_purpose":"\u0061cceptance"}`,
	} {
		r := decodeRequest(t, read.BackupTask, raw)
		if got := string(r.CanonicalJSON()); got != want || sha256.Sum256([]byte(got)) != sha256.Sum256([]byte(want)) {
			t.Fatal("equivalent business request changed bytes/hash", got)
		}
		copy := r.CanonicalJSON()
		copy[0] = 'x'
		if string(r.CanonicalJSON()) != want {
			t.Fatal("mutable canonical request")
		}
	}
}

func TestTaskRequestsPreflightCanonicalIdentity(t *testing.T) {
	want := `{"preflight_mode":"production_readonly","restore_target_config_ref":"target_v1","retry_of_public_id":null,"source_artifact_type":"backup","source_public_id":"sbk_00000000-0000-4000-8000-000000000001","target_profile":"cluster"}`
	for _, raw := range []string{localPreflightRequest, strings.TrimSuffix(localPreflightRequest, "}") + `,"preflight_mode":"production_readonly","retry_of_public_id":null}`} {
		if got := string(decodeRequest(t, read.PreflightTask, raw).CanonicalJSON()); got != want {
			t.Fatal("preflight canonical mismatch", got)
		}
	}
	functional := strings.TrimSuffix(localPreflightRequest, "}") + `,"preflight_mode":"functional_test"}`
	if string(decodeRequest(t, read.PreflightTask, functional).CanonicalJSON()) == want {
		t.Fatal("functional mode collapsed into production")
	}
}

func TestTaskRequestsFunctionalParts(t *testing.T) {
	r := decodeRequest(t, read.BackupTask, `{"task_purpose":"functional_test","requested_parts":["workspace","mysql"]}`)
	if string(r.CanonicalJSON()) != `{"requested_parts":["mysql","workspace"],"retry_of_public_id":null,"task_purpose":"functional_test"}` {
		t.Fatal("partial functional request changed")
	}
}

func TestTaskRequestsRejectInvalidBodies(t *testing.T) {
	cases := []struct {
		name, body string
		kind       read.TaskKind
	}{
		{"empty", `{}`, read.BackupTask},
		{"null", `null`, read.BackupTask},
		{"array", `[]`, read.BackupTask},
		{"partial-acceptance", `{"requested_parts":["mysql"]}`, read.BackupTask},
		{"null-purpose", strings.TrimSuffix(completeBackupRequest, "}") + `,"task_purpose":null}`, read.BackupTask},
		{"unknown", strings.TrimSuffix(completeBackupRequest, "}") + `,"force":true}`, read.BackupTask},
		{"duplicate-key", strings.TrimSuffix(completeBackupRequest, "}") + `,"requested_parts":[]}`, read.BackupTask},
		{"escaped-duplicate-key", strings.TrimSuffix(completeBackupRequest, "}") + `,"requested_\u0070arts":[]}`, read.BackupTask},
		{"case-alias", strings.Replace(completeBackupRequest, "requested_parts", "Requested_Parts", 1), read.BackupTask},
		{"duplicate-part", `{"task_purpose":"functional_test","requested_parts":["mysql","mysql"]}`, read.BackupTask},
		{"invalid-part", `{"task_purpose":"functional_test","requested_parts":["users"]}`, read.BackupTask},
		{"null-parts", `{"requested_parts":null}`, read.BackupTask},
		{"null-part", `{"task_purpose":"functional_test","requested_parts":[null]}`, read.BackupTask},
		{"numeric-part", `{"task_purpose":"functional_test","requested_parts":[1]}`, read.BackupTask},
		{"nested-part", `{"task_purpose":"functional_test","requested_parts":[{}]}`, read.BackupTask},
		{"surrogate", `{"task_purpose":"functional_test","requested_parts":["\ud800"]}`, read.BackupTask},
		{"invalid-utf8", `{"task_purpose":"functional_test","requested_parts":["` + string([]byte{0xff}) + `"]}`, read.BackupTask},
		{"trailing-object", completeBackupRequest + `{}`, read.BackupTask},
		{"trailing-token", completeBackupRequest + `true`, read.BackupTask},
		{"too-large", strings.Repeat(" ", maxTaskBody) + completeBackupRequest, read.BackupTask},
		{"missing-source", `{}`, read.PreflightTask},
		{"wrong-source-kind", strings.Replace(localPreflightRequest, `"backup"`, `"other"`, 1), read.PreflightTask},
		{"wrong-id-kind", strings.Replace(localPreflightRequest, "sbk_", "sci_", 1), read.PreflightTask},
		{"short-id", strings.Replace(localPreflightRequest, "sbk_00000000-0000-4000-8000-000000000001", "x", 1), read.PreflightTask},
		{"url-ref", strings.Replace(localPreflightRequest, "target_v1", "https://example.test/target", 1), read.PreflightTask},
		{"unicode-ref", strings.Replace(localPreflightRequest, "target_v1", `\ud800`, 1), read.PreflightTask},
		{"nonascii-ref", strings.Replace(localPreflightRequest, "target_v1", `\ud83d\ude00`, 1), read.PreflightTask},
		{"oversize-ref", strings.Replace(localPreflightRequest, "target_v1", strings.Repeat("a", 129), 1), read.PreflightTask},
		{"null-ref", strings.Replace(localPreflightRequest, `"target_v1"`, `null`, 1), read.PreflightTask},
		{"numeric-ref", strings.Replace(localPreflightRequest, `"target_v1"`, `123`, 1), read.PreflightTask},
		{"invalid-profile", strings.Replace(localPreflightRequest, "cluster", "docker", 1), read.PreflightTask},
		{"null-mode", strings.TrimSuffix(localPreflightRequest, "}") + `,"preflight_mode":null}`, read.PreflightTask},
		{"unknown-mode", strings.TrimSuffix(localPreflightRequest, "}") + `,"preflight_mode":"acceptance"}`, read.PreflightTask},
		{"wrong-retry-kind", strings.TrimSuffix(localPreflightRequest, "}") + `,"retry_of_public_id":"sbk_00000000-0000-4000-8000-000000000001"}`, read.PreflightTask},
	}
	for _, field := range []string{"request_id", "idempotency_key", "strong_auth_proof", "origin_installation_id", "runner", "profile", "credential"} {
		cases = append(cases, struct {
			name, body string
			kind       read.TaskKind
		}{field, strings.TrimSuffix(completeBackupRequest, "}") + `,"` + field + `":"injected"}`, read.BackupTask})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, endpoint, _ := taskRoute(tc.kind)
			r, err := NewTaskRequestContract().Decode(context.Background(), tc.kind, endpoint, json.RawMessage(tc.body))
			var business *Error
			if r != nil || !errors.As(err, &business) || business.Code != "validation_failed" {
				t.Fatal("invalid input escaped validation", err)
			}
		})
	}
}

func TestTaskRequestsUnavailablePaths(t *testing.T) {
	for _, tc := range []struct {
		kind read.TaskKind
		body string
	}{
		{read.BackupTask, strings.TrimSuffix(completeBackupRequest, "}") + `,"retry_of_public_id":"sbk_00000000-0000-4000-8000-000000000001"}`},
		{read.PreflightTask, strings.TrimSuffix(localPreflightRequest, "}") + `,"retry_of_public_id":"spf_00000000-0000-4000-8000-000000000001"}`},
		{read.PreflightTask, strings.Replace(strings.Replace(localPreflightRequest, `"backup"`, `"catalog_import"`, 1), "sbk_", "sci_", 1)},
	} {
		_, endpoint, _ := taskRoute(tc.kind)
		r, err := NewTaskRequestContract().Decode(context.Background(), tc.kind, endpoint, json.RawMessage(tc.body))
		var business *Error
		if r != nil || !errors.As(err, &business) || business.Code != "not_ready" {
			t.Fatal("unimplemented source/retry silently accepted")
		}
	}
}

func TestTaskRequestsContextAndEndpoint(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, canceled} {
		if r, err := NewTaskRequestContract().Decode(ctx, read.BackupTask, "createSystemBackup", []byte(completeBackupRequest)); err == nil || r != nil {
			t.Fatal("invalid context accepted")
		}
	}
	for _, kind := range []read.TaskKind{read.BackupTask, "unknown"} {
		if r, err := NewTaskRequestContract().Decode(context.Background(), kind, "createSystemBackupPreflight", []byte(completeBackupRequest)); err == nil || r != nil {
			t.Fatal("route/kind mismatch accepted")
		}
	}
}

func TestTaskRequestsConcreteSQLWriterPrepare(t *testing.T) {
	admission := &writerTestAdmission{}
	w, err := NewPublicSQLTaskWriter(NewTaskRequestContract(), admission, true)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := w.Prepare(context.Background(), read.PreflightTask, "createSystemBackupPreflight", []byte(localPreflightRequest))
	if err != nil {
		t.Fatal(err)
	}
	p := prepared.(*preparedSQLTaskWrite)
	if string(p.canonical) != string(decodeRequest(t, read.PreflightTask, localPreflightRequest).CanonicalJSON()) || admission.called != 0 {
		t.Fatal("writer did not freeze concrete request or called admission before authorization")
	}
	if _, err = w.Prepare(context.Background(), read.BackupTask, "createSystemBackup", []byte(`{}`)); err == nil {
		t.Fatal("writer accepted empty production request")
	}
}

func TestTaskRequestsMachineContract(t *testing.T) {
	raw, err := os.ReadFile("../../../contracts/system-backup/v12/admin-mutation-requests.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs map[string]struct {
			AdditionalProperties bool                       `json:"additionalProperties"`
			Required             []string                   `json:"required"`
			Properties           map[string]json.RawMessage `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"BackupCreateRequest", "PreflightCreateRequest"} {
		def, exists := schema.Defs[name]
		if !exists || def.AdditionalProperties || len(def.Required) == 0 || len(def.Properties) == 0 {
			t.Fatal("create schema absent or open", name)
		}
	}
	var openapi struct {
		Paths map[string]struct {
			Post struct {
				Body struct {
					Ref string `json:"$ref"`
				} `json:"requestBody"`
			} `json:"post"`
		} `json:"paths"`
	}
	raw, err = os.ReadFile("../../../contracts/system-backup/v12/admin.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &openapi) != nil {
		t.Fatal("invalid OpenAPI")
	}
	for _, path := range []string{"/admin/system-backups", "/admin/system-backup-preflights"} {
		if openapi.Paths[path].Post.Body.Ref == "" {
			t.Fatal("create route missing request body", path)
		}
	}
}
