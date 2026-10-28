package systembackupread

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestProjectTaskListMatchesCommonTaskContractAndRedactsColumns(t *testing.T) {
	for _, tc := range []struct {
		kind          TaskKind
		table, prefix string
	}{
		{BackupTask, "system_backup_v2_backups", "sbk_"},
		{DrillTask, "system_backup_v2_restore_drills", "sdr_"},
		{PreflightTask, "system_backup_v2_preflights", "spf_"},
		{VerificationTask, "system_backup_v2_artifact_verifications", "sav_"},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			fixture := makePageFixture(tc.table, string(tc.kind), tc.prefix)
			db := sql.OpenDB(pageConnector{fixture})
			defer db.Close()
			service, err := NewService(db, fixture, []byte(strings.Repeat("k", 32)))
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.ListTasks(context.Background(), tc.kind, "", 2, "")
			if err != nil {
				t.Fatal(err)
			}
			dto, err := ProjectTaskList(result)
			if err != nil || len(dto.Items) != 2 || dto.NextCursor == nil {
				t.Fatal(dto, err)
			}
			fromService, err := service.ListTaskDTO(context.Background(), tc.kind, "", 2, "")
			if err != nil || len(fromService.Items) != 2 || fromService.NextCursor == nil || fromService.Items[0].PublicID != dto.Items[0].PublicID {
				t.Fatal("service did not return a complete list DTO", fromService, err)
			}
			encoded, err := json.Marshal(dto)
			if err != nil {
				t.Fatal(err)
			}
			var body map[string]any
			if err := json.Unmarshal(encoded, &body); err != nil {
				t.Fatal(err)
			}
			if len(body) != 3 || body["consistency"] != "stable_cutoff" {
				t.Fatalf("invalid list envelope: %s", encoded)
			}
			item := body["items"].([]any)[0].(map[string]any)
			for _, required := range []string{"schema_version", "public_id", "origin_installation_id", "task_type", "actor_type", "actor_id", "endpoint", "idempotency_key", "request_hash", "request_id", "status", "pending_reason", "attention_reason", "can_cancel", "config_version", "retryable", "failure_category", "row_version", "deadline_at", "created_at", "updated_at"} {
				if _, ok := item[required]; !ok {
					t.Fatal("missing task contract field", required)
				}
			}
			for _, forbidden := range []string{"id", "config_snapshot_json", "failure_message", "controller_owner", "artifact_uri", "provider_data"} {
				if _, ok := item[forbidden]; ok {
					t.Fatal("sensitive or internal field escaped", forbidden)
				}
			}
			if item["retry_of_public_id"] != nil {
				t.Fatal("unexpected retry reference")
			}
			for _, query := range fixture.queries {
				if strings.Contains(query, "SELECT *") || strings.Contains(query, "config_snapshot_json") || strings.Contains(query, "failure_message") {
					t.Fatal("unsafe SQL projection", query)
				}
			}
		})
	}
}

func TestProjectTaskListFailsClosedOnMalformedOrMixedScope(t *testing.T) {
	f := makePageFixture("system_backup_v2_backups", "backup", "sbk_")
	db := sql.OpenDB(pageConnector{f})
	defer db.Close()
	service, err := NewService(db, f, []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.ListTasks(context.Background(), BackupTask, "", 2, "")
	if err != nil {
		t.Fatal(err)
	}
	validCursor := result.NextCursor
	result.Page.Items[0].InstallationID = "installation_other"
	if _, err := ProjectTaskList(result); !errors.Is(err, ErrUnavailable) {
		t.Fatal("mixed installation escaped", err)
	}
	result.Page.Items[0].InstallationID = "installation_test"
	result.Page.Items[0].RequestHash = "secret text"
	if _, err := ProjectTaskList(result); !errors.Is(err, ErrUnavailable) {
		t.Fatal("invalid hash escaped", err)
	}
	result.Page.Items[0].RequestHash = strings.Repeat("a", 64)
	result.Page.Items[0].RowVersion = maxJSONSafeInteger + 1
	if _, err := ProjectTaskList(result); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unsafe JSON integer escaped", err)
	}
	result.Page.Items[0].RowVersion = 1
	result.NextCursor = ""
	if _, err := ProjectTaskList(result); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unfinished page escaped", err)
	}
	result.NextCursor = validCursor
	result.Page.Items[1].ID = result.Page.Items[0].ID
	if _, err := ProjectTaskList(result); !errors.Is(err, ErrUnavailable) {
		t.Fatal("duplicate keyset row escaped", err)
	}
	result.Page.Items[1].ID = 2
	result.Page.Items[1].Kind = DrillTask
	if _, err := ProjectTaskList(result); !errors.Is(err, ErrUnavailable) {
		t.Fatal("mixed task kinds escaped", err)
	}
	result.Page.Items[1].Kind = BackupTask
	result.Page.BeforeID = 1
	if _, err := ProjectTaskList(result); !errors.Is(err, ErrUnavailable) {
		t.Fatal("cursor position disagreed with last row", err)
	}
}
