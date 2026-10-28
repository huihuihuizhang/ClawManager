package systembackupread

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Actual producer/reader code over scripted read transport. This does not
// establish an installed migration, real SQL locks or a download capability.
func downloadOperationFixture(t *testing.T) (*operationFixture, map[string]any) {
	t.Helper()
	raw, err := os.ReadFile("../../../contracts/system-backup/v12/download-admission-public-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Operation map[string]any `json:"operation"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&vector); err != nil {
		t.Fatal(err)
	}
	f := operationTestFixture()
	for i, name := range operationColumns {
		value, found := vector.Operation[name]
		if !found {
			t.Fatal("incomplete independent public vector", name)
		}
		switch v := value.(type) {
		case json.Number:
			f.row[i], err = v.Int64()
			if err != nil {
				t.Fatal(err)
			}
		case string:
			if strings.HasSuffix(name, "_at") {
				f.row[i], err = time.Parse(time.RFC3339Nano, v)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				f.row[i] = v
			}
		default:
			f.row[i] = value
		}
	}
	return f, vector.Operation
}
func publicDownloadJSON(t *testing.T, value any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDownloadAdmissionOperationReadsSharedPublicVector(t *testing.T) {
	f, expected := downloadOperationFixture(t)
	db := sql.OpenDB(operationConnector{f})
	defer db.Close()
	s, err := NewService(db, f, bytes.Repeat([]byte{'k'}, 32))
	if err != nil {
		t.Fatal(err)
	}
	dto, err := s.GetOperationDTO(context.Background(), operationTestID)
	if err != nil || !reflect.DeepEqual(publicDownloadJSON(t, dto), expected) || f.queries != 1 || f.rechecks != 1 {
		t.Fatal("public read lost or expanded original admission", err)
	}
	f.revoke = true
	if _, err := s.GetOperationDTO(context.Background(), operationTestID); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked scope returned admission", err)
	}
}

func TestDownloadAdmissionOperationListUsesExistingAuthorizedPagination(t *testing.T) {
	download, expected := downloadOperationFixture(t)
	f := makeOperationListFixture()
	f.rows = [][]driver.Value{append([]driver.Value{int64(7)}, download.row...), f.rows[0]}
	db := sql.OpenDB(operationListConnector{f})
	defer db.Close()
	s, err := NewService(db, f, bytes.Repeat([]byte{'k'}, 32))
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.ListOperationDTO(context.Background(), 1, "")
	if err != nil || len(first.Items) != 1 || first.NextCursor == nil || !reflect.DeepEqual(publicDownloadJSON(t, first.Items[0]), expected) {
		t.Fatal("admission missing from public list", err)
	}
	second, err := s.ListOperationDTO(context.Background(), 1, *first.NextCursor)
	if err != nil || len(second.Items) != 1 || second.Items[0].OperationType != "config_update" || second.NextCursor != nil || f.rechecks != 2 {
		t.Fatal("new admission disrupted existing pagination", err)
	}
}

func TestDownloadAdmissionOperationRejectsInconsistentCommittedFacts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		changes map[string]driver.Value
	}{
		{"wrong_type_for_evidence", map[string]driver.Value{"operation_type": "cleanup"}},
		{"wrong_target", map[string]driver.Value{"target_type": "backup", "target_public_id": "sbk_00000000-0000-4000-8000-000000000002"}},
		{"wrong_evidence_id", map[string]driver.Value{"target_public_id": "sev_bad"}},
		{"wrong_endpoint", map[string]driver.Value{"endpoint": "updateSystemBackupConfig"}},
		{"system_actor", map[string]driver.Value{"actor_type": "system", "actor_id": "system:controller"}},
		{"actor_zero", map[string]driver.Value{"actor_id": "0"}}, {"actor_alias", map[string]driver.Value{"actor_id": "042"}},
		{"actor_overflow", map[string]driver.Value{"actor_id": "2147483648"}},
		{"pending", map[string]driver.Value{"status": "pending", "http_status": nil, "started_at": nil, "finished_at": nil}},
		{"running", map[string]driver.Value{"status": "running", "http_status": nil, "finished_at": nil}},
		{"failed", map[string]driver.Value{"status": "failed", "failure_category": "internal_error", "http_status": int64(500)}},
		{"partial_http_is_not_admission_status", map[string]driver.Value{"http_status": int64(206)}},
		{"missing_http", map[string]driver.Value{"http_status": nil}}, {"retryable", map[string]driver.Value{"retryable": true}},
		{"failure", map[string]driver.Value{"failure_category": "internal_error"}},
		{"result_resource", map[string]driver.Value{"result_resource_public_id": "sev_00000000-0000-4000-8000-000000000002"}},
		{"result_config", map[string]driver.Value{"result_config_version": int64(2)}},
		{"missing_start", map[string]driver.Value{"started_at": nil}}, {"missing_finish", map[string]driver.Value{"finished_at": nil}},
		{"late_finish", map[string]driver.Value{"finished_at": time.Date(2026, 10, 19, 2, 0, 0, 1001, time.UTC)}},
		{"late_update", map[string]driver.Value{"updated_at": time.Date(2026, 10, 19, 2, 0, 0, 1001, time.UTC)}},
		{"expired_deadline", map[string]driver.Value{"deadline_at": time.Date(2026, 10, 19, 2, 0, 0, 1000, time.UTC)}},
		{"foreign_installation", map[string]driver.Value{"origin_installation_id": "installation_other"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := downloadOperationFixture(t)
			for name, value := range tc.changes {
				found := false
				for i, column := range operationColumns {
					if name == column {
						f.row[i] = value
						found = true
						break
					}
				}
				if !found {
					t.Fatal("unknown fault column", name)
				}
			}
			db := sql.OpenDB(operationConnector{f})
			defer db.Close()
			r, err := NewReader(db, f)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.GetOperation(context.Background(), operationTestID); !errors.Is(err, ErrUnavailable) || f.queries != 1 {
				t.Fatal("inconsistent admission escaped current public read", err)
			}
		})
	}
}
