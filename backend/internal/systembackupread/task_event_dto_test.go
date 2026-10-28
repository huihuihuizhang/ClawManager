package systembackupread

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestTaskEventsDTOFourKindsAndClosedPublicShape(t *testing.T) {
	for _, kind := range []TaskKind{BackupTask, DrillTask, PreflightTask, VerificationTask} {
		t.Run(string(kind), func(t *testing.T) {
			f := newEventControlFixture(kind)
			s := eventControlService(t, f)
			id := f.rows[0][1].(string)
			result, err := s.ListTaskEventsDTO(context.Background(), kind, id, 2, "")
			if err != nil || len(result.Resource.Items) != 2 || result.Resource.NextCursor == nil || result.InstallationID != "installation_test" || result.TaskRowVersion == 0 || f.commits != 1 || f.rechecks != 1 {
				t.Fatal(result, err)
			}
			if len(f.queries) != 4 || !strings.HasPrefix(f.queries[3], taskEventMessageSQLPrefix) {
				t.Fatal("message batch not part of read snapshot", f.queries)
			}
			raw, err := json.Marshal(result.Resource)
			if err != nil {
				t.Fatal(err)
			}
			var body map[string]json.RawMessage
			if err = json.Unmarshal(raw, &body); err != nil || len(body) != 3 {
				t.Fatal(string(raw), err)
			}
			var items []map[string]any
			json.Unmarshal(body["items"], &items)
			for _, item := range items {
				if len(item) != 10 || item["message"] != "Task is pending." || item["target_type"] != string(kind) || item["target_public_id"] != id || item["details"] != nil {
					t.Fatal(item)
				}
			}
			for _, private := range []string{"origin_installation_id", "row_version", "\"id\"", "config_snapshot"} {
				if strings.Contains(string(raw), private) {
					t.Fatal("private field in event body", string(raw))
				}
			}
			if _, err = json.Marshal(result); !errors.Is(err, ErrInvalid) {
				t.Fatal("transport context serialized", err)
			}
			// Each request is a new transaction; reset fixture boundary counters.
			f.commits, f.rechecks = 0, 0
			next, err := s.ListTaskEventsDTO(context.Background(), kind, id, 2, *result.Resource.NextCursor)
			if err != nil || len(next.Resource.Items) != 1 || next.Resource.NextCursor != nil {
				t.Fatal(next, err)
			}
		})
	}
}

func TestTaskEventsDTOEmptyAndNullableDetails(t *testing.T) {
	t.Run("empty message allowed by contract", func(t *testing.T) {
		f := newEventControlFixture(BackupTask)
		f.messageMode = "empty"
		r, err := eventControlService(t, f).ListTaskEventsDTO(context.Background(), BackupTask, f.rows[0][1].(string), 2, "")
		if err != nil || r.Resource.Items[0].Message != "" {
			t.Fatal(r, err)
		}
	})
	t.Run("empty", func(t *testing.T) {
		f := newEventControlFixture(BackupTask)
		f.events = nil
		r, err := eventControlService(t, f).ListTaskEventsDTO(context.Background(), BackupTask, f.rows[0][1].(string), 2, "")
		if err != nil || r.Resource.Items == nil || len(r.Resource.Items) != 0 || len(f.queries) != 2 {
			t.Fatal(r, err, f.queries)
		}
	})
	t.Run("details", func(t *testing.T) {
		f := newEventControlFixture(BackupTask)
		row := f.events[0]
		row[8], row[9], row[10], row[12] = true, "pending", "capturing", int64(2)
		row[15], row[16], row[17] = true, int64(4096), strings.Repeat("a", 64)
		r, err := eventControlService(t, f).ListTaskEventsDTO(context.Background(), BackupTask, f.rows[0][1].(string), 2, "")
		if err != nil {
			t.Fatal(err)
		}
		d := r.Resource.Items[0].Details
		if d == nil || d.Reason != nil || d.OperationPublicID != nil || !d.Truncated || *d.OriginalSize != 4096 || *d.AttemptNumber != 2 || *d.PreviousStatus != "pending" {
			t.Fatal(d)
		}
	})
}

func TestTaskEventsDTOFailureDiscardsAllPublicData(t *testing.T) {
	for _, scenario := range []string{"query", "stream", "close", "missing", "duplicate", "foreign", "long", "utf8", "unsafe integer", "final deny", "commit", "initial deny", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			f := newEventControlFixture(BackupTask)
			want := ErrUnavailable
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "unsafe integer":
				f.events[0][8], f.events[0][15], f.events[0][16], f.events[0][17] = true, true, "9007199254740992", strings.Repeat("a", 64)
			case "final deny":
				f.finalErr = ErrDenied
				want = ErrDenied
			case "initial deny":
				f.deny = true
				want = ErrDenied
			case "commit":
				f.commitErr = errors.New("lost commit reply")
			case "cancel":
				cancel()
				want = ErrDenied
			default:
				f.messageMode = scenario
			}
			result, err := eventControlService(t, f).ListTaskEventsDTO(ctx, BackupTask, f.rows[0][1].(string), 2, "")
			if !errors.Is(err, want) || !reflect.ValueOf(result).IsZero() {
				t.Fatal("failed event read published partial result", result, err)
			}
		})
	}
}
