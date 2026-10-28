package systembackupread

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type eventControlFixture struct {
	*executionFixture
	events                                            [][]driver.Value
	messageRows                                       [][]driver.Value
	messageMode                                       string
	queryError, streamError, closeError, ignoreBounds bool
}

func newEventControlFixture(kind TaskKind) *eventControlFixture {
	e := newExecutionFixture(kind)
	row := func(id int64, seconds int) []driver.Value {
		return []driver.Value{id, "system-backup-event.v1", "installation_test", string(kind), e.rows[0][1], "task_status_changed", "info", "pending",
			false, nil, nil, nil, nil, nil, nil, nil, nil, nil, "req_event", e.rows[0][20].(time.Time).Add(time.Duration(seconds) * time.Second)}
	}
	return &eventControlFixture{executionFixture: e, events: [][]driver.Value{row(2, 3), row(3, 2), row(1, 2)}}
}

type eventControlConnector struct{ f *eventControlFixture }

func (c eventControlConnector) Connect(context.Context) (driver.Conn, error) {
	return &eventControlConn{executionConn{c.f.executionFixture}, c.f}, nil
}
func (eventControlConnector) Driver() driver.Driver { return pageDriver{} }

type eventControlConn struct {
	executionConn
	f *eventControlFixture
}
type eventCloseErrorRows struct{ *pageRows }

func (eventCloseErrorRows) Close() error { return errors.New("event rows close failure") }
func (c *eventControlConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	f := c.f
	if strings.HasPrefix(query, taskEventMessageSQLPrefix) {
		f.queries = append(f.queries, query)
		if f.rechecks != 0 || f.commits != 0 || len(args) < 4 || args[0].Value != "installation_test" || args[1].Value != f.rows[0][3] || args[2].Value != f.rows[0][1] {
			return nil, errors.New("message read escaped authorized transaction")
		}
		if f.messageMode == "query" {
			return nil, errors.New("message query failed")
		}
		values := f.messageRows
		if values == nil {
			for _, arg := range args[3:] {
				values = append(values, []driver.Value{arg.Value, "Task is pending."})
			}
		}
		switch f.messageMode {
		case "missing":
			values = values[:0]
		case "duplicate":
			values = append(values, values[0])
		case "foreign":
			values[0][0] = int64(999)
		case "empty":
			values[0][1] = ""
		case "long":
			values[0][1] = strings.Repeat("中", 2049)
		case "utf8":
			values[0][1] = string([]byte{0xff})
		}
		rows := &pageRows{columns: []string{"id", "message"}, values: values}
		if f.messageMode == "stream" {
			return &overviewErrorRows{rows, true}, nil
		}
		if f.messageMode == "close" {
			return eventCloseErrorRows{rows}, nil
		}
		return rows, nil
	}
	if query != taskEventCutoffSQL && query != taskEventControlSQL(false) && query != taskEventControlSQL(true) {
		return c.executionConn.QueryContext(ctx, query, args)
	}
	f.queries = append(f.queries, query)
	if f.queryError {
		return nil, errors.New("event query failed")
	}
	if len(args) < 3 || args[0].Value != "installation_test" || args[1].Value != f.rows[0][3] || args[2].Value != f.rows[0][1] {
		return nil, errors.New("event query not installation/task scoped")
	}
	var max int64
	for _, row := range f.events {
		if row[0].(int64) > max {
			max = row[0].(int64)
		}
	}
	if query == taskEventCutoffSQL {
		return &pageRows{columns: []string{"cutoff"}, values: [][]driver.Value{{max}}}, nil
	}
	continued := query == taskEventControlSQL(true)
	if !continued && len(args) != 5 || continued && len(args) != 8 {
		return nil, errors.New("incorrect event keyset SQL arguments")
	}
	cutoff, _ := strconv.ParseUint(toEventString(args[3].Value), 10, 64)
	limit, _ := strconv.Atoi(toEventString(args[len(args)-1].Value))
	var values [][]driver.Value
	for _, row := range f.events {
		id := uint64(row[0].(int64))
		at := row[19].(time.Time)
		if !f.ignoreBounds {
			if id > cutoff {
				continue
			}
			if continued {
				if args[4].Value != args[5].Value {
					return nil, errors.New("continuation time not repeated exactly")
				}
				before, _ := strconv.ParseUint(toEventString(args[6].Value), 10, 64)
				if !eventPositionBefore(at, id, args[4].Value.(time.Time), before) {
					continue
				}
			}
		}
		values = append(values, row)
		if len(values) == limit {
			break
		}
	}
	rows := &pageRows{columns: strings.Split(taskEventControlColumns, ","), values: values}
	if f.streamError {
		return &overviewErrorRows{rows, true}, nil
	}
	if f.closeError {
		return eventCloseErrorRows{rows}, nil
	}
	return rows, nil
}
func toEventString(value any) string {
	switch v := value.(type) {
	case int64:
		return strconv.FormatInt(v, 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	case int:
		return strconv.Itoa(v)
	}
	return "invalid"
}
func eventControlService(t *testing.T, f *eventControlFixture) *Service {
	t.Helper()
	db := sql.OpenDB(eventControlConnector{f})
	t.Cleanup(func() { db.Close() })
	s, err := NewService(db, f, []byte(strings.Repeat("e", 32)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestTaskEventControlFourKindsScopedKeysetsAndPrivateCopies(t *testing.T) {
	for _, kind := range []TaskKind{BackupTask, DrillTask, PreflightTask, VerificationTask} {
		t.Run(string(kind), func(t *testing.T) {
			f := newEventControlFixture(kind)
			s := eventControlService(t, f)
			id := f.rows[0][1].(string)
			first, err := s.ListTaskEventControl(context.Background(), kind, id, 2, "")
			if err != nil || len(first.Page.Events()) != 2 || first.Page.Events()[0].ID != 2 || first.Page.Events()[1].ID != 3 || first.NextCursor == "" || !first.Page.HasMore() || f.options.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || f.rechecks != 1 || f.commits != 1 {
				t.Fatal("first event page invalid", err, first.Page.Events(), f.queries)
			}
			if len(f.queries) != 3 || f.queries[0] != "SELECT "+taskProjectionColumns+" FROM "+taskTables[kind].name+" WHERE origin_installation_id=? AND public_id=?" {
				t.Fatal("task was not authorized/read before events", f.queries)
			}
			// A newly committed, backdated event cannot enter the held ID cutoff.
			newRow := append([]driver.Value{}, f.events[2]...)
			newRow[0] = int64(4)
			f.events = append(f.events, newRow)
			next, err := s.ListTaskEventControl(context.Background(), kind, id, 2, first.NextCursor)
			if err != nil || len(next.Page.Events()) != 1 || next.Page.Events()[0].ID != 1 || next.Page.HasMore() || next.NextCursor != "" {
				t.Fatal("time/ID tie or stable cutoff failed", err, next.Page.Events())
			}
			copy := first.Page.Events()
			copy[0].EventType = "changed"
			if first.Page.Events()[0].EventType == "changed" {
				t.Fatal("event slice aliases page")
			}
			for _, value := range []any{first, first.Page, first.Page.Events()[0]} {
				if _, err = json.Marshal(value); !errors.Is(err, ErrInvalid) {
					t.Fatal("internal event metadata serialized", err)
				}
			}
			for _, query := range f.queries {
				for _, forbidden := range []string{"message", "SELECT *", "config_snapshot", "failure_message"} {
					if strings.Contains(query, forbidden) {
						t.Fatal("raw text selected", query)
					}
				}
			}
		})
	}
}

func TestTaskEventControlEmptyMissingAndForeignCursor(t *testing.T) {
	for _, scenario := range []string{"empty", "missing", "missing revoked", "foreign cursor"} {
		t.Run(scenario, func(t *testing.T) {
			f := newEventControlFixture(BackupTask)
			s := eventControlService(t, f)
			id := f.rows[0][1].(string)
			var token string
			switch scenario {
			case "empty":
				f.events = nil
			case "missing", "missing revoked":
				id = "sbk_00000000-0000-4000-8000-000000000099"
				if scenario == "missing revoked" {
					f.finalErr = ErrDenied
				}
			case "foreign cursor":
				first, err := s.ListTaskEventControl(context.Background(), BackupTask, id, 2, "")
				if err != nil {
					t.Fatal(err)
				}
				position, err := s.cursor.DecodeTaskEvents(first.NextCursor, BackupTask, id, 2)
				if err != nil {
					t.Fatal(err)
				}
				page := first.Page
				page.installation = "installation_other"
				page.task.InstallationID = page.installation
				for i := range page.events {
					page.events[i].InstallationID = page.installation
				}
				position.InstallationID = ""
				position.CutoffID = 0
				position.BeforeID = 0
				position.BeforeCreatedAt = time.Time{}
				token, err = s.cursor.EncodeTaskEvents(position, page)
				if err != nil {
					t.Fatal(err)
				}
				f.queries = nil
			}
			result, err := s.ListTaskEventControl(context.Background(), BackupTask, id, 2, token)
			if scenario == "empty" {
				if err != nil || result.Page.Events() == nil || len(result.Page.Events()) != 0 || result.NextCursor != "" || f.rechecks != 1 {
					t.Fatal("known empty events incorrect", result, err)
				}
				return
			}
			want := ErrNotFound
			if scenario == "foreign cursor" || scenario == "missing revoked" {
				want = ErrDenied
			}
			if !errors.Is(err, want) || !reflect.ValueOf(result).IsZero() {
				t.Fatal("missing/foreign event read escaped", result, err)
			}
			if scenario == "foreign cursor" && len(f.queries) != 0 || scenario != "foreign cursor" && len(f.queries) != 1 {
				t.Fatal("events selected before scope/task check", f.queries)
			}
		})
	}
}

func TestTaskEventControlRejectsCorruptRows(t *testing.T) {
	type mutate func(*eventControlFixture)
	cases := map[string]mutate{}
	for name, entry := range map[string]struct {
		column int
		value  driver.Value
	}{
		"zero ID": {0, int64(0)}, "schema": {1, "other"}, "installation": {2, "installation_other"}, "kind": {3, "drill"}, "task ID": {4, "sbk_00000000-0000-4000-8000-000000000099"},
		"event type": {5, "secret_payload"}, "diagnostic owner": {5, "diagnostic.z.invalid"}, "level": {6, "debug"}, "task status": {7, "running"},
		"details absent but reason": {11, "reason"}, "request token": {18, "unsafe request"}, "zero timestamp": {19, time.Time{}},
	} {
		column, value := entry.column, entry.value
		cases[name] = func(f *eventControlFixture) { f.events[0][column] = value }
	}
	cases["before task creation"] = func(f *eventControlFixture) { f.events[0][19] = f.rows[0][20].(time.Time).Add(-time.Second) }
	cases["non UTC"] = func(f *eventControlFixture) {
		f.events[0][19] = f.events[0][19].(time.Time).In(time.FixedZone("+08", 8*60*60))
	}
	cases["submicro precision"] = func(f *eventControlFixture) { f.events[0][19] = f.events[0][19].(time.Time).Add(time.Nanosecond) }
	cases["sort regression"] = func(f *eventControlFixture) { f.events[0], f.events[1] = f.events[1], f.events[0] }
	cases["duplicate position"] = func(f *eventControlFixture) { f.events[1] = append([]driver.Value{}, f.events[0]...) }
	for name, entry := range map[string]struct {
		column int
		value  driver.Value
	}{
		"invalid previous token": {9, "raw previous status"}, "invalid current token": {10, "raw current status"}, "invalid reason": {11, "UpperCase"}, "zero attempt": {12, int64(0)}, "large attempt": {12, int64(1 << 32)},
		"operation prefix": {13, "sbk_00000000-0000-4000-8000-000000000001"}, "evidence hash as ID": {14, strings.Repeat("a", 64)}, "truncated no hash": {15, true}, "not truncated extra size": {16, int64(30)},
	} {
		column, value := entry.column, entry.value
		cases[name] = func(f *eventControlFixture) { f.events[0][8] = true; f.events[0][column] = value }
	}
	for name, mutation := range cases {
		t.Run(name, func(t *testing.T) {
			f := newEventControlFixture(BackupTask)
			mutation(f)
			f.ignoreBounds = true
			r, err := eventControlService(t, f).ListTaskEventControl(context.Background(), BackupTask, f.rows[0][1].(string), 2, "")
			if !errors.Is(err, ErrUnavailable) || !reflect.ValueOf(r).IsZero() || f.commits != 0 {
				t.Fatal("corrupt event row published", r, err)
			}
		})
	}
}

func TestTaskEventControlDetailsAndDiagnosticTokensAreObservational(t *testing.T) {
	f := newEventControlFixture(BackupTask)
	row := f.events[0]
	row[5], row[8], row[9], row[10], row[11], row[12] = "diagnostic.d.artifact-state", true, "committed", "deleted", "provider_unavailable", int64(2)
	row[13], row[14] = "sop_00000000-0000-4000-8000-000000000001", "sev_00000000-0000-4000-8000-000000000001"
	row[15], row[16], row[17] = true, "18446744073709551615", strings.Repeat("a", 64)
	r, err := eventControlService(t, f).ListTaskEventControl(context.Background(), BackupTask, f.rows[0][1].(string), 2, "")
	if err != nil {
		t.Fatal(err)
	}
	e := r.Page.Events()[0]
	if e.CurrentStatus.String != "deleted" || e.OriginalSize.V != ^uint64(0) || r.Page.Task().Status != "pending" {
		t.Fatal("diagnostic event changed authoritative task or lost metadata")
	}
}

func TestTaskEventControlFailureAndBuilderBoundaries(t *testing.T) {
	for _, scenario := range []string{"initial deny", "final deny", "commit", "query", "stream", "close", "builder", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			f := newEventControlFixture(BackupTask)
			s := eventControlService(t, f)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := ErrUnavailable
			switch scenario {
			case "initial deny":
				f.deny = true
				want = ErrDenied
			case "final deny":
				f.finalErr = ErrDenied
				want = ErrDenied
			case "commit":
				f.commitErr = errors.New("commit reply lost")
			case "query":
				f.queryError = true
			case "stream":
				f.streamError = true
			case "close":
				f.closeError = true
			}
			result, err := readTaskEventControlInTransaction(ctx, s.reader, TaskEventPageRequest{Kind: BackupTask, PublicID: f.rows[0][1].(string), Limit: 2}, func(ctx context.Context, q detailReadSQL, page TaskEventControlPage) (string, error) {
				if f.rechecks != 0 || f.commits != 0 || len(page.Events()) != 2 {
					t.Fatal("event builder outside full snapshot")
				}
				if _, ok := any(q).(*sql.Tx); ok {
					t.Fatal("raw transaction exposed")
				}
				if _, ok := any(q).(interface{ Commit() error }); ok {
					t.Fatal("commit exposed")
				}
				if scenario == "builder" {
					return "partial", errors.New("A redactor unavailable")
				}
				if scenario == "cancel" {
					cancel()
				}
				return "complete", nil
			})
			if !errors.Is(err, want) || result != "" {
				t.Fatal("failed/unconfirmed event builder published", result, err)
			}
		})
	}
}

func TestTaskEventControlCursorBindsIdentityAndCanonicalPosition(t *testing.T) {
	f := newEventControlFixture(BackupTask)
	s := eventControlService(t, f)
	id := f.rows[0][1].(string)
	r, err := s.ListTaskEventControl(context.Background(), BackupTask, id, 2, "")
	if err != nil {
		t.Fatal(err)
	}
	position, err := s.cursor.DecodeTaskEvents(r.NextCursor, BackupTask, id, 2)
	if err != nil || position.BeforeID != 3 || position.CutoffID != 3 || !position.BeforeCreatedAt.Equal(f.events[1][19].(time.Time)) {
		t.Fatal("cursor failed roundtrip", position, err)
	}
	for name, token := range map[string]string{"changed": r.NextCursor + "x", "padding": strings.Split(r.NextCursor, ".")[0] + "=." + strings.Split(r.NextCursor, ".")[1], "oversize": strings.Repeat("a", maxCursorBytes+1)} {
		t.Run(name, func(t *testing.T) {
			if _, e := s.cursor.DecodeTaskEvents(token, BackupTask, id, 2); !errors.Is(e, ErrInvalid) {
				t.Fatal("bad cursor accepted", e)
			}
		})
	}
	for name, change := range map[string]func([]string){"version": func(v []string) { v[0] = "v2" }, "noncanonical ID": func(v []string) { v[5] = "03" }, "before outside cutoff": func(v []string) { v[7] = "4" }, "noncanonical time": func(v []string) { v[6] = strings.Replace(v[6], ".000000Z", "Z", 1) }, "installation": func(v []string) { v[1] = "invalid" }} {
		t.Run(name, func(t *testing.T) {
			fields := strings.Split(string(mustEventPayload(t, r.NextCursor)), "|")
			change(fields)
			raw := []byte(strings.Join(fields, "|"))
			token := base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(s.cursor.signTaskEventControl(raw))
			if _, e := s.cursor.DecodeTaskEvents(token, BackupTask, id, 2); !errors.Is(e, ErrInvalid) {
				t.Fatal("signed malformed cursor accepted", e)
			}
		})
	}
	for _, params := range []struct {
		kind  TaskKind
		id    string
		limit int
	}{{DrillTask, id, 2}, {BackupTask, "sbk_00000000-0000-4000-8000-000000000099", 2}, {BackupTask, id, 3}} {
		if _, e := s.cursor.DecodeTaskEvents(r.NextCursor, params.kind, params.id, params.limit); !errors.Is(e, ErrInvalid) {
			t.Fatal("cursor moved to another request", e)
		}
	}
	raw := mustEventPayload(t, r.NextCursor)
	wrongDomain := base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(s.cursor.sign(raw))
	if _, e := s.cursor.DecodeTaskEvents(wrongDomain, BackupTask, id, 2); !errors.Is(e, ErrInvalid) {
		t.Fatal("task-list signing domain reused")
	}
	page := r.Page
	page.before++
	if _, e := s.cursor.EncodeTaskEvents(TaskEventPageRequest{Kind: BackupTask, PublicID: id, Limit: 2}, page); !errors.Is(e, ErrInvalid) {
		t.Fatal("incorrect page continuation signed")
	}
}

func mustEventPayload(t *testing.T, token string) []byte {
	t.Helper()
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestTaskEventControlRequestsAndPublishedColumns(t *testing.T) {
	f := newEventControlFixture(BackupTask)
	s := eventControlService(t, f)
	id := f.rows[0][1].(string)
	for _, request := range []TaskEventPageRequest{{Kind: BackupTask, PublicID: id, Limit: 0}, {Kind: DrillTask, PublicID: id, Limit: 2}, {Kind: BackupTask, PublicID: id, Limit: 2, InstallationID: "installation_test"}, {Kind: BackupTask, PublicID: id, Limit: 2, CutoffID: 3, BeforeID: 2}} {
		if _, err := s.reader.ReadTaskEventControlPage(context.Background(), request); !errors.Is(err, ErrInvalid) {
			t.Fatal("malformed request queried events", request, err)
		}
	}
	if len(f.queries) != 0 {
		t.Fatal("invalid request selected task/events")
	}
	ddl, err := os.ReadFile("../db/migrations/099_backup_v2_add_system_backup_coordination_observability.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, column := range strings.Split(taskEventControlColumns, ",") {
		if !strings.Contains(string(ddl), "\n  "+column+" ") {
			t.Fatal("event query selects unknown column", column)
		}
	}
}
