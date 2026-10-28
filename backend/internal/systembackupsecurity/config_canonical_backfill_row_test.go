package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Independent A/Node row vectors supply actual SQL cells. The adapter receives
// only rows from this driver, never this fixture's precomputed row facts.
type backfillLockedSQLState struct {
	facts                               ConfigBackfillRowFacts
	cells                               map[string]driver.Value
	columns                             []string
	now                                 time.Time
	wrongDatabase                       bool
	offset                              int64
	mode                                string
	callback                            func(string)
	queries, commits, rollbacks, writes int
}
type backfillLockedConnector struct{ s *backfillLockedSQLState }

func (backfillLockedConnector) Driver() driver.Driver { return registrationTestDriver{} }
func (c backfillLockedConnector) Connect(context.Context) (driver.Conn, error) {
	return &backfillLockedConn{s: c.s}, nil
}

type backfillLockedConn struct{ s *backfillLockedSQLState }

func (*backfillLockedConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("not a prepared/write probe")
}
func (*backfillLockedConn) Close() error                { return nil }
func (c *backfillLockedConn) Begin() (driver.Tx, error) { return c, nil }
func (c *backfillLockedConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return c, nil
}
func (c *backfillLockedConn) Commit() error   { c.s.commits++; return nil }
func (c *backfillLockedConn) Rollback() error { c.s.rollbacks++; return nil }
func (c *backfillLockedConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.s.writes++
	return nil, errors.New("read adapter attempted write")
}
func (c *backfillLockedConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	s := c.s
	s.queries++
	stage := "row"
	if q == "SELECT @@server_uuid,DATABASE()" {
		stage = "identity"
	} else if q == "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))" {
		stage = "clock"
	}
	if s.callback != nil {
		s.callback(stage)
	}
	switch stage {
	case "identity":
		database := s.facts.TargetDatabase
		if s.wrongDatabase {
			database += "_wrong"
		}
		return registrationRow(s.facts.TargetServerUUID, database), nil
	case "clock":
		database := s.facts.TargetDatabase
		if s.wrongDatabase {
			database += "_wrong"
		}
		return registrationRow(s.facts.TargetServerUUID, database, s.now, s.offset), nil
	}
	if q != "SELECT * FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR UPDATE" || len(args) != 2 || args[0].Value != s.facts.InstallationID || args[1].Value != s.facts.Version {
		return nil, errors.New("wrong full-row scope/lock or source supplied as SQL facts")
	}
	if s.mode == "query-error" {
		return nil, errors.New("synthetic query failure")
	}
	values := make([]driver.Value, len(s.columns))
	for i, name := range s.columns {
		values[i] = s.cells[name]
	}
	count := 1
	if s.mode == "missing" {
		count = 0
	}
	if s.mode == "duplicate-row" {
		count = 2
	}
	return &backfillLockedRows{s: s, values: values, count: count}, nil
}

type backfillLockedRows struct {
	s      *backfillLockedSQLState
	values []driver.Value
	count  int
	closed bool
}

func (r *backfillLockedRows) Columns() []string { return r.s.columns }
func (r *backfillLockedRows) Close() error {
	if !r.closed {
		r.closed = true
		if r.s.callback != nil {
			r.s.callback("close")
		}
	}
	if r.s.mode == "close-error" {
		return errors.New("synthetic close failure")
	}
	return nil
}
func (r *backfillLockedRows) Next(dest []driver.Value) error {
	if r.s.callback != nil {
		r.s.callback("next")
	}
	if r.count == 0 {
		if r.s.mode == "rows-error" {
			return errors.New("synthetic late rows error")
		}
		return io.EOF
	}
	r.count--
	copy(dest, r.values)
	return nil
}

func backfillLockedFixture(t *testing.T) (*sql.DB, *sql.Tx, *backfillLockedSQLState, []byte, string) {
	t.Helper()
	facts, original := backfillIdentityRowFixture(t)
	_, digest, err := CanonicalConfigBackfillRowIdentity(facts, original)
	if err != nil {
		t.Fatal(err)
	}
	s := &backfillLockedSQLState{facts: facts, cells: map[string]driver.Value{}, now: facts.CreatedAt.Add(time.Hour)}
	for name, value := range facts.Materialized {
		s.cells[name] = []byte(value)
	}
	for name, value := range map[string]driver.Value{"id": []byte(facts.RowID), "schema_version": facts.SchemaVersion, "origin_installation_id": facts.InstallationID, "version": facts.Version, "row_version": facts.RowVersion, "config_sha256": facts.ConfigSHA256, "config_size_bytes": facts.ConfigSizeBytes, "created_by": facts.CreatedBy, "change_reason": nil, "copied_from_version": nil, "created_at": facts.CreatedAt, "canonical_config_json": nil} {
		s.cells[name] = value
	}
	if facts.ChangeReason != nil {
		s.cells["change_reason"] = *facts.ChangeReason
	}
	if facts.CopiedFromVersion != nil {
		s.cells["copied_from_version"] = *facts.CopiedFromVersion
	}
	for name := range s.cells {
		s.columns = append(s.columns, name)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(s.columns)))
	db := sql.OpenDB(backfillLockedConnector{s})
	db.SetMaxOpenConns(2)
	t.Cleanup(func() { db.Close() })
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	return db, tx, s, original, digest
}
func backfillLockedRead(ctx context.Context, tx *sql.Tx, s *backfillLockedSQLState, original []byte) (lockedConfigBackfillRow, error) {
	return readLockedConfigBackfillRow(ctx, tx, DatabaseIdentity{s.facts.TargetServerUUID, s.facts.TargetDatabase}, s.facts.InstallationID, s.facts.Version, original)
}
func backfillAssertEmpty(t *testing.T, result lockedConfigBackfillRow, err error) {
	t.Helper()
	if err == nil || result.tx != nil || result.original != nil || result.rowSHA256 != "" || result.rowID != "" {
		t.Fatal("failed scan disclosed usable row observation", err)
	}
}

func TestConfigBackfillLockedRowMatchesIndependentIdentityAndCallerTransaction(t *testing.T) {
	for _, state := range []string{"null", "same"} {
		t.Run(state, func(t *testing.T) {
			_, tx, s, original, digest := backfillLockedFixture(t)
			if state == "same" {
				s.cells["canonical_config_json"] = append([]byte(nil), original...)
			}
			result, err := backfillLockedRead(context.Background(), tx, s, original)
			if err != nil || result.tx != tx || result.rowSHA256 != digest || result.rowID != s.facts.RowID || !bytes.Equal(result.original, original) || !result.observedAt.Equal(s.now) {
				t.Fatal("lost exact SQL identity", err)
			}
			want := configBackfillCanonicalNull
			if state == "same" {
				want = configBackfillCanonicalOriginal
			}
			if result.canonical != want {
				t.Fatal("NULL and original states conflated")
			}
			if _, err := json.Marshal(result); err == nil {
				t.Fatal("private row metadata serialized")
			}
			if err := recheckLockedConfigBackfillRow(context.Background(), tx, result); err != nil {
				t.Fatal(err)
			}
			if s.writes != 0 || s.commits != 0 || s.rollbacks != 0 {
				t.Fatal("helper changed caller transaction ownership")
			}
			if err := tx.Rollback(); err != nil {
				t.Fatal("helper ended caller transaction", err)
			}
		})
	}
}

func TestConfigBackfillLockedRowEveryActualMaterializedCell(t *testing.T) {
	facts, _ := backfillIdentityRowFixture(t)
	for name := range facts.Materialized {
		t.Run(name, func(t *testing.T) {
			_, tx, s, original, _ := backfillLockedFixture(t)
			s.cells[name] = []byte("actual_SQL_drift")
			result, err := backfillLockedRead(context.Background(), tx, s, original)
			backfillAssertEmpty(t, result, err)
		})
	}
}
func TestConfigBackfillLockedRowMalformedAndMissingFacts(t *testing.T) {
	for _, name := range []string{"schema", "installation", "version", "row-version", "row-id-overflow", "row-id-leading-zero", "float-id", "bool-version", "hash", "size", "creator-null", "creator-type", "reason-type", "empty-reason", "creator-byte-overflow", "reason-byte-overflow", "decimal-float", "integer-float", "materialized-null", "created-offset", "created-submicrosecond", "created-type", "copied-invalid", "canonical-empty", "canonical-different", "canonical-type", "column-extra", "column-missing", "column-duplicate", "missing", "duplicate-row", "query-error", "rows-error", "close-error", "database", "database-at-clock", "clock-offset", "clock-zero", "source-whitespace", "source-different"} {
		t.Run(name, func(t *testing.T) {
			_, tx, s, original, _ := backfillLockedFixture(t)
			switch name {
			case "schema":
				s.cells["schema_version"] = "wrong"
			case "installation":
				s.cells["origin_installation_id"] = "installation_other"
			case "version":
				s.cells["version"] = int64(9007199254740992)
			case "row-version":
				s.cells["row_version"] = int64(2)
			case "row-id-overflow":
				s.cells["id"] = "18446744073709551616"
			case "row-id-leading-zero":
				s.cells["id"] = "01"
			case "float-id":
				s.cells["id"] = float64(1)
			case "bool-version":
				s.cells["version"] = true
			case "hash":
				s.cells["config_sha256"] = strings.Repeat("f", 64)
			case "size":
				s.cells["config_size_bytes"] = int64(len(original) + 1)
			case "creator-null":
				s.cells["created_by"] = nil
			case "creator-type":
				s.cells["created_by"] = true
			case "reason-type":
				s.cells["change_reason"] = int64(1)
			case "empty-reason":
				s.cells["change_reason"] = ""
			case "creator-byte-overflow":
				s.cells["created_by"] = strings.Repeat("旧", 43)
			case "reason-byte-overflow":
				s.cells["change_reason"] = strings.Repeat("史", 171)
			case "decimal-float":
				s.cells["source_size_safety_factor"] = float64(1.2)
			case "integer-float":
				s.cells["max_source_items"] = float64(1)
			case "materialized-null":
				s.cells["max_source_items"] = nil
			case "created-offset":
				s.cells["created_at"] = s.facts.CreatedAt.In(time.FixedZone("other", 3600))
			case "created-submicrosecond":
				s.cells["created_at"] = s.facts.CreatedAt.Add(time.Nanosecond)
			case "created-type":
				s.cells["created_at"] = s.facts.CreatedAt.Format(time.RFC3339Nano)
			case "copied-invalid":
				s.cells["copied_from_version"] = s.facts.Version
			case "canonical-empty":
				s.cells["canonical_config_json"] = []byte{}
			case "canonical-different":
				s.cells["canonical_config_json"] = []byte(`{}`)
			case "canonical-type":
				s.cells["canonical_config_json"] = true
			case "column-extra":
				s.columns = append(s.columns, "unreviewed_immutable_column")
			case "column-missing":
				s.columns = s.columns[1:]
			case "column-duplicate":
				s.columns[0] = s.columns[1]
			case "database":
				s.wrongDatabase = true
			case "database-at-clock":
				s.callback = func(stage string) {
					if stage == "clock" {
						s.wrongDatabase = true
					}
				}
			case "clock-offset":
				s.offset = 3600000000
			case "clock-zero":
				s.now = time.Time{}
			case "source-whitespace":
				original = append(original, ' ')
			case "source-different":
				original = []byte(`{}`)
			default:
				s.mode = name
			}
			result, err := backfillLockedRead(context.Background(), tx, s, original)
			backfillAssertEmpty(t, result, err)
			if s.writes != 0 || s.commits != 0 || s.rollbacks != 0 {
				t.Fatal("failed read ended/mutated transaction")
			}
		})
	}
}

func TestConfigBackfillLockedRowFreezesSourceBeforeSQLCallbacks(t *testing.T) {
	for _, stage := range []string{"identity", "row", "next", "close", "clock"} {
		t.Run(stage, func(t *testing.T) {
			_, tx, s, original, digest := backfillLockedFixture(t)
			expected := append([]byte(nil), original...)
			s.callback = func(at string) {
				if at == stage {
					for i := range original {
						original[i] = '!'
					}
				}
			}
			result, err := backfillLockedRead(context.Background(), tx, s, original)
			if err != nil || result.rowSHA256 != digest || !bytes.Equal(result.original, expected) {
				t.Fatal("callback rewrote validated original", err)
			}
		})
	}
}
func TestConfigBackfillLockedRowCancellationNeverReleasesObservation(t *testing.T) {
	for _, stage := range []string{"before", "identity", "row", "next", "close", "clock"} {
		t.Run(stage, func(t *testing.T) {
			_, tx, s, original, _ := backfillLockedFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if stage == "before" {
				cancel()
			}
			s.callback = func(at string) {
				if at == stage {
					cancel()
				}
			}
			result, err := backfillLockedRead(ctx, tx, s, original)
			backfillAssertEmpty(t, result, err)
			if s.commits != 0 || s.rollbacks != 0 || s.writes != 0 {
				t.Fatal("helper disposed caller transaction")
			}
		})
	}
}

func TestConfigBackfillLockedRowOwnsColumnNamesAndDriverBytesAfterClose(t *testing.T) {
	_, tx, s, original, digest := backfillLockedFixture(t)
	s.callback = func(stage string) {
		if stage == "close" {
			for i := range s.columns {
				s.columns[i] = "reused_driver_column"
			}
			for _, value := range s.cells {
				if raw, ok := value.([]byte); ok {
					for i := range raw {
						raw[i] = '!'
					}
				}
			}
		}
	}
	row, err := backfillLockedRead(context.Background(), tx, s, original)
	if err != nil || row.rowSHA256 != digest || !bytes.Equal(row.original, original) {
		t.Fatal("driver Close changed validated scan mapping/bytes", err)
	}
}
func TestConfigBackfillLockedRowFinalRecheckDetectsImmutableAndCanonicalDrift(t *testing.T) {
	for _, name := range []string{"creator", "reason-null-space", "created", "copied", "copied-valid-change", "materialized", "canonical-null-original", "row-id", "clock-backwards", "wrong-tx"} {
		t.Run(name, func(t *testing.T) {
			db, tx, s, original, _ := backfillLockedFixture(t)
			row, err := backfillLockedRead(context.Background(), tx, s, original)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "creator":
				s.cells["created_by"] = "other creator"
			case "reason-null-space":
				if s.cells["change_reason"] == nil {
					s.cells["change_reason"] = " "
				} else {
					s.cells["change_reason"] = nil
				}
			case "created":
				s.cells["created_at"] = s.facts.CreatedAt.Add(time.Microsecond)
			case "copied":
				s.cells["copied_from_version"] = s.facts.Version
			case "copied-valid-change":
				s.cells["copied_from_version"] = int64(1)
			case "materialized":
				s.cells["source_size_safety_factor"] = "9.99"
			case "canonical-null-original":
				s.cells["canonical_config_json"] = original
			case "row-id":
				s.cells["id"] = "18446744073709551614"
			case "clock-backwards":
				s.now = s.now.Add(-time.Microsecond)
			case "wrong-tx":
				other, e := db.BeginTx(context.Background(), nil)
				if e != nil {
					t.Fatal(e)
				}
				defer other.Rollback()
				tx = other
			}
			if err := recheckLockedConfigBackfillRow(context.Background(), tx, row); err == nil {
				t.Fatal("changed final row accepted")
			}
		})
	}
}
func TestConfigBackfillLockedColumnPinMatchesExactPublishedSchema(t *testing.T) {
	raw, err := os.ReadFile("../db/migrations/097_backup_v2_add_system_backup_config_and_operations.sql")
	if err != nil {
		t.Fatal(err)
	}
	if registrationHash(string(raw)) != "d7eb73daddfe563372cd6ffcbb135e366b35ad3d0f64e32f2c9f4c3d75e51103" {
		t.Fatal("published 066 changed")
	}
	text := string(raw)
	end := strings.Index(text, "  UNIQUE KEY uk_sb_config_version")
	if end < 0 {
		t.Fatal("unknown 066 config definition")
	}
	var names []string
	for _, match := range regexp.MustCompile(`(?m)^  ([a-z][a-z0-9_]*) `).FindAllStringSubmatch(text[:end], -1) {
		names = append(names, match[1])
	}
	names = append(names, "canonical_config_json")
	sort.Strings(names)
	if len(names) != configBackfillLockedColumnCount || registrationHash(strings.Join(names, "\n")) != configBackfillLockedColumnsSHA256 {
		t.Fatal("closed row profile omitted/evolved a physical column")
	}
}
func TestConfigBackfillLockedRowPreservesUnsignedIDAndNullableUnicodeMetadata(t *testing.T) {
	for _, name := range []string{"unsigned", "null-reason", "space-reason", "unicode", "copied", "native-numbers"} {
		t.Run(name, func(t *testing.T) {
			_, tx, s, original, _ := backfillLockedFixture(t)
			switch name {
			case "unsigned":
				s.cells["id"] = uint64(18446744073709551615)
				s.facts.RowID = strconv.FormatUint(18446744073709551615, 10)
			case "null-reason":
				s.cells["change_reason"] = nil
				s.facts.ChangeReason = nil
			case "space-reason":
				s.cells["change_reason"] = " "
				space := " "
				s.facts.ChangeReason = &space
			case "unicode":
				creator := strings.Repeat("旧", 42) + "ab"
				reason := strings.Repeat("史", 170) + "ab"
				s.cells["created_by"] = []byte(creator)
				s.cells["change_reason"] = []byte(reason)
				s.facts.CreatedBy = creator
				s.facts.ChangeReason = &reason
			case "copied":
				copied := int64(1)
				s.cells["copied_from_version"] = copied
				s.facts.CopiedFromVersion = &copied
			case "native-numbers":
				for column, actual := range s.facts.Materialized {
					if column == "enabled" {
						s.cells[column] = actual == "1"
						continue
					}
					if column == "source_size_safety_factor" {
						continue
					}
					if n, e := strconv.ParseInt(actual, 10, 64); e == nil {
						s.cells[column] = n
					}
				}
			}
			_, digest, err := CanonicalConfigBackfillRowIdentity(s.facts, original)
			if err != nil {
				t.Fatal(err)
			}
			row, err := backfillLockedRead(context.Background(), tx, s, original)
			if err != nil || row.rowSHA256 != digest {
				t.Fatal("lossy legacy SQL scalar decoding", err)
			}
		})
	}
}
