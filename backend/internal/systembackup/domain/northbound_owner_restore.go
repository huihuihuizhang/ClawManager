package domain

import (
	"context"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const NorthboundOwner067Normalizer = "northbound-owner-records.067"

const northboundOwnerColumns = "id record_type record_key scope_id owner owner_normalized instance_id runtime_type instance_mode source_kind source_key session_key question_key status occurred_at created_at updated_at version schema_version rule_version payload prompt_tokens completion_tokens total_tokens invocation_count question_count session_count active_day_count xp_value level_value streak_days longest_streak_days rank_position rank_score last_activity_at business_date timezone period_type period_start period_end category_key revision expires_at active_work_seconds login_day_count login_streak_days last_login_date task_completed_count interval_start interval_end task_code definition_version progress_value target_value completed_at rewarded_at"

var northboundOwnerRank = regexp.MustCompile(`^-?(0|[1-9][0-9]{0,17})\.[0-9]{6}$`)
var northboundOwnerKind = regexp.MustCompile(`^[A-Za-z0-9_]{1,24}$`)

func northboundOwnerShape(t Table) error {
	if t.Name != "northbound_owner_records" || t.Engine != "InnoDB" || len(t.Columns) != 56 || !slices.Equal(t.PrimaryKey, []string{"id"}) || len(t.ForeignKeys) != 0 || len(t.UniqueKeys) != 1 || t.UniqueKeys[0].Name != "uk_owner_record" || !slices.Equal(t.UniqueKeys[0].Columns, []string{"record_type", "record_key"}) {
		return ErrSchema
	}
	seen := map[string]bool{}
	for _, c := range t.Columns {
		kind, nullable := "datetime(6)", true
		switch c.Name {
		case "id", "scope_id", "version":
			kind = "bigint unsigned"
			nullable = false
		case "instance_id", "prompt_tokens", "completion_tokens", "total_tokens", "invocation_count", "question_count", "session_count", "rank_position", "active_work_seconds", "task_completed_count", "progress_value", "target_value":
			kind = "bigint unsigned"
		case "active_day_count", "level_value", "streak_days", "longest_streak_days", "login_day_count", "login_streak_days":
			kind = "int unsigned"
		case "revision":
			kind = "int unsigned"
			nullable = false
		case "xp_value":
			kind = "bigint"
		case "schema_version":
			kind = "smallint unsigned"
			nullable = false
		case "rank_score":
			kind = "decimal(24,6)"
		case "record_type", "status":
			kind = "varchar(24)"
			nullable = false
		case "record_key":
			kind = "char(64)"
			nullable = false
		case "owner", "owner_normalized":
			kind = "varchar(128)"
		case "runtime_type", "source_kind":
			kind = "varchar(32)"
		case "instance_mode", "period_type":
			kind = "varchar(16)"
		case "source_key", "session_key", "question_key":
			kind = "varchar(255)"
		case "rule_version", "category_key", "task_code", "definition_version":
			kind = "varchar(64)"
		case "timezone":
			kind = "varchar(64)"
			nullable = false
		case "payload":
			kind = "json"
		case "business_date", "period_start", "period_end", "last_login_date":
			kind = "date"
		case "created_at", "updated_at":
			nullable = false
		case "occurred_at", "last_activity_at", "expires_at", "interval_start", "interval_end", "completed_at", "rewarded_at":
		default:
			return ErrSchema
		}
		if seen[c.Name] || !slices.Contains(strings.Fields(northboundOwnerColumns), c.Name) || c.Type != kind || c.Nullable != nullable || generatedColumn(c.Extra) {
			return ErrSchema
		}
		seen[c.Name] = true
	}
	return nil
}

func northboundUint(cell Cell, bits int, nullable bool) error {
	if cell.Null {
		if nullable && len(cell.Bytes) == 0 {
			return nil
		}
		return ErrData
	}
	n, e := strconv.ParseUint(cell.String(), 10, bits)
	if e != nil || strconv.FormatUint(n, 10) != cell.String() {
		return ErrData
	}
	return nil
}
func northboundText(cell Cell, limit int, nullable bool) error {
	if cell.Null {
		if nullable && len(cell.Bytes) == 0 {
			return nil
		}
		return ErrData
	}
	if !utf8.Valid(cell.Bytes) || utf8.RuneCount(cell.Bytes) > limit || strings.ContainsRune(cell.String(), 0) {
		return ErrData
	}
	return nil
}
func northboundTime(cell Cell, dateOnly, nullable bool) error {
	if cell.Null {
		if nullable && len(cell.Bytes) == 0 {
			return nil
		}
		return ErrData
	}
	layout := "2006-01-02 15:04:05.999999"
	if dateOnly {
		layout = "2006-01-02"
	}
	at, e := time.Parse(layout, cell.String())
	if e != nil || at.Year() < 1000 || at.Year() > 9999 {
		return ErrData
	}
	canonical := "2006-01-02 15:04:05.000000"
	if dateOnly {
		canonical = "2006-01-02"
	}
	if at.Format(canonical) != cell.String() {
		return ErrData
	}
	return nil
}

// This owner table intentionally has no account/instance FK and no universal
// disabled flag. Preserve literal identities, private payload and every counter;
// never call Store.Bind/Apply/Report/VisitToday/Run to rebuild or verify them.
// In particular activity_window.version is a bitmap, not a CAS increment.
func validateNorthboundOwnerRows(ctx context.Context, t Table) error {
	if northboundOwnerShape(t) != nil {
		return ErrSchema
	}
	unique := map[string]bool{}
	ids := map[string]bool{}
	for _, row := range t.Rows {
		if e := ctx.Err(); e != nil {
			return e
		}
		if len(row) != 56 {
			return ErrData
		}
		for _, column := range t.Columns {
			cell, ok := row[column.Name]
			if !ok || cell.Null && (!column.Nullable || len(cell.Bytes) > 0) {
				return ErrData
			}
			var e error
			switch {
			case column.Type == "bigint unsigned":
				e = northboundUint(cell, 64, column.Nullable)
			case column.Type == "int unsigned":
				e = northboundUint(cell, 32, column.Nullable)
			case column.Type == "smallint unsigned":
				e = northboundUint(cell, 16, column.Nullable)
			case column.Name == "xp_value":
				if !cell.Null {
					n, err := strconv.ParseInt(cell.String(), 10, 64)
					if err != nil || strconv.FormatInt(n, 10) != cell.String() {
						e = ErrData
					}
				}
			case column.Name == "rank_score":
				if !cell.Null && (!northboundOwnerRank.Match(cell.Bytes) || cell.String() == "-0.000000") {
					e = ErrData
				}
			case column.Type == "date":
				e = northboundTime(cell, true, column.Nullable)
			case column.Type == "datetime(6)":
				e = northboundTime(cell, false, column.Nullable)
			case column.Name == "payload":
				if !cell.Null && (len(cell.Bytes) > 8<<20 || strictJSON(cell.Bytes) != nil) {
					e = ErrData
				}
			default:
				limit := 64
				switch column.Name {
				case "record_type", "status":
					limit = 24
				case "owner", "owner_normalized":
					limit = 128
				case "runtime_type", "source_kind":
					limit = 32
				case "instance_mode", "period_type":
					limit = 16
				case "source_key", "session_key", "question_key":
					limit = 255
				}
				e = northboundText(cell, limit, column.Nullable)
			}
			if e != nil {
				return e
			}
		}
		if row["id"].String() == "0" || ids[row["id"].String()] || !northboundOwnerKind.Match(row["record_type"].Bytes) || !ownerRecordKey(row["record_key"].String()) || row["schema_version"].String() != "1" || row["timezone"].String() == "" {
			return ErrData
		}
		ids[row["id"].String()] = true
		key := row["record_type"].String() + "\x00" + row["record_key"].String()
		if unique[key] {
			return ErrData
		}
		unique[key] = true
	}
	return ctx.Err()
}

// ASCII binary collation makes case significant. A stored key is not replaced
// by a newly generated hash or treated as a proof/credential for any endpoint.
func ownerRecordKey(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func validateNorthboundOwnerAdapter(a TableAdapter, t Table) error {
	if a.Normalizer != NorthboundOwner067Normalizer || len(a.LLMSecrets) != 0 || northboundOwnerShape(t) != nil || a.InterruptedAt != "" {
		return ErrSchema
	}
	for _, name := range strings.Fields(northboundOwnerColumns) {
		if a.Columns[name] != "preserve" {
			return ErrSchema
		}
	}
	return nil
}
