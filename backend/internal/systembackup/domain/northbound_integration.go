package domain

import (
	"context"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"

	resources "clawreef/internal/systembackupresources"
)

func northboundSettingsSelected(s Snapshot) bool {
	for _, t := range s.Tables {
		if t.Name == "northbound_admin_settings" || t.Name == "northbound_settings_audit" {
			return true
		}
	}
	return false
}
func northboundName(name string) bool {
	return name == "northbound_admin_settings" || name == "northbound_settings_audit" || name == "northbound_owner_records"
}
func northboundBudget() resources.NorthboundRestoreBudget {
	return resources.NorthboundRestoreBudget{Rows: 100000, Bytes: 32 << 20}
}

func northboundExportTable(t Table) resources.NorthboundRestoreTable {
	fields := northboundSettingsColumns
	if t.Name == "northbound_settings_audit" {
		fields = northboundAuditColumns
	}
	out := resources.NorthboundRestoreTable{Columns: strings.Fields(fields)}
	for _, row := range t.Rows {
		values := map[string]*string{}
		for _, name := range out.Columns {
			c := row[name]
			if c.Null {
				values[name] = nil
			} else {
				v := c.String()
				values[name] = &v
			}
		}
		out.Rows = append(out.Rows, values)
	}
	return out
}

// Conversion is lossless, including SQL NULL and numbers above signed BIGINT.
// Bound the complete original set before making any string copies. Only the
// settings/audit tables enter the scoped owner bridge; owner records have no FK
// and retain their independent uint64/DECIMAL/private-history validation.
func northboundBridgeSource(ctx context.Context, s Snapshot) (resources.NorthboundRestoreSource, error) {
	var out resources.NorthboundRestoreSource
	tables := map[string]Table{}
	var rows, bytes int64
	for _, t := range s.Tables {
		if t.Name != "northbound_admin_settings" && t.Name != "northbound_settings_audit" {
			continue
		}
		if _, ok := tables[t.Name]; ok {
			return out, ErrSchema
		}
		tables[t.Name] = t
		rows += int64(len(t.Rows))
		if rows > 100000 {
			return out, ErrCapacity
		}
		for _, row := range t.Rows {
			if e := ctx.Err(); e != nil {
				return out, e
			}
			for _, c := range row {
				bytes += int64(len(c.Bytes))
				if bytes > 32<<20 {
					return out, ErrCapacity
				}
			}
		}
	}
	if northboundSettingsShape(tables["northbound_admin_settings"]) != nil || northboundAuditShape(tables["northbound_settings_audit"]) != nil {
		return out, ErrSchema
	}
	if len(tables["northbound_admin_settings"].Rows) != 1 {
		return out, ErrData
	}
	if e := validateNorthboundAuditSource(ctx, tables["northbound_settings_audit"], s); e != nil {
		return out, e
	}
	users := northboundSourceUsers(s)
	actor := tables["northbound_admin_settings"].Rows[0]["updated_by"]
	if !actor.Null && !users[actor.String()] {
		return out, ErrData
	}
	out.Settings = northboundExportTable(tables["northbound_admin_settings"])
	out.Audit = northboundExportTable(tables["northbound_settings_audit"])
	bindings := map[resources.NorthboundRestoreBinding]bool{}
	add := func(kind string, c Cell, zero bool) error {
		if c.Null {
			return nil
		}
		n, e := strconv.ParseInt(c.String(), 10, 64)
		if e != nil || strconv.FormatInt(n, 10) != c.String() || n < 0 || n == 0 && !zero || kind == "user" && n > math.MaxInt32 {
			return ErrData
		}
		if n == 0 {
			return nil
		}
		bindings[resources.NorthboundRestoreBinding{Kind: kind, Source: n, Target: n}] = true
		return nil
	}
	for _, name := range []string{"updated_by", "owner_team_creation_user_id"} {
		if e := add("user", tables["northbound_admin_settings"].Rows[0][name], name == "owner_team_creation_user_id"); e != nil {
			return out, e
		}
	}
	for _, row := range tables["northbound_settings_audit"].Rows {
		if e := add("northbound_settings_audit", row["id"], false); e != nil {
			return out, e
		}
		if e := add("user", row["actor_user_id"], false); e != nil {
			return out, e
		}
	}
	for binding := range bindings {
		out.Bindings = append(out.Bindings, binding)
	}
	sort.Slice(out.Bindings, func(i, j int) bool {
		a, b := out.Bindings[i], out.Bindings[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Source < b.Source
	})
	return out, ctx.Err()
}

func validateRestoreAdapterWithNorthbound(a TableAdapter, t Table) error {
	var e error
	switch a.Normalizer {
	case NorthboundOwner067Normalizer:
		e = validateNorthboundOwnerAdapter(a, t)
	case NorthboundSettings077Normalizer, NorthboundAudit057Normalizer:
		e = validateNorthboundScalarAdapter(a, t)
	default:
		return validateRestoreTableAdapter(a, t)
	}
	if e != nil || SchemaDigest(t) != a.SchemaSHA256 || len(a.Columns) != len(t.Columns) {
		return ErrSchema
	}
	return nil
}

func validateNorthboundRestore(ctx context.Context, source Snapshot, target []Table, p Policy) (map[string]map[string]Row, error) {
	projections := map[string]map[string]Row{}
	src, dst := map[string]Table{}, map[string]Table{}
	for _, t := range source.Tables {
		src[t.Name] = t
	}
	for _, t := range target {
		dst[t.Name] = t
	}
	for _, name := range []string{"northbound_admin_settings", "northbound_settings_audit", "northbound_owner_records"} {
		t, exists := src[name]
		a := p.Dependencies[name]
		selected := exists && (len(t.Rows) > 0 || northboundSettingsSelected(source) || a.Normalizer != "")
		if !selected {
			continue
		}
		expected := NorthboundOwner067Normalizer
		if name == "northbound_admin_settings" {
			expected = NorthboundSettings077Normalizer
		}
		if name == "northbound_settings_audit" {
			expected = NorthboundAudit057Normalizer
		}
		if a.Normalizer != expected || validateRestoreAdapterWithNorthbound(a, t) != nil || validateRestoreAdapterWithNorthbound(a, dst[name]) != nil {
			return nil, ErrSchema
		}
		if name == "northbound_owner_records" {
			if e := validateNorthboundOwnerRows(ctx, t); e != nil {
				return nil, e
			}
		}
	}
	if !northboundSettingsSelected(source) {
		if p.northboundCandidate != nil || p.NorthboundTarget != nil {
			return nil, ErrNormalization
		}
		return projections, nil
	}
	if p.northboundCandidate == nil {
		return nil, ErrNormalization
	}
	original, e := northboundBridgeSource(ctx, source)
	if e != nil {
		return nil, e
	}
	if e = p.northboundCandidate.MatchesSource(original); e != nil {
		return nil, ErrNormalization
	}
	for name, table := range map[string]resources.NorthboundRestoreTable{"northbound_admin_settings": p.northboundCandidate.SettingsProjection(), "northbound_settings_audit": p.northboundCandidate.AuditProjection()} {
		projections[name] = map[string]Row{}
		for _, values := range table.Rows {
			row := Row{}
			for column, c := range values {
				if c == nil {
					row[column] = Cell{Null: true}
				} else {
					row[column] = Text(*c)
				}
			}
			if values["id"] == nil || projections[name][*values["id"]] != nil {
				return nil, ErrData
			}
			projections[name][*values["id"]] = row
		}
	}
	return projections, ctx.Err()
}

// Fresh verification uses only authenticated expected rows and a separate
// SELECT-only SQL connection. No process-local CAS candidate or application
// Store/Current/SaveSettings call is used to rebuild or inspect these tables.
func VerifyNorthboundQuarantine(ctx context.Context, s Snapshot) error {
	selected := northboundSettingsSelected(s)
	settings, audit := Table{}, Table{}
	for _, t := range s.Tables {
		switch t.Name {
		case "northbound_owner_records":
			if e := validateNorthboundOwnerRows(ctx, t); e != nil {
				return e
			}
		case "northbound_admin_settings":
			settings = t
		case "northbound_settings_audit":
			audit = t
		}
	}
	if !selected {
		return ctx.Err()
	}
	if northboundSettingsShape(settings) != nil || northboundAuditShape(audit) != nil || len(settings.Rows) != 1 {
		return ErrSchema
	}
	row := settings.Rows[0]
	if row["id"].String() != "1" || row["api_enabled"].String() != "0" || row["owner_teams_enabled"].String() != "0" || row["require_explicit_callers"].String() != "1" || gatewayNumber(row["version"], math.MaxInt64, false) != nil {
		return ErrNormalization
	}
	if e := validateNorthboundAuditSource(ctx, audit, s); e != nil {
		return e
	}
	for _, r := range audit.Rows {
		for _, name := range []string{"before_json", "after_json"} {
			if c := r[name]; !c.Null && !slices.Equal(c.Bytes, []byte(`"[REDACTED]"`)) {
				return ErrNormalization
			}
		}
	}
	return ctx.Err()
}
