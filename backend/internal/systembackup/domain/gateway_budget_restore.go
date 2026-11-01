package domain

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// GatewayBudget055Normalizer is one closed three-table contract. It never
// reconciles pending settlements or treats an all-time ledger as period spend.
// These data-only tables remain in an isolated database with no consumers;
// target writer revocation and independent SELECT-only readback remain required.
const GatewayBudget055Normalizer = "gateway-key-budget.055"

var gatewayBudgetColumns = map[string]string{
	"gateway_keys":                    "id key_id key_prefix token_hash key_type name description owner_user_id instance_id allowed_model_groups status expires_at last_used_at created_by_user_id revoked_at revoked_by_user_id revocation_reason created_at updated_at rpm_limit tpm_limit concurrent_requests_limit budget_limit budget_period budget_spent budget_reset_at budget_currency_review_required budget_currency_reviewed_at",
	"gateway_key_budget_reservations": "reservation_id gateway_key_id reserved_cost actual_cost settlement_status expires_at created_at",
	"gateway_key_budget_ledger":       "reservation_id gateway_key_id actual_cost recorded_at",
}

func isGatewayBudgetTable(name string) bool { _, ok := gatewayBudgetColumns[name]; return ok }

func gatewayBudgetShape(t Table) error {
	fields, known := gatewayBudgetColumns[t.Name]
	if !known || t.Engine != "InnoDB" || len(t.Columns) != len(strings.Fields(fields)) {
		return ErrSchema
	}
	pk := []string{"reservation_id"}
	fks := []ForeignKey{{"gateway_key_id", "gateway_keys", "id"}}
	unique := map[string][]string{}
	if t.Name == "gateway_keys" {
		pk = []string{"id"}
		fks = []ForeignKey{{"instance_id", "instances", "id"}, {"owner_user_id", "users", "id"}}
		unique = map[string][]string{"uk_gateway_keys_key_id": {"key_id"}, "uk_gateway_keys_token_hash": {"token_hash"}, "uk_gateway_keys_managed_instance": {"instance_id", "key_type"}}
	}
	if !slices.Equal(t.PrimaryKey, pk) || len(t.ForeignKeys) != len(fks) || len(t.UniqueKeys) != len(unique) {
		return ErrSchema
	}
	for _, fk := range fks {
		if !slices.Contains(t.ForeignKeys, fk) {
			return ErrSchema
		}
	}
	for _, key := range t.UniqueKeys {
		if !slices.Equal(unique[key.Name], key.Columns) {
			return ErrSchema
		}
		delete(unique, key.Name)
	}
	if len(unique) != 0 {
		return ErrSchema
	}
	for _, name := range strings.Fields(fields) {
		if !hasColumn(t, name) {
			return ErrSchema
		}
	}
	for _, column := range t.Columns {
		kind, nullable := "timestamp", false
		switch column.Name {
		case "id", "gateway_key_id":
			kind = "bigint"
		case "owner_user_id", "instance_id", "created_by_user_id", "revoked_by_user_id":
			kind, nullable = "int", true
		case "rpm_limit", "tpm_limit", "concurrent_requests_limit":
			kind = "int"
		case "key_id":
			kind = "varchar(96)"
		case "key_prefix":
			kind = "varchar(128)"
		case "token_hash":
			kind = "char(64)"
		case "key_type":
			kind = "varchar(32)"
		case "name":
			kind = "varchar(160)"
		case "description":
			kind, nullable = "text", true
		case "allowed_model_groups":
			kind, nullable = "json", true
		case "status":
			kind = "varchar(24)"
		case "revocation_reason":
			kind, nullable = "varchar(255)", true
		case "budget_limit", "budget_spent", "reserved_cost", "actual_cost":
			kind = "decimal(18,8)"
			nullable = column.Name == "actual_cost" && t.Name == "gateway_key_budget_reservations"
		case "budget_period", "settlement_status":
			kind = "varchar(16)"
		case "budget_currency_review_required":
			kind = "tinyint(1)"
		case "reservation_id":
			kind = "varchar(64)"
		case "last_used_at", "revoked_at", "budget_reset_at", "budget_currency_reviewed_at":
			nullable = true
		case "expires_at":
			nullable = t.Name == "gateway_keys"
		case "created_at", "updated_at", "recorded_at":
		default:
			return ErrSchema
		}
		if column.Type != kind || column.Nullable != nullable || generatedColumn(column.Extra) {
			return ErrSchema
		}
	}
	return nil
}

func validateGatewayBudgetAdapter(a TableAdapter, t Table) error {
	if a.Normalizer != GatewayBudget055Normalizer || len(a.LLMSecrets) != 0 || gatewayBudgetShape(t) != nil {
		return ErrSchema
	}
	if _, err := operationRestoreTime(a.InterruptedAt); err != nil {
		return err
	}
	for _, name := range strings.Fields(gatewayBudgetColumns[t.Name]) {
		if a.Columns[name] != "preserve" {
			return ErrSchema
		}
	}
	return nil
}

func validateGatewayBudgetRestore(ctx context.Context, s Snapshot, target []Table, adapters map[string]TableAdapter) (bool, error) {
	if err := validateGatewayAttributions(s); err != nil {
		return false, err
	}
	selected := false
	for _, t := range s.Tables {
		if isGatewayBudgetTable(t.Name) && (len(t.Rows) > 0 || adapters[t.Name].Normalizer == GatewayBudget055Normalizer) {
			selected = true
		}
	}
	if !selected {
		return false, nil
	}
	bySource, byTarget := map[string]Table{}, map[string]Table{}
	for _, t := range s.Tables {
		bySource[t.Name] = t
	}
	for _, t := range target {
		byTarget[t.Name] = t
	}
	frozen := ""
	for name := range gatewayBudgetColumns {
		a := adapters[name]
		if a.Normalizer != GatewayBudget055Normalizer || a.validate(bySource[name]) != nil || a.validate(byTarget[name]) != nil {
			return false, ErrSchema
		}
		if frozen != "" && frozen != a.InterruptedAt {
			return false, ErrNormalization
		}
		frozen = a.InterruptedAt
	}
	if err := validateGatewayBudgetRows(ctx, s, false); err != nil {
		return false, err
	}
	return true, nil
}

var gatewayASCII = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
var gatewayDecimal = regexp.MustCompile(`^(0|[1-9][0-9]{0,9})(\.[0-9]{1,8})?$`)

func gatewayNumber(cell Cell, max int64, nullable bool) error {
	if cell.Null {
		if nullable {
			return nil
		}
		return ErrData
	}
	n, e := strconv.ParseInt(cell.String(), 10, 64)
	if e != nil || n <= 0 || n > max || strconv.FormatInt(n, 10) != cell.String() {
		return ErrData
	}
	return nil
}
func gatewayMoney(cell Cell, nullable bool) (string, error) {
	if cell.Null {
		if nullable {
			return "", nil
		}
		return "", ErrData
	}
	if !gatewayDecimal.Match(cell.Bytes) {
		return "", ErrData
	}
	parts := strings.SplitN(cell.String(), ".", 2)
	fraction := ""
	if len(parts) == 2 {
		fraction = parts[1]
	}
	return parts[0] + "." + fraction + strings.Repeat("0", 8-len(fraction)), nil
}
func gatewayString(cell Cell, limit int, nullable, ascii bool) error {
	if cell.Null {
		if nullable {
			return nil
		}
		return ErrData
	}
	if !utf8.Valid(cell.Bytes) || strings.ContainsRune(cell.String(), 0) || utf8.RuneCount(cell.Bytes) > limit || (!nullable && len(cell.Bytes) == 0) || (ascii && !gatewayASCII.Match(cell.Bytes)) {
		return ErrData
	}
	return nil
}
func gatewayTimestamp(cell Cell, nullable bool) (time.Time, error) {
	if cell.Null {
		if nullable {
			return time.Time{}, nil
		}
		return time.Time{}, ErrData
	}
	var at time.Time
	if decodeOwnerCells(Row{"at": cell}, map[string]any{"at": &at}) != nil || at.Year() < 1000 || at.Year() > 9999 {
		return time.Time{}, ErrData
	}
	return at, nil
}

func validateGatewayBudgetRows(ctx context.Context, s Snapshot, quarantined bool) error {
	if ctx == nil {
		return ErrNormalization
	}
	if err := validateGatewayAttributions(s); err != nil {
		return err
	}
	tables := map[string]Table{}
	keys := map[string]Row{}
	users, instances := map[string]bool{}, map[string]bool{}
	for _, t := range s.Tables {
		tables[t.Name] = t
		for _, r := range t.Rows {
			if t.Name == "users" {
				users[r["id"].String()] = true
			}
			if t.Name == "instances" {
				instances[r["id"].String()] = true
			}
		}
	}
	active := false
	for name := range gatewayBudgetColumns {
		if len(tables[name].Rows) > 0 {
			active = true
		}
	}
	if !active {
		return nil
	}
	for name := range gatewayBudgetColumns {
		if gatewayBudgetShape(tables[name]) != nil {
			return ErrSchema
		}
		for _, row := range tables[name].Rows {
			if len(row) != len(tables[name].Columns) {
				return ErrData
			}
			for _, column := range tables[name].Columns {
				cell, ok := row[column.Name]
				if !ok || cell.Null && (!column.Nullable || len(cell.Bytes) > 0) {
					return ErrData
				}
			}
		}
	}
	keyIDs, hashes, managed := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, r := range tables["gateway_keys"].Rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if gatewayNumber(r["id"], math.MaxInt64, false) != nil || gatewayString(r["key_id"], 96, false, true) != nil || gatewayString(r["key_prefix"], 128, false, false) != nil || gatewayString(r["name"], 160, false, false) != nil || gatewayString(r["description"], 65535, true, false) != nil || gatewayString(r["revocation_reason"], 255, true, false) != nil {
			return ErrData
		}
		if r["token_hash"].Null || len(r["token_hash"].Bytes) != 64 {
			return ErrData
		}
		if _, e := hex.DecodeString(r["token_hash"].String()); e != nil {
			return ErrData
		}
		if !slices.Contains([]string{"managed_instance", "user_created", "service"}, r["key_type"].String()) || !slices.Contains([]string{"active", "disabled", "revoked"}, r["status"].String()) || quarantined && r["status"].String() != "revoked" {
			return ErrNormalization
		}
		for _, name := range []string{"owner_user_id", "instance_id", "created_by_user_id", "revoked_by_user_id"} {
			if gatewayNumber(r[name], math.MaxInt32, true) != nil {
				return ErrData
			}
		}
		if !r["owner_user_id"].Null && !users[r["owner_user_id"].String()] || !r["instance_id"].Null && !instances[r["instance_id"].String()] || r["key_type"].String() == "managed_instance" && r["instance_id"].Null {
			return ErrData
		}
		for _, name := range []string{"rpm_limit", "tpm_limit", "concurrent_requests_limit"} {
			n, e := strconv.ParseInt(r[name].String(), 10, 32)
			if r[name].Null || e != nil || n < 0 || strconv.FormatInt(n, 10) != r[name].String() {
				return ErrData
			}
		}
		for _, name := range []string{"budget_limit", "budget_spent"} {
			if _, e := gatewayMoney(r[name], false); e != nil {
				return e
			}
		}
		if !slices.Contains([]string{"lifetime", "daily", "weekly", "monthly"}, r["budget_period"].String()) || r["budget_currency_review_required"].Null || !slices.Contains([]string{"0", "1"}, r["budget_currency_review_required"].String()) {
			return ErrData
		}
		for _, name := range []string{"created_at", "updated_at", "expires_at", "last_used_at", "revoked_at", "budget_reset_at", "budget_currency_reviewed_at"} {
			if _, e := gatewayTimestamp(r[name], name != "created_at" && name != "updated_at"); e != nil {
				return e
			}
		}
		if !r["allowed_model_groups"].Null {
			var groups []string
			if len(r["allowed_model_groups"].Bytes) > 1<<20 || json.Unmarshal(r["allowed_model_groups"].Bytes, &groups) != nil || len(groups) > 1024 || groups == nil {
				return ErrData
			}
			for _, g := range groups {
				if gatewayString(Text(g), 100, false, false) != nil {
					return ErrData
				}
			}
		}
		id, hash := strings.ToLower(r["key_id"].String()), strings.ToLower(r["token_hash"].String())
		if keyIDs[id] || hashes[hash] || keys[r["id"].String()] != nil {
			return ErrData
		}
		keyIDs[id], hashes[hash] = true, true
		if !r["instance_id"].Null {
			key := r["instance_id"].String() + "/" + r["key_type"].String()
			if managed[key] {
				return ErrData
			}
			managed[key] = true
		}
		keys[r["id"].String()] = r
	}
	if quarantined {
		if len(tables["instance_gateway_token_aliases"].Rows) > 0 {
			return ErrNormalization
		}
		for _, row := range tables["instances"].Rows {
			if status, ok := row["status"]; ok && (status.Null || status.String() != "stopped") {
				return ErrNormalization
			}
			for _, field := range []string{"access_token", "agent_bootstrap_token"} {
				if cell, ok := row[field]; ok && !cell.Null && len(cell.Bytes) > 0 {
					return ErrNormalization
				}
			}
		}
	}
	ledger := map[string]Row{}
	for _, r := range tables["gateway_key_budget_ledger"].Rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if gatewayString(r["reservation_id"], 64, false, true) != nil || gatewayNumber(r["gateway_key_id"], math.MaxInt64, false) != nil || keys[r["gateway_key_id"].String()] == nil {
			return ErrData
		}
		if _, e := gatewayMoney(r["actual_cost"], false); e != nil {
			return e
		}
		if _, e := gatewayTimestamp(r["recorded_at"], false); e != nil {
			return e
		}
		id := strings.ToLower(r["reservation_id"].String())
		if ledger[id] != nil {
			return ErrData
		}
		ledger[id] = r
	}
	reservations := map[string]bool{}
	for _, r := range tables["gateway_key_budget_reservations"].Rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if gatewayString(r["reservation_id"], 64, false, true) != nil || gatewayNumber(r["gateway_key_id"], math.MaxInt64, false) != nil || keys[r["gateway_key_id"].String()] == nil {
			return ErrData
		}
		if _, e := gatewayMoney(r["reserved_cost"], false); e != nil {
			return e
		}
		actual, e := gatewayMoney(r["actual_cost"], true)
		if e != nil {
			return e
		}
		state := r["settlement_status"].String()
		if !slices.Contains([]string{"reserved", "pending", "image_pending"}, state) || state == "pending" && r["actual_cost"].Null || state != "pending" && !r["actual_cost"].Null {
			return ErrData
		}
		for _, name := range []string{"created_at", "expires_at"} {
			if _, e := gatewayTimestamp(r[name], false); e != nil {
				return e
			}
		}
		id := strings.ToLower(r["reservation_id"].String())
		if reservations[id] {
			return ErrData
		}
		reservations[id] = true
		if previous := ledger[id]; previous != nil {
			cost, e := gatewayMoney(previous["actual_cost"], false)
			if e != nil || state != "pending" || previous["gateway_key_id"].String() != r["gateway_key_id"].String() || cost != actual {
				return ErrData
			}
		}
		// An image reservation is not self-authenticating source/job/object
		// evidence. Until the image owner closes its actual job+object receipts,
		// this required nonempty state rejects before any common SQL write.
		if state == "image_pending" {
			return ErrNormalization
		}
	}
	return nil
}

// Migration052 adds nullable historical attribution without a foreign key.
// Deleted keys may legitimately be absent; do not remap to another live key or
// bootstrap identity. Current signed BIGINT bounds/NULL remain explicit.
func validateGatewayAttributions(s Snapshot) error {
	for _, table := range s.Tables {
		if !slices.Contains([]string{"model_invocations", "audit_events", "cost_records"}, table.Name) {
			continue
		}
		present := false
		for _, column := range table.Columns {
			if column.Name == "gateway_key_id" {
				present = true
				if column.Type != "bigint" || !column.Nullable || column.Default != nil || column.Extra != "" {
					return ErrSchema
				}
			}
		}
		if !present {
			continue
		}
		for _, fk := range table.ForeignKeys {
			if fk.Column == "gateway_key_id" {
				return ErrSchema
			}
		}
		for _, row := range table.Rows {
			cell, ok := row["gateway_key_id"]
			if !ok || cell.Null && len(cell.Bytes) > 0 || gatewayNumber(cell, math.MaxInt64, true) != nil {
				return ErrData
			}
		}
	}
	return nil
}

func normalizeGatewayBudgetKey(row Row, frozen string) error {
	if row["status"].String() == "revoked" {
		return nil
	}
	at, err := operationRestoreTime(frozen)
	if err != nil {
		return err
	}
	updated, err := gatewayTimestamp(row["updated_at"], false)
	if err != nil || at.Before(updated) {
		return ErrData
	}
	row["status"] = Text("revoked")
	row["revoked_at"], row["updated_at"] = Text(at.Format("2006-01-02 15:04:05")), Text(at.Format("2006-01-02 15:04:05"))
	row["revoked_by_user_id"] = Cell{Null: true}
	row["revocation_reason"] = Text("isolated restore: source credential disabled")
	return nil
}

// VerifyGatewayBudgetQuarantine reads only the sealed expected rows. The actual
// VerifyDrill subsequently reads the target with independent SELECT-only grants.
// Do not replace that readback with GetBudgetUsage or a repository finalizer.
func VerifyGatewayBudgetQuarantine(ctx context.Context, s Snapshot) error {
	return validateGatewayBudgetRows(ctx, s, true)
}
