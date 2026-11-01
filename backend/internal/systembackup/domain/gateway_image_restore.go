package domain

import (
	"context"
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"strings"
)

const GatewayImage074Normalizer = "gateway-image.074"

var gatewayImageColumns = map[string]string{
	"gateway_image_artifacts": "id user_id instance_id gateway_key_id model_id request_id media_type byte_size encryption_key ready created_at expires_at",
	"gateway_image_jobs":      "request_id scope_hash idempotency_hash request_hash user_id instance_id gateway_key_id model_id state reservation_id estimate charge settled result_metadata error_code deadline_at created_at updated_at analytics_context analytics_outcome analytics_recorded",
}

func stringInt(n int64) string             { return strconv.FormatInt(n, 10) }
func isGatewayImageTable(name string) bool { _, ok := gatewayImageColumns[name]; return ok }
func gatewayImageTables(s Snapshot) map[string]Table {
	out := map[string]Table{}
	for _, t := range s.Tables {
		out[t.Name] = t
	}
	return out
}

func gatewayImageShape(t Table) error {
	fields, ok := gatewayImageColumns[t.Name]
	if !ok || t.Engine != "InnoDB" || len(t.Columns) != len(strings.Fields(fields)) || len(t.ForeignKeys) != 0 {
		return ErrSchema
	}
	pk := []string{"id"}
	uniques := 0
	if t.Name == "gateway_image_jobs" {
		pk = []string{"request_id"}
		uniques = 1
	}
	if !slices.Equal(t.PrimaryKey, pk) || len(t.UniqueKeys) != uniques {
		return ErrSchema
	}
	if uniques == 1 && (t.UniqueKeys[0].Name != "idx_image_job_idempotency" || !slices.Equal(t.UniqueKeys[0].Columns, []string{"scope_hash", "idempotency_hash"})) {
		return ErrSchema
	}
	seen := map[string]bool{}
	for _, c := range t.Columns {
		kind, nullable := "datetime", false
		switch c.Name {
		case "id", "request_id", "reservation_id", "error_code":
			kind = "varchar(64)"
			if c.Name == "request_id" && t.Name == "gateway_image_artifacts" {
				kind = "varchar(100)"
			}
			nullable = c.Name == "reservation_id"
		case "scope_hash", "idempotency_hash", "request_hash":
			kind = "char(64)"
		case "user_id", "model_id", "instance_id":
			kind = "int"
			nullable = c.Name == "instance_id"
		case "gateway_key_id":
			kind = "bigint"
			nullable = true
		case "byte_size":
			kind = "bigint"
		case "encryption_key":
			kind = "varbinary(32)"
		case "media_type":
			kind = "varchar(32)"
		case "ready", "settled", "analytics_recorded":
			kind = "tinyint(1)"
		case "state":
			kind = "varchar(16)"
		case "estimate", "charge":
			kind = "decimal(18,8)"
		case "result_metadata", "analytics_context", "analytics_outcome":
			kind = "longtext"
			nullable = true
		case "created_at", "updated_at", "expires_at", "deadline_at":
		default:
			return ErrSchema
		}
		if seen[c.Name] || !slices.Contains(strings.Fields(fields), c.Name) || c.Type != kind || c.Nullable != nullable || generatedColumn(c.Extra) {
			return ErrSchema
		}
		seen[c.Name] = true
	}
	return nil
}
func validateGatewayImageAdapter(a TableAdapter, t Table) error {
	if a.Normalizer != GatewayImage074Normalizer || len(a.LLMSecrets) != 0 || gatewayImageShape(t) != nil {
		return ErrSchema
	}
	if _, e := operationRestoreTime(a.InterruptedAt); e != nil {
		return e
	}
	for _, name := range strings.Fields(gatewayImageColumns[t.Name]) {
		if a.Columns[name] != "preserve" {
			return ErrSchema
		}
	}
	return nil
}

func imageOwnerMatches(a, b Row) bool {
	for _, name := range []string{"user_id", "instance_id", "gateway_key_id", "model_id"} {
		if a[name].Null != b[name].Null || a[name].String() != b[name].String() {
			return false
		}
	}
	return true
}

func imageTerminal(state string) bool {
	return state == "completed" || state == "failed" || state == "unknown"
}
func imageCompleteBudgetShape(tables map[string]Table) bool {
	for name := range gatewayBudgetColumns {
		if gatewayBudgetShape(tables[name]) != nil {
			return false
		}
	}
	return true
}
func imageJSON(raw Cell, allowed []string) (map[string]json.RawMessage, error) {
	if raw.Null {
		return nil, nil
	}
	if len(raw.Bytes) > 65536 || strictJSON(raw.Bytes) != nil {
		return nil, ErrData
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw.Bytes, &fields) != nil || fields == nil {
		return nil, ErrData
	}
	for name := range fields {
		if !slices.Contains(allowed, name) {
			return nil, ErrData
		}
	}
	return fields, nil
}

// validateImageRows never calls recovery, settlement, analytics or wall clocks.
// Jobs without keys can legitimately have no reservation. Existing tombstones
// and partial Save metadata are preserved only with complete object material.
func validateImageRows(ctx context.Context, s Snapshot, quarantined bool) error {
	tables := gatewayImageTables(s)
	active := false
	for name := range gatewayImageColumns {
		active = active || len(tables[name].Rows) > 0
	}
	for _, row := range tables["gateway_key_budget_reservations"].Rows {
		active = active || row["settlement_status"].String() == "image_pending"
	}
	if !active {
		return ctx.Err()
	}
	if !imageCompleteBudgetShape(tables) {
		return ErrSchema
	}
	for name := range gatewayImageColumns {
		t := tables[name]
		if gatewayImageShape(t) != nil {
			return ErrSchema
		}
		for _, row := range t.Rows {
			if len(row) != len(t.Columns) {
				return ErrData
			}
			for _, column := range t.Columns {
				c, ok := row[column.Name]
				if !ok || c.Null && (!column.Nullable || len(c.Bytes) > 0) {
					return ErrData
				}
			}
		}
	}
	keys, reservations, ledger, jobs, artifacts := map[string]Row{}, map[string]Row{}, map[string]Row{}, map[string]Row{}, map[string]Row{}
	for _, r := range tables["gateway_keys"].Rows {
		keys[r["id"].String()] = r
	}
	for _, r := range tables["gateway_key_budget_reservations"].Rows {
		reservations[strings.ToLower(r["reservation_id"].String())] = r
	}
	for _, r := range tables["gateway_key_budget_ledger"].Rows {
		ledger[strings.ToLower(r["reservation_id"].String())] = r
	}
	for name := range gatewayImageColumns {
		for _, r := range tables[name].Rows {
			if e := ctx.Err(); e != nil {
				return e
			}
			if gatewayNumber(r["user_id"], math.MaxInt32, false) != nil || gatewayNumber(r["model_id"], math.MaxInt32, false) != nil || gatewayNumber(r["instance_id"], math.MaxInt32, true) != nil || gatewayNumber(r["gateway_key_id"], math.MaxInt64, true) != nil {
				return ErrData
			}
			if _, e := gatewayTimestamp(r["created_at"], false); e != nil {
				return e
			}
			if name == "gateway_image_artifacts" {
				id := r["id"].String()
				if !imageArtifactID.MatchString(id) || artifacts[id] != nil || gatewayString(r["request_id"], 100, false, true) != nil || gatewayString(r["media_type"], 32, false, false) != nil || gatewayNumber(r["byte_size"], 16<<20, false) != nil || r["encryption_key"].Null || len(r["encryption_key"].Bytes) != 32 || !slices.Contains([]string{"0", "1"}, r["ready"].String()) || quarantined && r["ready"].String() != "0" {
					return ErrData
				}
				if _, e := gatewayTimestamp(r["expires_at"], false); e != nil {
					return e
				}
				artifacts[id] = r
			} else {
				id := strings.ToLower(r["request_id"].String())
				if gatewayString(r["request_id"], 64, false, true) != nil || jobs[id] != nil || !slices.Contains([]string{"preparing", "running", "completed", "failed", "unknown"}, r["state"].String()) {
					return ErrData
				}
				if quarantined && (!slices.Contains([]string{"completed", "failed", "unknown"}, r["state"].String()) || r["settled"].String() != "1" || r["analytics_recorded"].String() != "1") {
					return ErrNormalization
				}
				for _, name := range []string{"scope_hash", "idempotency_hash", "request_hash"} {
					if r[name].Null || !imageValidHash(r[name].String()) {
						return ErrData
					}
				}
				for _, name := range []string{"settled", "analytics_recorded"} {
					if r[name].Null || !slices.Contains([]string{"0", "1"}, r[name].String()) {
						return ErrData
					}
				}
				for _, name := range []string{"estimate", "charge"} {
					if _, e := gatewayMoney(r[name], false); e != nil {
						return e
					}
				}
				for _, name := range []string{"updated_at", "deadline_at"} {
					if _, e := gatewayTimestamp(r[name], false); e != nil {
						return e
					}
				}
				if gatewayString(r["reservation_id"], 64, true, true) != nil || r["error_code"].Null || len(r["error_code"].Bytes) > 64 {
					return ErrData
				}
				jobs[id] = r
			}
		}
	}
	unique, holds := map[string]bool{}, map[string]bool{}
	for _, job := range jobs {
		uniqueID := strings.ToLower(job["scope_hash"].String() + "/" + job["idempotency_hash"].String())
		if unique[uniqueID] {
			return ErrData
		}
		unique[uniqueID] = true
		if !job["reservation_id"].Null {
			id := strings.ToLower(job["reservation_id"].String())
			key := keys[job["gateway_key_id"].String()]
			r, l := reservations[id], ledger[id]
			// Physical instance deletion cascades key/reservation/ledger rows,
			// while image idempotency tombstones retain their original IDs. Only
			// an actual complete source three-table absence plus an already
			// settled terminal tombstone admits that historical reference. A
			// present obligation never takes this branch, regardless of flags.
			historical := key == nil && r == nil && l == nil && !job["gateway_key_id"].Null && imageTerminal(job["state"].String()) && job["settled"].String() == "1" && imageCompleteBudgetShape(tables)
			if !historical && (holds[id] || job["gateway_key_id"].Null || key == nil || job["state"].String() == "preparing") {
				return ErrData
			}
			if !historical {
				holds[id] = true
			}
			if !historical && (!key["owner_user_id"].Null && key["owner_user_id"].String() != job["user_id"].String() || !key["instance_id"].Null && (job["instance_id"].Null || key["instance_id"].String() != job["instance_id"].String())) {
				return ErrData
			}
			if !historical && r == nil && l == nil {
				return ErrData
			}
			if r != nil {
				if r["gateway_key_id"].String() != job["gateway_key_id"].String() {
					return ErrData
				}
				estimate, e := gatewayMoney(job["estimate"], false)
				reserve, ee := gatewayMoney(r["reserved_cost"], false)
				if e != nil || ee != nil || estimate != reserve {
					return ErrData
				}
				if r["settlement_status"].String() == "image_pending" {
					if !r["actual_cost"].Null {
						return ErrData
					}
				} else if r["settlement_status"].String() != "pending" {
					return ErrData
				} else {
					actual, e := gatewayMoney(r["actual_cost"], false)
					charge, ee := gatewayMoney(job["charge"], false)
					if e != nil || ee != nil || actual != charge || job["state"].String() == "running" {
						return ErrData
					}
				}
			}
			if l != nil {
				charge, e := gatewayMoney(job["charge"], false)
				cost, ee := gatewayMoney(l["actual_cost"], false)
				if e != nil || ee != nil || charge != cost || l["gateway_key_id"].String() != job["gateway_key_id"].String() {
					return ErrData
				}
			}
		} else if !job["gateway_key_id"].Null && job["state"].String() == "running" {
			return ErrData
		}
		result, e := imageJSON(job["result_metadata"], []string{"created", "artifact_ids", "usage"})
		if e != nil {
			return e
		}
		outcome, e := imageJSON(job["analytics_outcome"], []string{"dispatched", "outcome_uncertain", "provider_status", "artifact_ids", "usage_reported", "rate_limit_tokens", "prompt_tokens", "completion_tokens", "latency_ms", "completed_at"})
		if e != nil {
			return e
		}
		analytics, e := imageJSON(job["analytics_context"], []string{"version", "invocation", "model_name"})
		if e != nil {
			return e
		}
		if analytics != nil {
			var version int
			if json.Unmarshal(analytics["version"], &version) != nil || version != 1 {
				return ErrData
			}
		}
		for _, metadata := range []map[string]json.RawMessage{result, outcome} {
			if raw, ok := metadata["artifact_ids"]; ok {
				var ids []string
				if json.Unmarshal(raw, &ids) != nil || len(ids) > 10 {
					return ErrData
				}
				seen := map[string]bool{}
				for _, id := range ids {
					a := artifacts[id]
					if !imageArtifactID.MatchString(id) || seen[id] {
						return ErrData
					}
					// GC intentionally removes artifact rows/objects before jobs.
					// Missing IDs stay literal tombstone metadata; never invent an
					// artifact, key, object version or receipt for a deleted output.
					if a == nil {
						if !imageTerminal(job["state"].String()) {
							return ErrData
						}
						seen[id] = true
						continue
					}
					if strings.ToLower(a["request_id"].String()) != strings.ToLower(job["request_id"].String()) || !imageOwnerMatches(a, job) {
						return ErrData
					}
					seen[id] = true
				}
			}
		}
	}
	for id, r := range reservations {
		if r["settlement_status"].String() == "image_pending" && !holds[id] {
			return ErrData
		}
	}
	for _, a := range artifacts {
		if job := jobs[strings.ToLower(a["request_id"].String())]; job != nil && !imageOwnerMatches(a, job) {
			return ErrData
		}
	}
	return nil
}

func normalizeGatewayImageRow(name string, row Row, frozen string) error {
	at, e := operationRestoreTime(frozen)
	if e != nil {
		return e
	}
	if name == "gateway_image_artifacts" {
		row["ready"] = Text("0")
		return nil
	}
	if name != "gateway_image_jobs" {
		return ErrSchema
	}
	updated, e := gatewayTimestamp(row["updated_at"], false)
	if e != nil || at.Before(updated) {
		return ErrData
	}
	changed := row["settled"].String() != "1" || row["analytics_recorded"].String() != "1"
	switch row["state"].String() {
	case "preparing":
		row["state"] = Text("failed")
		changed = true
	case "running":
		row["state"] = Text("unknown")
		changed = true
	case "completed", "failed", "unknown":
	default:
		return ErrData
	}
	row["settled"], row["analytics_recorded"] = Text("1"), Text("1")
	if changed {
		row["updated_at"] = Text(at.Format("2006-01-02 15:04:05"))
	}
	return nil
}
func imageProjection(s Snapshot, frozen string) (string, error) {
	projected := Snapshot{Version: Version}
	defer func() {
		for _, table := range projected.Tables {
			for _, row := range table.Rows {
				for _, cell := range row {
					clear(cell.Bytes)
				}
			}
		}
	}()
	for _, t := range s.Tables {
		if !isGatewayImageTable(t.Name) {
			continue
		}
		out := t
		out.Rows = nil
		for _, r := range t.Rows {
			row := cloneRow(r)
			if e := normalizeGatewayImageRow(t.Name, row, frozen); e != nil {
				return "", e
			}
			out.Rows = append(out.Rows, row)
		}
		projected.Tables = append(projected.Tables, out)
	}
	ordered, e := sortedTables(projected.Tables)
	if e != nil || len(ordered) != 2 {
		return "", ErrSchema
	}
	projected.Tables = ordered
	return Digest(projected)
}
