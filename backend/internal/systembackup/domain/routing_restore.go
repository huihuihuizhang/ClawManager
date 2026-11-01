package domain

import (
	"context"
	"slices"
	"strings"
	"time"

	"clawreef/internal/systembackup/gatewaypolicy"
	"clawreef/internal/systembackup/team"
)

const RoutingClassifier061Normalizer = "routing-classifier.061"
const routing061Columns = "id base_url timeout_ms encrypted_api_key updated_at routing_mode"

func validateRouting061Adapter(a TableAdapter, t Table) error {
	if a.InterruptedAt != "" || t.Name != "routing_classifier_settings" || len(t.Columns) != 6 || len(t.PrimaryKey) != 1 || t.PrimaryKey[0] != "id" {
		return ErrSchema
	}
	for _, name := range strings.Fields(routing061Columns) {
		if !hasColumn(t, name) || a.Columns[name] != "preserve" {
			return ErrSchema
		}
	}
	for _, column := range t.Columns {
		if column.Nullable {
			return ErrSchema
		}
	}
	return nil
}

func validateRouting061Row(row Row) error {
	var id, timeout int
	var endpoint, credential, mode string
	var updated time.Time
	if err := decodeOwnerCells(row, map[string]any{"id": &id, "base_url": &endpoint, "timeout_ms": &timeout, "encrypted_api_key": &credential, "routing_mode": &mode, "updated_at": &updated}); err != nil {
		return err
	}
	// The owner repository reads singleton 1; its service accepts only these
	// modes and timeout bounds. Do not decrypt or contact the archived endpoint.
	if id != 1 || timeout < 100 || timeout > 30000 || updated.Year() < 1000 || updated.Year() > 9999 || !slices.Contains([]string{"", "rules", "hybrid", "laya"}, mode) {
		return ErrData
	}
	return nil
}

func normalizeRouting061(row Row) error {
	if err := validateRouting061Row(row); err != nil {
		return err
	}
	source := make(team.Row, len(row))
	for name, cell := range row {
		source[name] = team.Cell{IsNull: cell.Null, Data: append([]byte(nil), cell.Bytes...)}
	}
	change := gatewaypolicy.DisableRoutingClassifier(source, map[string]bool{"base_url": false, "encrypted_api_key": false})
	for _, name := range []string{"base_url", "encrypted_api_key", "routing_mode"} {
		cell := change.After[name]
		row[name] = Cell{Null: cell.IsNull, Bytes: append([]byte(nil), cell.Data...)}
	}
	return nil
}

func VerifyRoutingQuarantine(ctx context.Context, snapshot Snapshot) error {
	for _, table := range snapshot.Tables {
		if table.Name != "routing_classifier_settings" || len(table.Rows) == 0 {
			continue
		}
		if len(table.Columns) != 6 || len(table.Rows) != 1 {
			return ErrSchema
		}
		for _, row := range table.Rows {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := validateRouting061Row(row); err != nil {
				return err
			}
			if row["routing_mode"].String() != "rules" || row["base_url"].String() != "" || row["encrypted_api_key"].String() != "" {
				return ErrNormalization
			}
		}
	}
	return nil
}
