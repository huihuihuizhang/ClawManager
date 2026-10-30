package team

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"reflect"
)

// Only the current reviewed repository shape; not arbitrary historic DDL.
//
//go:embed schema.json
var schemaJSON []byte

type schemaColumn struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable string `json:"nullable"`
	Extra    string `json:"extra"`
}
type schemaTable struct {
	Name       string         `json:"name"`
	Columns    []schemaColumn `json:"columns"`
	PrimaryKey []string       `json:"primary_key"`
}

func SchemaSHA256() string { sum := sha256.Sum256(schemaJSON); return hex.EncodeToString(sum[:]) }

// CheckSQLSchema runs on the original authenticated discovery transaction.
// Unknown columns fail before writers are stopped instead of being omitted.
func CheckSQLSchema(ctx context.Context, tx *sql.Tx) error {
	if ctx == nil || tx == nil {
		return ErrInventory
	}
	var expected []schemaTable
	if json.Unmarshal(schemaJSON, &expected) != nil || len(expected) != 11 {
		return ErrInventory
	}
	for _, table := range expected {
		rows, err := tx.QueryContext(ctx, "SELECT COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,EXTRA FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? ORDER BY ORDINAL_POSITION", table.Name)
		if err != nil {
			return ErrInventory
		}
		var actual []schemaColumn
		for rows.Next() {
			var c schemaColumn
			if rows.Scan(&c.Name, &c.Type, &c.Nullable, &c.Extra) != nil {
				rows.Close()
				return ErrInventory
			}
			actual = append(actual, c)
			if len(actual) > len(table.Columns) {
				rows.Close()
				return ErrInventory
			}
		}
		e := rows.Err()
		rows.Close()
		if e != nil || !reflect.DeepEqual(actual, table.Columns) {
			return ErrInventory
		}
	}
	return nil
}
