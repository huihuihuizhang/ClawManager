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

func SchemaSHA256() string {
	var tables []schemaTable
	if json.Unmarshal(schemaJSON, &tables) != nil {
		return ""
	}
	raw, _ := json.Marshal(tables)
	sum := sha256.Sum256(append([]byte("teams-sql-shape.v1\x00"), raw...))
	return hex.EncodeToString(sum[:])
}

// ValidateCapturedTable checks inert rows without a second SQL transaction.
func ValidateCapturedTable(name string, columns [][4]string, primary []string) error {
	var expected []schemaTable
	if json.Unmarshal(schemaJSON, &expected) != nil {
		return ErrInventory
	}
	for _, t := range expected {
		if t.Name != name {
			continue
		}
		if len(columns) != len(t.Columns) || !reflect.DeepEqual(primary, t.PrimaryKey) {
			return ErrInventory
		}
		for n, c := range t.Columns {
			if columns[n] != [4]string{c.Name, c.Type, c.Nullable, c.Extra} {
				return ErrInventory
			}
		}
		return nil
	}
	return ErrInventory
}
func SQLTableNames() []string {
	var tables []schemaTable
	json.Unmarshal(schemaJSON, &tables)
	out := make([]string, 0, len(tables))
	for _, t := range tables {
		out = append(out, t.Name)
	}
	return out
}

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
		// Table discovery is bounded as well as each column inventory.
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
	rows, err := tx.QueryContext(ctx, "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND (TABLE_NAME='teams' OR LEFT(TABLE_NAME,5)='team_' OR LEFT(TABLE_NAME,11)='owner_team_' OR LEFT(TABLE_NAME,12)='custom_team_') ORDER BY TABLE_NAME")
	if err != nil {
		return ErrInventory
	}
	var names []string
	for rows.Next() {
		var name string
		if rows.Scan(&name) != nil {
			rows.Close()
			return ErrInventory
		}
		names = append(names, name)
		if len(names) > len(expected) {
			rows.Close()
			return ErrInventory
		}
	}
	e := rows.Err()
	rows.Close()
	if e != nil || !reflect.DeepEqual(names, SQLTableNames()) {
		return ErrInventory
	}
	return nil
}
