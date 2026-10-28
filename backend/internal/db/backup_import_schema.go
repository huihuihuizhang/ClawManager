package db

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

func hashImportFile(raw []byte) string {
	raw = bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	raw = bytes.ReplaceAll(raw, []byte("\r"), []byte("\n"))
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

type importSchema struct {
	Tables []importTable `json:"tables"`
	Facts  [][][]*string `json:"facts"`
}
type importTable struct {
	Name    string   `json:"name"`
	Columns []string `json:"columns"`
}

type importQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Metadata, not SHOW CREATE's changing AUTO_INCREMENT cursor, identifies a
// reviewed source shape. Defaults, generated expressions, keys and constraints
// are included; NULL and empty strings remain distinct.
func readImportSchema(ctx context.Context, q importQueryer) (importSchema, error) {
	var out importSchema
	var executable int
	if err := q.QueryRowContext(ctx, `SELECT
(SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE())+
(SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=DATABASE())+
(SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA=DATABASE())+
(SELECT COUNT(*) FROM information_schema.VIEWS WHERE TABLE_SCHEMA=DATABASE())`).Scan(&executable); err != nil || executable != 0 {
		return out, errors.New("backup import requires a reviewed data-only source schema")
	}
	queries := []string{
		`SELECT TABLE_NAME,TABLE_TYPE,ENGINE,TABLE_COLLATION FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME<>'system_backup_v2_import_journal' ORDER BY BINARY TABLE_NAME`,
		`SELECT TABLE_NAME,COLUMN_NAME,CAST(ORDINAL_POSITION AS CHAR),COLUMN_TYPE,IS_NULLABLE,COLUMN_DEFAULT,EXTRA,CHARACTER_SET_NAME,COLLATION_NAME,GENERATION_EXPRESSION FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME<>'system_backup_v2_import_journal' ORDER BY BINARY TABLE_NAME,ORDINAL_POSITION`,
		`SELECT TABLE_NAME,INDEX_NAME,CAST(NON_UNIQUE AS CHAR),CAST(SEQ_IN_INDEX AS CHAR),COLUMN_NAME,COLLATION,CAST(SUB_PART AS CHAR),NULLABLE,INDEX_TYPE,EXPRESSION FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME<>'system_backup_v2_import_journal' ORDER BY BINARY TABLE_NAME,BINARY INDEX_NAME,SEQ_IN_INDEX`,
		`SELECT k.TABLE_NAME,k.CONSTRAINT_NAME,CAST(k.ORDINAL_POSITION AS CHAR),k.COLUMN_NAME,IF(k.REFERENCED_TABLE_SCHEMA=DATABASE(),'same_schema','foreign_schema'),k.REFERENCED_TABLE_NAME,k.REFERENCED_COLUMN_NAME,r.UPDATE_RULE,r.DELETE_RULE FROM information_schema.KEY_COLUMN_USAGE k JOIN information_schema.REFERENTIAL_CONSTRAINTS r ON r.CONSTRAINT_SCHEMA=k.CONSTRAINT_SCHEMA AND r.TABLE_NAME=k.TABLE_NAME AND r.CONSTRAINT_NAME=k.CONSTRAINT_NAME WHERE k.TABLE_SCHEMA=DATABASE() AND k.TABLE_NAME<>'system_backup_v2_import_journal' AND k.REFERENCED_TABLE_NAME IS NOT NULL ORDER BY BINARY k.TABLE_NAME,BINARY k.CONSTRAINT_NAME,k.ORDINAL_POSITION`,
		`SELECT t.TABLE_NAME,t.CONSTRAINT_NAME,c.CHECK_CLAUSE FROM information_schema.TABLE_CONSTRAINTS t JOIN information_schema.CHECK_CONSTRAINTS c ON c.CONSTRAINT_SCHEMA=t.CONSTRAINT_SCHEMA AND c.CONSTRAINT_NAME=t.CONSTRAINT_NAME WHERE t.TABLE_SCHEMA=DATABASE() AND t.TABLE_NAME<>'system_backup_v2_import_journal' AND t.CONSTRAINT_TYPE='CHECK' ORDER BY BINARY t.TABLE_NAME,BINARY t.CONSTRAINT_NAME`,
	}
	for _, query := range queries {
		rows, err := q.QueryContext(ctx, query)
		if err != nil {
			return out, err
		}
		columns, err := rows.Columns()
		if err != nil {
			rows.Close()
			return out, err
		}
		var records [][]*string
		for rows.Next() {
			values := make([]sql.NullString, len(columns))
			dest := make([]any, len(columns))
			for i := range values {
				dest[i] = &values[i]
			}
			if err = rows.Scan(dest...); err != nil {
				rows.Close()
				return out, err
			}
			record := make([]*string, len(values))
			for i, value := range values {
				if value.Valid {
					copy := value.String
					record[i] = &copy
				}
			}
			records = append(records, record)
		}
		err = errors.Join(rows.Err(), rows.Close())
		if err != nil {
			return out, err
		}
		out.Facts = append(out.Facts, records)
	}
	byName := map[string][]string{}
	for _, row := range out.Facts[1] {
		if row[0] == nil || row[1] == nil {
			return out, errors.New("invalid source column inventory")
		}
		byName[*row[0]] = append(byName[*row[0]], *row[1])
	}
	for name, columns := range byName {
		out.Tables = append(out.Tables, importTable{name, columns})
	}
	sort.Slice(out.Tables, func(i, j int) bool { return out.Tables[i].Name < out.Tables[j].Name })
	return out, nil
}

func importDigest(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func importIdentifier(name string) (string, error) {
	if !regexpImportName.MatchString(name) {
		return "", fmt.Errorf("invalid import identifier")
	}
	return "`" + name + "`", nil
}
