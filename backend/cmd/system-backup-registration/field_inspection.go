package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

// This mode never loads registration/download authority, opens a journal,
// reserves capacity, contacts providers, starts HTTP or commits a transaction.
var errFieldSQLInspection = errors.New("SQL field inspection rejected")

const fieldSQLRequestVersion = "system-backup-sql-field-request.v1"
const fieldSQLResultVersion = "system-backup-sql-field-result.v1"

var fieldSQLIdentifier = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
var fieldSQLUUID = regexp.MustCompile(`^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$`)

type fieldSQLRequest struct {
	SchemaVersion string   `json:"schema_version"`
	Mode          string   `json:"mode"`
	DSNEnv        string   `json:"dsn_env"`
	ServerUUID    string   `json:"server_uuid"`
	Database      string   `json:"database"`
	ExpectedUser  string   `json:"expected_user"`
	Tables        []string `json:"tables"`
}

type fieldSQLIdentity struct {
	ServerUUID  string `json:"server_uuid"`
	Database    string `json:"database"`
	CurrentUser string `json:"current_user"`
	CurrentRole string `json:"current_role"`
	SQLTime     string `json:"sql_time"`
}

type fieldSQLCapacityIdentity struct {
	ServerUUID    string `json:"server_uuid"`
	Database      string `json:"database"`
	DataDirectory string `json:"data_directory"`
	Now           string `json:"now"`
}

type fieldSQLResult struct {
	SchemaVersion    string                    `json:"schema_version"`
	Mode             string                    `json:"mode"`
	RequestSHA256    string                    `json:"request_sha256"`
	Identity         *fieldSQLIdentity         `json:"identity"`
	AfterIdentity    *fieldSQLIdentity         `json:"after_identity"`
	Grants           []string                  `json:"grants"`
	Metadata         []json.RawMessage         `json:"metadata"`
	CapacityIdentity *fieldSQLCapacityIdentity `json:"capacity_identity"`
	ReadOnly         bool                      `json:"readonly"`
	RolledBack       bool                      `json:"rolled_back"`
}

func fieldInspectionFlags(names []string, positional int) bool {
	return positional == 0 && len(names) == 1 && names[0] == "inspect-sql-evidence"
}

func decodeFieldSQLRequest(raw []byte) (fieldSQLRequest, error) {
	var r fieldSQLRequest
	if len(raw) == 0 || len(raw) > 65536 || strictDeploymentJSON(raw, &r) != nil || r.SchemaVersion != fieldSQLRequestVersion ||
		!fieldSQLUUID.MatchString(r.ServerUUID) || !fieldSQLIdentifier.MatchString(r.Database) || !fieldSQLIdentifier.MatchString(r.ExpectedUser) || r.Tables == nil {
		return fieldSQLRequest{}, errFieldSQLInspection
	}
	if r.DSNEnv != "SYSTEM_BACKUP_REGISTRATION_DSN_FILE" && r.DSNEnv != "SYSTEM_BACKUP_DOWNLOAD_DSN_FILE" && r.DSNEnv != "SYSTEM_BACKUP_GC_DSN_FILE" {
		return fieldSQLRequest{}, errFieldSQLInspection
	}
	if r.Mode != "metadata" && r.Mode != "identity" || r.Mode == "metadata" && (len(r.Tables) == 0 || len(r.Tables) > 256) || r.Mode == "identity" && len(r.Tables) != 0 {
		return fieldSQLRequest{}, errFieldSQLInspection
	}
	seen := map[string]bool{}
	for _, table := range r.Tables {
		if !fieldSQLIdentifier.MatchString(table) || seen[table] {
			return fieldSQLRequest{}, errFieldSQLInspection
		}
		seen[table] = true
	}
	return r, nil
}

func fieldInspectionDSN(r fieldSQLRequest, getenv func(string) string) (*mysql.Config, error) {
	// Reuse the existing bounded file reader, including projected Secret files.
	raw, err := deploymentBytes(getenv(r.DSNEnv), 8192)
	if err != nil {
		return nil, errFieldSQLInspection
	}
	defer func() { clear(raw) }()
	cfg, err := mysql.ParseDSN(strings.TrimSpace(string(raw)))
	if err != nil || cfg.User != r.ExpectedUser || cfg.DBName != r.Database || cfg.MultiStatements {
		return nil, errFieldSQLInspection
	}
	// Preserve the mounted DSN's transport/TLS configuration, as the actual
	// runtime does. Never print its path, contents, network address or password.
	cfg.ParseTime, cfg.Loc, cfg.MultiStatements = true, time.UTC, false
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 10*time.Second, 10*time.Second
	if cfg.Params == nil {
		cfg.Params = map[string]string{}
	}
	cfg.Params["time_zone"] = "'+00:00'"
	return cfg, nil
}

func runFieldSQLInspection(ctx context.Context, input io.Reader, output io.Writer, getenv func(string) string) error {
	if ctx == nil || ctx.Err() != nil || input == nil || output == nil || getenv == nil {
		return errFieldSQLInspection
	}
	raw, err := io.ReadAll(io.LimitReader(input, 65537))
	if err != nil {
		return errFieldSQLInspection
	}
	r, err := decodeFieldSQLRequest(raw)
	if err != nil {
		return errFieldSQLInspection
	}
	cfg, err := fieldInspectionDSN(r, getenv)
	if err != nil {
		return errFieldSQLInspection
	}
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return errFieldSQLInspection
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)
	probe, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	result, err := inspectFieldSQL(probe, db, r)
	if err != nil {
		return errFieldSQLInspection
	}
	sum := sha256.Sum256(raw)
	result.RequestSHA256 = hex.EncodeToString(sum[:])
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > 4*1024*1024 || probe.Err() != nil {
		return errFieldSQLInspection
	}
	// No public partial result is emitted on SQL, scan, close or rollback failure.
	if _, err = output.Write(append(encoded, '\n')); err != nil {
		return errFieldSQLInspection
	}
	return nil
}

func fieldReadIdentity(ctx context.Context, tx *sql.Tx, r fieldSQLRequest) (*fieldSQLIdentity, error) {
	var v fieldSQLIdentity
	err := tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),CURRENT_USER(),CURRENT_ROLE(),DATE_FORMAT(UTC_TIMESTAMP(6),'%Y-%m-%dT%H:%i:%s.%fZ')").Scan(&v.ServerUUID, &v.Database, &v.CurrentUser, &v.CurrentRole, &v.SQLTime)
	if err != nil || v.ServerUUID != r.ServerUUID || v.Database != r.Database || !strings.HasPrefix(v.CurrentUser, r.ExpectedUser+"@") || len(v.CurrentUser) <= len(r.ExpectedUser)+1 || v.CurrentRole == "" {
		return nil, errFieldSQLInspection
	}
	if t, err := time.Parse(time.RFC3339Nano, v.SQLTime); err != nil || t.IsZero() {
		return nil, errFieldSQLInspection
	}
	return &v, nil
}

func inspectFieldSQL(ctx context.Context, db *sql.DB, r fieldSQLRequest) (fieldSQLResult, error) {
	empty := fieldSQLResult{}
	if ctx == nil || ctx.Err() != nil || db == nil {
		return empty, errFieldSQLInspection
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return empty, errFieldSQLInspection
	}
	defer tx.Rollback()
	result := fieldSQLResult{SchemaVersion: fieldSQLResultVersion, Mode: r.Mode, Grants: []string{}, Metadata: []json.RawMessage{}, ReadOnly: true}
	result.Identity, err = fieldReadIdentity(ctx, tx, r)
	if err != nil {
		return empty, errFieldSQLInspection
	}
	if r.Mode == "identity" {
		var v fieldSQLCapacityIdentity
		err = tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),@@datadir,DATE_FORMAT(UTC_TIMESTAMP(6),'%Y-%m-%dT%H:%i:%s.%fZ')").Scan(&v.ServerUUID, &v.Database, &v.DataDirectory, &v.Now)
		if err != nil || v.ServerUUID != r.ServerUUID || v.Database != r.Database || v.DataDirectory == "" {
			return empty, errFieldSQLInspection
		}
		result.CapacityIdentity = &v
	} else {
		rows, e := tx.QueryContext(ctx, "SHOW GRANTS")
		if e != nil {
			return empty, errFieldSQLInspection
		}
		for rows.Next() {
			var grant string
			if rows.Scan(&grant) != nil || !strings.HasPrefix(grant, "GRANT ") || strings.ContainsAny(grant, "\x00\r\n") || len(grant) > 4096 || len(result.Grants) >= 256 {
				rows.Close()
				return empty, errFieldSQLInspection
			}
			result.Grants = append(result.Grants, grant)
		}
		streamErr, closeErr := rows.Err(), rows.Close()
		if streamErr != nil || closeErr != nil || len(result.Grants) == 0 {
			return empty, errFieldSQLInspection
		}
		total := 0
		for _, query := range fieldMetadataSQL(r.Tables) {
			rows, e := tx.QueryContext(ctx, query)
			if e != nil {
				return empty, errFieldSQLInspection
			}
			for rows.Next() {
				var raw []byte
				if rows.Scan(&raw) != nil || len(raw) == 0 || len(raw) > 65536 || total+len(raw) > 3*1024*1024 || len(result.Metadata) >= 16384 {
					rows.Close()
					return empty, errFieldSQLInspection
				}
				var record map[string]json.RawMessage
				if strictDeploymentJSON(raw, &record) != nil || len(record["kind"]) == 0 || len(record["table"]) == 0 {
					rows.Close()
					return empty, errFieldSQLInspection
				}
				result.Metadata = append(result.Metadata, bytes.Clone(raw))
				total += len(raw)
			}
			streamErr, closeErr := rows.Err(), rows.Close()
			if streamErr != nil || closeErr != nil {
				return empty, errFieldSQLInspection
			}
		}
		seen := map[string]bool{}
		for _, raw := range result.Metadata {
			var record struct{ Kind, Table string }
			if json.Unmarshal(raw, &record) != nil {
				return empty, errFieldSQLInspection
			}
			if record.Kind == "table" {
				if seen[record.Table] {
					return empty, errFieldSQLInspection
				}
				seen[record.Table] = true
			}
		}
		if len(seen) != len(r.Tables) {
			return empty, errFieldSQLInspection
		}
		for _, name := range r.Tables {
			if !seen[name] {
				return empty, errFieldSQLInspection
			}
		}
	}
	result.AfterIdentity, err = fieldReadIdentity(ctx, tx, r)
	if err != nil || result.Identity.CurrentUser != result.AfterIdentity.CurrentUser || result.Identity.CurrentRole != result.AfterIdentity.CurrentRole {
		return empty, errFieldSQLInspection
	}
	if tx.Rollback() != nil || ctx.Err() != nil {
		return empty, errFieldSQLInspection
	}
	result.RolledBack = true
	return result, nil
}

func fieldMetadataSQL(tables []string) []string {
	names := append([]string(nil), tables...)
	sort.Strings(names)
	for n := range names {
		names[n] = "'" + names[n] + "'"
	}
	list := strings.Join(names, ",")
	return []string{
		"SELECT JSON_OBJECT('kind','table','table',TABLE_NAME,'engine',ENGINE,'collation',TABLE_COLLATION) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN (" + list + ") ORDER BY TABLE_NAME",
		"SELECT JSON_OBJECT('kind','column','table',TABLE_NAME,'name',COLUMN_NAME,'ordinal',ORDINAL_POSITION,'type',COLUMN_TYPE,'nullable',IS_NULLABLE,'extra',EXTRA,'default_sha256',IF(COLUMN_DEFAULT IS NULL,NULL,SHA2(COLUMN_DEFAULT,256))) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN (" + list + ") ORDER BY TABLE_NAME,ORDINAL_POSITION",
		"SELECT JSON_OBJECT('kind','index','table',TABLE_NAME,'name',INDEX_NAME,'ordinal',SEQ_IN_INDEX,'column',COLUMN_NAME,'unique',NON_UNIQUE,'prefix',SUB_PART,'type',INDEX_TYPE,'expression_sha256',IF(EXPRESSION IS NULL,NULL,SHA2(EXPRESSION,256))) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN (" + list + ") ORDER BY TABLE_NAME,INDEX_NAME,SEQ_IN_INDEX",
		"SELECT JSON_OBJECT('kind','foreign_key','schema',TABLE_SCHEMA,'table',TABLE_NAME,'name',CONSTRAINT_NAME,'column',COLUMN_NAME,'ordinal',ORDINAL_POSITION,'referenced_schema',REFERENCED_TABLE_SCHEMA,'referenced_table',REFERENCED_TABLE_NAME,'referenced_column',REFERENCED_COLUMN_NAME) FROM information_schema.KEY_COLUMN_USAGE WHERE REFERENCED_TABLE_NAME IS NOT NULL AND ((TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN (" + list + ")) OR (REFERENCED_TABLE_SCHEMA=DATABASE() AND REFERENCED_TABLE_NAME IN (" + list + "))) ORDER BY TABLE_SCHEMA,TABLE_NAME,CONSTRAINT_NAME,ORDINAL_POSITION",
		"SELECT JSON_OBJECT('kind','constraint','table',t.TABLE_NAME,'name',t.CONSTRAINT_NAME,'type',t.CONSTRAINT_TYPE,'enforced',t.ENFORCED,'check_sha256',IF(c.CHECK_CLAUSE IS NULL,NULL,SHA2(c.CHECK_CLAUSE,256))) FROM information_schema.TABLE_CONSTRAINTS t LEFT JOIN information_schema.CHECK_CONSTRAINTS c ON c.CONSTRAINT_SCHEMA=t.CONSTRAINT_SCHEMA AND c.CONSTRAINT_NAME=t.CONSTRAINT_NAME WHERE t.TABLE_SCHEMA=DATABASE() AND t.TABLE_NAME IN (" + list + ") ORDER BY t.TABLE_NAME,t.CONSTRAINT_NAME",
		"SELECT JSON_OBJECT('kind','referential_rule','schema',CONSTRAINT_SCHEMA,'table',TABLE_NAME,'name',CONSTRAINT_NAME,'update',UPDATE_RULE,'delete',DELETE_RULE,'referenced_schema',UNIQUE_CONSTRAINT_SCHEMA,'referenced_table',REFERENCED_TABLE_NAME) FROM information_schema.REFERENTIAL_CONSTRAINTS WHERE (CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME IN (" + list + ")) OR (UNIQUE_CONSTRAINT_SCHEMA=DATABASE() AND REFERENCED_TABLE_NAME IN (" + list + ")) ORDER BY CONSTRAINT_SCHEMA,TABLE_NAME,CONSTRAINT_NAME",
		"SELECT JSON_OBJECT('kind','trigger','table',EVENT_OBJECT_TABLE,'name',TRIGGER_NAME,'timing',ACTION_TIMING,'event',EVENT_MANIPULATION,'body_sha256',SHA2(ACTION_STATEMENT,256)) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE() AND EVENT_OBJECT_TABLE IN (" + list + ") ORDER BY EVENT_OBJECT_TABLE,TRIGGER_NAME",
		"SELECT JSON_OBJECT('kind','routine','table','','name',ROUTINE_NAME,'type',ROUTINE_TYPE,'security',SECURITY_TYPE,'body_sha256',IF(ROUTINE_DEFINITION IS NULL,NULL,SHA2(ROUTINE_DEFINITION,256))) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA=DATABASE() ORDER BY ROUTINE_TYPE,ROUTINE_NAME",
	}
}
