package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

//go:embed backup_import_map.json
var backupImportMapJSON []byte

//go:embed backup_source_schema.json
var backupSourceSchemaJSON []byte

var regexpImportName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var regexpImportDatabase = regexp.MustCompile(`^cm_import_[a-f0-9]{32}$`)

type backupImportMap struct {
	SourceGitSHA string            `json:"source_git_sha"`
	Migrations   map[string]string `json:"migrations"`
	Tables       map[string]string `json:"tables"`
	Constraints  map[string]string `json:"constraints"`
	Aliases      map[string]string `json:"aliases"`
}
type importTableProof struct {
	Table  importTable `json:"table"`
	Rows   int64       `json:"rows"`
	SHA256 string      `json:"sha256"`
}
type importPreservation struct {
	Tables []importTableProof `json:"tables"`
}

// BackupImportReport contains no row payloads or connection information.
type BackupImportReport struct {
	State         string `json:"state"`
	SourceGitSHA  string `json:"source_git_sha"`
	SourceSchema  string `json:"source_schema_sha256"`
	TableCount    int    `json:"preserved_table_count"`
	Rows          int64  `json:"preserved_rows"`
	HistorySHA256 string `json:"preservation_sha256"`
}

// ImportBackupCopy is an operator-only, explicitly isolated-copy import. The
// application connection path never calls it. Original business/control rows
// and ledger entries are preserved; imported work is never dispatched here.
func ImportBackupCopy(ctx context.Context, pool *sql.DB) (report BackupImportReport, resultErr error) {
	return importBackupCopy(ctx, pool, nil)
}

func importBackupCopy(ctx context.Context, pool *sql.DB, afterRename func() error) (report BackupImportReport, resultErr error) {
	if pool == nil || ctx == nil || ctx.Err() != nil {
		return report, errors.New("backup import unavailable")
	}
	var mapping backupImportMap
	var source importSchema
	if json.Unmarshal(backupImportMapJSON, &mapping) != nil || json.Unmarshal(backupSourceSchemaJSON, &source) != nil || len(source.Tables) == 0 {
		return report, errors.New("reviewed backup import profile unavailable")
	}
	conn, err := pool.Conn(ctx)
	if err != nil {
		return report, err
	}
	defer conn.Close()
	var database string
	if err = conn.QueryRowContext(ctx, "SELECT DATABASE()").Scan(&database); err != nil || !regexpImportDatabase.MatchString(database) {
		return report, errors.New("backup import requires a cm_import_<32hex> isolated copy")
	}
	release, err := acquireMigrationLocks(ctx, conn)
	if err != nil {
		return report, err
	}
	defer func() { resultErr = errors.Join(resultErr, release()) }()
	var present int
	if err = conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='system_backup_v2_import_journal'").Scan(&present); err != nil {
		return report, err
	}
	var state, originalSchema, sourceSHA, rawProof string
	var proof importPreservation
	if present != 0 {
		err = conn.QueryRowContext(ctx, "SELECT source_git_sha,source_schema_sha256,state,preservation_json FROM system_backup_v2_import_journal WHERE singleton_id=1").Scan(&sourceSHA, &originalSchema, &state, &rawProof)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return report, err
		}
	}
	if state == "" {
		actual, err := readImportSchema(ctx, conn)
		if err != nil {
			return report, err
		}
		if importDigest(actual) != importDigest(source) {
			return report, errors.New("unsupported backup source schema; no conversion performed")
		}
		if err = assertImportSourceIdle(ctx, conn, mapping, false); err != nil {
			return report, err
		}
		if err = assertSourceLedger(ctx, conn, mapping); err != nil {
			return report, err
		}
		for _, table := range source.Tables {
			item, err := proveImportTable(ctx, conn, table, table.Name, mapping)
			if err != nil {
				return report, err
			}
			proof.Tables = append(proof.Tables, item)
		}
		encoded, err := json.Marshal(proof)
		if err != nil {
			return report, err
		}
		journalDDL, err := embeddedMigrations.ReadFile("migrations/118_backup_v2_import_journal.sql")
		if err != nil {
			return report, err
		}
		for _, statement := range splitSQLStatements(string(journalDDL)) {
			if _, err = conn.ExecContext(ctx, statement); err != nil {
				return report, err
			}
		}
		sourceSHA, originalSchema = mapping.SourceGitSHA, importDigest(source)
		if _, err = conn.ExecContext(ctx, `INSERT INTO system_backup_v2_import_journal(singleton_id,source_git_sha,source_schema_sha256,state,preservation_json) VALUES(1,?,?,'prepared',?)`, sourceSHA, originalSchema, encoded); err != nil {
			return report, err
		}
		state = "prepared"
	} else if sourceSHA != mapping.SourceGitSHA || originalSchema != importDigest(source) || json.Unmarshal([]byte(rawProof), &proof) != nil || len(proof.Tables) != len(source.Tables) {
		return report, errors.New("backup import journal does not match the reviewed source")
	}
	// Only known immutable identifiers from the embedded profile reach DDL.
	if state == "prepared" {
		var renames []string
		oldCount, newCount := 0, 0
		for _, table := range source.Tables {
			target, mapped := mapping.Tables[table.Name]
			if !mapped {
				continue
			}
			var oldExists, newExists int
			if err = conn.QueryRowContext(ctx, `SELECT SUM(TABLE_NAME=?),SUM(TABLE_NAME=?) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN (?,?)`, table.Name, target, table.Name, target).Scan(&oldExists, &newExists); err != nil {
				return report, err
			}
			oldCount += oldExists
			newCount += newExists
			left, _ := importIdentifier(table.Name)
			right, _ := importIdentifier(target)
			renames = append(renames, left+" TO "+right)
		}
		if oldCount == len(renames) && newCount == 0 {
			if _, err = conn.ExecContext(ctx, "RENAME TABLE "+strings.Join(renames, ",")); err != nil {
				return report, err
			}
		} else if oldCount != 0 || newCount != len(renames) {
			return report, errors.New("backup import table identity conflict")
		}
		if err = setImportState(ctx, conn, "renamed"); err != nil {
			return report, err
		}
		state = "renamed"
	}
	if state == "renamed" && afterRename != nil {
		if err = afterRename(); err != nil {
			return report, err
		}
	}
	if state == "renamed" {
		if err = assertImportSourceIdle(ctx, conn, mapping, true); err != nil {
			return report, err
		}
		if err = canonicalizeImportConstraints(ctx, conn, source, mapping); err != nil {
			return report, err
		}
		// Aliases record exact, reviewed source migrations that already built
		// these renamed tables. Keep every original ledger row intact.
		for old, next := range mapping.Aliases {
			if _, err = conn.ExecContext(ctx, `INSERT IGNORE INTO schema_migrations(filename,applied_at) SELECT ?,applied_at FROM schema_migrations WHERE filename=?`, next, old); err != nil {
				return report, err
			}
		}
		if err = applyEmbeddedMigrationsLockedContext(ctx, conn); err != nil {
			return report, err
		}
		if err = setImportState(ctx, conn, "migrated"); err != nil {
			return report, err
		}
		state = "migrated"
	}
	if state != "migrated" && state != "verified" {
		return report, errors.New("unknown backup import stage")
	}
	for _, expected := range proof.Tables {
		target := expected.Table.Name
		if mapped := mapping.Tables[target]; mapped != "" {
			target = mapped
		}
		actual, err := proveImportTable(ctx, conn, expected.Table, target, mapping)
		if err != nil {
			return report, err
		}
		if actual.Rows != expected.Rows || actual.SHA256 != expected.SHA256 {
			return report, fmt.Errorf("backup import preservation check failed: %s", expected.Table.Name)
		}
		report.Rows += actual.Rows
	}
	if err = setImportState(ctx, conn, "verified"); err != nil {
		return report, err
	}
	report.State, report.SourceGitSHA, report.SourceSchema = "verified", sourceSHA, originalSchema
	report.TableCount, report.HistorySHA256 = len(proof.Tables), importDigest(proof)
	return report, nil
}

func setImportState(ctx context.Context, conn *sql.Conn, state string) error {
	_, err := conn.ExecContext(ctx, "UPDATE system_backup_v2_import_journal SET state=?,updated_at=UTC_TIMESTAMP(6) WHERE singleton_id=1", state)
	return err
}

func assertSourceLedger(ctx context.Context, conn *sql.Conn, mapping backupImportMap) error {
	rows, err := conn.QueryContext(ctx, "SELECT filename FROM schema_migrations")
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var file string
		if err = rows.Scan(&file); err != nil {
			return err
		}
		if mapping.Migrations[file] == "" {
			return errors.New("unknown source migration provenance")
		}
		seen[file] = true
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if len(seen) != len(mapping.Migrations) {
		return errors.New("source migration ledger incomplete")
	}
	return nil
}

func assertImportSourceIdle(ctx context.Context, conn *sql.Conn, m backupImportMap, renamed bool) error {
	checks := map[string]string{
		"system_backups":                       "status NOT IN ('succeeded','failed','canceled')",
		"system_restore_drills":                "status NOT IN ('succeeded','failed','canceled')",
		"system_backup_preflights":             "status NOT IN ('succeeded','failed','canceled')",
		"system_backup_artifact_verifications": "status NOT IN ('succeeded','failed','canceled')",
		"system_backup_operations":             "status NOT IN ('succeeded','failed')",
		"system_maintenance_locks":             "gate_state<>'idle'",
		"system_maintenance_mutation_leases":   "1=1",
		"system_maintenance_participants":      "observed_state<>'running' OR desired_state<>'running'",
		"system_backup_attempts":               "status IN ('preparing','running','sealed')",
		"system_backup_external_actions":       "state IN ('request_sent','provider_unreachable','conflict')",
	}
	for table, predicate := range checks {
		if renamed {
			table = m.Tables[table]
		}
		name, err := importIdentifier(table)
		if err != nil {
			return err
		}
		var count int
		if err = conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+name+" WHERE "+predicate).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return errors.New("backup source has unresolved work; preserve it and finish recovery before importing")
		}
	}
	return nil
}

func proveImportTable(ctx context.Context, conn *sql.Conn, table importTable, target string, m backupImportMap) (importTableProof, error) {
	proof := importTableProof{Table: table}
	name, err := importIdentifier(target)
	if err != nil {
		return proof, err
	}
	var columns []string
	for _, column := range table.Columns {
		quoted, err := importIdentifier(column)
		if err != nil {
			return proof, err
		}
		columns = append(columns, quoted)
	}
	query := "SELECT " + strings.Join(columns, ",") + " FROM " + name
	var args []any
	if table.Name == "schema_migrations" {
		for filename := range m.Migrations {
			args = append(args, filename)
		}
		query += " WHERE filename IN (" + strings.TrimSuffix(strings.Repeat("?,", len(args)), ",") + ")"
	}
	rows, err := conn.QueryContext(ctx, query, args...)
	if err != nil {
		return proof, err
	}
	defer rows.Close()
	var hashes []string
	var total int64
	for rows.Next() {
		values := make([]sql.RawBytes, len(columns))
		dest := make([]any, len(columns))
		for i := range values {
			dest[i] = &values[i]
		}
		if err = rows.Scan(dest...); err != nil {
			return proof, err
		}
		h := sha256.New()
		for _, value := range values {
			if value == nil {
				h.Write([]byte{0})
				continue
			}
			h.Write([]byte{1})
			var frame [8]byte
			binary.BigEndian.PutUint64(frame[:], uint64(len(value)))
			h.Write(frame[:])
			h.Write(value)
			total += int64(len(value))
		}
		hashes = append(hashes, hex.EncodeToString(h.Sum(nil)))
		proof.Rows++
		if proof.Rows > 1000000 || total > 1<<30 {
			return proof, errors.New("backup import preservation budget exceeded")
		}
	}
	if err = rows.Err(); err != nil {
		return proof, err
	}
	sort.Strings(hashes)
	proof.SHA256 = importDigest(hashes)
	return proof, nil
}

func canonicalizeImportConstraints(ctx context.Context, conn *sql.Conn, source importSchema, m backupImportMap) error {
	// Clauses come only from a schema whose exact fingerprint was checked
	// against the reviewed source profile before the first mutation.
	for _, fact := range source.Facts[4] {
		table, old := *fact[0], *fact[1]
		if m.Tables[table] == "" || m.Constraints[old] == "" {
			continue
		}
		body, err := importCheckDefinition(m.Constraints[old])
		if err != nil {
			return err
		}
		if err := renameImportConstraint(ctx, conn, m.Tables[table], old, m.Constraints[old], "CHECK", body); err != nil {
			return err
		}
	}
	type foreign struct {
		table, name, reference, update, delete string
		columns, refs                          []string
	}
	fks := map[string]*foreign{}
	for _, fact := range source.Facts[3] {
		table, old := *fact[0], *fact[1]
		if m.Tables[table] == "" || m.Constraints[old] == "" {
			continue
		}
		key := table + "/" + old
		fk := fks[key]
		if fk == nil {
			if *fact[4] != "same_schema" {
				return errors.New("foreign-schema import reference rejected")
			}
			ref := *fact[5]
			if m.Tables[ref] != "" {
				ref = m.Tables[ref]
			}
			fk = &foreign{table: m.Tables[table], name: old, reference: ref, update: *fact[7], delete: *fact[8]}
			fks[key] = fk
		}
		column, err := importIdentifier(*fact[3])
		if err != nil {
			return err
		}
		ref, err := importIdentifier(*fact[6])
		if err != nil {
			return err
		}
		fk.columns = append(fk.columns, column)
		fk.refs = append(fk.refs, ref)
	}
	for _, fk := range fks {
		ref, err := importIdentifier(fk.reference)
		if err != nil {
			return err
		}
		for _, rule := range []string{fk.update, fk.delete} {
			if rule != "RESTRICT" && rule != "CASCADE" && rule != "SET NULL" && rule != "NO ACTION" {
				return errors.New("unsupported import FK rule")
			}
		}
		body := "FOREIGN KEY (" + strings.Join(fk.columns, ",") + ") REFERENCES " + ref + " (" + strings.Join(fk.refs, ",") + ") ON UPDATE " + fk.update + " ON DELETE " + fk.delete
		if err = renameImportConstraint(ctx, conn, fk.table, fk.name, m.Constraints[fk.name], "FOREIGN KEY", body); err != nil {
			return err
		}
	}
	return nil
}

// Never execute INFORMATION_SCHEMA's escaped CHECK_CLAUSE text. Select the
// reviewed canonical definition from this binary's embedded migrations.
func importCheckDefinition(name string) (string, error) {
	pattern := regexp.MustCompile(`(?i)CONSTRAINT\s+` + regexp.QuoteMeta(name) + `\s+CHECK\s*\(`)
	files, err := embeddedMigrations.ReadDir("migrations")
	if err != nil {
		return "", err
	}
	definition := ""
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".sql") {
			continue
		}
		raw, err := embeddedMigrations.ReadFile("migrations/" + file.Name())
		if err != nil {
			return "", err
		}
		text := string(raw)
		for _, match := range pattern.FindAllStringIndex(text, -1) {
			start := match[1] - 1
			depth := 0
			var quote byte
			for i := start; i < len(text); i++ {
				c := text[i]
				if quote != 0 {
					if c == '\\' {
						i++
						continue
					}
					if c == quote {
						if i+1 < len(text) && text[i+1] == quote {
							i++
							continue
						}
						quote = 0
					}
					continue
				}
				if c == '\'' || c == '"' || c == '`' {
					quote = c
					continue
				}
				if c == '(' {
					depth++
				}
				if c == ')' {
					depth--
					if depth == 0 {
						definition = "CHECK " + text[start:i+1]
						// Some additive DDL is inside a PREPARE string. Decode
						// that SQL string layer before executing the constraint.
						if importSQLStringAt(text, match[0]) {
							definition = strings.ReplaceAll(definition, "''", "'")
						}
						break
					}
				}
			}
		}
	}
	if definition == "" {
		return "", errors.New("reviewed import CHECK definition missing")
	}
	return definition, nil
}

func importSQLStringAt(text string, end int) bool {
	quoted := false
	for i := 0; i < end; i++ {
		if text[i] == '\\' && quoted {
			i++
			continue
		}
		if text[i] != '\'' {
			continue
		}
		if quoted && i+1 < end && text[i+1] == '\'' {
			i++
			continue
		}
		quoted = !quoted
	}
	return quoted
}

func renameImportConstraint(ctx context.Context, conn *sql.Conn, table, old, next, kind, body string) error {
	var oldExists, newExists int
	if err := conn.QueryRowContext(ctx, `SELECT COALESCE(SUM(CONSTRAINT_NAME=?),0),COALESCE(SUM(CONSTRAINT_NAME=?),0) FROM information_schema.TABLE_CONSTRAINTS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND CONSTRAINT_TYPE=?`, old, next, table, kind).Scan(&oldExists, &newExists); err != nil {
		return err
	}
	if oldExists == 0 && newExists == 1 {
		return nil
	}
	if oldExists != 1 || newExists != 0 {
		return errors.New("import constraint identity conflict")
	}
	tableSQL, err := importIdentifier(table)
	if err != nil {
		return err
	}
	oldSQL, err := importIdentifier(old)
	if err != nil {
		return err
	}
	nextSQL, err := importIdentifier(next)
	if err != nil {
		return err
	}
	drop := kind
	if kind == "FOREIGN KEY" {
		drop = "FOREIGN KEY"
	}
	_, err = conn.ExecContext(ctx, "ALTER TABLE "+tableSQL+" DROP "+drop+" "+oldSQL+", ADD CONSTRAINT "+nextSQL+" "+body)
	return err
}
