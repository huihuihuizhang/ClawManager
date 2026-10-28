package systembackupevidence

import (
	"context"
	"database/sql"
	"sort"
	"strings"
)

const taskDownloadReferenceColumnsSQL = `SELECT TABLE_NAME,COLUMN_NAME,DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_SCHEMA=DATABASE() AND LEFT(TABLE_NAME,7)='system_' AND COLUMN_NAME REGEXP '(^|_)evidence_(public_)?id$'
ORDER BY TABLE_NAME,COLUMN_NAME LIMIT 10001`
const taskDownloadEvidenceKeySQL = `SELECT id,origin_installation_id,owner_target_type,owner_target_public_id,redaction_classification FROM system_backup_v2_evidence WHERE public_id=?`
const maxTaskDownloadReferences = 10000

type taskDownloadReference struct {
	table                  string
	columns, publicColumns []string
	scoped                 bool
	stage                  int
}

func taskDownloadReferences() []taskDownloadReference {
	r := []taskDownloadReference{
		{"system_backup_v2_operations", []string{"redacted_response_evidence_id", "download_evidence_id"}, nil, true, 3},
		{"system_backup_v2_download_admission_receipts", []string{"evidence_id"}, []string{"evidence_public_id"}, true, 3},
		{"system_backup_v2_download_result_receipts", []string{"evidence_id"}, []string{"evidence_public_id"}, true, 3},
		{"system_backup_v2_log_chunks", []string{"redacted_evidence_id"}, nil, false, 5},
		{"system_backup_v2_dependency_health", []string{"evidence_id"}, nil, false, 5},
		{"system_backup_v2_provider_capabilities", []string{"evidence_id"}, nil, false, 5},
		{"system_backup_v2_events", nil, []string{"detail_evidence_public_id"}, true, 5},
		{"system_backup_v2_promotions", nil, []string{"drill_evidence_public_id"}, true, 5},
		{"system_backup_v2_external_actions", nil, []string{"provider_proof_evidence_public_id"}, true, 5},
		{"system_backup_v2_source_writer_check_states", nil, []string{"evidence_public_id"}, true, 5},
		{"system_backup_v2_check_results", nil, []string{"evidence_public_id"}, true, 5},
		{"system_backup_v2_staging_resources", []string{"ownership_resolution_evidence_id"}, nil, true, 5},
		{"system_backup_v2_restore_drill_resources", []string{"ownership_resolution_evidence_id"}, nil, true, 5},
	}
	sort.Slice(r, func(i, j int) bool {
		if r[i].stage != r[j].stage {
			return r[i].stage < r[j].stage
		}
		return r[i].table < r[j].table
	})
	return r
}

type taskDownloadTable struct {
	kind, table string
	columns     []string
}

func taskDownloadTables() []taskDownloadTable {
	return []taskDownloadTable{
		{"backup", "system_backup_v2_backups", nil},
		{"drill", "system_backup_v2_restore_drills", []string{"preflight_evidence_public_id", "diff_evidence_public_id", "verifier_report_evidence_public_id"}},
		{"preflight", "system_backup_v2_preflights", []string{"report_evidence_public_id", "diff_evidence_public_id", "verifier_report_evidence_public_id"}},
		{"artifact_verify", "system_backup_v2_artifact_verifications", []string{"health_report_evidence_public_id", "verifier_report_evidence_public_id"}},
	}
}

var taskDownloadSystemProducerTables = []string{"system_backup_producer_evidence_bindings", "system_backup_producer_evidence_refs", "system_backup_producer_result_receipts", "system_backup_producer_runs"}

// The closed catalog includes logical references that published DDL only CHECKs
// (task/report/event public IDs), not just SQL FKs. Unknown visible columns and
// missing required columns/privileges fail closed; metadata never supplies SQL
// identifiers. Producer tables, when installed, may reference system evidence
// only, so a task-evidence match there is an integrity failure.
func checkTaskDownloadReferenceSchema(ctx context.Context, tx *sql.Tx) (map[string]bool, error) {
	expected := map[string]bool{"system_backup_v2_evidence_chunks.evidence_id": true}
	for _, r := range taskDownloadReferences() {
		for _, c := range r.columns {
			expected[r.table+"."+c] = true
		}
		for _, c := range r.publicColumns {
			expected[r.table+"."+c] = false
		}
	}
	for _, t := range taskDownloadTables() {
		for _, c := range t.columns {
			expected[t.table+"."+c] = false
		}
	}
	optional := map[string]bool{}
	for _, t := range taskDownloadSystemProducerTables {
		optional[t+".evidence_id"] = true
	}
	rows, err := tx.QueryContext(ctx, taskDownloadReferenceColumnsSQL)
	if err != nil {
		return nil, ErrDownloadAdmissionNotReady
	}
	defer rows.Close()
	seen, producers := map[string]bool{}, map[string]bool{}
	count := 0
	for rows.Next() {
		var table, column, kind string
		if rows.Scan(&table, &column, &kind) != nil {
			return nil, ErrDownloadAdmissionNotReady
		}
		key := table + "." + column
		numeric, required := expected[key]
		if seen[key] || count >= maxTaskDownloadReferences {
			return nil, ErrDownloadAdmissionNotReady
		}
		seen[key] = true
		count++
		if !required {
			if !optional[key] || !oneOf(kind, "char", "varchar") {
				return nil, ErrDownloadAdmissionNotReady
			}
			producers[table] = true
			continue
		}
		if numeric && kind != "bigint" || !numeric && !oneOf(kind, "char", "varchar") {
			return nil, ErrDownloadAdmissionNotReady
		}
	}
	if rows.Err() != nil {
		return nil, ErrDownloadAdmissionNotReady
	}
	for key := range expected {
		if !seen[key] {
			return nil, ErrDownloadAdmissionNotReady
		}
	}
	if len(producers) > 0 && len(producers) != len(taskDownloadSystemProducerTables) {
		return nil, ErrDownloadAdmissionNotReady
	}
	return producers, nil
}

func taskDownloadReferenceSQL(r taskDownloadReference, locking bool) string {
	columns := append(append([]string{}, r.columns...), r.publicColumns...)
	conditions := make([]string, len(columns))
	for n, c := range columns {
		conditions[n] = c + "=?"
	}
	key := "id"
	if r.table == "system_backup_v2_download_admission_receipts" || r.table == "system_backup_v2_download_result_receipts" {
		key = "operation_id"
	}
	q := "SELECT " + key + " FROM " + r.table + " WHERE "
	if r.scoped {
		q += "origin_installation_id=? AND "
	}
	q += "(" + strings.Join(conditions, " OR ") + ") ORDER BY " + key + " LIMIT 10001"
	if locking {
		q += " FOR UPDATE"
	}
	return q
}
func lockTaskDownloadReferenceStage(ctx context.Context, tx *sql.Tx, stage int, installation, evidence string, evidenceID int64, locking bool, count *int) error {
	for _, r := range taskDownloadReferences() {
		if r.stage != stage {
			continue
		}
		args := []any{}
		if r.scoped {
			args = append(args, installation)
		}
		for range r.columns {
			args = append(args, evidenceID)
		}
		for range r.publicColumns {
			args = append(args, evidence)
		}
		rows, err := tx.QueryContext(ctx, taskDownloadReferenceSQL(r, locking), args...)
		if err != nil {
			return ErrDownloadAdmissionNotReady
		}
		var previous int64
		for rows.Next() {
			var id int64
			if rows.Scan(&id) != nil || id <= previous || *count >= maxTaskDownloadReferences {
				rows.Close()
				return ErrDownloadAdmissionNotReady
			}
			previous = id
			*count++
		}
		err, closeErr := rows.Err(), rows.Close()
		if err != nil || closeErr != nil {
			return ErrDownloadAdmissionNotReady
		}
	}
	return nil
}

func checkTaskDownloadProducerStage(ctx context.Context, tx *sql.Tx, installed map[string]bool, evidence string, stage int, locking bool) error {
	for _, definition := range producerDownloadDefinitions() {
		if definition.stage != stage {
			continue
		}
		table := definition.table
		if !installed[table] {
			continue
		}
		q := "SELECT evidence_id FROM " + table + " WHERE evidence_id=? ORDER BY scope_key LIMIT 1"
		if locking {
			q += " FOR UPDATE"
		}
		rows, err := tx.QueryContext(ctx, q, evidence)
		if err != nil {
			return ErrDownloadAdmissionNotReady
		}
		found := rows.Next()
		err, closed := rows.Err(), rows.Close()
		if err != nil || closed != nil {
			return ErrDownloadAdmissionNotReady
		}
		if found {
			return ErrIntegrity
		}
	}
	return nil
}
