package systembackupresources

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Private integration candidate. These callbacks are trusted B adapters, not
// request flags. Target must authenticate this exact writable transaction,
// isolated database, RR/UTC/strict session, clock/fence, full schema (including
// triggers/FKs) and sustained DDL/startup exclusion. Candidate must authenticate
// BOTH complete row sets against the dump/checkpoint and reviewed normalizers,
// mappings, occupancy and target version. Final repeats current authority.
// None of these production adapters or registry approvals are supplied here.
type restoreWriteProofs struct {
	Target    func(context.Context, *sql.Tx) error
	Candidate func(context.Context, *sql.Tx, []restoreFieldTable, []restoreFieldTable) error
	Final     func(context.Context, *sql.Tx) error
}

// applyRestoreWriteInTransaction never begins/ends a transaction. B must call
// it inside the common restore transaction, roll back on ANY error, and perform
// the common final authority check before committing. Success means only that
// the uncommitted nine-table rows match the candidate. It neither destroys the
// write credential nor replaces the separate SELECT-only readback/activation.
func applyRestoreWriteInTransaction(ctx context.Context, tx *sql.Tx, registryJSON []byte,
	before, after []restoreFieldTable, budget restoreFieldBudget, proof restoreWriteProofs) error {
	if ctx == nil || tx == nil || proof.Target == nil || proof.Candidate == nil || proof.Final == nil ||
		budget.Rows <= 0 || budget.Rows == math.MaxInt64 || budget.Bytes <= 0 {
		return errors.New("resources writer requires transaction, complete proofs and bounded capacity")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	controls, err := ControlExclusionAllowlist(append([]byte(nil), registryJSON...))
	if err != nil {
		return errors.New("resources writer requires frozen complete registry")
	}
	if _, err := indexRestoreFields(ctx, before, budget); err != nil {
		return err
	}
	if _, err := indexRestoreFields(ctx, after, budget); err != nil {
		return err
	}
	// Copy before invoking external adapters; a callback cannot change the plan.
	frozenBefore, frozenAfter := cloneRestoreFieldTables(before), cloneRestoreFieldTables(after)
	oldRows, err := indexRestoreFields(ctx, frozenBefore, budget)
	if err != nil {
		return err
	}
	newRows, err := indexRestoreFields(ctx, frozenAfter, budget)
	if err != nil {
		return err
	}
	if proof.Target(ctx, tx) != nil || ctx.Err() != nil {
		return errors.New("resources writer target proof failed")
	}
	if proof.Candidate(ctx, tx, cloneRestoreFieldTables(frozenBefore), cloneRestoreFieldTables(frozenAfter)) != nil || ctx.Err() != nil {
		return errors.New("resources writer candidate proof failed")
	}
	// Acquire the complete primary-key ranges in a fixed order, including empty
	// ranges. B's target adapter must establish the compatible outer lock prefix.
	definitions := restoreFieldColumns()
	tables := restoreWriteTableOrder()
	remaining := budget.Rows
	for _, table := range tables {
		if err := inspectRestoreFieldTable(ctx, tx, table, definitions[table]); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, "SELECT `id` FROM `"+table+"` ORDER BY `id` LIMIT "+strconv.FormatInt(remaining+1, 10)+" FOR UPDATE")
		if err != nil {
			return errors.New("resources writer target lock failed")
		}
		err = scanRestoreWriteLocks(ctx, rows, &remaining)
		if err != nil {
			return err
		}
	}
	actual, err := readRestoreFieldRowsMode(ctx, tx, budget, true)
	if err != nil {
		return err
	}
	if err := compareRestoreFields(ctx, frozenBefore, actual, budget); err != nil {
		return errors.New("resources writer target changed")
	}
	if err := verifyRestoreControlRowsEmpty(ctx, tx, controls); err != nil {
		return err
	}
	// Remove obsolete children first, but retain old job parents until kept
	// children have moved to their new parents. Deleting an old job earlier
	// would cascade-delete a child whose ID is retained by the new plan.
	// Never disable FK checks or use REPLACE/IGNORE/upsert to hide conflicts.
	deleteMissing := func(table string) error {
		for _, id := range restoreWriteIDs(oldRows[table]) {
			if _, keep := newRows[table][id]; keep {
				continue
			}
			if err := execRestoreWrite(ctx, tx, "DELETE FROM `"+table+"` WHERE `id`=?", []any{id}); err != nil {
				return err
			}
		}
		return nil
	}
	for i := len(tables) - 1; i >= 0; i-- {
		if table := tables[i]; table != "security_scan_jobs" {
			if err := deleteMissing(table); err != nil {
				return err
			}
		}
	}
	for _, table := range tables {
		columns := definitions[table]
		for _, id := range restoreWriteIDs(newRows[table]) {
			row := newRows[table][id]
			old, exists := oldRows[table][id]
			if exists && restoreWriteRowsEqual(columns, old, row) {
				continue
			}
			args := make([]any, 0, len(columns)+1)
			var fields, placeholders []string
			for _, column := range columns {
				if exists && column == "id" {
					continue
				}
				field := "`" + column + "`"
				if exists {
					field += "=?"
				}
				fields = append(fields, field)
				placeholders = append(placeholders, "?")
				var value any
				if row[column] != nil {
					value = *row[column]
				}
				args = append(args, value)
			}
			query := "INSERT INTO `" + table + "` (" + strings.Join(fields, ",") + ") VALUES (" + strings.Join(placeholders, ",") + ")"
			if exists {
				query = "UPDATE `" + table + "` SET " + strings.Join(fields, ",") + " WHERE `id`=?"
				args = append(args, id)
				if table == "northbound_admin_settings" {
					if old["version"] == nil {
						return errors.New("resources writer target version missing")
					}
					query += " AND `version`=?"
					args = append(args, *old["version"])
				}
			}
			if err := execRestoreWrite(ctx, tx, query, args); err != nil {
				return err
			}
		}
	}
	if err := deleteMissing("security_scan_jobs"); err != nil {
		return err
	}
	actual, err = readRestoreFieldRowsMode(ctx, tx, budget, true)
	if err != nil {
		return err
	}
	if err := compareRestoreFields(ctx, frozenAfter, actual, budget); err != nil {
		return errors.New("resources writer readback differs")
	}
	if err := verifyRestoreControlRowsEmpty(ctx, tx, controls); err != nil {
		return err
	}
	if proof.Final(ctx, tx) != nil {
		return errors.New("resources writer final authority proof failed")
	}
	return ctx.Err()
}

func restoreWriteTableOrder() []string {
	return []string{"audit_logs", "egress_private_exceptions", "northbound_admin_settings", "northbound_settings_audit",
		"security_scan_configs", "security_scan_jobs", "security_scan_job_items", "security_scan_reports", "system_image_settings"}
}

func scanRestoreWriteLocks(ctx context.Context, rows *sql.Rows, remaining *int64) error {
	defer rows.Close()
	for rows.Next() {
		var id int64
		if ctx.Err() != nil || *remaining == 0 || rows.Scan(&id) != nil || id <= 0 {
			return errors.New("resources writer lock scan failed or capacity exceeded")
		}
		*remaining--
	}
	if rows.Err() != nil || rows.Close() != nil {
		return errors.New("resources writer lock scan failed")
	}
	return ctx.Err()
}

func execRestoreWrite(ctx context.Context, tx *sql.Tx, query string, args []any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return errors.New("resources writer mutation failed")
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return errors.New("resources writer mutation outcome differs")
	}
	return ctx.Err()
}

func restoreWriteIDs(rows map[string]restoreFieldRow) []string {
	ids := make([]string, 0, len(rows))
	for id := range rows {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, _ := strconv.ParseInt(ids[i], 10, 64)
		b, _ := strconv.ParseInt(ids[j], 10, 64)
		return a < b
	})
	return ids
}

func restoreWriteRowsEqual(columns []string, a, b restoreFieldRow) bool {
	for _, column := range columns {
		if (a[column] == nil) != (b[column] == nil) || a[column] != nil && *a[column] != *b[column] {
			return false
		}
	}
	return true
}
