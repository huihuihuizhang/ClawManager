package systembackupresources

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"strings"
)

// Private composition seam, not a production proof implementation. Candidate
// must authenticate ALL nine expected tables/values and their reviewed
// normalizer/source/target binding on this exact transaction. Final must recheck
// current authority, isolation/schema/freeze and credential destruction before
// completion. A reference, historical valid flag or caller bool is insufficient.
type restoreReadbackProofs struct {
	Target    TargetReadProofVerifier
	Candidate func(context.Context, *sql.Tx, []restoreFieldTable) error
	Final     func(context.Context, *sql.Tx) error
}

// verifyRestoreReadback composes nine-table equality and control-row exclusion
// in one read-only RR transaction. Success is only an internal readback result:
// it does not authorize activation or certify a production restore. No caller is
// wired to production, and the frozen registry/proof requirements remain closed.
func verifyRestoreReadback(ctx context.Context, db *sql.DB, registryJSON []byte, expected []restoreFieldTable, budget restoreFieldBudget, proof restoreReadbackProofs) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if db == nil || missingProofVerifier(proof.Target) || proof.Candidate == nil || proof.Final == nil || budget.Rows <= 0 || budget.Rows == math.MaxInt64 || budget.Bytes <= 0 {
		return errors.New("resources readback requires database, complete proofs and bounded capacity")
	}
	// Freeze selected registry decisions and bounded comparison values before
	// invoking external proof code. Callers must not mutate inputs concurrently.
	controls, err := ControlExclusionAllowlist(append([]byte(nil), registryJSON...))
	if err != nil {
		return errors.New("resources readback requires frozen complete registry")
	}
	if _, err := indexRestoreFields(ctx, expected, budget); err != nil {
		return err
	}
	frozen := cloneRestoreFieldTables(expected)
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return errors.New("resources readback snapshot begin failed")
	}
	commitAttempted := false
	defer func() {
		if !commitAttempted {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				err = errors.New("resources readback rollback outcome is unknown")
			}
		}
	}()
	if proof.Target.VerifyReadOnlyTarget(ctx, tx) != nil {
		return errors.New("resources readback target proof failed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if proof.Candidate(ctx, tx, cloneRestoreFieldTables(frozen)) != nil {
		return errors.New("resources readback candidate proof failed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := verifyRestoreControlRowsEmpty(ctx, tx, controls); err != nil {
		return err
	}
	actual, err := readRestoreFieldRows(ctx, tx, budget)
	if err != nil {
		return err
	}
	if err := compareRestoreFields(ctx, frozen, actual, budget); err != nil {
		return err
	}
	if proof.Final(ctx, tx) != nil {
		return errors.New("resources readback final authority proof failed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// After Commit has been attempted, Rollback cannot confirm its outcome.
	commitAttempted = true
	if tx.Commit() != nil {
		return errors.New("resources readback completion is unconfirmed")
	}
	return ctx.Err()
}

func verifyRestoreControlRowsEmpty(ctx context.Context, tx *sql.Tx, controls []string) error {
	for _, table := range controls {
		if err := ctx.Err(); err != nil {
			return err
		}
		var engine string
		if tx.QueryRowContext(ctx, `SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND TABLE_TYPE = 'BASE TABLE'`, table).Scan(&engine) != nil || !strings.EqualFold(engine, "InnoDB") {
			return errors.New("resources readback control structure is unavailable")
		}
		// An existence probe is bounded even for a wrongly populated control
		// table. Closed identifiers only; schema_migrations stays target-local.
		var one int64
		readErr := tx.QueryRowContext(ctx, "SELECT 1 FROM `"+table+"` LIMIT 1").Scan(&one)
		if readErr == nil {
			return errors.New("resources readback contains source control rows")
		}
		if !errors.Is(readErr, sql.ErrNoRows) {
			return errors.New("resources readback control read failed")
		}
	}
	return ctx.Err()
}

func cloneRestoreFieldTables(source []restoreFieldTable) []restoreFieldTable {
	result := make([]restoreFieldTable, len(source))
	for i, table := range source {
		result[i] = restoreFieldTable{Name: table.Name, Columns: append([]string(nil), table.Columns...)}
		if table.Rows != nil {
			result[i].Rows = make([]restoreFieldRow, len(table.Rows))
		}
		for j, row := range table.Rows {
			result[i].Rows[j] = cloneRestoreAuditRow(row)
		}
	}
	return result
}
