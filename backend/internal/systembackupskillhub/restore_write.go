package systembackupskillhub

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
)

// RestoreWriteAuthority belongs to the target coordinator. Verify must bind
// the full authenticated source/mapping/limits and trusted registry/schema to
// this isolated target connection, including disabled startup writers and write
// permission. Recheck MUST lock/revalidate its current fencing authority in
// this same transaction, keeping it valid through commit. Returning nil without
// that lock is not a production implementation.
type RestoreWriteAuthority interface {
	VerifyTargetWrite(context.Context, ReadOnlyQueries, RestoreRequest) error
	RecheckTargetWrite(context.Context, ReadOnlyQueries, RestoreRequest) error
}

type SQLRestorer struct {
	DB        *sql.DB
	Authority RestoreWriteAuthority
}

var (
	ErrTargetOccupied       = errors.New("skill hub restore target is not empty")
	ErrTargetWrite          = errors.New("skill hub restore target write failed")
	ErrRestoreCommitUnknown = errors.New("skill hub restore commit outcome requires reconciliation")
)

// Restore writes only the eight Skill Hub tables. It refuses existing rows,
// never truncates/upserts and never disables foreign keys. A/B dependencies
// must already exist. B must reconcile seeded tags before invoking it.
// It does NOT run business services or grant public acceptance; a separately
// credentialed SQLRestoreVerifier and object/workspace verification must follow.
func (w SQLRestorer) Restore(ctx context.Context, request RestoreRequest) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if w.DB == nil || nilObjectAdapter(w.Authority) {
		return ErrRestoreAuthority
	}
	frozen, err := freezeRestoreRequest(ctx, request)
	if err != nil {
		return err
	}
	tx, err := w.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return restoreFailure(ctx, ErrTargetWrite)
	}
	defer tx.Rollback()
	queries := readOnlyTransaction{tx: tx}
	if err := w.Authority.VerifyTargetWrite(ctx, queries, cloneRestoreRequest(frozen)); err != nil {
		return restoreFailure(ctx, ErrRestoreAuthority)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	rows, err := PrepareRestoreRows(ctx, frozen.Source, frozen.Mapping)
	if err != nil {
		return err
	}
	if err := checkRowsCapacity(ctx, rows, frozen.Limits); err != nil {
		return err
	}
	if err := lockEmptyRestoreTables(ctx, tx); err != nil {
		return err
	}
	if err := checkExternalRestoreReferences(ctx, tx, rows); err != nil {
		return err
	}

	// Defer cyclic back-references until their target records exist. All other
	// columns, including historical timestamps and json:"-" data, are explicit.
	staged := cloneRows(rows)
	for i := range staged.Blobs {
		staged.Blobs[i].LastScanResultID = nil
	}
	for i := range staged.Skills {
		staged.Skills[i].CurrentVersionID = nil
		staged.Skills[i].LastScanResultID = nil
	}
	byName := map[string]tableView{}
	for _, table := range tables(staged) {
		byName[table.name] = table
	}
	for _, name := range []string{"skill_blobs", "skills", "skill_scan_results", "skill_versions", "skill_hub_tags", "instance_skills", "skill_package_materialize_jobs", "skill_hub_tag_assignments"} {
		if err := insertRestoreTable(ctx, tx, byName[name]); err != nil {
			return err
		}
	}
	for _, blob := range rows.Blobs {
		if blob.LastScanResultID == nil {
			continue
		}
		if err := execRestoreRow(ctx, tx, "UPDATE `skill_blobs` SET `last_scan_result_id`=?,`updated_at`=? WHERE `id`=? AND `last_scan_result_id` IS NULL", *blob.LastScanResultID, blob.UpdatedAt, blob.ID); err != nil {
			return err
		}
	}
	for _, skill := range rows.Skills {
		if skill.CurrentVersionID == nil && skill.LastScanResultID == nil {
			continue
		}
		if err := execRestoreRow(ctx, tx, "UPDATE `skills` SET `current_version_id`=?,`last_scan_result_id`=?,`updated_at`=? WHERE `id`=? AND `current_version_id` IS NULL AND `last_scan_result_id` IS NULL", skill.CurrentVersionID, skill.LastScanResultID, skill.UpdatedAt, skill.ID); err != nil {
			return err
		}
	}

	// Read back on the writing transaction to catch DB conversion, unexpected
	// triggers and omitted fields before commit. This is not the independent
	// SELECT-only verification required after the restore coordinator commits.
	actual, err := readRestoreRows(ctx, tx, frozen)
	if err != nil {
		return err
	}
	if err := CompareRestoredRows(ctx, frozen.Source, frozen.Mapping, actual); err != nil {
		return err
	}
	if err := w.Authority.RecheckTargetWrite(ctx, queries, cloneRestoreRequest(frozen)); err != nil {
		return restoreFailure(ctx, ErrRestoreAuthority)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		// A lost commit acknowledgement can mean the rows ARE durable. Do not retry
		// inserts, delete the target, or report a normal rollback on this path.
		return ErrRestoreCommitUnknown
	}
	// Commit was acknowledged. A cancellation arriving after this point must
	// not disguise durable writes as an interrupted/rolled-back operation.
	return nil
}
func lockEmptyRestoreTables(ctx context.Context, tx *sql.Tx) error {
	for _, table := range tables(Rows{}) {
		var engine string
		if err := tx.QueryRowContext(ctx, "SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND TABLE_TYPE='BASE TABLE'", table.name).Scan(&engine); err != nil {
			return restoreFailure(ctx, ErrTargetRead)
		}
		if !strings.EqualFold(engine, "InnoDB") {
			return ErrTargetRead
		}
		// Lock the empty primary-index range under Serializable, in fixed order.
		// Any existing row, even a seed tag, prevents this component from writing.
		var id int
		err := tx.QueryRowContext(ctx, "SELECT `id` FROM `"+table.name+"` ORDER BY `id` LIMIT 1 FOR UPDATE").Scan(&id)
		if err == nil {
			return ErrTargetOccupied
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return restoreFailure(ctx, ErrTargetRead)
		}
	}
	return ctx.Err()
}
func insertRestoreTable(ctx context.Context, tx *sql.Tx, table tableView) error {
	columns := sqlLayout(table).columns
	query := "INSERT INTO `" + table.name + "` (" + strings.Join(columns, ",") + ") VALUES (" + strings.TrimSuffix(strings.Repeat("?,", len(columns)), ",") + ")"
	for i := 0; i < table.rows.Len(); i++ {
		row := table.rows.Index(i)
		args := make([]any, row.NumField())
		for j := range args {
			field := row.Field(j)
			if field.Kind() == reflect.Pointer && field.IsNil() {
				args[j] = nil
			} else {
				args[j] = field.Interface()
			}
		}
		if err := execRestoreRow(ctx, tx, query, args...); err != nil {
			return err
		}
	}
	return ctx.Err()
}
func execRestoreRow(ctx context.Context, tx *sql.Tx, query string, args ...any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return restoreFailure(ctx, ErrTargetWrite)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return restoreFailure(ctx, ErrTargetWrite)
	}
	return ctx.Err()
}
