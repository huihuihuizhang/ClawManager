package systembackupcontroller

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type claimTransactionStarter interface {
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
}

func renewClaimLocked(ctx context.Context, executor Executor, installation string, token ClaimToken, descriptor targetDescriptor, ttlMicros int64) (ClaimToken, error) {
	var zero ClaimToken
	renewalTTL := time.Duration(ttlMicros) * time.Microsecond
	starter, ok := executor.(claimTransactionStarter)
	if !ok {
		return zero, fmt.Errorf("%w: %w", ErrClaimTransactionRequired, ErrClaimLost)
	}
	tx, err := starter.BeginTx(ctx, nil)
	if err != nil {
		return zero, fmt.Errorf("begin renew %s claim: %w", token.Target.Kind, err)
	}
	defer tx.Rollback()
	heartbeat := descriptor.heartbeat
	if heartbeat == "" {
		heartbeat = "NULL"
	}
	where := fmt.Sprintf("origin_installation_id = ? AND public_id = ? AND row_version = ? AND %s = ? AND %s", descriptor.ownerColumn, descriptor.activeSQL)
	query := fmt.Sprintf("SELECT %s,UTC_TIMESTAMP(6),%s FROM %s WHERE %s FOR UPDATE", descriptor.leaseColumn, heartbeat, descriptor.table, where)
	var originalUntil, statementAt, now time.Time
	var originalHeartbeat sql.NullTime
	err = tx.QueryRowContext(ctx, query, installation, token.Target.PublicID, token.RowVersion, token.Owner).Scan(&originalUntil, &statementAt, &originalHeartbeat)
	if err == sql.ErrNoRows {
		return zero, ErrClaimLost
	}
	if err != nil {
		return zero, fmt.Errorf("lock renew %s claim: %w", token.Target.Kind, err)
	}
	// MySQL statement UTC can precede the actual lock wait. This separate
	// statement begins only after the locked row has been delivered.
	if err = tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); err != nil {
		return zero, err
	}
	if now.IsZero() || statementAt.IsZero() || now.Before(statementAt) || !now.Before(originalUntil) || originalHeartbeat.Valid && now.Before(originalHeartbeat.Time) {
		return zero, ErrClaimLost
	}
	query = fmt.Sprintf("UPDATE %s SET %s = GREATEST(%s,DATE_ADD(UTC_TIMESTAMP(6), INTERVAL ? MICROSECOND))%s, row_version = row_version + 1 WHERE %s AND %s > UTC_TIMESTAMP(6) AND %s = ?", descriptor.table, descriptor.leaseColumn, descriptor.leaseColumn, heartbeatAssignment(descriptor), where, descriptor.leaseColumn, descriptor.leaseColumn)
	result, err := tx.ExecContext(ctx, query, ttlMicros, installation, token.Target.PublicID, token.RowVersion, token.Owner, originalUntil)
	if err != nil {
		return zero, fmt.Errorf("renew %s claim: %w", token.Target.Kind, err)
	}
	matched, err := exactlyOneRow(result)
	if err != nil {
		return zero, err
	}
	if !matched {
		return zero, ErrClaimLost
	}
	// Observe the actual update time even for operation claims, which have no
	// heartbeat column. The lease calculation is bounded by the two SQL clocks.
	query = fmt.Sprintf("SELECT %s,%s,UTC_TIMESTAMP(6) FROM %s WHERE %s FOR UPDATE", descriptor.leaseColumn, heartbeat, descriptor.table, where)
	var renewedUntil, rowAt, deliveredAt time.Time
	var renewedHeartbeat sql.NullTime
	err = tx.QueryRowContext(ctx, query, installation, token.Target.PublicID, token.RowVersion+1, token.Owner).Scan(&renewedUntil, &renewedHeartbeat, &rowAt)
	if err != nil {
		return zero, fmt.Errorf("read renew %s claim: %w", token.Target.Kind, err)
	}
	if err = tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&deliveredAt); err != nil {
		return zero, err
	}
	minimum, maximum := now.Add(renewalTTL), rowAt.Add(renewalTTL)
	if originalUntil.After(minimum) {
		minimum = originalUntil
	}
	if originalUntil.After(maximum) {
		maximum = originalUntil
	}
	if rowAt.IsZero() || deliveredAt.IsZero() || rowAt.Before(now) || deliveredAt.Before(rowAt) || !deliveredAt.Before(originalUntil) || !deliveredAt.Before(renewedUntil) || renewedUntil.Before(minimum) || renewedUntil.After(maximum) {
		return zero, ErrClaimLost
	}
	if descriptor.heartbeat != "" {
		wantUntil := renewedHeartbeat.Time.Add(renewalTTL)
		if originalUntil.After(wantUntil) {
			wantUntil = originalUntil
		}
		if !renewedHeartbeat.Valid || renewedHeartbeat.Time.Before(now) || rowAt.Before(renewedHeartbeat.Time) || originalHeartbeat.Valid && renewedHeartbeat.Time.Before(originalHeartbeat.Time) || !renewedUntil.Equal(wantUntil) {
			return zero, ErrClaimLost
		}
	}
	if err = tx.Commit(); err != nil {
		return zero, fmt.Errorf("commit renew %s claim: %w", token.Target.Kind, err)
	}
	token.RowVersion++
	return token, nil
}
