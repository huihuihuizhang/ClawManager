package domain

import (
	"context"
	"database/sql"
)

// PreflightDrill validates a blank target without modifying it.
// RestoreDrill repeats these checks in its write transaction.
func PreflightDrill(ctx context.Context, db *sql.DB, target DrillTarget) error {
	return PreflightDrillWithPolicy(ctx, db, target, Policy{})
}

// PreflightDrillWithPolicy admits the canonical empty allocator seed only for
// an explicitly pinned WorkBuddy UID adapter. Restore repeats the same check.
func PreflightDrillWithPolicy(ctx context.Context, db *sql.DB, target DrillTarget, policy Policy) error {
	return preflightDrill(ctx, db, target, policy, nil)
}

// PreflightRestoreDrill also validates the authenticated source against target
// metadata and the exact restore policy. No DDL, DML or evidence is written.
func PreflightRestoreDrill(ctx context.Context, db *sql.DB, target DrillTarget, source Snapshot, policy Policy) error {
	return preflightDrill(ctx, db, target, policy, &source)
}

func preflightDrill(ctx context.Context, db *sql.DB, target DrillTarget, policy Policy, source *Snapshot) error {
	if db == nil {
		return ErrDatabase
	}
	conn, e := db.Conn(ctx)
	if e != nil {
		return ErrDatabase
	}
	defer conn.Close()
	if e = target.check(ctx, conn); e != nil {
		return e
	}
	tx, e := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return ErrDatabase
	}
	defer tx.Rollback()
	tables, e := Catalog(ctx, tx)
	if e != nil {
		return e
	}
	if policy.WorkBuddy != nil && policy.WorkBuddy.Layout != "" {
		targets := map[string]Table{}
		for _, t := range tables {
			targets[t.Name] = t
		}
		if e := validateWorkBuddyUIDTarget(targets, policy.WorkBuddy); e != nil {
			return e
		}
	}
	if source != nil {
		plan, e := Normalize(ctx, *source, tables, policy)
		if e != nil {
			return e
		}
		// Normalization may contain password hashes and configured secrets.
		for _, t := range plan.Data.Tables {
			for _, r := range t.Rows {
				for _, c := range r {
					clear(c.Bytes)
				}
			}
		}
	}
	if e = checkBlankPolicy(ctx, tx, tables, policy); e != nil {
		return e
	}
	return target.check(ctx, conn)
}
