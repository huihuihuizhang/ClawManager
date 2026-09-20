package systembackupresources

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"
)

// TableCount is a redacted, source-side statistic. It does not contain row
// contents, business identifiers, credentials, or a dump checksum.
type TableCount struct {
	Table string `json:"table"`
	Rows  int64  `json:"rows"`
}

// SourceSnapshot is source-side, redacted metadata from one repeatable-read
// transaction. AuditMaxID is nil when audit_logs is empty. A separate capture
// certificate must prove that a dump used the same database checkpoint.
type SourceSnapshot struct {
	Tables     []TableCount `json:"tables"`
	AuditMaxID *int64       `json:"audit_max_id"`
}

// SQLCountCollector reads a complete resources-domain count snapshot. It is
// not a MySQL dump and does not prove that a separately captured dump contains
// the same rows; that requires the B-owned capture certificate/verifier.
type SQLCountCollector struct {
	DB *sql.DB
}

func (c SQLCountCollector) Collect(ctx context.Context, registryJSON []byte) ([]TableCount, error) {
	snapshot, err := c.CollectSnapshot(ctx, registryJSON)
	if err != nil {
		return nil, err
	}
	return snapshot.Tables, nil
}

// CollectSnapshot captures all nine D-owned table counts and the audit cutoff
// inside one read-only transaction. It returns nothing on any partial failure.
func (c SQLCountCollector) CollectSnapshot(ctx context.Context, registryJSON []byte) (SourceSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return SourceSnapshot{}, err
	}
	tables, err := CaptureTableAllowlist(registryJSON)
	if err != nil {
		return SourceSnapshot{}, err
	}
	if c.DB == nil {
		return SourceSnapshot{}, errors.New("nil resources count database")
	}
	tx, err := c.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return SourceSnapshot{}, fmt.Errorf("begin resources read-only snapshot: %w", err)
	}
	defer tx.Rollback()
	snapshot := SourceSnapshot{Tables: make([]TableCount, 0, len(tables))}
	var total int64
	for _, table := range tables {
		var engine string
		if err := tx.QueryRowContext(ctx, `SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND TABLE_TYPE = 'BASE TABLE'`, table).Scan(&engine); err != nil {
			return SourceSnapshot{}, fmt.Errorf("inspect resources table %s engine: %w", table, err)
		}
		if !strings.EqualFold(engine, "InnoDB") {
			return SourceSnapshot{}, fmt.Errorf("resources table %s is not transactional InnoDB", table)
		}
		// table comes only from the closed, frozen allowlist above.
		var rows int64
		if table == "audit_logs" {
			var maxID sql.NullInt64
			if err := tx.QueryRowContext(ctx, "SELECT COUNT(*), MAX(id) FROM `audit_logs`").Scan(&rows, &maxID); err != nil {
				return SourceSnapshot{}, fmt.Errorf("count resources table %s: %w", table, err)
			}
			if maxID.Valid != (rows > 0) || (maxID.Valid && maxID.Int64 < 0) {
				return SourceSnapshot{}, errors.New("invalid audit snapshot cutoff")
			}
			if maxID.Valid {
				value := maxID.Int64
				snapshot.AuditMaxID = &value
			}
		} else if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+table+"`").Scan(&rows); err != nil {
			return SourceSnapshot{}, fmt.Errorf("count resources table %s: %w", table, err)
		}
		if rows < 0 || rows > math.MaxInt64-total {
			return SourceSnapshot{}, fmt.Errorf("invalid resources count for %s", table)
		}
		total += rows
		snapshot.Tables = append(snapshot.Tables, TableCount{Table: table, Rows: rows})
	}
	if err := tx.Commit(); err != nil {
		return SourceSnapshot{}, fmt.Errorf("commit resources count snapshot: %w", err)
	}
	return snapshot, nil
}
