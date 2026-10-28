package systembackupread

// The isolated index probe uses the same projections and predicates as the
// reader. Authorization remains in the reader's transaction.
func taskPageSQL(table taskTable, filtered bool) string {
	query := "SELECT " + taskProjectionColumns + " FROM " + table.name +
		" WHERE origin_installation_id=? AND id<?"
	if filtered {
		query += " AND status=?"
	}
	return query + " ORDER BY id DESC LIMIT ?"
}

const operationPageSQL = `SELECT id,` + operationProjectionColumns + ` FROM system_backup_v2_operations
WHERE origin_installation_id=? AND id<? ORDER BY id DESC LIMIT ?`
