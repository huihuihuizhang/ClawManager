package systembackupexecution

import (
	"database/sql"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
)

// This separate native role has ONLY USAGE and exact SELECT on the participants
// table. It cannot borrow the controller/task DB or business source credentials.
func (x *bootstrapSourceRegistryReader) readControlParticipants() ([]string, error) {
	binding, err := x.connection("control_sql")
	if err != nil || binding.ServerUUID != x.association.Target.ServerUUID || binding.Database != x.association.Target.Database || x.config.ApplicationScope != x.association.Source.ApplicationScope {
		return nil, install.ErrInstall
	}
	db, verified, err := openBootstrapControlSQL(x.ctx, x.access, binding, x.association.Source.ApplicationScope)
	if err != nil {
		return nil, install.ErrInstall
	}
	defer db.Close()
	conn, err := db.Conn(x.physical)
	if err != nil {
		return nil, install.ErrInstall
	}
	defer conn.Close()
	floor := time.Time{}
	identity := func(q sourceIdentityReader) error {
		var account, role, database, server string
		var clock any
		if q.QueryRowContext(x.physical, "SELECT CURRENT_USER(),CURRENT_ROLE(),DATABASE(),@@server_uuid,UTC_TIMESTAMP(6)").Scan(&account, &role, &database, &server, &clock) != nil || !verified.Load() || account != binding.Account || role != "NONE" || database != binding.Database || server != binding.ServerUUID {
			return install.ErrInstall
		}
		now, err := decodeSourceObservationSQLTime(clock)
		if err != nil || now.Before(floor) || now.Before(x.association.NotBefore) || !now.Before(x.association.Until) {
			return install.ErrInstall
		}
		floor = now
		rows, err := q.QueryContext(x.physical, "SHOW GRANTS FOR CURRENT_USER")
		if err != nil {
			return install.ErrInstall
		}
		selectGrant := regexp.MustCompile("^GRANT SELECT ON `" + regexp.QuoteMeta(database) + "`\\.`system_backup_participants` TO (?:'[^']+'|`[^`]+`)@(?:'[^']+'|`[^`]+`)$")
		found, count := false, 0
		for rows.Next() {
			var grant string
			count++
			if rows.Scan(&grant) != nil || count > 2 || len(grant) > 16384 {
				rows.Close()
				return install.ErrInstall
			}
			if strings.HasPrefix(grant, "GRANT USAGE ON *.* TO ") && !strings.Contains(grant, " WITH GRANT OPTION") {
				continue
			}
			if found || !selectGrant.MatchString(grant) {
				rows.Close()
				return install.ErrInstall
			}
			found = true
		}
		if errors.Join(rows.Err(), rows.Close()) != nil || !found {
			return install.ErrInstall
		}
		return x.access.Check(x.ctx)
	}
	tx, err := conn.BeginTx(x.physical, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, install.ErrInstall
	}
	defer tx.Rollback()
	if identity(tx) != nil {
		return nil, install.ErrInstall
	}
	rows, err := tx.QueryContext(x.physical, "SELECT participant_id FROM system_backup_participants WHERE scope=? ORDER BY participant_id", x.association.Source.ApplicationScope)
	if err != nil {
		return nil, install.ErrInstall
	}
	columns, err := rows.Columns()
	if err != nil || len(columns) != 1 || columns[0] != "participant_id" {
		rows.Close()
		return nil, install.ErrInstall
	}
	actual, seen := []string{}, map[string]bool{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil || id == "" || len(id) > 128 || strings.ContainsAny(id, "\x00\r\n") || seen[id] || len(actual) >= 10000 {
			rows.Close()
			return nil, install.ErrInstall
		}
		seen[id] = true
		actual = append(actual, id)
	}
	if errors.Join(rows.Err(), rows.Close()) != nil || identity(tx) != nil || tx.Commit() != nil || x.access.Check(x.ctx) != nil {
		return nil, install.ErrInstall
	}
	sort.Strings(actual)
	return actual, nil
}
