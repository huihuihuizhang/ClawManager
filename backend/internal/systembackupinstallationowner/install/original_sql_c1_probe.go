package install

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"

	"github.com/go-sql-driver/mysql"
)

// Runs on the newly produced actual TLS principal, after exact root-side
// role/proxy/dynamic privilege checks. EXPLAIN checks native SQL permissions
// without inserting/updating/deleting a real source or metadata row.
func originalSQLC1OwnGrantProbe(ctx context.Context, db *sql.DB, p originalSQLPlan, a originalSQLAccount) error {
	if a.Role != "installer" && a.Role != "business" {
		return nil
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return originalSQLVerifyFailure("verify_c1_connect", a.Role, err)
	}
	defer conn.Close()
	var actual []originalSQLPrivilege
	for _, q := range []struct{ kind, sql string }{
		{"global", "SELECT '','','',PRIVILEGE_TYPE,IS_GRANTABLE FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=? AND PRIVILEGE_TYPE<>'USAGE'"},
		{"schema", "SELECT TABLE_SCHEMA,'','',PRIVILEGE_TYPE,IS_GRANTABLE FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE=?"},
		{"table", "SELECT TABLE_SCHEMA,TABLE_NAME,'',PRIVILEGE_TYPE,IS_GRANTABLE FROM information_schema.TABLE_PRIVILEGES WHERE GRANTEE=?"},
		{"column", "SELECT TABLE_SCHEMA,TABLE_NAME,COLUMN_NAME,PRIVILEGE_TYPE,IS_GRANTABLE FROM information_schema.COLUMN_PRIVILEGES WHERE GRANTEE=?"},
	} {
		rows, err := conn.QueryContext(ctx, q.sql, originalSQLAccountName(a))
		if err != nil {
			return originalSQLVerifyFailure("verify_c1_grant_metadata", a.Role, err)
		}
		for rows.Next() {
			var v originalSQLPrivilege
			var grantable string
			v.Kind = q.kind
			if rows.Scan(&v.Database, &v.Object, &v.Column, &v.Verb, &grantable) != nil || grantable != "NO" || len(actual) >= 2000 {
				rows.Close()
				return errOriginalSQLAccounts
			}
			actual = append(actual, v)
		}
		if errors.Join(rows.Err(), rows.Close()) != nil {
			return errOriginalSQLAccounts
		}
	}
	expected := append([]originalSQLPrivilege(nil), a.Privileges...)
	for j := range expected {
		if expected[j].Database == "" {
			expected[j].Database = p.Database
		}
		if expected[j].Kind != "table" && expected[j].Kind != "column" {
			return errOriginalSQLAccounts
		}
	}
	originalSQLSortPrivileges(actual)
	originalSQLSortPrivileges(expected)
	if !reflect.DeepEqual(actual, expected) {
		return originalSQLVerifyFailure("verify_c1_own_grants_mismatch", a.Role, nil)
	}
	explain := func(statement string, want bool) error {
		stage := "verify_c1_explain_" + strings.ToLower(strings.Fields(statement)[1])
		rows, err := conn.QueryContext(ctx, statement)
		if !want {
			if rows != nil {
				rows.Close()
			}
			var denied *mysql.MySQLError
			if !errors.As(err, &denied) || denied.Number != 1142 {
				return originalSQLVerifyFailure(stage+"_denial", a.Role, err)
			}
			return nil
		}
		if err != nil {
			return originalSQLVerifyFailure(stage+"_access", a.Role, err)
		}
		for rows.Next() {
		}
		if err = errors.Join(rows.Err(), rows.Close()); err != nil {
			return originalSQLVerifyFailure(stage+"_readback", a.Role, err)
		}
		return nil
	}
	for _, table := range originalSQLC1Tables {
		if a.Role == "business" && table == "system_backup_producer_command_receipts" {
			if err := explain("EXPLAIN SELECT * FROM `"+table+"` WHERE FALSE", false); err != nil {
				return err
			}
			continue
		}
		if err := explain("EXPLAIN SELECT * FROM `"+table+"` WHERE FALSE", true); err != nil {
			return err
		}
		if err := explain("EXPLAIN DELETE FROM `"+table+"` WHERE FALSE", false); err != nil {
			return err
		}
		if err := explain("EXPLAIN UPDATE `"+table+"` SET scope_key=scope_key WHERE FALSE", a.Role == "installer" || table == "system_backup_producer_domains"); err != nil {
			return err
		}
		if err := explain("EXPLAIN INSERT INTO `"+table+"` SELECT * FROM `"+table+"` WHERE FALSE", a.Role == "installer"); err != nil {
			return err
		}
	}
	if a.Role == "business" {
		for _, statement := range []string{
			"EXPLAIN SELECT * FROM audit_logs WHERE FALSE FOR SHARE",
			"EXPLAIN INSERT INTO audit_logs(user_id,action,resource_type,details) SELECT NULL,'','','' WHERE FALSE",
			"EXPLAIN SELECT id,username,role,is_active,auth_provider FROM users WHERE FALSE FOR SHARE",
			"EXPLAIN SELECT * FROM system_backup_v2_evidence_chunks WHERE FALSE FOR SHARE",
		} {
			if err := explain(statement, true); err != nil {
				return err
			}
		}
		for _, statement := range []string{
			"EXPLAIN UPDATE audit_logs SET details=details WHERE FALSE",
			"EXPLAIN DELETE FROM audit_logs WHERE FALSE",
			"EXPLAIN UPDATE users SET username=username WHERE FALSE",
			"EXPLAIN DELETE FROM system_backup_v2_evidence_chunks WHERE FALSE",
		} {
			if err := explain(statement, false); err != nil {
				return err
			}
		}
	}
	return nil
}
