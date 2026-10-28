//go:build systembackup_mysql

package systembackupevidence

import (
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"

	"github.com/go-sql-driver/mysql"
)

// Uses the guarded isolated database and exact embedded/current DDL capsule of
// the admission probe. These cases must run against actual InnoDB; seed/model
// tests and a successful compile cannot stand in for their FK/rollback results.
func TestDDownloadResultRetentionMySQL(t *testing.T) {
	raw, err := os.ReadFile(os.Getenv("D_PROVIDER_REGISTRATION_DDL"))
	mustSQL(t, err)
	if hash(raw) != os.Getenv("D_PROVIDER_REGISTRATION_DDL_SHA256") {
		t.Fatal("result retention capsule pin")
	}
	input, err := decodeADownloadMFAInputs(raw)
	mustSQL(t, err)
	for _, name := range []string{"result_audit_delete_restrict", "admission_delete_restrict", "parent_retention_update_restrict", "retention_group_fk", "intent_group_fk", "installation_group_fk", "link_insert_rollback", "duplicate_result_rejected", "cold_group_after_revocation", "cold_group_duplicate_nonce", "cold_group_corrupt_intent"} {
		t.Run(name, func(t *testing.T) {
			x := newAAdmissionMySQLFixture(t, input)
			db := x.aDownloadMFAFixture.db
			c := x.admitted(t)
			if name == "cold_group_after_revocation" || name == "cold_group_duplicate_nonce" || name == "cold_group_corrupt_intent" {
				x.result(t, c)
				var duplicateID int64
				if name == "cold_group_after_revocation" {
					_, err = db.ExecContext(x.ctx, "UPDATE users SET is_active=FALSE WHERE id=?", c.actor.UserID)
					mustSQL(t, err)
				}
				if name == "cold_group_duplicate_nonce" {
					insert, e := db.ExecContext(x.ctx, `INSERT INTO system_backup_v2_strong_auth_nonces
(schema_version,origin_installation_id,issuer_sha256,subject_sha256,session_sha256,nonce_hmac,nonce_hmac_key_version,endpoint,request_hash,idempotency_key,authenticated_at,expires_at,consumed_at,operation_id,response_sha256,audit_log_id,retain_until,created_at)
SELECT schema_version,origin_installation_id,issuer_sha256,subject_sha256,session_sha256,?,nonce_hmac_key_version,endpoint,request_hash,idempotency_key,authenticated_at,expires_at,consumed_at,operation_id,response_sha256,audit_log_id,retain_until,created_at
FROM system_backup_v2_strong_auth_nonces WHERE operation_id=?`, hash([]byte(c.rows.active.HMAC+":duplicate")), c.rows.operationID)
					mustSQL(t, e)
					duplicateID, e = insert.LastInsertId()
					mustSQL(t, e)
				}
				if name == "cold_group_corrupt_intent" {
					_, err = db.ExecContext(x.ctx, "UPDATE audit_logs SET details=JSON_OBJECT('changed',TRUE) WHERE id=?", c.intentAuditID)
					mustSQL(t, err)
				}
				tx, e := db.BeginTx(x.ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
				mustSQL(t, e)
				t.Cleanup(func() { tx.Rollback() })
				identity := sec.DatabaseIdentity{ServerUUID: x.registry.ServerUUID, Database: x.registry.Database}
				scope, e := sec.LockSensitiveDownloadNonceScope(x.ctx, tx, identity, x.registry.Installation)
				mustSQL(t, e)
				config, e := scope.LoadConfig(x.ctx, tx)
				mustSQL(t, e)
				group, e := LockDownloadRetentionGroup(x.ctx, tx, identity, config, c.operationID)
				mustSQL(t, e)
				mustSQL(t, x.owners.LockOwnerReferences(x.ctx, tx, x.initial))
				e = group.LockNonce(x.ctx, tx)
				if e == nil {
					e = group.VerifyAudits(x.ctx, tx)
				}
				if name == "cold_group_after_revocation" {
					mustSQL(t, e)
					mustSQL(t, group.Recheck(x.ctx, tx))
					if digest, complete := group.DetailRollingHash(); !complete || !digestPattern.MatchString(digest) {
						t.Fatal("cold original group missing complete digest")
					}
				} else if e == nil {
					t.Fatal("invalid cold durable group accepted", name)
				}
				mustSQL(t, tx.Rollback())
				if duplicateID > 0 {
					_, e = db.ExecContext(x.ctx, "DELETE FROM system_backup_v2_strong_auth_nonces WHERE id=? AND operation_id=?", duplicateID, c.rows.operationID)
					mustSQL(t, e)
				}
				if name == "cold_group_corrupt_intent" {
					_, e = db.ExecContext(x.ctx, "UPDATE audit_logs SET details=? WHERE id=?", c.rows.audit.body, c.intentAuditID)
					mustSQL(t, e)
				}
				x.requireRows(t, 1, 1, true)
				return
			}
			if name == "link_insert_rollback" {
				_, err := db.ExecContext(x.ctx, `CREATE TRIGGER synthetic_result_link_reject BEFORE INSERT ON system_backup_v2_download_result_receipts FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic result link rejection'`)
				mustSQL(t, err)
				if x.results.Finish(x.ctx, c, DownloadResultObservation{Outcome: "rejected"}) == nil {
					t.Fatal("result with failed retention link committed")
				}
				x.requireRows(t, 1, 0, false)
				return
			}
			x.result(t, c)
			var resultID int64
			var retain time.Time
			mustSQL(t, db.QueryRowContext(x.ctx, "SELECT result_audit_id,retain_until FROM system_backup_v2_download_result_receipts WHERE operation_id=?", c.rows.operationID).Scan(&resultID, &retain))
			code := uint16(1452)
			switch name {
			case "result_audit_delete_restrict":
				_, err = db.ExecContext(x.ctx, "DELETE FROM audit_logs WHERE id=?", resultID)
				code = 1451
			case "admission_delete_restrict":
				_, err = db.ExecContext(x.ctx, "DELETE FROM system_backup_v2_download_admission_receipts WHERE operation_id=?", c.rows.operationID)
				code = 1451
			case "parent_retention_update_restrict":
				_, err = db.ExecContext(x.ctx, "UPDATE system_backup_v2_download_admission_receipts SET retain_until=? WHERE operation_id=?", retain.Add(-time.Microsecond), c.rows.operationID)
				code = 1451
			case "retention_group_fk":
				_, err = db.ExecContext(x.ctx, "UPDATE system_backup_v2_download_result_receipts SET retain_until=? WHERE operation_id=?", retain.Add(-time.Microsecond), c.rows.operationID)
			case "intent_group_fk":
				_, err = db.ExecContext(x.ctx, "UPDATE system_backup_v2_download_result_receipts SET intent_audit_id=? WHERE operation_id=?", c.intentAuditID+100000, c.rows.operationID)
			case "installation_group_fk":
				_, err = db.ExecContext(x.ctx, "UPDATE system_backup_v2_download_result_receipts SET origin_installation_id='installation_other' WHERE operation_id=?", c.rows.operationID)
			case "duplicate_result_rejected":
				_, err = db.ExecContext(x.ctx, "INSERT INTO system_backup_v2_download_result_receipts SELECT * FROM system_backup_v2_download_result_receipts WHERE operation_id=?", c.rows.operationID)
				code = 1062
			}
			var failure *mysql.MySQLError
			if !errors.As(err, &failure) || failure.Number != code {
				t.Fatal("actual result retention constraint did not reject with expected SQL code", name, code)
			}
			x.requireRows(t, 1, 1, true)
		})
	}
}
