//go:build systembackup_mysql

package install

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	appdb "clawreef/internal/db"
)

type nativeSigningSQLFixture struct {
	n *nativeAuthorityFixture
}

const nativeSignerTestTimeout = 4 * time.Minute

// Reuse A's actual independent-UUID/localhost non3306/TLS13 ownership and
// marker-protected account/schema cleanup. Replace ONLY its three minimal
// test-created tables before any signer declaration, then apply ALL177 real
// migrations; no historical migration/native fixture source is modified.
func newNativeSigningSQLFixture(t *testing.T, ctx context.Context) *nativeSigningSQLFixture {
	t.Helper()
	n := newNativeAuthorityFixture(t, ctx)
	var uuid, database string
	if n.root.QueryRowContext(ctx, `SELECT @@server_uuid,DATABASE()`).Scan(&uuid, &database) != nil || uuid != n.f.i.plan.Target.ServerUUID || database != n.database || !strings.HasPrefix(database, "a_owner_authority_") {
		t.Fatal("owned signer schema identity")
	}
	for _, table := range []string{"system_backup_installation_owner_heads", "system_backup_installation_owner_grants"} {
		var count int
		if n.root.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+table+"`").Scan(&count) != nil || count != 0 {
			t.Fatal("refusing nonempty original minimal owner fixture", table)
		}
	}
	var users, original int
	if n.root.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&users) != nil || users != 1 || n.root.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE id=7 AND username=? AND role='admin' AND is_active=TRUE AND auth_provider='local'`, n.f.i.plan.LocalAdminUsername).Scan(&original) != nil || original != 1 {
		t.Fatal("unexpected minimal native admin fixture")
	}
	for _, table := range []string{"system_backup_installation_owner_grants", "system_backup_installation_owner_heads", "users"} {
		if _, err := n.root.ExecContext(ctx, "DROP TABLE `"+table+"`"); err != nil {
			t.Fatal("remove exact test-owned minimal schema", err)
		}
	}
	catalog, err := appdb.EmbeddedMigrationCatalog()
	if err != nil || len(catalog.Filenames) != 177 || catalog.Hash != "0031e3825416f419fb7308b6bd72c9616c6179eab376e0579f448965fbe7b4c3" {
		t.Fatal("actual reviewed signer catalog177 required", err)
	}
	if err := appdb.ApplyPinnedMigrations(ctx, n.root, appdb.MigrationTarget{ServerUUID: uuid, Database: database, CatalogSHA256: catalog.Hash}); err != nil {
		t.Fatal("actual full177 signer migration runner", err)
	}
	var migrations int
	if n.root.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&migrations) != nil || migrations != 177 {
		t.Fatal("not all177 migrations recorded")
	}
	// Restore the exact authenticated original actor7 into the real full users
	// schema; migration-created default actor1 is retained and never reused.
	if _, err := n.root.ExecContext(ctx, `INSERT INTO users(id,username,email,password_hash,role,is_active,auth_provider) VALUES(7,?,? ,?,'admin',TRUE,'local')`, n.f.i.plan.LocalAdminUsername, "native-signer-"+nativeAuthorityRandom(t, 8)+"@example.invalid", n.f.s.auth.stored); err != nil {
		t.Fatal("actual original native admin actor", err)
	}
	for _, entry := range []struct {
		account   string
		installer bool
	}{{n.f.i.plan.InstallerDatabaseAccount, true}, {n.f.i.plan.Target.DatabaseAccount, false}} {
		parts := strings.Split(entry.account, "@")
		if len(parts) != 2 || parts[1] != "127.0.0.1" || !strings.HasPrefix(parts[0], "a_oi_") && !strings.HasPrefix(parts[0], "a_oc_") {
			t.Fatal("owned native signer account scope")
		}
		for _, c := range parts[0] {
			if c != '_' && !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') {
				t.Fatal("owned account identifier")
			}
		}
		account := "'" + parts[0] + "'@'127.0.0.1'"
		// Remove old fixture capture DML too: these are truly distinct narrowly
		// scoped signer sessions, not an installer inheriting capture privileges.
		if _, err := n.root.ExecContext(ctx, "REVOKE ALL PRIVILEGES, GRANT OPTION FROM "+account); err != nil {
			t.Fatal("owned native signer grant reset", err)
		}
		userColumns := "id,username,role,is_active,auth_provider"
		if entry.installer {
			userColumns += " ,password_hash"
		}
		grant := func(privileges, table string) {
			t.Helper()
			if _, err := n.root.ExecContext(ctx, "GRANT "+privileges+" ON `"+database+"`.`"+table+"` TO "+account); err != nil {
				t.Fatal("exact native signer grants", err)
			}
		}
		grant("SELECT ("+userColumns+")", "users")
		for _, table := range []string{"system_backup_signing_resource_heads", "system_backup_signing_resource_grants"} {
			columns := nativeSignerColumns(table)
			grant("SELECT ("+columns+")", table)
			if entry.installer {
				grant("INSERT ("+columns+")", table)
				update := "grant_state,row_version"
				if table == "system_backup_signing_resource_heads" {
					update = "head_revision,head_sha256,signed_head,signature,head_state,row_version,updated_at"
				}
				grant("UPDATE ("+update+")", table)
			}
		}
	}
	requireNativeAuthorityTLS(t, ctx, n.installer)
	requireNativeAuthorityTLS(t, ctx, n.consumer)
	t.Log("actual owned signer catalog177 applied; independent installer/SELECT-only consumer; Kube/Vault controlled; not field acceptance")
	return &nativeSigningSQLFixture{n: n}
}

func nativeSignerColumns(table string) string {
	if table == "system_backup_signing_resource_heads" {
		return "installation_id,enrollment_id,authority_id,purpose,head_revision,permission_epoch,current_grant_id,current_grant_revision,head_sha256,signed_head,signature,head_state,row_version"
	}
	return "installation_id,enrollment_id,authority_id,purpose,grant_id,record_revision,permission_epoch,record_sha256,signed_record,signature,grant_state,row_version"
}

func TestSigningResourceSQLNativeFull177AndNarrowRoles(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), nativeSignerTestTimeout)
	defer cancel()
	f := newNativeSigningSQLFixture(t, ctx)
	n := f.n
	for _, entry := range []struct {
		db      *sql.DB
		account string
	}{{n.installer, n.f.i.plan.InstallerDatabaseAccount}, {n.consumer, n.f.i.plan.Target.DatabaseAccount}} {
		var account, role string
		if entry.db.QueryRowContext(ctx, `SELECT CURRENT_USER(),CURRENT_ROLE()`).Scan(&account, &role) != nil || account != entry.account || role != "NONE" {
			t.Fatal("actual distinct native signer identity")
		}
		rows, err := entry.db.QueryContext(ctx, `SHOW GRANTS FOR CURRENT_USER`)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for rows.Next() {
			var grant string
			if rows.Scan(&grant) != nil {
				rows.Close()
				t.Fatal("actual native grant EOF")
			}
			if !strings.HasPrefix(grant, "GRANT USAGE ON *.*") && strings.Contains(grant, " ON *.* ") {
				rows.Close()
				t.Fatal("broad native signer global privilege")
			}
			count++
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if rows.Close() != nil || count < 3 {
			t.Fatal("incomplete actual role grants")
		}
	}
	var denied string
	err := n.consumer.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id=7`).Scan(&denied)
	requireNativeAuthorityDenied(t, err)
	for _, db := range []*sql.DB{n.installer, n.consumer} {
		_, err = db.ExecContext(ctx, `UPDATE users SET is_active=FALSE WHERE id=7`)
		requireNativeAuthorityDenied(t, err)
		_, err = db.ExecContext(ctx, `DELETE FROM system_backup_signing_resource_grants WHERE 1=0`)
		requireNativeAuthorityDenied(t, err)
		_, err = db.ExecContext(ctx, `SELECT * FROM system_backup_installation_owner_heads`)
		requireNativeAuthorityDenied(t, err)
	}
	_, err = n.consumer.ExecContext(ctx, `UPDATE system_backup_signing_resource_heads SET row_version=row_version WHERE 1=0`)
	requireNativeAuthorityDenied(t, err)
	tx, err := n.consumer.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, table := range []string{"system_backup_signing_resource_heads", "system_backup_signing_resource_grants"} {
		rows, err := tx.QueryContext(ctx, fmt.Sprintf("SELECT %s FROM `%s` WHERE installation_id=? AND enrollment_id=? AND authority_id=? AND purpose=? FOR SHARE", nativeSignerColumns(table), table), n.f.i.plan.Target.InstallationID, n.f.i.plan.EnrollmentID, "empty-native-signer", "acceptance_record")
		if err != nil {
			t.Fatal("real SELECT-only FOR SHARE unavailable", err)
		}
		if rows.Next() || rows.Err() != nil || rows.Close() != nil {
			t.Fatal("unexpected uninstalled signer resource row")
		}
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	nativeSignerDDLConstraints(t, ctx, f)
}
