package control

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"strings"
	"testing"
)

func TestCredentialGrantRejectsSourceWritesAndBroadPrivileges(t *testing.T) {
	for _, g := range []DatabaseGrant{
		{Database: "production", ServerUUID: "server", Host: "%", Mode: "restore"},
		{Database: "production", ServerUUID: "server", Host: "%", Mode: "verify"},
		{Database: "cm_drill_x", ServerUUID: "server", Host: "%' OR 1=1", Mode: "restore"},
	} {
		if g.valid() {
			t.Fatal("unsafe credential specification")
		}
	}
	for _, scenario := range []string{"select", "global", "write", "grant-option", "foreign-db", "role", "missing"} {
		t.Run(scenario, func(t *testing.T) {
			grant := "GRANT SELECT ON `production`.* TO 'worker'@'%'"
			switch scenario {
			case "global":
				grant = "GRANT SELECT ON *.* TO 'worker'@'%'"
			case "write":
				grant = "GRANT SELECT, UPDATE ON `production`.* TO 'worker'@'%'"
			case "grant-option":
				grant += " WITH GRANT OPTION"
			case "foreign-db":
				grant = "GRANT SELECT ON `other`.* TO 'worker'@'%'"
			case "role":
				grant = "GRANT 'root'@'%' TO 'worker'@'%'"
			case "missing":
				grant = "GRANT USAGE ON *.* TO 'worker'@'%'"
			}
			store, _ := scriptStore(t, sqlStep{contains: "SHOW GRANTS", rows: [][]driver.Value{{grant}}})
			conn, e := store.DB.Conn(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			e = verifyAccountGrants(context.Background(), conn, storedCredential{Spec: DatabaseGrant{Database: "production", Mode: "capture"}, Username: "worker"})
			if (scenario == "select") != (e == nil) {
				t.Fatal("grant policy mismatch", e)
			}
		})
	}
}
func TestCredentialRevokeKillsExistingSessionsBeforeDrop(t *testing.T) {
	task, _, _ := grantFixture()
	spec := DatabaseGrant{Database: "production", ServerUUID: "source-server", Host: "%", Mode: "capture"}
	ref := "database-worker"
	owner := credentialOwner(task, ref, spec)
	r := storedCredential{Spec: spec, Owner: owner, Username: "cm_bk_" + owner[:24], Password: []byte("Cm9!" + strings.Repeat("a", 64))}
	v := testVault()
	raw, _ := json.Marshal(r)
	sealed, _ := v.seal(task, ref, "database-credential", raw)
	steps := readRecordSteps(task, sealed)
	steps = append(steps, workerCommit(task)...)
	steps = append(steps, sqlStep{contains: "SELECT active,revoked", rows: [][]driver.Value{{true, false}}}, sqlStep{contains: "SET revoked=TRUE,active=FALSE", affected: 1})
	steps = append(steps, workerCommit(task)...)
	// lock account, first process scan, kill, second scan, drop
	for range 5 {
		steps = append(steps, workerCommit(task)...)
	}
	steps = append(steps, workerCommit(task)...)
	steps = append(steps, sqlStep{contains: "SELECT active,revoked", rows: [][]driver.Value{{false, true}}}, sqlStep{contains: "SET removed=TRUE", affected: 1})
	steps = append(steps, workerCommit(task)...)
	store, controlScript := scriptStore(t, steps...)
	v.Store = store
	remote, remoteScript := scriptStore(t,
		sqlStep{contains: "SELECT DATABASE(), @@server_uuid", rows: [][]driver.Value{{spec.Database, spec.ServerUUID}}},
		sqlStep{contains: "Ssl_cipher", rows: [][]driver.Value{{"Ssl_cipher", "TLS_AES_256_GCM_SHA384"}}},
		sqlStep{contains: "GET_LOCK", rows: [][]driver.Value{{int64(1)}}},
		sqlStep{contains: "USER_ATTRIBUTES", rows: [][]driver.Value{{owner}}},
		sqlStep{contains: "ACCOUNT LOCK", affected: 1},
		sqlStep{contains: "Host<>?", rows: [][]driver.Value{{int64(0)}}},
		sqlStep{contains: "SELECT ID", rows: [][]driver.Value{{int64(42)}}},
		sqlStep{contains: "KILL CONNECTION 42", affected: 1},
		sqlStep{contains: "SELECT ID"},
		sqlStep{contains: "DROP USER", affected: 1},
		sqlStep{contains: "USER_ATTRIBUTES"},
		sqlStep{contains: "COUNT(*) FROM information_schema.PROCESSLIST", rows: [][]driver.Value{{int64(0)}}},
	)
	provider := DatabaseCredentials{Vault: v, Admin: remote.DB}
	if e := provider.Revoke(context.Background(), task, ref); e != nil || remoteScript.writes != 3 || controlScript.writes != 2 {
		t.Fatal("account revocation incomplete", e)
	}
}
