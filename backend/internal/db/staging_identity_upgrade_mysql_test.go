package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"clawreef/internal/migrationcatalog"
	"github.com/go-sql-driver/mysql"
)

const stagingIdentityCorrection = "132_backup_v2_staging_backup_identity.sql"
const original172Catalog = "718e4509d2c83c73636dd9745ac7c2b350a57c01d75b5ac50e482ffcb4f537d8"

// Only new marker-owned schemas on the explicitly UUID-pinned local server.
// The old 172-file install is prepared from its unchanged original SQL bytes;
// both fresh installation and 172 -> 173 upgrade use ApplyPinnedMigrations.
func TestStagingIdentityFreshAndOriginal172UpgradeMySQL(t *testing.T) {
	file := os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE")
	expectedUUID := os.Getenv("A_SIGNING_MYSQL_SERVER_UUID")
	if file == "" || expectedUUID == "" {
		t.Skip("requires owned UUID-pinned local MySQL")
	}
	var credential struct {
		Host, User, Password string
		Port                 int
	}
	raw, err := os.ReadFile(file)
	if err != nil || json.Unmarshal(raw, &credential) != nil || credential.Host != "127.0.0.1" || credential.Port < 1 || credential.User == "" {
		t.Fatal("owned local credential unavailable")
	}
	cfg := mysql.NewConfig()
	cfg.User, cfg.Passwd, cfg.Net, cfg.Addr = credential.User, credential.Password, "tcp", net.JoinHostPort(credential.Host, strconv.Itoa(credential.Port))
	credential.Password = ""
	cfg.ParseTime, cfg.Loc = true, time.UTC
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 5*time.Second, 30*time.Second, 30*time.Second
	cfg.Logger = &mysql.NopLogger{}
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal("owned admin unavailable")
	}
	defer admin.Close()
	var server string
	if admin.QueryRow("SELECT @@server_uuid").Scan(&server) != nil || server != expectedUUID {
		t.Fatal("owned server UUID mismatch")
	}
	catalog, err := EmbeddedMigrationCatalog()
	if err != nil || len(catalog.Filenames) != 173 || catalog.Hash != migrationcatalog.ReviewedHash {
		t.Fatal("actual reviewed 173 catalog mismatch", err)
	}
	oldSources := fstest.MapFS{}
	for _, name := range catalog.Filenames {
		if name == stagingIdentityCorrection {
			continue
		}
		body, z := embeddedMigrations.ReadFile("migrations/" + name)
		if z != nil {
			t.Fatal(z)
		}
		oldSources["migrations/"+name] = &fstest.MapFile{Data: body}
	}
	oldCatalog, err := migrationcatalog.Compute(oldSources, "migrations")
	if err != nil || len(oldCatalog.Filenames) != 172 || oldCatalog.Hash != original172Catalog {
		t.Fatal("original 172 SQL bytes/history changed", err)
	}
	for _, scenario := range []string{"fresh", "upgrade"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
			defer cancel()
			var nonce [12]byte
			if _, z := rand.Read(nonce[:]); z != nil {
				t.Fatal(z)
			}
			marker := hex.EncodeToString(nonce[:])
			name := "ad_a_stage_" + marker
			if _, z := admin.ExecContext(ctx, "CREATE DATABASE `"+name+"` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"); z != nil {
				t.Fatal("create owned migration schema", z)
			}
			ownedCfg := cfg.Clone()
			ownedCfg.DBName = name
			database, z := sql.Open("mysql", ownedCfg.FormatDSN())
			if z != nil {
				t.Fatal(z)
			}
			defer database.Close()
			if _, z = database.ExecContext(ctx, "CREATE TABLE _a_staging_upgrade_marker(nonce CHAR(24) PRIMARY KEY)"); z != nil {
				t.Fatal(z)
			}
			if _, z = database.ExecContext(ctx, "INSERT INTO _a_staging_upgrade_marker VALUES(?)", marker); z != nil {
				t.Fatal(z)
			}
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
				defer stop()
				var gotUUID, gotDB, gotMarker string
				if database.QueryRowContext(cleanup, "SELECT @@server_uuid,DATABASE(),(SELECT nonce FROM _a_staging_upgrade_marker)").Scan(&gotUUID, &gotDB, &gotMarker) != nil || gotUUID != expectedUUID || gotDB != name || gotMarker != marker {
					t.Error("owned migration schema cleanup identity mismatch")
					return
				}
				if _, e := admin.ExecContext(cleanup, "DROP DATABASE `"+name+"`"); e != nil {
					t.Error("owned migration cleanup", e)
				}
			}()
			if scenario == "upgrade" {
				func() {
					conn, e := database.Conn(ctx)
					if e != nil {
						t.Fatal(e)
					}
					defer conn.Close()
					release, e := acquireMigrationLocks(ctx, conn)
					if e != nil {
						t.Fatal(e)
					}
					defer func() {
						if e := release(); e != nil {
							t.Error("old fixture migration lock release", e)
						}
					}()
					// This is only preparation of a NEW old-version fixture. No production
					// migration API accepts a shortened catalog or bypasses its pin.
					if e = ensureSchemaMigrationsTable(conn); e != nil {
						t.Fatal(e)
					}
					for _, filename := range oldCatalog.Filenames {
						if e = assertBackupCaptureIdle(ctx, conn); e != nil {
							t.Fatal(e)
						}
						body, e := oldSources.ReadFile("migrations/" + filename)
						if e != nil {
							t.Fatal(e)
						}
						for i, statement := range splitSQLStatements(string(body)) {
							if _, e = conn.ExecContext(ctx, statement); e != nil {
								t.Fatalf("original 172 %s statement %d: %v", filename, i+1, e)
							}
						}
						if _, e = conn.ExecContext(ctx, "INSERT INTO schema_migrations(filename,applied_at) VALUES(?,UTC_TIMESTAMP(6))", filename); e != nil {
							t.Fatal(e)
						}
					}
				}()
				var count int
				if e := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&count); e != nil || count != 172 {
					t.Fatal("old actual migration ledger", count, e)
				}
				checkOriginalStagingIdentityExpression(t, ctx, database, false)
			}
			if z = ApplyPinnedMigrations(ctx, database, MigrationTarget{ServerUUID: expectedUUID, Database: name, CatalogSHA256: catalog.Hash}); z != nil {
				t.Fatal("actual pinned migration entrypoint", z)
			}
			var count, correction int
			if z = database.QueryRowContext(ctx, "SELECT COUNT(*),SUM(filename=?) FROM schema_migrations", stagingIdentityCorrection).Scan(&count, &correction); z != nil || count != 173 || correction != 1 {
				t.Fatal("actual 173 ledger", count, correction, z)
			}
			checkOriginalStagingIdentityExpression(t, ctx, database, true)
			if z = ApplyPinnedMigrations(ctx, database, MigrationTarget{ServerUUID: expectedUUID, Database: name, CatalogSHA256: catalog.Hash}); z != nil {
				t.Fatal("idempotent actual pinned migration", z)
			}
			t.Logf("%s: actual original ledger 173, correction once, UUID CHECK valid/bad cases, old 172 bytes pinned", scenario)
		})
	}
}

func checkOriginalStagingIdentityExpression(t *testing.T, ctx context.Context, database *sql.DB, corrected bool) {
	t.Helper()
	var clause string
	if e := database.QueryRowContext(ctx, "SELECT CHECK_CLAUSE FROM information_schema.CHECK_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND CONSTRAINT_NAME='sbv2_chk_sb_staging_identity'").Scan(&clause); e != nil {
		t.Fatal(e)
	}
	if clause == "" || strings.Contains(clause, ";") {
		t.Fatal("actual identity CHECK unavailable")
	}
	// MySQL's metadata representation escapes the SQL string delimiters. The
	// original identity CHECK has no quote-bearing values or regex escapes;
	// decode only that presentation escape before evaluating its exact terms.
	clause = strings.ReplaceAll(clause, "\\'", "'")
	for _, test := range []struct {
		name, backup, resource string
		attempt                int
		valid                  bool
	}{
		{"original-valid", "sbk_11111111-1111-4111-8111-111111111111", "sbs_22222222-2222-4222-8222-222222222222", 1, corrected},
		{"old-missing-group", "sbk_11111111-1111-4111-111111111111", "sbs_22222222-2222-4222-8222-222222222222", 1, !corrected},
		{"bad-resource", "sbk_11111111-1111-4111-8111-111111111111", "sbs_bad", 1, false},
		{"zero-attempt", "sbk_11111111-1111-4111-8111-111111111111", "sbs_22222222-2222-4222-8222-222222222222", 0, false},
	} {
		var valid bool
		// Match 104's actual ascii_bin columns; bare bound strings inherit the
		// connection collation and cannot represent this table's CHECK inputs.
		query := "SELECT (" + clause + ") FROM (SELECT CAST(? AS CHAR CHARACTER SET ascii) COLLATE ascii_bin AS schema_version,CAST(? AS CHAR CHARACTER SET ascii) COLLATE ascii_bin AS public_id,CAST(? AS CHAR CHARACTER SET ascii) COLLATE ascii_bin AS origin_installation_id,CAST(? AS CHAR CHARACTER SET ascii) COLLATE ascii_bin AS backup_public_id,? AS attempt_no,CAST(? AS CHAR CHARACTER SET ascii) COLLATE ascii_bin AS phase_uid,? AS row_version) AS original_identity"
		if e := database.QueryRowContext(ctx, query, "system-backup-staging-resource.v1", test.resource, "installation_test", test.backup, test.attempt, "original-capture", 1).Scan(&valid); e != nil || valid != test.valid {
			t.Fatal("actual original server CHECK expression", test.name, valid, test.valid, e)
		}
	}
}
