package publicadapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
	sh "clawreef/internal/systembackupskillhub"
	mysql "github.com/go-sql-driver/mysql"
)

// Actual local MySQL and production discovery/SQL worker calls. Source Skill
// CREATE statements are the repository's 008/023/039 DDL; surrounding users/
// instances are focused shapes, not a complete migration or live TLS proof.
func TestSkillsDiscoveryAndSharedSQLWorkerNonemptyMySQL(t *testing.T) {
	reader, admin, name, uuid := skillsSourceMySQL(t)
	f := moduleTestInput(t)
	var original *sql.Tx
	authentications, reads := 0, 0
	cfg := WithSkillCaptureInventory(LinuxProfileConfig{Source: reader, Database: name, ServerUUID: uuid, Supported: map[AgentKind]bool{{"openclaw", "lite", "linux", "linux"}: true}, HoldLimit: time.Minute,
		VerifySource: func(ctx context.Context, tx *sql.Tx) error {
			authentications++
			if original == nil {
				original = tx
			} else if original != tx {
				t.Fatal("source authentication changed discovery RR transaction")
			}
			var database, server, current, role string
			if err := tx.QueryRowContext(ctx, "SELECT DATABASE(),@@server_uuid,CURRENT_USER(),CURRENT_ROLE()").Scan(&database, &server, &current, &role); err != nil || database != name || server != uuid || !strings.HasPrefix(current, "ad_d_skill_") || role != "NONE" {
				t.Fatal("wrong independently scoped source session", err)
			}
			return nil
		},
		BuildWriters: func(context.Context, d.Input, SourceInventory, []FrozenWriter) ([]flow.Writer, error) {
			return []flow.Writer{}, nil
		},
		BuildParts: func(d.Input, SourceInventory, time.Time) ([]JobPart, error) { return f.x.Parts, nil },
	})
	actualReader := cfg.ReadSkills
	cfg.ReadSkills = func(ctx context.Context, tx *sql.Tx, inv SourceInventory) (*sh.CaptureInventory, error) {
		reads++
		if tx != original {
			t.Fatal("Skills opened second snapshot")
		}
		// Users were already read in this RR transaction. A separately
		// committed admin write must not change what the Skills reader sees.
		if _, err := admin.Exec("UPDATE skills SET current_version_id=19 WHERE id=11"); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := admin.Exec("UPDATE skills SET current_version_id=13 WHERE id=11"); err != nil {
				t.Error(err)
			}
		}()
		result, err := actualReader(ctx, tx, inv)
		if err == nil && (len(result.Skills) != 1 || result.Skills[0].CurrentVersionID != 13) {
			t.Fatal("Skills escaped the original discovery RR snapshot")
		}
		return result, err
	}
	profile, err := NewLinuxProfile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := profile.Discover(context.Background(), f.in)
	if err != nil {
		t.Fatal("actual discovery", err)
	}
	var source SourceInventory
	if json.Unmarshal(discovery.Source, &source) != nil || source.Skills == nil || authentications != 2 || reads != 1 || len(source.Skills.Tables) != 8 || len(source.Skills.Blobs) != 2 || len(source.Skills.Jobs) != 1 {
		t.Fatal("production discovery lost nonempty Skills projection", authentications, reads)
	}
	requirements, err := source.Skills.WorkspaceRequirements()
	if err != nil || len(requirements) != 2 || requirements[0].BlobID != 18 {
		t.Fatal("unpackaged blob requirements lost", err)
	}
	// Readonly discovery is finished; a separate capture transaction below must
	// reproduce this exact identity/keyset projection before it seals a result.
	request := worker.Request{Version: worker.Version, Operation: "capture-database", Binding: staging.Binding{BackupID: "sbk_skills_sql", Attempt: "3", Path: UsersInstancesDatabasePart, EnvelopeID: "explicit-local-key", CaptureContextHash: strings.Repeat("c", 64)}, Deadline: time.Now().Add(time.Minute), ArtifactName: "source.enc", MaxArchiveBytes: 8 << 20, MaxCompressedBytes: 8 << 20, Database: &worker.DatabaseSpec{Address: "fixture.invalid:3306", Name: name, ServerUUID: uuid, TLSServerName: "fixture.invalid", RootCA: []byte("not used by injected actual MySQL reader"), MaxRows: 100, MaxMemoryBytes: 8 << 20, SkillsInventory: sh.CloneCaptureInventory(source.Skills)}}
	key := bytes.Repeat([]byte{19}, 32)
	defer clear(key)
	for _, mode := range []string{"valid", "missing-projection-row", "changed-version-blob", "missing-table", "wrong-schema", "changed-source-row"} {
		t.Run(mode, func(t *testing.T) {
			r := request
			dbspec := *request.Database
			r.Database = &dbspec
			dbspec.SkillsInventory = sh.CloneCaptureInventory(source.Skills)
			switch mode {
			case "missing-projection-row":
				dbspec.SkillsInventory.Tables[0].IDs = nil
			case "changed-version-blob":
				dbspec.SkillsInventory.Versions[0].BlobID = 18
			case "missing-table":
				dbspec.SkillsInventory.Tables = dbspec.SkillsInventory.Tables[:7]
			case "wrong-schema":
				dbspec.SkillsInventory.Tables[0].SchemaSHA256 = strings.Repeat("f", 64)
			case "changed-source-row":
				if _, err := admin.Exec("UPDATE skills SET current_version_id=19 WHERE id=11"); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := admin.Exec("UPDATE skills SET current_version_id=13 WHERE id=11"); err != nil {
						t.Error(err)
					}
				}()
			}
			root, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			result, err := worker.RunDatabase(context.Background(), r, worker.DatabaseEnvironment{Database: reader, Staging: root, Key: key, Check: func(context.Context, string, worker.Request) error { return nil }})
			if mode != "valid" {
				if err == nil || result.Receipt.Name != "" {
					t.Fatal("raw SQL worker accepted changed original Skills projection", mode, err)
				}
				entries, _ := os.ReadDir(root.Name())
				if len(entries) != 0 {
					t.Fatal("projection failure retained candidate")
				}
				return
			}
			if err != nil || result.Tables != 11 || result.Rows < 11 {
				t.Fatal("actual shared SQL capture", err, result.Tables, result.Rows)
			}
			encrypted, err := staging.OpenFile(context.Background(), root, result.Receipt)
			if err != nil {
				t.Fatal(err)
			}
			defer encrypted.Close()
			var snapshot domain.Snapshot
			err = staging.ConsumeCompressed(context.Background(), encrypted, key, r.Binding, r.MaxCompressedBytes, r.MaxArchiveBytes, func(plain io.Reader) error {
				var err error
				snapshot, err = domain.Decode(plain, domain.Limits{MaxRows: 100, MaxBytes: 8 << 20})
				return err
			})
			if err != nil || domain.VerifySkillCapture(snapshot, *source.Skills) != nil {
				t.Fatal("actual sealed raw SQL projection/readback", err)
			}
			tables := map[string]domain.Table{}
			for _, table := range snapshot.Tables {
				tables[table.Name] = table
			}
			if tables["skill_versions"].Rows[0]["manifest_json"].String() != `{"private_manifest":"retained"}` || tables["skill_scan_results"].Rows[0]["findings_json"].String() != `{"private_findings":"retained"}` || tables["skill_package_materialize_jobs"].Rows[0]["idempotency_key"].String() != "original-materialize" {
				t.Fatal("business model JSON omission lost raw Skill columns")
			}
			for _, name := range sh.CaptureTableNames() {
				if len(tables[name].Rows) == 0 {
					t.Fatal("one of eight Skill tables omitted", name)
				}
			}
		})
	}
}

func skillsSourceMySQL(t *testing.T) (*sql.DB, *sql.DB, string, string) {
	t.Helper()
	file := os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS")
	if file == "" {
		t.Skip("requires disposable local MySQL")
	}
	var creds struct {
		Host, User, Password string
		Port                 int
	}
	raw, err := os.ReadFile(file)
	if err != nil || json.Unmarshal(raw, &creds) != nil || creds.Host != "127.0.0.1" {
		t.Fatal("local MySQL credentials unavailable")
	}
	clear(raw)
	cfg := mysql.NewConfig()
	cfg.Net = "tcp"
	cfg.Addr = creds.Host + ":" + strconv.Itoa(creds.Port)
	cfg.User, cfg.Passwd = creds.User, creds.Password
	cfg.Timeout = 5 * time.Second
	root, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	var entropy [8]byte
	rand.Read(entropy[:])
	suffix := hex.EncodeToString(entropy[:])
	name, user := "ad_d_skills_"+suffix, "ad_d_skill_"+suffix
	if _, err = root.Exec("CREATE DATABASE `" + name + "`"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := root.Exec("DROP DATABASE `" + name + "`"); err != nil {
			t.Error("owned Skills DB cleanup failed")
		}
	})
	cfg.DBName = name
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	for _, statement := range []string{
		"CREATE TABLE users(id INT PRIMARY KEY) ENGINE=InnoDB",
		"CREATE TABLE user_quotas(id INT PRIMARY KEY,user_id INT) ENGINE=InnoDB",
		"CREATE TABLE instances(id INT PRIMARY KEY,user_id INT,instance_mode VARCHAR(20),type VARCHAR(20),runtime_type VARCHAR(20),runtime_variant VARCHAR(20),os_type VARCHAR(20),status VARCHAR(20),runtime_generation INT,pod_name VARCHAR(50),pod_namespace VARCHAR(50),workspace_path VARCHAR(255)) ENGINE=InnoDB",
	} {
		if _, err = admin.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{"008_add_skill_management.sql", "023_add_skill_hub.sql", "039_add_skill_package_materialize.sql"} {
		raw, err := os.ReadFile("../../db/migrations/" + file)
		if err != nil {
			t.Fatal(err)
		}
		statements := regexp.MustCompile(`(?s)CREATE TABLE IF NOT EXISTS (?:skill_blobs|skills|skill_versions|instance_skills|skill_scan_results|skill_hub_tags|skill_hub_tag_assignments|skill_package_materialize_jobs)\s*\(.*?;`).FindAllString(string(raw), -1)
		for _, statement := range statements {
			if _, err = admin.Exec(statement); err != nil {
				t.Fatal("original Skill DDL", file, err)
			}
		}
	}
	if _, err = admin.Exec("ALTER TABLE instance_skills ADD COLUMN workspace_dir VARCHAR(120) NULL AFTER install_path"); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"INSERT INTO users VALUES(1)", "INSERT INTO user_quotas VALUES(1,1)",
		"INSERT INTO instances VALUES(7,1,'lite','openclaw','gateway','linux','linux','running',3,'original-pod','source','/workspaces/1/7')",
		"INSERT INTO skills(id,user_id,skill_key,name,current_version_id) VALUES(11,1,'original','Original Skill',13)",
		"INSERT INTO skill_blobs(id,content_hash,archive_hash,object_key,file_name,size_bytes) VALUES(12,REPEAT('b',32),REPEAT('c',64),'original.zip','original.zip',3),(18,REPEAT('a',32),'','','local',12)",
		"INSERT INTO skill_versions(id,skill_id,blob_id,version_no,manifest_json) VALUES(13,11,12,1,'{\"private_manifest\":\"retained\"}'),(19,11,18,2,'{\"workspace_manifest\":true}')",
		"INSERT INTO instance_skills(id,instance_id,skill_id,skill_version_id,workspace_dir,observed_hash) VALUES(14,7,11,19,'demo',REPEAT('a',32))",
		"INSERT INTO skill_scan_results(id,blob_id,engine,findings_json) VALUES(15,12,'original-scan','{\"private_findings\":\"retained\"}')",
		"INSERT INTO skill_hub_tags(id,tag_key,name) VALUES(16,'original','Original tag')",
		"INSERT INTO skill_hub_tag_assignments(id,skill_id,tag_id) VALUES(17,11,16)",
		"INSERT INTO skill_package_materialize_jobs(id,instance_id,skill_id,blob_id,workspace_dir,content_hash,idempotency_key) VALUES(20,7,11,18,'previous',REPEAT('a',32),'original-materialize')",
	} {
		if _, err = admin.Exec(statement); err != nil {
			t.Fatal("nonempty original Skills fixture", err)
		}
	}
	var password [24]byte
	rand.Read(password[:])
	pass := hex.EncodeToString(password[:])
	clear(password[:])
	if _, err = root.Exec("CREATE USER '" + user + "'@'127.0.0.1' IDENTIFIED BY '" + pass + "'"); err != nil {
		t.Fatal("source user create failed")
	}
	t.Cleanup(func() {
		if _, err := root.Exec("DROP USER '" + user + "'@'127.0.0.1'"); err != nil {
			t.Error("owned Skills reader cleanup failed")
		}
	})
	conn, err := root.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	grant, err := domain.QuotedGrantDatabase(context.Background(), conn, name)
	conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = root.Exec("GRANT SELECT ON " + grant + ".* TO '" + user + "'@'127.0.0.1'"); err != nil {
		t.Fatal("readonly source grant failed")
	}
	cfg.User, cfg.Passwd = user, pass
	reader, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	reader.SetMaxOpenConns(1)
	t.Cleanup(func() { reader.Close() })
	var uuid string
	if admin.QueryRow("SELECT @@server_uuid").Scan(&uuid) != nil {
		t.Fatal("source UUID unavailable")
	}
	return reader, admin, name, uuid
}
