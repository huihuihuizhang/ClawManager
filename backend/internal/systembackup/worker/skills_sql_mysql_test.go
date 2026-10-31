package worker

import (
	"bytes"
	"clawreef/internal/systembackup/domain"
	sh "clawreef/internal/systembackupskillhub"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	mysql "github.com/go-sql-driver/mysql"
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// Real local MySQL rows/RR/SELECT-only grants flow through the ACTUAL formal
// SQL collector and C framing. The key callback/source admission are explicit
// local fixtures, separately covered by original-control and TLS source tests.
func TestFormalSkillsSQLChecksOriginalProjectionBeforeCandidateMySQL(t *testing.T) {
	reader, admin, name, uuid := skillWorkerSourceMySQL(t)
	ctx := context.Background()
	tx, err := reader.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := domain.ReadSkillCaptureInventory(ctx, tx, map[int]bool{1: true}, map[int]int{7: 1})
	tx.Rollback()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "lost-row", "changed-version", "missing-table", "changed-source"} {
		t.Run(mode, func(t *testing.T) {
			i, env, key := formalInvocationFixture(t)
			i.WorkspacePath = ""
			env.Workspace = nil
			env.Database = reader
			env.SourceAuthorize = func(context.Context, Invocation) error { return nil }
			i.Request.Operation = "capture-database"
			i.Request.MaxFiles, i.Request.MaxFileBytes = 0, 0
			i.Request.Files = nil
			i.Request.RuntimePolicy = nil
			i.Request.PolicyVersion = ""
			i.Request.Binding.Path = "users_instances_database"
			i.ProviderKey.Request.Context.Part = i.Request.Binding.Path
			key.request = i.ProviderKey.Request
			spec := databaseRequestFixture(t).Request.Database
			spec.Name, spec.ServerUUID = name, uuid
			spec.MaxMemoryBytes = 8 << 20
			spec.SkillsInventory = sh.CloneCaptureInventory(&inventory)
			i.Request.Database = spec
			i.Request.MaxArchiveBytes, i.Request.MaxCompressedBytes = 8<<20, 1<<20
			if !ValidateRecordedInvocation(i) {
				t.Fatal("invalid original formal SQL fixture")
			}
			switch mode {
			case "lost-row":
				spec.SkillsInventory.Tables[0].IDs = nil
			case "changed-version":
				spec.SkillsInventory.Versions[0].BlobID = 18
			case "missing-table":
				spec.SkillsInventory.Tables = spec.SkillsInventory.Tables[:7]
			case "changed-source":
				if _, err := admin.Exec("UPDATE skills SET current_version_id=19 WHERE id=11"); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := admin.Exec("UPDATE skills SET current_version_id=13 WHERE id=11"); err != nil {
						t.Error(err)
					}
				}()
			}
			result, err := runFormalCapture(ctx, i, key, env)
			if mode != "valid" {
				if err == nil || result.Ciphertext.Name != "" || result.Envelope.Name != "" {
					t.Fatal("changed Skill projection got formal candidate", err)
				}
				entries, _ := os.ReadDir(i.StagingPath)
				if len(entries) != 0 {
					t.Fatal("projection failure retained cipher/envelope/partial")
				}
				return
			}
			if err != nil || result.Tables != 11 {
				t.Fatal("actual formal SQL capture", err, result.Tables)
			}
			cipher, _ := env.Staging.ReadFile(result.Ciphertext.Name)
			envelope, _ := env.Staging.ReadFile(result.Envelope.Name)
			plain := openTeamCandidateForTest(t, i, cipher, envelope)
			snapshot, err := domain.Decode(bytes.NewReader(plain), domain.Limits{MaxRows: 100, MaxBytes: 8 << 20})
			if err != nil || domain.VerifySkillCapture(snapshot, inventory) != nil {
				t.Fatal("C candidate lost original raw Skill tables", err)
			}
			tables := map[string]domain.Table{}
			for _, table := range snapshot.Tables {
				tables[table.Name] = table
			}
			if tables["skill_versions"].Rows[0]["manifest_json"].String() != `{"private_manifest":"retained"}` || tables["skill_scan_results"].Rows[0]["findings_json"].String() != `{"private_findings":"retained"}` {
				t.Fatal("C candidate lost raw columns hidden by business JSON")
			}
		})
	}
}

func skillWorkerSourceMySQL(t *testing.T) (*sql.DB, *sql.DB, string, string) {
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
