package publicadapter

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/team"
	d "clawreef/internal/systembackupdispatch"
)

func TestAutomaticTeamsDiscoveryUsesOriginalSnapshotAndAcceptsNewTeamsMySQL(t *testing.T) {
	reader, admin, name, uuid := skillsSourceMySQL(t)
	createOriginalTeamSchemaFixture(t, admin)
	insertAutomaticTeamFixture(t, admin, 20, 21)
	f := moduleTestInput(t)
	storage := team.AutomaticStorageMapping{RedisID: "original_redis", RedisServerID: strings.Repeat("a", 40), RedisDatabase: 2}
	var original *sql.Tx
	checks, reads := 0, 0
	cfg := WithSkillCaptureInventory(WithAutomaticTeamsInventory(LinuxProfileConfig{Source: reader, Database: name, ServerUUID: uuid, Supported: map[AgentKind]bool{{"openclaw", "lite", "linux", "linux"}: true}, HoldLimit: time.Minute,
		VerifySource: func(ctx context.Context, tx *sql.Tx) error {
			checks++
			if original == nil {
				original = tx
			} else if original != tx {
				t.Fatal("automatic Teams changed authenticated discovery snapshot")
			}
			var database, server, current, role string
			if tx.QueryRowContext(ctx, "SELECT DATABASE(),@@server_uuid,CURRENT_USER(),CURRENT_ROLE()").Scan(&database, &server, &current, &role) != nil || database != name || server != uuid || !strings.HasPrefix(current, "ad_d_skill_") || role != "NONE" {
				t.Fatal("automatic Teams lost original source identity")
			}
			return nil
		},
		BuildWriters: func(context.Context, d.Input, SourceInventory, []FrozenWriter) ([]flow.Writer, error) {
			return []flow.Writer{}, nil
		},
		BuildParts: func(d.Input, SourceInventory, time.Time) ([]JobPart, error) { return f.x.Parts, nil },
	}, storage))
	actual := cfg.ReadTeams
	cfg.ReadTeams = func(ctx context.Context, tx *sql.Tx, inv SourceInventory) (*team.Inventory, error) {
		if tx != original {
			t.Fatal("automatic Teams opened another transaction")
		}
		reads++
		if reads == 1 {
			// A real committed new Team while the original snapshot is open.
			insertAutomaticTeamFixture(t, admin, 30, 31)
		}
		return actual(ctx, tx, inv)
	}
	profile, err := NewLinuxProfile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for run, expected := range []int{1, 2} {
		original = nil
		start := checks
		discovery, err := profile.Discover(context.Background(), f.in)
		if err != nil || checks-start != 2 {
			t.Fatal("actual original profile discovery", run, err, checks-start)
		}
		var source SourceInventory
		if json.Unmarshal(discovery.Source, &source) != nil || source.Teams == nil || source.Skills == nil || len(source.Teams.Teams) != expected || len(source.Teams.Redis) != 1 || len(source.Teams.Redis[0].TeamIDs) != expected || len(source.Teams.Teams[0].Members) != 1 || source.Teams.Teams[0].Members[0].InstanceID != 7 {
			t.Fatal("automatic source inventory omitted original relationships", run)
		}
		if run == 1 {
			// ONE shared real SQL export, not a second Team dump. No provider or
			// physical source proof is claimed by this source metadata test.
			snapshot, err := domain.CaptureSource(context.Background(), reader, domain.Limits{MaxRows: 100000, MaxBytes: 32 << 20}, name, uuid)
			if err != nil || domain.VerifyTeamCapture(snapshot, *source.Teams) != nil || domain.VerifySkillCapture(snapshot, *source.Skills) != nil {
				t.Fatal("automatic inventory disagrees with original atomic SQL capture", err)
			}
		}
	}
	for _, mode := range []string{"freeze-after-rr", "freeze-replaced-sql-facts"} {
		t.Run(mode, func(t *testing.T) {
			frozenConfig := cfg
			frozenConfig.ReadTeams = nil
			calls := 0
			metadataVersion := "original-version"
			frozenConfig.FreezeSources = func(ctx context.Context, in d.Input, observed SourceInventory) (*team.Inventory, json.RawMessage, error) {
				calls++
				if reader.Stats().InUse != 0 || observed.TeamFacts == nil || len(observed.TeamFacts.Teams) != 2 || observed.Teams != nil {
					t.Fatal("remote source metadata boundary still holds the SQL snapshot")
				}
				inventory, err := team.BindAutomaticStorage(ctx, *observed.TeamFacts, storage, map[int]bool{1: true}, map[int]int{7: 1})
				observed.Users[0] = 999
				observed.Instances[0].ID = 999
				observed.Skills.Blobs[0].ObjectKey = "foreign-object"
				if mode == "freeze-replaced-sql-facts" && err == nil {
					// Even a valid storage inventory cannot replace original SQL
					// names/relationships. Callback also cannot alias the source.
					inventory.Teams[0].Status = "failed"
					observed.TeamFacts.Teams[0].Status = "failed"
				}
				metadata, _ := json.Marshal(struct{ Version, PVCUID, ObjectVersion string }{"named-provider-metadata-fixture", metadataVersion, metadataVersion})
				return inventory, metadata, err
			}
			frozenConfig = WithTeamsSourceFacts(frozenConfig)
			profile, err := NewLinuxProfile(frozenConfig)
			if err != nil {
				t.Fatal(err)
			}
			original = nil
			result, err := profile.Discover(context.Background(), f.in)
			if mode == "freeze-replaced-sql-facts" {
				if err == nil || len(result.Source) != 0 {
					t.Fatal("storage resolver replaced original SQL facts")
				}
				return
			}
			var source SourceInventory
			if err != nil || calls != 1 || json.Unmarshal(result.Source, &source) != nil || source.TeamFacts == nil || source.Teams == nil || len(source.CaptureMetadata) == 0 || !source.TeamFacts.MatchesInventory(*source.Teams) || source.Users[0] != 1 || source.Instances[0].ID != 7 || source.Skills.Blobs[0].ObjectKey != "original.zip" {
				t.Fatal("post-RR metadata did not join the original frozen inventory", err)
			}
			original = nil
			if profile.CheckSource(context.Background(), f.in, result) != nil || calls != 2 {
				t.Fatal("source recheck omitted metadata boundary")
			}
			metadataVersion = "changed-original-source-version"
			original = nil
			if profile.CheckSource(context.Background(), f.in, result) == nil || calls != 3 {
				t.Fatal("changed original PVC/object version reused frozen source")
			}
			preflight := cloneInput(f.in)
			preflight.Authority.TaskType = "preflight"
			original = nil
			if _, err := profile.Discover(context.Background(), preflight); err != nil || calls != 3 {
				t.Fatal("preflight called source providers", err)
			}
		})
	}
	t.Run("original-pvc-and-fixed-objects", func(t *testing.T) {
		if _, err := admin.Exec("UPDATE teams SET shared_pvc_name='original-team',shared_pvc_namespace='source',shared_mount_path='/team' WHERE id=20"); err != nil {
			t.Fatal(err)
		}
		defer admin.Exec("UPDATE teams SET shared_pvc_name=NULL,shared_pvc_namespace=NULL,shared_mount_path='/team' WHERE id=20")
		mapping := storage
		mapping.Claims = []team.SharedClaimIdentity{{Namespace: "source", PVC: "original-team", UID: "original-pvc-uid"}}
		mapping.Objects = []team.ObjectRef{{TeamID: 30, Bucket: "original", Key: "teams/30/object", Version: "fixed-v2", SHA256: strings.Repeat("b", 64)}, {TeamID: 20, Bucket: "original", Key: "teams/20/object", Version: "fixed-v1", SHA256: strings.Repeat("c", 64)}}
		tx, err := reader.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		inventory, err := team.ReadAutomaticInventory(context.Background(), tx, mapping, map[int]bool{1: true}, map[int]int{7: 1})
		if err != nil || len(inventory.Mounts) != 1 || inventory.Mounts[0].TeamID != 20 || inventory.Mounts[0].UID != "original-pvc-uid" || inventory.Mounts[0].Root != "/team" || inventory.Teams[0].SharedMountID != inventory.Mounts[0].ID || inventory.Objects[0].TeamID != 20 || inventory.Objects[1].TeamID != 30 {
			t.Fatal("automatic mapping lost original SQL/PVC/object identities", err)
		}
	})
	for _, mode := range []string{"missing-claim", "extra-claim", "duplicate-claim", "foreign-object", "foreign-member", "unknown-schema"} {
		t.Run(mode, func(t *testing.T) {
			mapping := storage
			switch mode {
			case "missing-claim":
				if _, err := admin.Exec("UPDATE teams SET shared_pvc_name='original-team',shared_pvc_namespace='source',shared_mount_path='/team' WHERE id=20"); err != nil {
					t.Fatal(err)
				}
				defer admin.Exec("UPDATE teams SET shared_pvc_name=NULL,shared_pvc_namespace=NULL,shared_mount_path='/team' WHERE id=20")
			case "extra-claim":
				mapping.Claims = []team.SharedClaimIdentity{{Namespace: "source", PVC: "foreign", UID: "foreign-uid"}}
			case "duplicate-claim":
				mapping.Claims = []team.SharedClaimIdentity{{Namespace: "source", PVC: "same", UID: "uid"}, {Namespace: "source", PVC: "same", UID: "uid"}}
			case "foreign-object":
				mapping.Objects = []team.ObjectRef{{TeamID: 999, Bucket: "original", Key: "teams/foreign", Version: "original-version", SHA256: strings.Repeat("b", 64)}}
			case "foreign-member":
				if _, err := admin.Exec("UPDATE team_members SET user_id=999 WHERE id=21"); err != nil {
					t.Fatal(err)
				}
				defer admin.Exec("UPDATE team_members SET user_id=1 WHERE id=21")
			case "unknown-schema":
				if _, err := admin.Exec("ALTER TABLE teams ADD COLUMN unreviewed_original_data TEXT NULL"); err != nil {
					t.Fatal(err)
				}
				defer admin.Exec("ALTER TABLE teams DROP COLUMN unreviewed_original_data")
			}
			tx, err := reader.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			inventory, err := team.ReadAutomaticInventory(context.Background(), tx, mapping, map[int]bool{1: true}, map[int]int{7: 1})
			if err == nil || inventory != nil {
				t.Fatal("inconsistent automatic source mapping was admitted", mode, err)
			}
		})
	}
}

func insertAutomaticTeamFixture(t *testing.T, db *sql.DB, id, member int) {
	t.Helper()
	if _, err := db.Exec("INSERT INTO teams(id,user_id,name,status,communication_mode,redis_events_last_id,shared_mount_path,resource_scope) VALUES(?,1,'original','running','redis','0-0','/team','cm')", id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO team_members(id,team_id,instance_id,user_id,member_key,display_name,role,runtime_type,instance_mode,status,progress,availability) VALUES(?,?,7,1,'original','Original','worker','openclaw','lite','running',0,'available')", member, id); err != nil {
		t.Fatal(err)
	}
}

// Exact reviewed schema metadata, with no synthetic SQL driver results. This
// fixture has no foreign keys/default business behavior and is not migration QA.
func createOriginalTeamSchemaFixture(t *testing.T, db *sql.DB) {
	t.Helper()
	raw, err := os.ReadFile("../team/schema.json")
	var tables []struct {
		Name    string                                         `json:"name"`
		Columns []struct{ Name, Type, Nullable, Extra string } `json:"columns"`
		Primary []string                                       `json:"primary_key"`
	}
	if err != nil || json.Unmarshal(raw, &tables) != nil || len(tables) != 11 {
		t.Fatal("original Team schema fixture", err)
	}
	for _, table := range tables {
		var columns []string
		for _, column := range table.Columns {
			definition := "`" + column.Name + "` " + column.Type
			if column.Nullable == "NO" {
				definition += " NOT NULL"
			} else {
				definition += " NULL"
			}
			if column.Extra == "auto_increment" {
				definition += " AUTO_INCREMENT"
			}
			if strings.Contains(column.Extra, "DEFAULT_GENERATED") {
				definition += " DEFAULT CURRENT_TIMESTAMP"
			}
			if strings.Contains(column.Extra, "on update CURRENT_TIMESTAMP") {
				definition += " ON UPDATE CURRENT_TIMESTAMP"
			}
			columns = append(columns, definition)
		}
		columns = append(columns, "PRIMARY KEY (`"+strings.Join(table.Primary, "`,`")+"`)")
		if _, err := db.Exec("CREATE TABLE `" + table.Name + "` (" + strings.Join(columns, ",") + ") ENGINE=InnoDB"); err != nil {
			t.Fatal("original Team schema fixture", table.Name, err)
		}
	}
}
