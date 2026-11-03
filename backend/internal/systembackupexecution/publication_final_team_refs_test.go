package systembackupexecution

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"clawreef/internal/systembackup/domain"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/team"
	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	pc "clawreef/internal/systembackuppartcontainer"
)

// Local inert SQL/manifest DATA, not a source grant or finalization receipt.
func finalTeamRelationsFixture(t *testing.T) (b.SourceInventory, domain.Snapshot) {
	t.Helper()
	raw, err := os.ReadFile("../systembackup/team/schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var shapes []struct {
		Name       string
		Columns    []struct{ Name, Type, Nullable, Extra string }
		PrimaryKey []string `json:"primary_key"`
	}
	if err = json.Unmarshal(raw, &shapes); err != nil {
		t.Fatal(err)
	}
	snapshot := domain.Snapshot{Version: domain.Version}
	for _, row := range []struct {
		name   string
		values domain.Row
	}{
		{"users", domain.Row{"id": domain.Text("4")}},
		{"instances", domain.Row{"id": domain.Text("7"), "user_id": domain.Text("4")}},
		{"user_quotas", domain.Row{"id": domain.Text("8"), "user_id": domain.Text("4")}},
	} {
		table := domain.Table{Name: row.name, Engine: "InnoDB", PrimaryKey: []string{"id"}, Rows: []domain.Row{row.values}}
		for name := range row.values {
			table.Columns = append(table.Columns, domain.Column{Name: name, Type: "varchar(255)", Nullable: true})
		}
		snapshot.Tables = append(snapshot.Tables, table)
	}
	for _, shape := range shapes {
		table := domain.Table{Name: shape.Name, Engine: "InnoDB", PrimaryKey: shape.PrimaryKey}
		row := domain.Row{}
		for _, c := range shape.Columns {
			table.Columns = append(table.Columns, domain.Column{Name: c.Name, Type: c.Type, Nullable: c.Nullable == "YES", Extra: c.Extra})
			row[c.Name] = domain.Text("0")
			if c.Nullable == "YES" {
				row[c.Name] = domain.Cell{Null: true}
			}
		}
		if shape.Name == "teams" {
			for name, value := range map[string]string{"id": "20", "user_id": "4", "resource_scope": "cm", "status": "running", "shared_pvc_name": "team-pvc", "shared_pvc_namespace": "source", "shared_mount_path": "/team"} {
				row[name] = domain.Text(value)
			}
			table.Rows = []domain.Row{row}
		}
		if shape.Name == "team_events" {
			row["id"], row["team_id"], row["payload_json"] = domain.Text("90"), domain.Text("20"), domain.Text(`{"artifactRefs":["/team/results/report.bin"]}`)
			table.Rows = []domain.Row{row}
		}
		snapshot.Tables = append(snapshot.Tables, table)
	}
	inv := &team.Inventory{Version: team.InventoryVersion, SchemaSHA256: team.SchemaSHA256(), Teams: []team.SourceTeam{{ID: 20, UserID: 4, ResourceScope: "cm", Status: "running", SharedMountID: "team_20", RedisScopeID: "redis_a"}}, Mounts: []team.SharedMount{{ID: "team_20", TeamID: 20, Namespace: "source", PVC: "team-pvc", UID: "team-pvc-uid", Root: "/team"}}, Redis: []team.RedisScope{{ID: "redis_a", ServerID: strings.Repeat("a", 40), TeamIDs: []int{20}}}}
	source := b.SourceInventory{Database: "original", ServerUUID: "original-server", Users: []int{4}, Instances: []b.InstanceIdentity{{ID: 7, UserID: 4}}, Teams: inv}
	if err := domain.VerifyTeamCapture(snapshot, *inv); err != nil {
		t.Fatal("local SQL fixture", err)
	}
	return source, snapshot
}

func finalTeamSQLInvocation(source b.SourceInventory) worker.Invocation {
	return worker.Invocation{Request: worker.Request{Operation: "capture-database", Binding: staging.Binding{BackupID: "sbk_local_team_DATA", Attempt: "1", Path: b.UsersInstancesDatabasePart, CaptureContextHash: strings.Repeat("a", 64)}, Database: &worker.DatabaseSpec{Name: source.Database, ServerUUID: source.ServerUUID, TeamsInventory: team.CloneInventory(source.Teams)}}, FormalCapture: &worker.FormalCaptureSpec{ConfigSHA256: strings.Repeat("b", 64)}}
}

func finalTeamObservedSQL(t *testing.T, source b.SourceInventory, snapshot domain.Snapshot, sql worker.Invocation) *publicationFinalTeamRelations {
	t.Helper()
	r, err := newPublicationFinalTeamRelations(source)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.begin(sql); err != nil {
		t.Fatal(err)
	}
	if err = r.observeSQL(snapshot); err != nil {
		t.Fatal(err)
	}
	if err = r.parsedPart(sql); err != nil {
		t.Fatal(err)
	}
	if err = r.confirmPart(sql); err != nil {
		t.Fatal(err)
	}
	return r
}

func finalTeamTar(t *testing.T, mode string) ([]byte, worker.FormalCaptureResult) {
	t.Helper()
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	headers := []*tar.Header{{Name: "results", Typeflag: tar.TypeDir, Mode: 0700}, {Name: "results/report.bin", Typeflag: tar.TypeReg, Mode: 0600, Size: 3}}
	switch mode {
	case "missing":
		headers = headers[:1]
	case "implicit-parent":
		headers = headers[1:]
	case "directory":
		headers[1].Typeflag, headers[1].Size = tar.TypeDir, 0
	case "link":
		headers[1].Typeflag, headers[1].Size, headers[1].Linkname = tar.TypeSymlink, 0, "other.bin"
	case "parent-link":
		headers[0].Typeflag, headers[0].Linkname = tar.TypeSymlink, "other"
	}
	var candidate worker.FormalCaptureResult
	for _, header := range headers {
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		candidate.Files++
		candidate.Bytes += header.Size
		if header.Size > 0 {
			if _, err := tw.Write([]byte{0, 255, 13}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes(), candidate
}

func TestPublicationFinalTeamRefsRequireActualWorkspaceAndConfirmation(t *testing.T) {
	for _, mode := range []string{"current", "missing", "implicit-parent", "directory", "link", "parent-link", "unconfirmed", "duplicate-confirm", "required-objects-unread"} {
		t.Run(mode, func(t *testing.T) {
			source, snapshot := finalTeamRelationsFixture(t)
			if mode == "required-objects-unread" {
				source.Teams.Objects = []team.ObjectRef{{TeamID: 20, Bucket: "original", Key: "artifact", Version: "v1", SHA256: strings.Repeat("c", 64), Size: 3}}
			}
			sql := finalTeamSQLInvocation(source)
			r := finalTeamObservedSQL(t, source, snapshot, sql)
			if r.complete() == nil {
				t.Fatal("SQL alone certified unconsumed workspace")
			}
			i := sql
			i.Request = worker.Request{Operation: "capture-workspace", Binding: sql.Request.Binding, MaxFiles: 10, MaxFileBytes: 1024}
			i.Request.Binding.Path, i.WorkspacePath = "team_20_workspace", "/workspace"
			if err := r.begin(i); err != nil {
				t.Fatal(err)
			}
			archive, candidate := finalTeamTar(t, mode)
			err := inspectOwnedWorkspaceRelations(context.Background(), i, candidate, bytes.NewReader(archive), r.workspaceRead(i))
			if mode != "current" && mode != "unconfirmed" && mode != "duplicate-confirm" && mode != "required-objects-unread" {
				if err == nil {
					t.Fatal("uncovered SQL reference accepted", mode)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = r.parsedPart(i); err != nil {
				t.Fatal(err)
			}
			if r.complete() == nil {
				t.Fatal("parser success became authenticated confirmation")
			}
			if mode == "unconfirmed" {
				return
			}
			if err = r.confirmPart(i); err != nil {
				t.Fatal(err)
			}
			if mode == "duplicate-confirm" {
				if r.confirmPart(i) == nil || r.complete() == nil {
					t.Fatal("repeated confirm was adopted")
				}
			} else if mode == "required-objects-unread" {
				if r.complete() == nil {
					t.Fatal("required object payload was never read")
				}
			} else if err = r.complete(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPublicationFinalTeamRefsRejectCrossScopeAndObjects(t *testing.T) {
	for _, mode := range []string{"task", "attempt", "context", "config", "inventory", "object-team", "object-version", "unknown-workspace", "before-sql", "workspace-spec-substitution"} {
		t.Run(mode, func(t *testing.T) {
			source, snapshot := finalTeamRelationsFixture(t)
			if strings.HasPrefix(mode, "object-") {
				source.Teams.Objects = []team.ObjectRef{{TeamID: 20, Bucket: "original", Key: "artifact", Version: "v1", SHA256: strings.Repeat("c", 64), Size: 3}}
			}
			sql := finalTeamSQLInvocation(source)
			r := finalTeamObservedSQL(t, source, snapshot, sql)
			i := sql
			i.Request = worker.Request{Operation: "capture-workspace", Binding: sql.Request.Binding}
			i.Request.Binding.Path, i.WorkspacePath = "team_20_workspace", "/workspace"
			// Detach the config pointer before mutating the candidate invocation.
			i.FormalCapture = &worker.FormalCaptureSpec{ConfigSHA256: sql.FormalCapture.ConfigSHA256}
			switch mode {
			case "task":
				i.Request.Binding.BackupID = "sbk_other_DATA"
			case "attempt":
				i.Request.Binding.Attempt = "2"
			case "context":
				i.Request.Binding.CaptureContextHash = strings.Repeat("d", 64)
			case "config":
				i.FormalCapture.ConfigSHA256 = strings.Repeat("d", 64)
			case "inventory":
				r, _ = newPublicationFinalTeamRelations(source)
				i = sql
				i.Request.Database = &worker.DatabaseSpec{Name: source.Database, ServerUUID: source.ServerUUID, TeamsInventory: team.CloneInventory(source.Teams)}
				i.Request.Database.TeamsInventory.Teams[0].Owner = "foreign"
			case "object-team", "object-version":
				i.Request.Operation, i.Request.Binding.Path = "capture-team-objects", "teams_objects"
				i.Request.Teams = &worker.TeamCaptureSpec{InventorySHA256: source.Teams.SHA256(), Objects: append([]team.ObjectRef(nil), source.Teams.Objects...)}
				if mode == "object-team" {
					i.Request.Teams.Objects[0].TeamID = 21
				} else {
					i.Request.Teams.Objects[0].Version = "v2"
				}
			case "unknown-workspace":
				i.Request.Binding.Path = "team_21_workspace"
			case "workspace-spec-substitution":
				i.Request.SkillObjects = &worker.SkillObjectCaptureSpec{}
			case "before-sql":
				var err error
				r, err = newPublicationFinalTeamRelations(source)
				if err != nil {
					t.Fatal(err)
				}
			}
			if r.begin(i) == nil {
				t.Fatal("foreign or unconsumed relationship accepted", mode)
			}
		})
	}
}

func TestPublicationFinalTeamRefsGzipCompletion(t *testing.T) {
	_, _, _, i, candidate, _ := formalObserverFixture(t, func(root *os.Root, i *worker.Invocation) {
		i.Request.Binding.Path, i.ProviderKey.Request.Context.Part = "team_20_workspace", "team_20_workspace"
		if err := root.Mkdir("results", 0700); err != nil {
			t.Fatal(err)
		}
		if err := root.WriteFile("results/report.bin", []byte{0, 255, 13}, 0600); err != nil {
			t.Fatal(err)
		}
	})
	source, snapshot := finalTeamRelationsFixture(t)
	sql := finalTeamSQLInvocation(source)
	sql.Request.Binding = i.Request.Binding
	sql.Request.Binding.Path = b.UsersInstancesDatabasePart
	sql.FormalCapture = i.FormalCapture
	archive, counts := finalTeamTar(t, "current")
	var compressed bytes.Buffer
	if err := staging.Compress(&compressed, func(dst io.Writer) error { _, err := dst.Write(archive); return err }); err != nil {
		t.Fatal(err)
	}
	candidate.Files, candidate.Bytes = counts.Files, counts.Bytes
	for _, mode := range []string{"current", "footer"} {
		t.Run(mode, func(t *testing.T) {
			r := finalTeamObservedSQL(t, source, snapshot, sql)
			payload := compressed.Bytes()
			if mode == "footer" {
				payload = payload[:len(payload)-8]
			}
			// Named local candidate metadata; no authorization or remote receipt.
			var out ownedPayloadCounts
			err := inspectOwnedBusinessPayloadRelations(context.Background(), i, candidate, bytes.NewReader(payload), r, &out)
			if mode == "footer" {
				if err == nil || out.Complete || r.confirmPart(i) == nil || r.complete() == nil {
					t.Fatal("truncated gzip retained relation proof", err, out)
				}
				return
			}
			if err != nil || !out.Complete {
				t.Fatal("complete original workspace rejected", err, out)
			}
			if r.complete() == nil {
				t.Fatal("outer authentication was not required")
			}
			if err = r.confirmPart(i); err != nil {
				t.Fatal(err)
			}
			if err = r.complete(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPublicationFinalTeamRefsEmptyInventoryStillRequiresSQL(t *testing.T) {
	source, snapshot := finalTeamRelationsFixture(t)
	source.Teams = &team.Inventory{Version: team.InventoryVersion, SchemaSHA256: team.SchemaSHA256()}
	for n := range snapshot.Tables {
		if snapshot.Tables[n].Name == "teams" || snapshot.Tables[n].Name == "team_events" {
			snapshot.Tables[n].Rows = nil
		}
	}
	r, err := newPublicationFinalTeamRelations(source)
	if err != nil {
		t.Fatal(err)
	}
	if r.complete() == nil {
		t.Fatal("empty inventory skipped original SQL read")
	}
	r = finalTeamObservedSQL(t, source, snapshot, finalTeamSQLInvocation(source))
	if err = r.complete(); err != nil {
		t.Fatal("empty Teams added fabricated workspace requirement", err)
	}
}

func TestPublicationFinalTeamObjectsRequireConfirmedSQL(t *testing.T) {
	source, _ := finalTeamRelationsFixture(t)
	source.Teams.Objects = []team.ObjectRef{{TeamID: 20, Bucket: "original", Key: "artifact", Version: "v1", SHA256: strings.Repeat("c", 64), Size: 3}}
	r, err := newPublicationFinalTeamRelations(source)
	if err != nil {
		t.Fatal(err)
	}
	i := finalTeamSQLInvocation(source)
	i.Request.Database = nil
	i.Request.Operation, i.Request.Binding.Path = "capture-team-objects", "teams_objects"
	i.Request.Teams = &worker.TeamCaptureSpec{InventorySHA256: source.Teams.SHA256(), Objects: source.Teams.Objects}
	if err := r.begin(i); err == nil {
		t.Fatal("Team objects accepted before original SQL authenticated confirmation")
	}
}

func TestPublicationFinalTeamOuterFailureDiscardsRound(t *testing.T) {
	source, snapshot := finalTeamRelationsFixture(t)
	i := finalTeamSQLInvocation(source)
	r := finalTeamObservedSQL(t, source, snapshot, i)
	samples, _, _, _, _, _ := publicationContentSampleData()
	var service *DeploymentService // The outer verifier cannot issue authority.
	_, err := service.inspectOriginalRemoteContainerMemberSamples(context.Background(), c.ClaimToken{}, 1, nil, ArtifactReadObject{}, publicationVerifiedCapture{}, publicationVerifiedPart{}, pc.Member{}, pc.MemberLocation{}, r, samples)
	if err == nil {
		t.Fatal("missing independent verifier accepted")
	}
	if !r.failed || !samples.failed {
		t.Fatal("outer read failure retained a reusable partial Team/report round")
	}
	i.Request.Database = nil
	i.Request.Operation, i.Request.Binding.Path = "capture-workspace", "team_20_workspace"
	i.WorkspacePath = "/workspace"
	if r.begin(i) == nil {
		t.Fatal("failed round continued into another member")
	}
}
