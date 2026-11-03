package systembackupexecution

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"testing"

	source "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/domain"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/recovery"
	"clawreef/internal/systembackup/team"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	pc "clawreef/internal/systembackuppartcontainer"
)

// Inert local relation/report DATA, not a real product, authenticated reader,
// signature, acceptance or typed Ready. Actual auth remains public C's reader.
func finalTeamReportFixture(t *testing.T) (*publicationFinalTeamRelations, publicationContentSampleReport) {
	return finalTeamReportObjectsFixture(t, nil)
}

func finalTeamReportObjectsFixture(t *testing.T, objects []team.ObjectRef) (*publicationFinalTeamRelations, publicationContentSampleReport) {
	t.Helper()
	s, snapshot := finalTeamRelationsFixture(t)
	s.Teams.Objects = objects
	s.Teams.Teams[0].Members = []team.SourceMember{{ID: 21, InstanceID: 7}}
	for n := range snapshot.Tables {
		name := snapshot.Tables[n].Name
		if name != "team_members" && name != "team_tasks" && name != "team_work_items" {
			continue
		}
		row := domain.Row{}
		for _, col := range snapshot.Tables[n].Columns {
			row[col.Name] = domain.Text("0")
			if col.Nullable {
				row[col.Name] = domain.Cell{Null: true}
			}
		}
		row["team_id"] = domain.Text("20")
		if name == "team_members" {
			row["id"] = domain.Text("21")
			row["user_id"] = domain.Text("4")
			row["instance_id"] = domain.Text("7")
			row["status"] = domain.Text("idle")
		} else if name == "team_tasks" {
			row["id"] = domain.Text("101")
			row["target_member_id"] = domain.Text("21")
			row["status"] = domain.Text("running")
			row["workflow_state"] = domain.Text("executing")
		} else {
			row["id"] = domain.Text("102")
			row["root_task_id"] = domain.Text("101")
			row["status"] = domain.Text("awaiting_review")
		}
		snapshot.Tables[n].Rows = []domain.Row{row}
	}
	sql := finalTeamSQLInvocation(s)
	r := finalTeamObservedSQL(t, s, snapshot, sql)
	i := sql
	i.Request = worker.Request{Operation: "capture-workspace", Binding: sql.Request.Binding, MaxFiles: 10, MaxFileBytes: 1024}
	i.Request.Binding.Path, i.WorkspacePath = "team_20_workspace", "/workspace"
	if err := r.begin(i); err != nil {
		t.Fatal(err)
	}
	archive, candidate := finalTeamTar(t, "current")
	if err := inspectOwnedWorkspaceRelations(context.Background(), i, candidate, bytes.NewReader(archive), r.workspaceRead(i)); err != nil {
		t.Fatal(err)
	}
	if err := r.parsedPart(i); err != nil {
		t.Fatal(err)
	}
	if err := r.confirmPart(i); err != nil {
		t.Fatal(err)
	}
	a := publicationContentSampleReport{Version: "system-backup-final-content-observations.v1", Installation: "fixture-installation", Backup: sql.Request.Binding.BackupID, Attempt: 1, SourceSHA256: strings.Repeat("d", 64), TeamsInventorySHA256: s.Teams.SHA256(), ArtifactReadIdentitySHA256: strings.Repeat("e", 64), Manifest: ArtifactReadObject{Key: "original/manifest.json", Version: "original-manifest-version", SHA256: strings.Repeat("f", 64), Size: 100}}
	return r, teamAuthReportMembers(r, a)
}

func teamAuthReportMembers(r *publicationFinalTeamRelations, a publicationContentSampleReport) publicationContentSampleReport {
	a.Members = nil
	for part, h := range r.confirmed {
		counts := ownedPayloadCounts{Version: "system-backup-inert-payload-counts.v1", Complete: true}
		if read := r.observations.workspaces[part]; read != nil {
			counts.Kind = "archive_entry_bytes"
			counts.ArchiveEntries = read.entries
			counts.ContentBytes = read.bytes
		}
		if part == "teams_objects" {
			counts.Items = int64(len(r.inventory.Objects))
			for _, ref := range r.inventory.Objects {
				counts.ContentBytes += ref.Size
			}
		}
		a.Members = append(a.Members, publicationContentMemberSample{Part: part, InvocationSHA256: h, Container: ArtifactReadObject{Key: part + "/container", Version: "original-container-version", SHA256: strings.Repeat("a", 64), Size: 100}, Member: pc.MemberLocation{Part: part, ObjectVersion: "original-container-version"}, Counts: counts})
	}
	sort.Slice(a.Members, func(i, j int) bool { return a.Members[i].Part < a.Members[j].Part })
	return a
}

func teamReportDigest(t *testing.T, a publicationContentSampleReport) string {
	t.Helper()
	raw, err := ce.Canonical(a)
	if err != nil {
		t.Fatal(err)
	}
	return hash(raw)
}

func TestPublicationTeamReportUsesCompleteOriginalRoundAndCopiesData(t *testing.T) {
	r, a := finalTeamReportFixture(t)
	digest := teamReportDigest(t, a)
	report, err := r.contentReport(a, digest)
	if err != nil || len(report.Teams) != 1 || !report.RelationsComplete {
		t.Fatal(report, err)
	}
	ob := report.Teams[0]
	if ob.TeamID != 20 || ob.UserID != 4 || ob.Workspace == nil || ob.Workspace.ReferencesExpected != 1 || ob.Workspace.ReferencesVerified != 1 || ob.Workspace.RegularFiles != 1 || ob.Workspace.ContentBytes != 3 || ob.Workspace.SampledReferences[0].Path != "results/report.bin" {
		t.Fatal("actual Team/ref observations missing", ob)
	}
	if ob.ObjectScope != "original_inventory_empty_not_absence_proof" || ob.Redis.Scope != "no_authenticated_shared_redis_member" {
		t.Fatal("empty/unobserved domains were claimed verified", ob)
	}
	if report.AuthenticatedRead.Manifest != a.Manifest || report.ContentObservationsSHA256 != digest {
		t.Fatal("original product locator lost")
	}
	for _, row := range ob.SQLRows {
		if row.Table == "team_events" && row.Rows != 1 {
			t.Fatal("SQL history count lost")
		}
	}
	report.Teams[0].Workspace.SampledReferences[0].Path = "changed"
	report.AuthenticatedRead.Members[0].Counts.Complete = false
	again, err := r.contentReport(a, digest)
	if err != nil || again.Teams[0].Workspace.SampledReferences[0].Path != "results/report.bin" || !again.AuthenticatedRead.Members[0].Counts.Complete {
		t.Fatal("consumer aliases changed original observation", err)
	}
}

func TestPublicationTeamReportRejectsPartialFailedOrForeignData(t *testing.T) {
	for _, mode := range []string{"failed-round", "unconfirmed", "bad-digest", "task", "attempt", "inventory", "missing-member", "invocation", "object-version", "workspace-count", "null-manifest-version"} {
		t.Run(mode, func(t *testing.T) {
			r, a := finalTeamReportFixture(t)
			switch mode {
			case "failed-round":
				r.failed = true
			case "unconfirmed":
				delete(r.confirmed, "team_20_workspace")
			case "task":
				a.Backup = "other-task"
			case "attempt":
				a.Attempt++
			case "inventory":
				a.TeamsInventorySHA256 = strings.Repeat("0", 64)
			case "missing-member":
				a.Members = a.Members[:1]
			case "invocation":
				a.Members[0].InvocationSHA256 = strings.Repeat("0", 64)
			case "object-version":
				a.Members[0].Container.Version = "replacement-version"
			case "workspace-count":
				for n := range a.Members {
					if a.Members[n].Part == "team_20_workspace" {
						a.Members[n].Counts.ContentBytes++
					}
				}
			case "null-manifest-version":
				a.Manifest.Version = "null"
			}
			digest := teamReportDigest(t, a)
			if mode == "bad-digest" {
				digest = strings.Repeat("0", 64)
			}
			if report, err := r.contentReport(a, digest); err == nil || report.RelationsComplete || len(report.Teams) != 0 {
				t.Fatal("partial/foreign report escaped", report, err)
			}
		})
	}
}

func TestPublicationTeamReportRedisScopeCountsWithoutRawKeys(t *testing.T) {
	r, a := finalTeamReportFixture(t)
	key := []byte("claw:team:20:private-result-name")
	snapshot := source.RedisSourceSnapshot{Header: source.RedisSourceSnapshotHeader{Source: recovery.Reference{ID: "redis_a"}, ServerID: strings.Repeat("a", 40), CapturedAtMillis: 1234}, Items: []recovery.RedisItem{{Key: key, Dump: []byte("private-DUMP")}, {Key: []byte("claw:team:200:other-team"), Dump: []byte("other")}, {Key: []byte("other-domain"), Dump: []byte("other")}}}
	if err := r.observeSharedRedis(snapshot); err != nil {
		t.Fatal(err)
	}
	if report, err := r.contentReport(a, teamReportDigest(t, a)); err == nil || report.RelationsComplete {
		t.Fatal("unconfirmed Redis observation escaped into report")
	}
	i := finalTeamSQLInvocation(b.SourceInventory{})
	i.Request.Database = nil
	i.Request.Operation = "capture-source-redis"
	i.Request.Binding.Path = b.SourceRedisPart
	if err := r.begin(i); err != nil {
		t.Fatal(err)
	}
	if err := r.parsedPart(i); err != nil {
		t.Fatal(err)
	}
	if err := r.confirmPart(i); err != nil {
		t.Fatal(err)
	}
	a = teamAuthReportMembers(r, a)
	report, err := r.contentReport(a, teamReportDigest(t, a))
	if err != nil {
		t.Fatal(err)
	}
	redis := report.Teams[0].Redis
	if redis.Keys != 1 || redis.ContentBytes != int64(len(key)+len("private-DUMP")) || redis.CapturedAtMillis != 1234 || !strings.Contains(redis.Scope, "not_sql_stream_semantic_join") {
		t.Fatal(redis)
	}
	raw, _ := json.Marshal(report)
	if bytes.Contains(raw, key) || bytes.Contains(raw, []byte("private-DUMP")) {
		t.Fatal("raw Redis data leaked")
	}
	r, a = finalTeamReportFixture(t)
	snapshot.Header.ServerID = strings.Repeat("b", 40)
	if err := r.observeSharedRedis(snapshot); err == nil {
		t.Fatal("foreign Redis scope accepted")
	}
}

func TestPublicationTeamReportFixedObjectInventoryAndStates(t *testing.T) {
	ref := team.ObjectRef{TeamID: 20, Bucket: "original-bucket", Key: "original-object", Version: "fixed-original-version", SHA256: strings.Repeat("c", 64), Size: 3}
	r, a := finalTeamReportObjectsFixture(t, []team.ObjectRef{ref})
	i := finalTeamSQLInvocation(b.SourceInventory{})
	i.Request.Database = nil
	i.Request.Operation = "capture-team-objects"
	i.Request.Binding.Path = "teams_objects"
	i.Request.Teams = &worker.TeamCaptureSpec{InventorySHA256: r.inventory.SHA256(), Objects: []team.ObjectRef{ref}}
	if err := r.begin(i); err != nil {
		t.Fatal(err)
	}
	if err := r.parsedPart(i); err != nil {
		t.Fatal(err)
	}
	if err := r.confirmPart(i); err != nil {
		t.Fatal(err)
	}
	a.TeamsInventorySHA256 = r.inventory.SHA256()
	a = teamAuthReportMembers(r, a)
	report, err := r.contentReport(a, teamReportDigest(t, a))
	if err != nil {
		t.Fatal(err)
	}
	ob := report.Teams[0]
	if len(ob.Objects) != 1 || ob.Objects[0] != ref || ob.TaskStates[0].State != "running" || ob.WorkItemStates[0].State != "awaiting_review" || ob.WorkItemStates[0].Rows != 1 {
		t.Fatal("original object/state data lost", ob)
	}
}

func TestPublicationTeamReportSampleLimitDoesNotLimitRelationCheck(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(strconv.FormatBool(missing), func(t *testing.T) {
			s, snapshot := finalTeamRelationsFixture(t)
			for n := range snapshot.Tables {
				if snapshot.Tables[n].Name == "team_events" {
					snapshot.Tables[n].Rows[0]["payload_json"] = domain.Text(`{"artifactRefs":["/team/results/a","/team/results/b","/team/results/c","/team/results/z"]}`)
				}
			}
			r := finalTeamObservedSQL(t, s, snapshot, finalTeamSQLInvocation(s))
			i := finalTeamSQLInvocation(s)
			i.Request.Database = nil
			i.Request.Operation = "capture-workspace"
			i.Request.Binding.Path = "team_20_workspace"
			i.Request.MaxFiles = 10
			i.Request.MaxFileBytes = 1024
			i.WorkspacePath = "/workspace"
			if err := r.begin(i); err != nil {
				t.Fatal(err)
			}
			var data bytes.Buffer
			tw := tar.NewWriter(&data)
			if err := tw.WriteHeader(&tar.Header{Name: "results", Typeflag: tar.TypeDir, Mode: 0700}); err != nil {
				t.Fatal(err)
			}
			names := []string{"results/z", "results/b", "results/c", "results/a"}
			if missing {
				names = names[1:]
			}
			for _, name := range names {
				if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0600, Size: 1}); err != nil {
					t.Fatal(err)
				}
				if _, err := tw.Write([]byte{42}); err != nil {
					t.Fatal(err)
				}
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			err := inspectOwnedWorkspaceRelations(context.Background(), i, worker.FormalCaptureResult{Files: int64(len(names) + 1), Bytes: int64(len(names))}, bytes.NewReader(data.Bytes()), r.workspaceRead(i))
			if missing {
				if err == nil {
					t.Fatal("fourth non-sampled reference was not checked")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := r.parsedPart(i); err != nil {
				t.Fatal(err)
			}
			if err := r.confirmPart(i); err != nil {
				t.Fatal(err)
			}
			_, a := finalTeamReportFixture(t)
			a.TeamsInventorySHA256 = r.inventory.SHA256()
			a = teamAuthReportMembers(r, a)
			report, err := r.contentReport(a, teamReportDigest(t, a))
			if err != nil {
				t.Fatal(err)
			}
			w := report.Teams[0].Workspace
			if w.ReferencesVerified != 4 || len(w.SampledReferences) != 3 || w.SampledReferences[0].Path != "results/a" {
				t.Fatal("sampling replaced complete verification", w)
			}
		})
	}
}

func TestPublicationTeamReportBoundaryRequiresExistingTypedAuthority(t *testing.T) {
	for _, ready := range []*publicationTerminalReady{nil, {}} {
		var dst bytes.Buffer
		if err := ready.WriteTeamContentSamples(&dst); err == nil || dst.Len() != 0 {
			t.Fatal("raw/unissued Ready produced a report")
		}
	}
}
