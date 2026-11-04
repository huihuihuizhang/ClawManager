package systembackupexecution

import (
	"archive/tar"
	"bytes"
	"context"
	"strings"
	"testing"

	source "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/domain"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/recovery"
	"clawreef/internal/systembackup/team"
	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	pc "clawreef/internal/systembackuppartcontainer"
)

// These tests exercise inert relation/report DATA and the existing parsers.
// They neither mint a Ready nor stand in for a formal authenticated artifact.
func TestPublicationTeamReportEmptyInventoryRequiresConfirmedSQL(t *testing.T) {
	s, snapshot := finalTeamRelationsFixture(t)
	s.Teams = &team.Inventory{Version: team.InventoryVersion, SchemaSHA256: team.SchemaSHA256()}
	for n := range snapshot.Tables {
		if snapshot.Tables[n].Name == "teams" || snapshot.Tables[n].Name == "team_events" {
			snapshot.Tables[n].Rows = nil
		}
	}
	i := finalTeamSQLInvocation(s)
	r, err := newPublicationFinalTeamRelations(s)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.begin(i); err != nil {
		t.Fatal(err)
	}
	if err = r.observeSQL(snapshot); err != nil {
		t.Fatal(err)
	}
	if err = r.parsedPart(i); err != nil {
		t.Fatal(err)
	}
	a := finalTeamReportData(r)
	if report, err := r.contentReport(a, teamReportDigest(t, a)); err == nil || report.RelationsComplete {
		t.Fatal("empty Teams bypassed original SQL confirmation")
	}
	if err = r.confirmPart(i); err != nil {
		t.Fatal(err)
	}
	a = finalTeamReportData(r)
	report, err := r.contentReport(a, teamReportDigest(t, a))
	if err != nil || !report.RelationsComplete || len(report.Teams) != 0 || len(report.AuthenticatedRead.Members) != 1 || report.AuthenticatedRead.Members[0].Part != b.UsersInstancesDatabasePart {
		t.Fatal("valid empty inventory rejected or invented a Team member", report, err)
	}
}

func TestPublicationTeamReportEmptyWorkspaceIsNotMissingWorkspace(t *testing.T) {
	s, snapshot := finalTeamRelationsFixture(t)
	for n := range snapshot.Tables {
		if snapshot.Tables[n].Name == "team_events" {
			snapshot.Tables[n].Rows[0]["payload_json"] = domain.Text(`{}`)
		}
	}
	sql := finalTeamSQLInvocation(s)
	r := finalTeamObservedSQL(t, s, snapshot, sql)
	a := finalTeamReportData(r)
	if report, err := r.contentReport(a, teamReportDigest(t, a)); err == nil || report.RelationsComplete {
		t.Fatal("missing required workspace was treated as empty")
	}
	i := sql
	i.Request = worker.Request{Operation: "capture-workspace", Binding: sql.Request.Binding, MaxFiles: 10, MaxFileBytes: 1024}
	i.Request.Binding.Path, i.WorkspacePath = "team_20_workspace", "/workspace"
	if err := r.begin(i); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if err := tar.NewWriter(&archive).Close(); err != nil {
		t.Fatal(err)
	}
	if err := inspectOwnedWorkspaceRelations(context.Background(), i, worker.FormalCaptureResult{}, &archive, r.workspaceRead(i)); err != nil {
		t.Fatal(err)
	}
	if err := r.parsedPart(i); err != nil {
		t.Fatal(err)
	}
	a = finalTeamReportData(r)
	if report, err := r.contentReport(a, teamReportDigest(t, a)); err == nil || report.RelationsComplete {
		t.Fatal("parsed but unconfirmed empty workspace was adopted")
	}
	if err := r.confirmPart(i); err != nil {
		t.Fatal(err)
	}
	a = finalTeamReportData(r)
	report, err := r.contentReport(a, teamReportDigest(t, a))
	if err != nil || len(report.Teams) != 1 || report.Teams[0].Workspace == nil {
		t.Fatal(report, err)
	}
	w := report.Teams[0].Workspace
	if w.Entries != 0 || w.RegularFiles != 0 || w.ContentBytes != 0 || w.ReferencesExpected != 0 || w.ReferencesVerified != 0 || len(w.SampledFiles) != 0 || len(w.SampledReferences) != 0 {
		t.Fatal("valid empty archive was represented as nonempty", w)
	}
}

func TestPublicationTeamReportZeroRedisAndObjectsRemainScoped(t *testing.T) {
	r, a := finalTeamReportFixture(t)
	scope := r.inventory.Redis[0]
	snapshot := source.RedisSourceSnapshot{Header: source.RedisSourceSnapshotHeader{Source: recovery.Reference{ID: scope.ID}, ServerID: scope.ServerID, Database: scope.Database, CapturedAtMillis: 1234}}
	if err := r.observeSharedRedis(snapshot); err != nil {
		t.Fatal(err)
	}
	i := finalTeamSQLInvocation(b.SourceInventory{})
	i.Request.Database = nil
	i.Request.Operation, i.Request.Binding.Path = "capture-source-redis", b.SourceRedisPart
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
	ob := report.Teams[0]
	if ob.Redis.Keys != 0 || ob.Redis.ContentBytes != 0 || ob.Redis.SourceID != scope.ID || ob.Redis.Database != scope.Database || ob.Redis.CapturedAtMillis != 1234 || ob.Redis.Scope != "authenticated_prefix_counts_not_sql_stream_semantic_join" {
		t.Fatal("confirmed zero Redis observation lost its original scope", ob.Redis)
	}
	if len(ob.Objects) != 0 || ob.ObjectScope != "original_inventory_empty_not_absence_proof" {
		t.Fatal("empty object inventory became an absence proof", ob)
	}
	for _, member := range report.AuthenticatedRead.Members {
		if member.Part == "teams_objects" {
			t.Fatal("empty original object inventory created a required member")
		}
	}
}

func TestPublicationTeamReportOuterFailureRejectsPreviouslyCompleteRound(t *testing.T) {
	r, a := finalTeamReportFixture(t)
	digest := teamReportDigest(t, a)
	if _, err := r.contentReport(a, digest); err != nil {
		t.Fatal("initial relation DATA not complete", err)
	}
	samples, _, _, _, _, _ := publicationContentSampleData()
	var service *DeploymentService // Real outer authority rejection, not a fake receipt.
	if _, err := service.inspectOriginalRemoteContainerMemberSamples(context.Background(), c.ClaimToken{}, 1, nil, ArtifactReadObject{}, publicationVerifiedCapture{}, publicationVerifiedPart{}, pc.Member{}, pc.MemberLocation{}, r, samples); err == nil {
		t.Fatal("missing original verifier accepted")
	}
	if report, err := r.contentReport(a, digest); err == nil || report.RelationsComplete || len(report.Teams) != 0 || !samples.failed {
		t.Fatal("prior complete results survived a failed outer member", report, err)
	}
}

func TestPublicationTeamReportRetainsSharedSkillsObservation(t *testing.T) {
	r, a := finalTeamReportFixture(t)
	a.SkillsInventorySHA256 = strings.Repeat("b", 64)
	a.SkillsSelectionSHA256 = strings.Repeat("c", 64)
	report, err := r.contentReport(a, teamReportDigest(t, a))
	if err != nil || report.AuthenticatedRead.SkillsInventorySHA256 != a.SkillsInventorySHA256 || report.AuthenticatedRead.SkillsSelectionSHA256 != a.SkillsSelectionSHA256 {
		t.Fatal("Teams report dropped shared original observation fields", report, err)
	}
	staleDigest := teamReportDigest(t, a)
	a.SkillsSelectionSHA256 = strings.Repeat("d", 64)
	if report, err := r.contentReport(a, staleDigest); err == nil || report.RelationsComplete {
		t.Fatal("changed shared observation bypassed the report digest")
	}
}
