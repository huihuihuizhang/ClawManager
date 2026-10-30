package domain

import (
	"reflect"
	"testing"
)

func TestTeamArtifactReferencesUseOriginalSQLAndRejectUncoveredPaths(t *testing.T) {
	s := Snapshot{Version: Version, Tables: []Table{table("team_work_items", Row{"team_id": Text("20"), "artifact_refs_json": Text(`["/team/results/报告.md","results/legacy.bin"]`), "result_json": Text(`{"artifactRefs":["/team/results/final.md"],"body":"keep original task data"}`)}), table("team_events", Row{"team_id": Text("21"), "payload_json": Text(`{"artifactRefs":["/team/foreign-team.md"]}`)})}}
	before, _ := Digest(s)
	refs, err := TeamArtifactReferences(s, 20)
	if err != nil || !reflect.DeepEqual(refs, []string{"results/final.md", "results/legacy.bin", "results/报告.md"}) {
		t.Fatal(refs, err)
	}
	after, _ := Digest(s)
	if before != after {
		t.Fatal("source SQL changed")
	}
	for _, value := range []string{`["../escape"]`, `["/team/../escape"]`, `["/other/file"]`, `["s3://bucket/file"]`, `["/team/dir/"]`, `[12]`, `{"path":"results/file"}`} {
		s.Tables[0].Rows[0]["artifact_refs_json"] = Text(value)
		if _, err := TeamArtifactReferences(s, 20); err == nil {
			t.Fatalf("uncovered reference accepted: %s", value)
		}
	}
}
