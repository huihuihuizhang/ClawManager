package systembackupexecution

import (
	"strings"
	"testing"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/team"
	"clawreef/internal/systembackup/worker"
)

// Scope DATA only, never a source grant or complete native observation.
func TestTeamFilesOnlySourceCannotBorrowSkillsScope(t *testing.T) {
	for _, mode := range []string{"separate", "nil", "codec", "schema", "credential", "grant", "overlap", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			m := productionCaptureMaterials{Objects: worker.FormalSourceMount{CredentialFile: "/private/skills", CredentialSHA256: strings.Repeat("a", 64), GrantFile: "/private/skills-grant", ObjectPrefixes: []worker.ObjectSourcePrefix{{Bucket: "business", Prefix: "skills/"}}}, Redis: worker.FormalSourceMount{GrantFile: "/private/redis-grant"}}
			m.TeamObjects = &productionTeamObjectsSource{Codec: team.SharedFileSourceVersion, SchemaSHA256: team.SchemaSHA256(), Source: worker.FormalSourceMount{Objects: &worker.SourceTLSMapping{Address: "source.invalid:9000", ServerName: "source.invalid", CAFile: "/private/ca", CASHA256: strings.Repeat("b", 64)}, CredentialFile: "/private/teams", CredentialSHA256: strings.Repeat("c", 64), GrantFile: "/private/teams-grant", ObjectPrefixes: []worker.ObjectSourcePrefix{{Bucket: "business", Prefix: "teams/"}}}}
			switch mode {
			case "nil":
				m.TeamObjects = nil
			case "codec":
				m.TeamObjects.Codec = "unknown"
			case "schema":
				m.TeamObjects.SchemaSHA256 = strings.Repeat("d", 64)
			case "credential":
				m.TeamObjects.Source.CredentialSHA256 = m.Objects.CredentialSHA256
			case "grant":
				m.TeamObjects.Source.GrantFile = m.Objects.GrantFile
			case "overlap":
				m.TeamObjects.Source.ObjectPrefixes[0].Prefix = "skills/sub/"
			case "duplicate":
				m.TeamObjects.Source.ObjectPrefixes = append(m.TeamObjects.Source.ObjectPrefixes, m.TeamObjects.Source.ObjectPrefixes[0])
			}
			err := validateTeamObjectsSource(m)
			if (err == nil) != (mode == "separate" || mode == "nil") {
				t.Fatal("scope selection", mode, err)
			}
		})
	}
}

func TestTeamFilesOnlyCodecPreservesEmptyAndRejectsObjectReferences(t *testing.T) {
	for _, input := range []string{`[]`, `["/team/results/file.bin"]`, `["s3://business/teams/file"]`, `["../escape"]`, `{"path":"/team/file"}`, `[12]`} {
		s := domain.Snapshot{Tables: []domain.Table{{Name: "team_work_items", Rows: []domain.Row{{"team_id": domain.Text("20"), "artifact_refs_json": domain.Text(input)}}}}}
		refs, err := domain.TeamArtifactReferences(s, 20)
		valid := input == `[]` || input == `["/team/results/file.bin"]`
		if (err == nil) != valid {
			t.Fatal("codec", input, err)
		}
		if input == `[]` && len(refs) != 0 {
			t.Fatal("empty file refs invented")
		}
	}
}
