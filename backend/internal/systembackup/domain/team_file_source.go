package domain

import (
	"context"
	"database/sql"
	"sort"
	"strconv"

	"clawreef/internal/buildinfo"
	"clawreef/internal/systembackup/team"
)

// ReadTeamFileSource runs within the EXISTING complete source RR transaction.
// It selects every reviewed artifact-bearing row, including deleted history.
// Explicit references use the same closed codec as final SQL/file verification;
// unknown external/object references fail rather than become an empty inventory.
func ReadTeamFileSource(ctx context.Context, tx *sql.Tx) (*team.SharedFileSource, error) {
	if ctx == nil || tx == nil || ctx.Err() != nil {
		return nil, ErrData
	}
	result := &team.SharedFileSource{Codec: team.SharedFileSourceVersion, SchemaSHA256: team.SchemaSHA256(), AppVersion: buildinfo.Version, GitCommit: buildinfo.Commit, References: []team.SharedFileReference{}}
	byTeam := map[int]map[string]bool{}
	var bytes int64
	for _, spec := range []struct {
		name, columns string
		count         int
	}{
		{"team_tasks", "payload_json,result_json", 2},
		{"team_work_items", "artifact_refs_json,result_json", 2},
		{"team_events", "payload_json", 1},
	} {
		rows, err := tx.QueryContext(ctx, "SELECT team_id,"+spec.columns+" FROM "+spec.name+" ORDER BY id")
		if err != nil {
			return nil, ErrData
		}
		for rows.Next() {
			var id int
			var first, second sql.NullString
			var err error
			if spec.count == 1 {
				err = rows.Scan(&id, &first)
			} else {
				err = rows.Scan(&id, &first, &second)
			}
			result.Rows++
			bytes += int64(len(first.String) + len(second.String))
			if err != nil || ctx.Err() != nil || id <= 0 || result.Rows > 100000 || bytes > 32<<20 {
				rows.Close()
				return nil, ErrData
			}
			row := Row{"team_id": Text(strconv.Itoa(id))}
			firstName := "payload_json"
			if spec.name == "team_work_items" {
				firstName = "artifact_refs_json"
			}
			if first.Valid {
				row[firstName] = Text(first.String)
			} else {
				row[firstName] = Cell{Null: true}
			}
			if spec.count == 2 {
				if second.Valid {
					row["result_json"] = Text(second.String)
				} else {
					row["result_json"] = Cell{Null: true}
				}
			}
			refs, e := TeamArtifactReferences(Snapshot{Tables: []Table{{Name: spec.name, Rows: []Row{row}}}}, id)
			for _, cell := range row {
				clear(cell.Bytes)
			}
			if e != nil {
				rows.Close()
				return nil, e
			}
			if byTeam[id] == nil {
				byTeam[id] = map[string]bool{}
			}
			for _, ref := range refs {
				byTeam[id][ref] = true
			}
		}
		readErr, closeErr := rows.Err(), rows.Close()
		if readErr != nil || closeErr != nil {
			return nil, ErrData
		}
	}
	ids := []int{}
	for id := range byTeam {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		refs := []string{}
		for ref := range byTeam[id] {
			refs = append(refs, ref)
		}
		sort.Strings(refs)
		result.References = append(result.References, team.SharedFileReference{TeamID: id, Paths: refs})
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return result, nil
}
