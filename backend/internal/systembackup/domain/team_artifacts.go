package domain

import (
	"encoding/json"
	"path"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// TeamArtifactPath accepts current /team references and historical relative
// references. An external URL or another instance's absolute path requires an
// explicit owner adapter; it cannot silently disappear from completeness.
func TeamArtifactPath(ref string) (string, error) {
	if strings.HasPrefix(ref, "/team/") {
		ref = strings.TrimPrefix(ref, "/team/")
	}
	if !utf8.ValidString(ref) || ref == "" || len(ref) > 4096 || ref == "." || path.IsAbs(ref) || path.Clean(ref) != ref || ref == ".." || strings.HasPrefix(ref, "../") || strings.ContainsAny(ref, "\\\x00\r\n:") {
		return "", ErrData
	}
	return ref, nil
}

func validateTeamArtifactList(raw []byte) error {
	var refs []string
	if len(raw) > 8<<20 || strictJSON(raw) != nil || json.Unmarshal(raw, &refs) != nil || len(refs) > 100000 {
		return ErrData
	}
	for _, ref := range refs {
		if _, err := TeamArtifactPath(ref); err != nil {
			return err
		}
	}
	return nil
}

// TeamArtifactReferences consumes the SAME authenticated SQL snapshot as C's
// coverage verifier. No live SQL rediscovery or rewriting of task data occurs.
func TeamArtifactReferences(snapshot Snapshot, teamID int) ([]string, error) {
	if teamID <= 0 {
		return nil, ErrData
	}
	refs := map[string]bool{}
	add := func(raw json.RawMessage) error {
		var values []string
		if len(raw) > 8<<20 || strictJSON(raw) != nil || json.Unmarshal(raw, &values) != nil {
			return ErrData
		}
		for _, value := range values {
			p, e := TeamArtifactPath(value)
			if e != nil {
				return e
			}
			refs[p] = true
			if len(refs) > 100000 {
				return ErrData
			}
		}
		return nil
	}
	for _, table := range snapshot.Tables {
		if table.Name != "team_tasks" && table.Name != "team_work_items" && table.Name != "team_events" {
			continue
		}
		for _, row := range table.Rows {
			if row["team_id"].String() != strconv.Itoa(teamID) {
				continue
			}
			if value := row["artifact_refs_json"]; !value.Null && len(value.Bytes) != 0 {
				if err := add(value.Bytes); err != nil {
					return nil, err
				}
			}
			for _, column := range []string{"result_json", "payload_json"} {
				value := row[column]
				if value.Null || len(value.Bytes) == 0 {
					continue
				}
				var object map[string]json.RawMessage
				// An arbitrary task/result body is archival data. Only explicit
				// reference fields in a valid object carry file dependencies.
				if json.Unmarshal(value.Bytes, &object) != nil {
					continue
				}
				for _, key := range []string{"artifactRefs", "artifact_refs"} {
					if raw, ok := object[key]; ok {
						if strictJSON(value.Bytes) != nil {
							return nil, ErrData
						}
						if err := add(raw); err != nil {
							return nil, err
						}
					}
				}
			}
		}
	}
	out := make([]string, 0, len(refs))
	for ref := range refs {
		out = append(out, ref)
	}
	slices.Sort(out)
	return out, nil
}
