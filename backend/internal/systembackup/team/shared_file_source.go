package team

const SharedFileSourceVersion = "teams-first-party-shared-file-source.v1"

// Pure SQL facts, not a claim of provider absence. Native whole-scope census
// remains mandatory. Retained in the original encrypted source selection.
type SharedFileSource struct {
	Codec, SchemaSHA256, AppVersion, GitCommit string
	Rows                                       int64
	References                                 []SharedFileReference
}

type SharedFileReference struct {
	TeamID int
	Paths  []string
}

func CloneSharedFileSource(source *SharedFileSource) *SharedFileSource {
	if source == nil {
		return nil
	}
	out := *source
	out.References = append([]SharedFileReference{}, source.References...)
	for i := range out.References {
		out.References[i].Paths = append([]string{}, source.References[i].Paths...)
	}
	return &out
}
