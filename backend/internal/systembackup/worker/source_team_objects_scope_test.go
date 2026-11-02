package worker

import (
	"clawreef/internal/systembackup/team"
	"strings"
	"testing"
)

func TestOriginalTeamsObjectPrefixScopeMatchesActualWorkerScope(t *testing.T) {
	mount := FormalSourceMount{Objects: &SourceTLSMapping{Address: "original-source.invalid:443", ServerName: "original-source.invalid", CAFile: "/run/backup/materials/teams/ca.pem", CASHA256: strings.Repeat("a", 64)}, ObjectPrefixes: []ObjectSourcePrefix{{Bucket: "teams", Prefix: "owned/team/"}}}
	request := Request{Operation: "capture-team-objects", Teams: &TeamCaptureSpec{Objects: []team.ObjectRef{{TeamID: 1, Bucket: "teams", Key: "owned/team/original", Version: "immutable-v1", SHA256: strings.Repeat("b", 64), Size: 1}}}}
	original, err := TeamObjectsSourceScopeSHA256(mount)
	actual, actualErr := FormalSourceScopeSHA256(Invocation{Request: request}, mount)
	if err != nil || actualErr != nil || original != actual {
		t.Fatal("original prefix/actual inventory scope mismatch", err, actualErr)
	}
	request.Teams.Objects[0].Key = "foreign/team/object"
	if _, err := FormalSourceScopeSHA256(Invocation{Request: request}, mount); err == nil {
		t.Fatal("original delegation admitted an object outside its actual prefix")
	}
}
