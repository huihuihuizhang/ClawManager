package install

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"clawreef/internal/systembackup/team"
	"clawreef/internal/systembackup/worker"
)

func teamsSourceScopeFixture() (worker.FormalSourceMount, *team.Inventory) {
	m := worker.FormalSourceMount{Issuer: make([]byte, ed25519.PublicKeySize), Objects: &worker.SourceTLSMapping{Address: "teams.example:443", ServerName: "teams.example", CAFile: "/private/teams-ca.pem", CASHA256: strings.Repeat("c", 64)}, ObjectPrefixes: []worker.ObjectSourcePrefix{{Bucket: "teams", Prefix: "results/"}}}
	i := &team.Inventory{Version: team.InventoryVersion, SchemaSHA256: team.SchemaSHA256(), Objects: []team.ObjectRef{{TeamID: 7, Bucket: "teams", Key: "results/a", Version: "original-version", SHA256: strings.Repeat("a", 64), Size: 4}}}
	return m, i
}

func TestTeamsSourceDeclarationRejectsMissingAndForeignScope(t *testing.T) {
	for _, name := range []string{"valid", "explicit-empty", "missing", "missing-array", "wider-root", "foreign-bucket", "duplicate-key-version", "redis", "null-version", "already-signed"} {
		t.Run(name, func(t *testing.T) {
			m, i := teamsSourceScopeFixture()
			switch name {
			case "explicit-empty":
				i.Objects = []team.ObjectRef{}
			case "missing":
				i = nil
			case "missing-array":
				i.Objects = nil
			case "wider-root":
				m.ObjectPrefixes[0].Prefix = "other/"
			case "foreign-bucket":
				i.Objects[0].Bucket = "other"
			case "duplicate-key-version":
				ref := i.Objects[0]
				ref.Version = "another-version"
				i.Objects = append(i.Objects, ref)
			case "redis":
				m.Redis = &worker.SourceTLSMapping{}
			case "null-version":
				i.Objects[0].Version = "null"
			case "already-signed":
				m.GrantSHA256 = strings.Repeat("f", 64)
			}
			err := ValidateTeamsSourceInventory(m, i)
			if (err == nil) != (name == "valid" || name == "explicit-empty") {
				t.Fatalf("unexpected admission: %v", err)
			}
		})
	}
}

// Existing Redis/Skills authority must remain unable to sign Teams even if a
// caller submits their valid scope/credential digest and original window.
func TestTeamsSourceCannotBorrowSkillsSignerComponent(t *testing.T) {
	f, ctx, intent := sourceMaterialFixture(t)
	p, e := f.i.PrepareSourceMaterialIssue(ctx, f.password, f.enrollment, intent)
	if e != nil {
		t.Fatal(e)
	}
	g := worker.FormalSourceGrant{Version: worker.FormalSourceGrantVersion, InstallationID: intent.InstallationID, ConfigSHA256: intent.ConfigSHA256, WorkerNamespace: intent.Namespace, WorkerServiceAccountUID: intent.WorkerServiceAccountUID, Operation: "capture-team-objects", ScopeSHA256: intent.ObjectScopeSHA256, CredentialSHA256: intent.ObjectCredentialSHA256, NotBefore: intent.NotBefore, Until: intent.Until}
	if raw, e := p.SignWorkerSource(ctx, g, f.key); e == nil || len(raw) != 0 {
		t.Fatal("Skills grant became Teams authority")
	}
	if result, e := p.IssueTeamsSource(ctx, f.key); e == nil || result.Source.GrantSHA256 != "" {
		t.Fatal("incomplete original declaration issued Teams grant")
	}
	if result, e := p.QueryTeamsSource(ctx); e == nil || result.Source.GrantSHA256 != "" {
		t.Fatal("missing Teams inventory queried as success")
	}
	if f.s.writes != 0 {
		t.Fatal("rejection changed SQL")
	}
}

func TestTeamsSourceClosedJSONRefusesDuplicateAliasAndUnknown(t *testing.T) {
	for _, raw := range []string{`{"Version":"x","Version":"y"}`, `{"Version":"x","version":"x"}`, `{"Version":"x","Passed":true}`, `null`} {
		var d TeamsSourceIssueDefinition
		if teamsExactJSON([]byte(raw), &d) == nil {
			t.Fatal("ambiguous/unrecognized Teams declaration accepted")
		}
	}
}
