package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/staging"
)

func TestTeamSharedWorkspaceRestoresWithoutRuntimeConfigRules(t *testing.T) {
	r, env, target := teamWorkspaceFixture(t)
	backup, err := Run(context.Background(), r, env)
	if err != nil {
		t.Fatal(err)
	}
	r = restoreRequest(r, backup.Receipt)
	r.Files = nil
	r.PolicyVersion = "teams-shared-workspace.v1"
	// Decode the new opt-in wire shape, so the baseline reproducer exercises
	// the real worker rather than depending on a not-yet-declared Go field.
	raw, _ := json.Marshal(r)
	var object map[string]json.RawMessage
	json.Unmarshal(raw, &object)
	object["team_workspace"] = json.RawMessage(`{"version":"teams-shared-workspace.v1","team_id":20,"inventory_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_sql_ciphertext_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","artifact_refs":["tasks.txt"]}`)
	raw, _ = json.Marshal(object)
	json.Unmarshal(raw, &r)
	env.Workspace = target
	if _, err := Run(context.Background(), r, env); err != nil {
		t.Fatalf("data-only Team shared volume cannot restore without invented Runtime rules: %v", err)
	}
}

func sharedTeamRequest(r Request, receipt staging.Receipt) Request {
	r = restoreRequest(r, receipt)
	r.Files = nil
	r.PolicyVersion = TeamWorkspaceVersion
	r.TeamWorkspace = &TeamWorkspaceSpec{Version: TeamWorkspaceVersion, TeamID: 20, InventorySHA256: strings.Repeat("a", 64), SourceSQLCiphertextSHA256: strings.Repeat("b", 64), ArtifactRefs: []string{"tasks.txt"}}
	return r
}

func teamWorkspaceFixture(t *testing.T) (Request, Environment, *os.Root) {
	r, env, target := fixture(t)
	r.Binding.Path = "team_20_workspace"
	return r, env, target
}

func TestSharedTeamRestoreAndSeparateReadOnlyVerification(t *testing.T) {
	r, env, target := teamWorkspaceFixture(t)
	if err := env.Workspace.Mkdir("results", 0700); err != nil {
		t.Fatal(err)
	}
	if err := env.Workspace.WriteFile("results/中断前产物.bin", []byte{0, 255, 13, 10}, 0600); err != nil {
		t.Fatal(err)
	}
	backup, err := Run(context.Background(), r, env)
	if err != nil {
		t.Fatal(err)
	}
	env.Workspace.Close() // No source is available to either restore or verify.
	env.Workspace = target
	r = sharedTeamRequest(r, backup.Receipt)
	r.TeamWorkspace.ArtifactRefs = append(r.TeamWorkspace.ArtifactRefs, "results/中断前产物.bin")
	var points []string
	env.Check = func(_ context.Context, point string, copy Request) error {
		points = append(points, point)
		copy.TeamWorkspace.ArtifactRefs[0] = "foreign/modified-by-authorizer"
		return nil
	}
	result, err := Run(context.Background(), r, env)
	if err != nil || !result.Quarantined || result.Verified || r.TeamWorkspace.ArtifactRefs[0] != "tasks.txt" {
		t.Fatal(result, err)
	}
	data, _ := target.ReadFile("results/中断前产物.bin")
	if !bytes.Equal(data, []byte{0, 255, 13, 10}) {
		t.Fatal("partial result bytes lost")
	}
	r.Operation = "verify-team-workspace"
	before, _ := target.Stat("tasks.txt")
	result, err = Run(context.Background(), r, env)
	after, _ := target.Stat("tasks.txt")
	if err != nil || !result.Verified || !before.ModTime().Equal(after.ModTime()) || !ValidateResult(r, &result) {
		t.Fatal("independent C verify", result, err, points)
	}
	if err := target.WriteFile("tasks.txt", []byte("keep fake definitions"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), r, env); err == nil {
		t.Fatal("tampered target accepted")
	}
}

func TestSharedTeamFailuresNeverDeleteOrReportVerified(t *testing.T) {
	for _, mode := range []string{"wrong-key", "corrupt-terminal", "not-empty", "missing-artifact", "extra-file", "denied", "cancelled", "bad-scope", "foreign-part"} {
		t.Run(mode, func(t *testing.T) {
			r, env, target := teamWorkspaceFixture(t)
			backup, err := Run(context.Background(), r, env)
			if err != nil {
				t.Fatal(err)
			}
			env.Workspace = target
			r = sharedTeamRequest(r, backup.Receipt)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "wrong-key":
				env.Key = bytes.Repeat([]byte{9}, 32)
			case "corrupt-terminal":
				raw, _ := env.Staging.ReadFile(r.Receipt.Name)
				raw[len(raw)-1] ^= 1
				if err := env.Staging.Chmod(r.Receipt.Name, 0600); err != nil {
					t.Fatal(err)
				}
				if err := env.Staging.WriteFile(r.Receipt.Name, raw, 0600); err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(raw)
				r.Receipt.SHA256 = hex.EncodeToString(sum[:])
			case "not-empty":
				if err := target.WriteFile("keep-user-data", []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-artifact":
				r.TeamWorkspace.ArtifactRefs = append(r.TeamWorkspace.ArtifactRefs, "missing.bin")
			case "denied":
				env.Check = func(context.Context, string, Request) error { return errors.New("revoked") }
			case "cancelled":
				cancel()
			case "bad-scope":
				r.TeamWorkspace.ArtifactRefs = []string{"../foreign"}
			case "foreign-part":
				r.Binding.Path = "instance_7_workspace"
			case "extra-file":
				if _, err := Run(ctx, r, env); err != nil {
					t.Fatal(err)
				}
				r.Operation = "verify-team-workspace"
				if err := target.WriteFile("unexpected", []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			result, err := Run(ctx, r, env)
			if err == nil || result.Quarantined || result.Verified {
				t.Fatal("unsafe success", result, err)
			}
			entries, e := fs.ReadDir(target.FS(), ".")
			if e != nil {
				t.Fatal(e)
			}
			if mode == "not-empty" {
				value, _ := target.ReadFile("keep-user-data")
				if string(value) != "keep" {
					t.Fatal("preexisting data lost")
				}
			}
			if mode == "missing-artifact" || mode == "extra-file" {
				if _, e := target.Stat("tasks.txt"); e != nil {
					t.Fatal("partial restore was deleted")
				}
			} else if mode != "not-empty" && len(entries) != 0 {
				t.Fatal("target touched before authentication/admission", entries)
			}
		})
	}
}

func TestTeamWorkspaceUsesOriginalWorkerControlAndImmutableHash(t *testing.T) {
	r, _, _ := teamWorkspaceFixture(t)
	r = sharedTeamRequest(r, staging.Receipt{Name: "original.enc", Size: 100, SHA256: strings.Repeat("c", 64)})
	r.Operation = "verify-team-workspace"
	i := Invocation{Request: r, WorkspacePath: "/workspace", StagingPath: "/staging"}
	hash, err := i.Hash()
	if err != nil {
		t.Fatal(err)
	}
	for _, point := range []string{"prepare", "before-verify", "verified-quarantine"} {
		if !ValidateControl(ControlRequest{Invocation: i, InvocationSHA256: hash, Action: "check", Point: point}) {
			t.Fatal("real C checkpoint rejected", point)
		}
	}
	if ValidateControl(ControlRequest{Invocation: i, InvocationSHA256: hash, Action: "check", Point: "database-isolation"}) {
		t.Fatal("invented database proof accepted for C files")
	}
	r.TeamWorkspace.ArtifactRefs = []string{"foreign.txt"}
	i.Request = r
	if ValidateControl(ControlRequest{Invocation: i, InvocationSHA256: hash, Action: "ready"}) {
		t.Fatal("reference scope changed without changing original invocation")
	}
	i.Request.Deadline = time.Now().Add(-time.Second)
	if !ValidateRecordedInvocation(i) || ValidateControl(ControlRequest{Invocation: i, InvocationSHA256: hash, Action: "ready"}) {
		t.Fatal("recorded plan validation granted execution after deadline")
	}
}
