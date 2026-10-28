//go:build linux

package worker

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/scope"
)

func TestWorkBuddyWorkerChecksSQLIdentityBeforeCaptureAndAfterRestore(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("isolated Linux root required")
	}
	for _, bad := range []bool{false, true} {
		t.Run(map[bool]string{false: "matching", true: "wrong-sql-identity"}[bad], func(t *testing.T) {
			r, env, target := fixture(t)
			want := domain.WorkBuddyUIDIdentity{Schema: 1, InstanceID: 7, UserID: 4, UID: 21000, GID: 21000}
			r.WorkBuddyIdentity = &want
			r.RuntimePolicy = &RuntimePolicy{Version: "wb-test", Image: "wb@sha256:" + strings.Repeat("a", 64), Runtime: scope.Runtime{Type: "workbuddy", Mode: "lite", Backend: "gateway", Variant: "linux", OS: "linux"}, Files: restoreRequest(r, r.Receipt).Files}
			raw, _ := json.Marshal(want)
			if e := env.Workspace.WriteFile(".workbuddy-identity.json", raw, 0600); e != nil {
				t.Fatal(e)
			}
			if e := env.Workspace.Mkdir("home", 0700); e != nil {
				t.Fatal(e)
			}
			if e := env.Workspace.Chown("home", 21000, 21000); e != nil {
				t.Fatal(e)
			}
			result, e := Run(context.Background(), r, env)
			if e != nil {
				t.Fatal(e)
			}
			if bad {
				want.InstanceID = 8
			}
			env.Workspace = target
			env.PreserveOwner = true
			_, e = Run(context.Background(), restoreRequest(r, result.Receipt), env)
			if (e != nil) != bad {
				t.Fatalf("identity mismatch handling: %v", e)
			}
		})
	}
	r, env, _ := fixture(t)
	r.WorkBuddyIdentity = &domain.WorkBuddyUIDIdentity{Schema: 1, InstanceID: 7, UserID: 4, UID: 21000, GID: 21000}
	r.RuntimePolicy = &RuntimePolicy{Version: "wb-test", Image: "wb@sha256:" + strings.Repeat("a", 64), Runtime: scope.Runtime{Type: "workbuddy", Mode: "lite", Backend: "gateway", Variant: "linux", OS: "linux"}, Files: restoreRequest(r, r.Receipt).Files}
	if _, e := Run(context.Background(), r, env); e == nil {
		t.Fatal("missing identity marker captured")
	}
	files, e := os.ReadDir(env.Staging.Name())
	if e != nil || len(files) != 0 {
		t.Fatal("failed identity capture published artifact")
	}
}
