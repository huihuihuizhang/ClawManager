package systembackupexecution

import (
	"context"
	"os"
	"strings"
	"testing"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/scope"
	"clawreef/internal/systembackup/worker"
	sh "clawreef/internal/systembackupskillhub"
)

// Actual original encrypted plan/candidate, production deployment wrapper,
// Evidence->independent observer->private custody->saveResult transaction.
// Kubernetes/Unwrap/source admission remain explicit existing local fixtures.
func TestFormalSkillMySQLEvidenceRejectsUnsafeWholeArchives(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires disposable local MySQL")
	}
	for _, mode := range []string{"safe-relative-link", "absolute-link", "character-device", "hard-link", "setuid", "unknown-pax"} {
		t.Run(mode, func(t *testing.T) {
			var original *os.Root
			options := &consumerFixtureOptions{PrepareSource: func(root *os.Root, i *worker.Invocation) {
				original = root
				runtime := scope.Runtime{Type: "hermes", Mode: "lite", Backend: "gateway", Variant: "linux", OS: "linux"}
				i.Request.RuntimePolicy = &worker.RuntimePolicy{Version: "original-r1", Image: "worker@sha256:" + strings.Repeat("a", 64), Runtime: runtime, Files: []worker.FileRule{{Path: "history.json", Fields: []domain.JSONRule{{Path: []string{"fixture"}, Action: "preserve"}}}}}
				i.Request.SkillWorkspace = &sh.WorkspaceCaptureSpec{Version: sh.WorkspaceCaptureVersion, InventorySHA256: strings.Repeat("e", 64), InstanceID: 7, MountID: "workspace", Runtime: runtime, SkillRoot: "home/.hermes/skills", Requirements: []sh.WorkspaceCaptureRequirement{{BlobID: 12, InstanceID: 7, BindingID: 14, WorkspaceDirectory: "demo", ContentMD5: "7c876ed8f2fc9206f8cc0914cb0a24f0"}}, MaxFiles: 100, MaxBytes: 2 << 20, MaxProofBytes: 1 << 20}
				if err := root.MkdirAll("home/.hermes/skills/demo/src", 0700); err != nil {
					t.Fatal(err)
				}
				for name, body := range map[string]string{"SKILL.md": "# demo\n", "src/main.py": "print('demo')\n"} {
					if err := root.WriteFile("home/.hermes/skills/demo/"+name, []byte(body), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}, RewriteCandidate: func(_ *os.Root, i worker.Invocation, c worker.FormalCaptureResult, k *candidateContentUnwrapper) (*os.Root, worker.FormalCaptureResult) {
				return forgeSkillArchiveCandidate(t, original, i, c, k, mode)
			}}
			owner, _, _, db, a, job, _, _, refresh := newConsumerMySQLFixtureOptions(t, options)
			refresh()
			ref, err := owner.Evidence(context.Background(), a, job)
			if mode == "safe-relative-link" {
				if err != nil || ref == nil {
					t.Fatal("valid whole archive rejected by actual SQL Evidence", err)
				}
				return
			}
			if err == nil || ref != nil {
				t.Fatal("unsafe archive yielded original evidence", mode, err)
			}
			var count int
			if db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE result_sha256 IS NOT NULL").Scan(&count) != nil || count != 0 {
				t.Fatal("unsafe archive committed a ModuleResult")
			}
			if db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_evidence").Scan(&count) != nil || count != 0 {
				t.Fatal("unsafe archive registered original evidence")
			}
		})
	}
}
