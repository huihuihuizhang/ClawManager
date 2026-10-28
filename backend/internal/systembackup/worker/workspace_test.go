package worker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/staging"
)

func fixture(t *testing.T) (Request, Environment, *os.Root) {
	t.Helper()
	source, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	store, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	target, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { source.Close(); store.Close(); target.Close() })
	for name, value := range map[string]string{"config.json": `{"model":"fixture","apiKey":"source-fixture-secret","enabled":true}`, "history.json": `{"messages":["fixture conversation"]}`, "SKILL.md": "fixture skill", "tasks.txt": "keep task definitions"} {
		if e = source.WriteFile(name, []byte(value), 0600); e != nil {
			t.Fatal(e)
		}
	}
	r := Request{Version: Version, Operation: "capture-workspace", Binding: staging.Binding{BackupID: "fixture", Attempt: "1", Path: "workspace/7", CaptureContextHash: string(bytes.Repeat([]byte{'a'}, 64)), EnvelopeID: "memory-only"}, Deadline: time.Now().Add(time.Minute), ArtifactName: "workspace.enc", MaxFiles: 100, MaxFileBytes: 1 << 20, MaxArchiveBytes: 2 << 20, MaxCompressedBytes: 2 << 20}
	return r, Environment{Workspace: source, Staging: store, Key: make([]byte, 32), Check: func(context.Context, string, Request) error { return nil }}, target
}
func restoreRequest(r Request, receipt staging.Receipt) Request {
	r.Operation = "restore-workspace"
	r.Receipt = receipt
	r.ArtifactName = ""
	r.PolicyVersion = "fixture-config.v1"
	r.Files = []FileRule{{Path: "config.json", Required: true, Fields: []domain.JSONRule{{Path: []string{"model"}, Action: "preserve", Required: true}, {Path: []string{"apiKey"}, Action: "stub", Required: true}, {Path: []string{"enabled"}, Action: "disable", Required: true}}}}
	return r
}
func TestWorkspaceWorkerCapturesAndRestoresWithoutSource(t *testing.T) {
	r, env, target := fixture(t)
	var checks []string
	env.Check = func(_ context.Context, p string, _ Request) error { checks = append(checks, p); return nil }
	backup, e := Run(context.Background(), r, env)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(checks, []string{"prepare", "before-capture", "before-seal", "sealed"}) {
		t.Fatal(checks)
	}
	if backup.Files != 5 || backup.Receipt.Size <= 0 {
		t.Fatal("bad receipt")
	}
	env.Workspace.Close()
	env.Workspace = target
	checks = nil
	restored, e := Run(context.Background(), restoreRequest(r, backup.Receipt), env)
	if e != nil {
		t.Fatal(e)
	}
	if !restored.Quarantined || restored.NormalizedFiles != 1 || !reflect.DeepEqual(checks, []string{"prepare", "before-restore", "before-normalize", "restored-quarantine"}) {
		t.Fatal("missing boundary checks")
	}
	config, _ := target.ReadFile("config.json")
	history, _ := target.ReadFile("history.json")
	if bytes.Contains(config, []byte("source-fixture-secret")) || !bytes.Contains(config, []byte(`"enabled":false`)) || !bytes.Contains(history, []byte("fixture conversation")) {
		t.Fatal("normalization or history failed")
	}
	if _, e = Run(context.Background(), restoreRequest(r, backup.Receipt), env); e == nil {
		t.Fatal("overwrote nonempty target")
	}
}
func TestWorkerRejectsMissingGrantBadReceiptAndLostFence(t *testing.T) {
	for _, mode := range []string{"no-grant", "lost-fence", "overlap", "expired", "invalid-receipt", "unknown-config"} {
		t.Run(mode, func(t *testing.T) {
			r, env, target := fixture(t)
			switch mode {
			case "no-grant":
				env.Check = nil
			case "lost-fence":
				env.Check = func(_ context.Context, p string, _ Request) error {
					if p == "before-seal" {
						return errors.New("fence lost")
					}
					return nil
				}
			case "overlap":
				env.Staging = env.Workspace
			case "expired":
				r.Deadline = time.Now().Add(-time.Second)
			case "invalid-receipt", "unknown-config":
				b, e := Run(context.Background(), r, env)
				if e != nil {
					t.Fatal(e)
				}
				r = restoreRequest(r, b.Receipt)
				env.Workspace = target
				if mode == "invalid-receipt" {
					r.Receipt.SHA256 = string(bytes.Repeat([]byte{'f'}, 64))
				} else {
					r.Files[0].Fields = r.Files[0].Fields[:1]
				}
			}
			if _, e := Run(context.Background(), r, env); e == nil {
				t.Fatal("unsafe operation succeeded")
			}
			if mode == "invalid-receipt" {
				entries, _ := target.ReadFile("config.json")
				if entries != nil {
					t.Fatal("wrote before full integrity check")
				}
			}
			if mode == "lost-fence" {
				if _, e := env.Staging.Stat(r.ArtifactName); !os.IsNotExist(e) {
					t.Fatal("sealed after losing fence")
				}
			}
		})
	}
}
