package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/assets"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/staging"
)

func TestAssetsRestoreVerifyAndRejectTamperInIsolatedDirectory(t *testing.T) {
	ctx := context.Background()
	stage, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer stage.Close()
	target, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	payload := []byte("original skill content")
	sum := sha256.Sum256(payload)
	o := assets.ObjectRef{Key: "../../source-object-key", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(payload))}
	s := assets.SecretRef{Namespace: "source", Name: "model", UID: "uid", ResourceVersion: "1", Role: "model", Keys: []string{"api-key"}}
	set := assets.Set{Version: "business-assets.v1", Inventory: assets.Inventory{Namespace: "source", Secrets: []assets.SecretRef{s}, Objects: []assets.ObjectRef{o}}, Secrets: []assets.Secret{{Reference: s, Data: map[string][]byte{"api-key": []byte("original-secret")}}}, Objects: []assets.Object{{Reference: o, Data: payload}}}
	config := assets.ConfigMapRef{Namespace: "source", Name: "agent-config", UID: "config-uid", ResourceVersion: "1", Rules: map[string]assets.DocumentRules{"agent.json": {Format: "json", Fields: []domain.JSONRule{{Path: []string{"token"}, Action: "stub"}, {Path: []string{"enabled"}, Action: "disable"}, {Path: []string{"task"}, Action: "preserve"}}}}}
	set.Inventory.ConfigMaps = []assets.ConfigMapRef{config}
	set.ConfigMaps = []assets.ConfigMap{{Reference: config, Data: map[string][]byte{"agent.json": []byte(`{"token":"original-config-token","enabled":true,"task":"keep-task-definition"}`)}}}
	key := make([]byte, 32)
	binding := staging.Binding{BackupID: "fixture", Attempt: "1", Path: "assets", CaptureContextHash: strings.Repeat("a", 64), EnvelopeID: "key"}
	receipt, e := staging.SealFile(ctx, stage, "assets.enc", key, binding, func(w io.Writer) error { return json.NewEncoder(w).Encode(set) })
	if e != nil {
		t.Fatal(e)
	}
	r := Request{Version: Version, Operation: "restore-assets", Deadline: time.Now().Add(time.Minute), PolicyVersion: "fixture", Binding: binding, Receipt: receipt, MaxArchiveBytes: 48 << 20, MaxCompressedBytes: 48 << 20}
	env := Environment{Workspace: target, Staging: stage, Key: key, Check: func(context.Context, string, Request) error { return nil }}
	result, e := Run(ctx, r, env)
	if e != nil || !result.Quarantined || result.Files != 4 {
		t.Fatal(e)
	}
	r.Operation = "verify-assets"
	result, e = Run(ctx, r, env)
	if e != nil || !result.Verified {
		t.Fatal(e)
	}
	dir, _ := target.Open(".")
	files, _ := dir.ReadDir(-1)
	dir.Close()
	for _, entry := range files {
		b, _ := target.ReadFile(entry.Name())
		if strings.Contains(string(b), "original-secret") {
			t.Fatal("live business credential restored")
		}
		if strings.HasPrefix(entry.Name(), "config-") {
			var values map[string][]byte
			if json.Unmarshal(b, &values) != nil {
				t.Fatal("config asset is not readable")
			}
			var config map[string]any
			if json.Unmarshal(values["agent.json"], &config) != nil || config["enabled"] != false || config["task"] != "keep-task-definition" || !strings.HasPrefix(config["token"].(string), "drill-disabled-") {
				t.Fatal("configuration definition lost or credential/trigger still active")
			}
		}
		if strings.HasPrefix(entry.Name(), "object-") {
			f, _ := target.OpenFile(entry.Name(), os.O_WRONLY, 0600)
			f.WriteAt([]byte("corrupt"), 0)
			f.Close()
		}
	}
	if _, e := Run(ctx, r, env); e == nil {
		t.Fatal("object tamper passed independent verifier")
	}
	r.Operation = "restore-assets"
	if _, e := Run(ctx, r, env); e == nil {
		t.Fatal("overwrote nonempty asset target")
	}
}
