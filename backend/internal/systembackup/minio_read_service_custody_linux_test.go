package systembackup

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The second process opens the original persisted ciphertext; it has no parent
// custody object, plaintext snapshot or in-memory resolved/pending state.
func TestMinIOReadServiceCustodyIndependentProcess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dir := os.Getenv("CLAW_TEST_MINIO_CUSTODY_REOPEN")
	child := dir != ""
	if !child {
		dir = t.TempDir()
		if e := os.Chmod(dir, 0700); e != nil {
			t.Fatal(e)
		}
	}
	in := MinIOReadGateInput{Operation: "originalfixture", InventorySHA256: string(bytes.Repeat([]byte{'a'}, 64)), CustodyDirectory: dir}
	g := &MinIOReadServiceGate{in: in}
	key := bytes.Repeat([]byte{37}, 32)
	if child {
		c, e := openMinioGateCustody(g, key)
		if e != nil {
			t.Fatal(e)
		}
		defer c.close()
		plain, e := c.read(ctx, minioGateOriginalName(in.Operation))
		if e != nil || minioGateDecode(plain, &g.original) != nil || g.original.Version != "original-minio-read-gate-state.v1" {
			t.Fatal("original encrypted snapshot cannot reopen")
		}
		clear(plain)
		c.original = g.original
		if e := c.replay(ctx, g); e != nil || g.sequence != 2 || g.pending == nil || g.pending.Kind != "bucket_policy" || !g.mutated {
			t.Fatal("full original journal did not preserve unknown outcome")
		}
		if e := c.recheckOriginal(ctx, g); e != nil {
			t.Fatal(e)
		}
		return
	}
	g.original = minioGateOriginal{Version: "original-minio-read-gate-state.v1", Input: in, RootAccess: "on", APIConfig: json.RawMessage(`[]`), Users: []minioGateUser{{Name: "unbound-original", Status: "disabled", Policy: json.RawMessage("null")}}}
	c, e := newMinioGateCustody(ctx, g, key)
	if e != nil {
		t.Fatal(e)
	}
	m := minioGateMutation{"root_access", "api", "off"}
	for _, phase := range []string{"send_unknown", "resolved"} {
		if e = c.append(ctx, 1, phase, m); e != nil {
			t.Fatal(e)
		}
	}
	if e = c.append(ctx, 2, "send_unknown", minioGateMutation{"bucket_policy", "business", ""}); e != nil {
		t.Fatal(e)
	}
	c.close()
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestMinIOReadServiceCustodyIndependentProcess$", "-test.count=1")
	cmd.Env = append(os.Environ(), "CLAW_TEST_MINIO_CUSTODY_REOPEN="+dir)
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("fresh process readback failed: %v: %s", e, out)
	}
	// A trailing byte must fail complete AEAD/EOF validation, even after a
	// successful independent reopen; it cannot be ignored as an extra record.
	f, e := os.OpenFile(filepath.Join(dir, minioGateOriginalName(in.Operation)), os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.Write([]byte{1}); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	c, e = openMinioGateCustody(g, key)
	if e != nil {
		t.Fatal(e)
	}
	defer c.close()
	if _, e = c.read(ctx, minioGateOriginalName(in.Operation)); e == nil {
		t.Fatal("trailing ciphertext accepted")
	}
}
