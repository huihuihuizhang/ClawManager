//go:build linux

package systembackup

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Real encryption/file/directory fsync/readback only. ACL and SQL authority
// inputs are a model here; this test is not native Redis gate validation.
func TestRedisReadGateActualEncryptedOriginalCustody(t *testing.T) {
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("mode")
	}
	g := &RedisReadServiceGate{in: RedisReadGateInput{CustodyDirectory: dir, Operation: strings.Repeat("a", 32), InventorySHA256: strings.Repeat("b", 64)}, ownerValue: strings.Repeat("c", 64), original: []redisGateUser{{Name: "original", Passwords: []string{strings.Repeat("d", 64)}, redisGateSelector: redisGateSelector{Commands: "+@all", Keys: "~*"}}}}
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x71}, 32)
	if g.sealOriginal(ctx, key) != nil {
		t.Fatal("seal/fsync/readback")
	}
	defer g.custody.Close()
	defer clear(g.custodyKey)
	if g.readOriginalCustody(ctx) != nil {
		t.Fatal("original custody")
	}
	file := filepath.Join(dir, g.custodyName)
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(strings.Repeat("d", 64))) || bytes.Contains(raw, []byte("+@all")) {
		t.Fatal("ACL private material persisted unencrypted")
	}
	if err = os.WriteFile(file, raw[:len(raw)-1], 0600); err != nil {
		t.Fatal(err)
	}
	if g.readOriginalCustody(ctx) == nil {
		t.Fatal("truncated original accepted")
	}
	if err = os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	g.original[0].Commands = "-@all +get"
	if g.readOriginalCustody(ctx) == nil {
		t.Fatal("memory/original drift accepted")
	}
}
