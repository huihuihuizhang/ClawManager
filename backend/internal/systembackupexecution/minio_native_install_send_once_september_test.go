//go:build systembackup_minio_september_native

package systembackupexecution

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	mn "clawreef/internal/systembackup/minionative"
)

// Real fixed-version native protocol experiment in the existing independent
// disposable owned fixture. It proves neither a B/D hold nor field authority.
func TestMinIOSeptemberNativeSingleSendInstallerWire(t *testing.T) {
	f, _ := loadCOnceNativeFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var root nativePublicationCredential
	cOnceNativeRead(t, "secrets/root.json", &root)
	n := cOnceNativeClient(t, f, root)
	defer n.close()
	if _, _, e := cOnceNativeServer(ctx, n); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(cOnceNativeRoot, "single-send-"+f.Owner[:12])
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal("new independent fixture operation required", e)
	}
	name := "cn-once-" + f.Owner[:12]
	policy := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:ListBucket"],"Resource":["arn:aws:s3:::` + name + `"]}]}`)
	file := filepath.Join(dir, "policy.json")
	if e := os.WriteFile(file, policy, 0600); e != nil {
		t.Fatal(e)
	}
	secret := cOnceNativeRandom(t, 32)
	for _, args := range [][]string{{"mb", "native/" + name}, {"version", "enable", "native/" + name}, {"admin", "policy", "create", "native", name, file}, {"admin", "user", "add", "native"}, {"admin", "policy", "attach", "native", name, "--user", name}} {
		var input []byte
		if args[1] == "user" {
			input = []byte(name + "\n" + secret + "\n")
		}
		e := nativeInstallWriteOnce(ctx, dir, n, input, args...)
		clear(input)
		if e != nil {
			t.Fatalf("native %s protocol failed: %v", args[0], e)
		}
	}
	// Exercise server decryption for this exact PBKDF2/SIO config format while
	// retaining the fixture's original root-access-on value.
	body, e := mn.EncryptAdminData([]byte(root.SecretKey), []byte("api root_access=on"))
	if e != nil {
		t.Fatal(e)
	}
	defer clear(body)
	if e = nativeInstallSignedOnce(ctx, n, "PUT", "/minio/admin/v3/set-config-kv", nil, body); e != nil {
		t.Fatal("actual native config decryption rejected", e)
	}
}
