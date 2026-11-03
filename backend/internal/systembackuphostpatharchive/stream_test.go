package systembackuphostpatharchive

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	backup "clawreef/internal/systembackup"
)

// These exercise the REAL process/pipe/AEAD boundary, not MinIO, B stop proof,
// Installer permission, provider credentials or field archive acceptance.
func nativePipeFixture(t *testing.T, script string) NativeStream {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("root isolated pipe regression requires python3")
	}
	file := filepath.Join(t.TempDir(), "native-pipe-fixture.py")
	if err := os.WriteFile(file, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	return NativeStream{PythonFile: python, ScriptFile: file, PlanFile: "unused-native-pipe-model",
		MaxFiles: 1, MaxBytes: 2 << 20, MaxSeconds: 5}
}

func TestHostPathNativePipeFailureCannotReceiveAuthenticatedEOF(t *testing.T) {
	native := nativePipeFixture(t, "import sys\nsys.stdout.buffer.write(b'x'*(1048576+64))\nsys.stdout.buffer.flush()\nsys.exit(73)\n")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	key, aad := bytes.Repeat([]byte{7}, 32), []byte("original-maintenance-native-pipe-model")
	var ciphertext bytes.Buffer
	if err := encryptNative(ctx, &ciphertext, key, aad, native); err == nil {
		t.Fatal("child failure after output was accepted")
	}
	var plaintext bytes.Buffer
	if err := backup.Decrypt(ctx, &plaintext, bytes.NewReader(ciphertext.Bytes()), key, aad); err == nil {
		t.Fatal("failed native output received authenticated EOF")
	}
}

func TestHostPathNativePipeSuccessEncryptsOnlyThroughPipe(t *testing.T) {
	native := nativePipeFixture(t, "import sys\nsys.stdout.buffer.write(b'original-bytes'*100000)\n")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	key, aad := bytes.Repeat([]byte{8}, 32), []byte("original-maintenance-native-pipe-model")
	var ciphertext, plaintext bytes.Buffer
	if err := encryptNative(ctx, &ciphertext, key, aad, native); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext.Bytes(), []byte("original-bytes")) {
		t.Fatal("source plaintext escaped encrypted writer")
	}
	if err := backup.Decrypt(ctx, &plaintext, bytes.NewReader(ciphertext.Bytes()), key, aad); err != nil ||
		!bytes.Equal(plaintext.Bytes(), bytes.Repeat([]byte("original-bytes"), 100000)) {
		t.Fatal("successful native pipe did not round-trip exact bytes")
	}
}

func TestHostPathNativePipeCancellationLeavesNoValidSeal(t *testing.T) {
	native := nativePipeFixture(t, "import sys,time\nsys.stdout.buffer.write(b'partial')\nsys.stdout.buffer.flush()\ntime.sleep(60)\n")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	key, aad := bytes.Repeat([]byte{9}, 32), []byte("original-maintenance-native-pipe-model")
	var ciphertext bytes.Buffer
	if err := encryptNative(ctx, &ciphertext, key, aad, native); err == nil {
		t.Fatal("cancelled native source was sealed")
	}
	if err := backup.Decrypt(context.Background(), &bytes.Buffer{}, bytes.NewReader(ciphertext.Bytes()), key, aad); err == nil {
		t.Fatal("cancelled native source retained a valid final frame")
	}
}
