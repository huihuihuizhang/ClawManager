package systembackuphostpatharchive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	backup "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/staging"
)

type restartWriteRequest struct {
	File                   string
	Header, Plaintext, Key []byte
}
type restartVersion struct {
	Receipt   staging.Receipt
	Identity  FileIdentity
	HeaderSHA string
}

// Only the fixture producer subprocess encrypts/writes this retained file.
// No provider token/key is persisted in its durable version descriptor.
func TestArchiveRestartWriterEntry(t *testing.T) {
	if os.Getenv("C_ARCHIVE_RESTART_WRITER") != "1" {
		return
	}
	if err := restartWrite(); err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}
func restartWrite() error {
	var r restartWriteRequest
	if json.NewDecoder(os.Stdin).Decode(&r) != nil {
		return ErrArchive
	}
	defer clear(r.Key)
	defer clear(r.Plaintext)
	f, err := os.OpenFile(r.File, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0400)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	w := io.MultiWriter(f, h)
	prefix := make([]byte, 16)
	copy(prefix, []byte("CMHPARCH0001"))
	binary.BigEndian.PutUint32(prefix[12:], uint32(len(r.Header)))
	if _, err = w.Write(prefix); err != nil {
		return err
	}
	if _, err = w.Write(r.Header); err != nil {
		return err
	}
	if err = backup.Encrypt(context.Background(), w, bytes.NewReader(r.Plaintext), r.Key, r.Header); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	identity, err := fileIdentity(info)
	if err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Dir(r.File))
	if err != nil {
		return err
	}
	defer root.Close()
	if err = staging.SyncDirectory(root); err != nil {
		return err
	}
	header := sha256.Sum256(r.Header)
	return json.NewEncoder(os.Stdout).Encode(restartVersion{staging.Receipt{Name: filepath.Base(r.File), Size: info.Size(), SHA256: hex.EncodeToString(h.Sum(nil))}, identity, hex.EncodeToString(header[:])})
}

// Real OS-process exit -> durable descriptor -> reopen with no LocalArchive
// producer handle -> NEW verifier process -> whole ciphertext/AEAD EOF.
// TLS unwrap remains the existing protocol fixture, not field qualification.
func TestRecoveredArchiveAfterProducerProcessExit(t *testing.T) {
	grant, plain, cleanup := independentReaderFixture(t)
	defer cleanup()
	original, err := os.ReadFile(grant.File)
	if err != nil {
		t.Fatal(err)
	}
	size := binary.BigEndian.Uint32(original[12:16])
	header := original[16 : 16+size]
	rootPath := t.TempDir()
	file := filepath.Join(rootPath, "restarted.enc")
	request, err := json.Marshal(restartWriteRequest{file, header, plain, bytes.Repeat([]byte{31}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(request)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestArchiveRestartWriterEntry$")
	cmd.Env = append(os.Environ(), "C_ARCHIVE_RESTART_WRITER=1")
	cmd.Stdin = bytes.NewReader(request)
	raw, err := cmd.Output()
	if err != nil {
		t.Fatal("original producer process", err)
	}
	if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
		t.Fatal("producer has not exited")
	}
	descriptor := filepath.Join(rootPath, "retained-version.json")
	if err = os.WriteFile(descriptor, raw, 0400); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	var saved restartVersion
	if json.Unmarshal(raw, &saved) != nil {
		t.Fatal("durable descriptor")
	}
	want := sha256.Sum256(plain)
	for n := 0; n < 2; n++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		root, err := os.OpenRoot(rootPath)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		recovered, err := OpenRecoveredReadSource(ctx, root, saved.Receipt, saved.HeaderSHA)
		if err != nil {
			root.Close()
			cancel()
			t.Fatal(err)
		}
		fresh, err := recovered.NewPipeGrant(file, grant.OperationID, grant.NativePlanSHA256, grant.Transit, grant.Credential, grant.Until, bytes.Repeat([]byte{byte(70 + n)}, 32), bytes.Repeat([]byte{byte(80 + n)}, 32))
		recovered.Close()
		root.Close()
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if fresh.Identity != saved.Identity {
			t.Fatal("reopen changed original fixed inode")
		}
		result, pid, err := runIndependentReaderFixture(t, fresh)
		if err != nil {
			t.Fatal("new process readback", err)
		}
		receipt, err := AuthenticateReaderReceipt(result, fresh, pid)
		if err != nil || receipt.PlaintextSHA256 != hex.EncodeToString(want[:]) || receipt.PlaintextBytes != int64(len(plain)) || pid == cmd.ProcessState.Pid() {
			t.Fatal("restarted full AEAD readback", err)
		}
	}
}
