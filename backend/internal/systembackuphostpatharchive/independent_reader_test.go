package systembackuphostpatharchive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	backup "clawreef/internal/systembackup"
	ev "clawreef/internal/systembackupevidence"
)

func TestOriginalIndependentReaderProcessEntry(t *testing.T) {
	if os.Getenv("C_ORIGINAL_READER_HELPER") != "1" {
		return
	}
	if RunIndependentReader() != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

// These use a REAL separate OS process, anonymous stdin, local TLS server and
// actual AEAD/ciphertext files. The Vault response is a protocol fixture, not
// real Installer/native writer/isolation/field qualification.
func independentReaderFixture(t *testing.T) (PipeGrant, []byte, func()) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("native inode independent reader is Linux profile")
	}
	key := bytes.Repeat([]byte{31}, 32)
	transit := ev.TransitConfig{Installation: "installation_custody_model", KeyName: "original-evidence",
		Key: ev.KeyRef{Identity: strings.Repeat("a", 64), Version: "evidence-v1"}, KeyVersion: 1}
	wrapped := []byte("vault:v1:" + base64.StdEncoding.EncodeToString(make([]byte, 60)))
	contextValue, _ := ev.EvidenceTransitContext(transit.Installation, transit.Key)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/transit/decrypt/original-evidence" ||
			r.Header.Get("X-Vault-Token") != "model-original-unwrap-token-123456" {
			w.WriteHeader(403)
			return
		}
		var request struct{ Ciphertext, Context string }
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.Ciphertext != string(wrapped) || request.Context != contextValue {
			w.WriteHeader(403)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(key)}})
	}))
	transit.Endpoint = server.URL
	transit.CAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	caHash := sha256.Sum256(transit.CAPEM)
	transit.CASHA256 = hex.EncodeToString(caHash[:])
	native := NativeStream{PlanSHA256: strings.Repeat("b", 64)}
	header, err := json.Marshal(archiveHeader{"original-minio-hostpath-encrypted-copy.v1",
		Binding{Installation: transit.Installation, MaintenanceID: strings.Repeat("c", 32)}, native, transit.Key, wrapped})
	if err != nil {
		t.Fatal(err)
	}
	var ciphertext bytes.Buffer
	prefix := make([]byte, 16)
	copy(prefix, []byte("CMHPARCH0001"))
	binary.BigEndian.PutUint32(prefix[12:], uint32(len(header)))
	ciphertext.Write(prefix)
	ciphertext.Write(header)
	plaintext := bytes.Repeat([]byte("original-source-model-bytes"), 70000)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err = backup.Encrypt(ctx, &ciphertext, bytes.NewReader(plaintext), key, header); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "original-ciphertext.enc")
	if err = os.WriteFile(file, ciphertext.Bytes(), 0400); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := fileIdentity(info)
	if err != nil {
		t.Fatal(err)
	}
	cipherHash, headerHash := sha256.Sum256(ciphertext.Bytes()), sha256.Sum256(header)
	grant := PipeGrant{Version: "original-custody-independent-read.v1", File: file,
		HeaderSHA256: hex.EncodeToString(headerHash[:]), OperationID: strings.Repeat("c", 32), NativePlanSHA256: native.PlanSHA256,
		Receipt:  stagingReceipt{Name: "original-ciphertext.enc", Size: int64(ciphertext.Len()), SHA256: hex.EncodeToString(cipherHash[:])},
		Identity: identity, Transit: transit, Credential: ev.TransitCredential{Key: transit.Key, Installation: transit.Installation,
			Operation: ev.TransitUnwrap, Secret: []byte("model-original-unwrap-token-123456"), ExpiresAt: time.Now().Add(15 * time.Second)},
		Until: time.Now().Add(time.Minute), Challenge: bytes.Repeat([]byte{43}, 32), Authenticator: bytes.Repeat([]byte{44}, 32)}
	return grant, plaintext, func() { server.Close(); clear(key) }
}

func runIndependentReaderFixture(t *testing.T, grant PipeGrant) ([]byte, int, error) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestOriginalIndependentReaderProcessEntry$")
	cmd.Env = append(os.Environ(), "C_ORIGINAL_READER_HELPER=1")
	cmd.Stdin = bytes.NewReader(body)
	cmd.Stderr = io.Discard
	var output bytes.Buffer
	cmd.Stdout = &output
	err = cmd.Run()
	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}
	return output.Bytes(), pid, err
}

func TestOriginalIndependentReaderRealProcessEOFAndAEAD(t *testing.T) {
	grant, plain, cleanup := independentReaderFixture(t)
	defer cleanup()
	raw, pid, err := runIndependentReaderFixture(t, grant)
	if err != nil {
		t.Fatal("independent readback failed", err)
	}
	result, err := AuthenticateReaderReceipt(raw, grant, pid)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(plain)
	if result.PID == os.Getpid() || result.PlaintextBytes != int64(len(plain)) || result.PlaintextSHA256 != hex.EncodeToString(h[:]) {
		t.Fatal("readback did not prove independent full plaintext EOF")
	}
	wrong := grant
	wrong.Challenge = bytes.Repeat([]byte{99}, 32)
	if _, err = AuthenticateReaderReceipt(raw, wrong, pid); err == nil {
		t.Fatal("another original challenge accepted")
	}
}

func TestOriginalIndependentReaderRejectsAEADDespiteMatchingCipherSHA(t *testing.T) {
	grant, _, cleanup := independentReaderFixture(t)
	defer cleanup()
	raw, err := os.ReadFile(grant.File)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	if os.Chmod(grant.File, 0600) != nil || os.WriteFile(grant.File, raw, 0400) != nil || os.Chmod(grant.File, 0400) != nil {
		t.Fatal("fixture mutation failed")
	}
	h := sha256.Sum256(raw)
	grant.Receipt.SHA256 = hex.EncodeToString(h[:])
	if out, _, err := runIndependentReaderFixture(t, grant); err == nil || len(out) != 0 {
		t.Fatal("SHA-only readback accepted corrupted authenticated EOF")
	}
}

func TestOriginalIndependentReaderRefusesReplacedInode(t *testing.T) {
	grant, _, cleanup := independentReaderFixture(t)
	defer cleanup()
	raw, err := os.ReadFile(grant.File)
	if err != nil {
		t.Fatal(err)
	}
	replacement := grant.File + ".replacement"
	if os.WriteFile(replacement, raw, 0400) != nil || os.Rename(replacement, grant.File) != nil {
		t.Fatal("fixture replace failed")
	}
	if out, _, err := runIndependentReaderFixture(t, grant); err == nil || len(out) != 0 {
		t.Fatal("same digest replacement inode accepted as original fixed version")
	}
}
