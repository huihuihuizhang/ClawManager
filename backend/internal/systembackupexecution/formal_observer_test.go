package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	"clawreef/internal/systembackup/workspace"
	k "clawreef/internal/systembackupkms"
	w "clawreef/internal/systembackupwire"
)

type candidateContentUnwrapper struct {
	expected    w.KeyRequest
	key         []byte
	calls       int
	deny, after bool
}

func (u *candidateContentUnwrapper) Unwrap(ctx context.Context, r w.KeyRequest, wrapped w.WrappedKey, use w.WithDEK) error {
	u.calls++
	if u.deny || r != u.expected || wrapped.Request != r {
		return w.ErrStreamAuthority
	}
	if err := use(u.key); err != nil {
		return err
	}
	if u.after {
		return w.ErrStreamAuthority
	}
	return ctx.Err()
}

func formalObserverFixture(t *testing.T) (*os.Root, *os.Root, staging.SealScope, worker.Invocation, worker.FormalCaptureResult, *candidateContentUnwrapper) {
	t.Helper()
	ctx := context.Background()
	open := func() *os.Root {
		root, err := os.OpenRoot(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { root.Close() })
		return root
	}
	source, parent, original := open(), open(), open()
	custody, err := staging.OpenSealCustody(parent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { custody.Close() })
	a, j, _ := resultEvidenceFixture()
	a.ConfigSHA256 = strings.Repeat("a", 64)
	a.DeadlineAt = time.Now().Add(time.Minute).UTC()
	i := worker.Invocation{Request: worker.Request{Version: worker.Version, Operation: "capture-workspace", Binding: staging.Binding{BackupID: a.TaskPublicID, Attempt: "3", Path: "workspace", EnvelopeID: "original-envelope", CaptureContextHash: strings.Repeat("b", 64)}, Deadline: a.DeadlineAt, ArtifactName: "workspace.enc", MaxFiles: 100, MaxFileBytes: 2 << 20, MaxArchiveBytes: 4 << 20, MaxCompressedBytes: 2 << 20}, WorkspacePath: "/workspace", StagingPath: "/staging", FormalCapture: &worker.FormalCaptureSpec{Version: worker.FormalCaptureVersion, ConfigSHA256: strings.Repeat("c", 64), EnvelopeName: "envelope.json", MaxFrames: 8}}
	i.ProviderKey = &k.Access{Operation: k.Generate, Endpoint: "https://kms.fixture.invalid", KeyName: "original-key", Request: w.KeyRequest{Key: w.KeyBinding{Provider: "external-kms", IdentityHash: strings.Repeat("d", 64), RegistryVersion: "original-r1", ProviderKeyID: "original-key", ProviderVersion: "1"}, Context: w.KeyContext{InstallationID: a.InstallationID, BackupPublicID: a.TaskPublicID, AttemptNo: "3", Phase: "capture", Part: "workspace", PartIndex: "0", EnvelopeID: i.Request.Binding.EnvelopeID, CaptureContextHash: i.Request.Binding.CaptureContextHash}}}
	if err = original.WriteFile("history.json", []byte(`{"fixture":"original private conversation"}`), 0600); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{9}, 32)
	keys := &candidateContentUnwrapper{expected: i.ProviderKey.Request, key: key}
	spec := w.StreamSpec{Request: keys.expected, Path: i.Request.ArtifactName, MaxPlaintextBytes: i.Request.MaxCompressedBytes, MaxFrames: i.FormalCapture.MaxFrames}
	var seal w.StreamSeal
	var report workspace.Report
	ciphertext, err := staging.WriteUnpublishedFile(ctx, source, i.Request.ArtifactName, func(dst io.Writer) error {
		var err error
		seal, err = w.EncryptStream(ctx, spec, key, dst, func(stream io.Writer) error {
			return staging.Compress(stream, func(compressed io.Writer) error {
				var err error
				report, err = workspace.Archive(ctx, original, compressed, workspace.Limits{MaxFiles: 100, MaxBytes: 2 << 20})
				return err
			})
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := seal.EnvelopeJSON(w.WrappedKey{Request: keys.expected, Algorithm: "provider-native", Ciphertext: []byte("vault:v1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 60)))})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := staging.WriteUnpublishedFile(ctx, source, i.FormalCapture.EnvelopeName, func(dst io.Writer) error { _, err := dst.Write(envelope); return err })
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := i.Hash()
	candidate := worker.FormalCaptureResult{Version: "public-c-stream-candidate.v1alpha1", InvocationSHA256: hash, Ciphertext: ciphertext, Envelope: receipt, Files: report.Files, Bytes: report.Bytes}
	return source, custody, workerSealScope(a, j, i), i, candidate, keys
}

func TestFormalObserverAuthenticatesOriginalCandidateAndReopensBothPrivateVersions(t *testing.T) {
	source, custody, scope, i, candidate, keys := formalObserverFixture(t)
	policy := staging.CustodyPolicy{Installation: scope.Installation, MaxBytes: 16 << 20}
	observed, err := observeOriginalFormalCandidate(context.Background(), source, custody, policy, scope, i, candidate, keys)
	if err != nil || observed.Reference() == "" || keys.calls != 1 || observed.Ciphertext().Name == candidate.Ciphertext.Name || observed.Envelope().Name == candidate.Envelope.Name {
		t.Fatal("formal candidate not independently authenticated", err, keys.calls)
	}
	for _, receipt := range []staging.Receipt{candidate.Ciphertext, candidate.Envelope} {
		if err = source.Remove(receipt.Name); err != nil {
			t.Fatal(err)
		}
	}
	// Restart/retry needs only controller custody and the original journal.
	next, err := observeOriginalFormalCandidate(context.Background(), source, custody, policy, scope, i, candidate, keys)
	if err != nil || next.Reference() != observed.Reference() || keys.calls != 2 {
		t.Fatal("retry consulted removed worker bytes/repeated unwrap", err, keys.calls)
	}
	files, again, err := staging.OpenFormalObserved(context.Background(), custody, scope, candidate.Ciphertext, candidate.Envelope)
	files.Close()
	if err != nil || again.Reference() != observed.Reference() {
		t.Fatal("private readback failed", err)
	}
	if err = custody.Chmod(observed.Ciphertext().Name, 0600); err != nil {
		t.Fatal(err)
	}
	if err = custody.WriteFile(observed.Ciphertext().Name, []byte("corrupt private version"), 0600); err != nil {
		t.Fatal(err)
	}
	files, _, err = staging.OpenFormalObserved(context.Background(), custody, scope, candidate.Ciphertext, candidate.Envelope)
	files.Close()
	if err == nil {
		t.Fatal("corrupted original custody accepted")
	}
}

func TestFormalObserverRefusesMissingUnwrapAndTamperedOrRevokedCandidate(t *testing.T) {
	for _, fault := range []string{"missing-unwrapper", "ciphertext", "envelope-context", "wrong-key", "denied", "revoked-after-use", "attempt", "invocation", "capacity"} {
		t.Run(fault, func(t *testing.T) {
			source, custody, scope, i, candidate, keys := formalObserverFixture(t)
			policy := staging.CustodyPolicy{Installation: scope.Installation, MaxBytes: 16 << 20}
			var unwrap w.Unwrapper = keys
			switch fault {
			case "missing-unwrapper":
				unwrap = nil
			case "ciphertext":
				source.Chmod(candidate.Ciphertext.Name, 0600)
				source.WriteFile(candidate.Ciphertext.Name, []byte("changed"), 0600)
			case "envelope-context":
				raw, err := source.ReadFile(candidate.Envelope.Name)
				if err != nil {
					t.Fatal(err)
				}
				raw = []byte(strings.Replace(string(raw), `"provider_version":"1"`, `"provider_version":"2"`, 1))
				source.Chmod(candidate.Envelope.Name, 0600)
				if err = source.WriteFile(candidate.Envelope.Name, raw, 0600); err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(raw)
				candidate.Envelope.SHA256 = hex.EncodeToString(sum[:])
				candidate.Envelope.Size = int64(len(raw))
			case "wrong-key":
				keys.key[0]++
			case "denied":
				keys.deny = true
			case "revoked-after-use":
				keys.after = true
			case "attempt":
				scope.Binding.Attempt = "4"
			case "invocation":
				candidate.InvocationSHA256 = strings.Repeat("e", 64)
			case "capacity":
				policy.MaxBytes = 1
			}
			observed, err := observeOriginalFormalCandidate(context.Background(), source, custody, policy, scope, i, candidate, unwrap)
			if err == nil || observed.Reference() != "" {
				t.Fatal("unverified candidate produced usable part", fault, err)
			}
			if fault == "missing-unwrapper" || fault == "envelope-context" || fault == "attempt" || fault == "invocation" || fault == "capacity" {
				if keys.calls != 0 {
					t.Fatal("invalid candidate reached provider")
				}
			}
		})
	}
}
