// Package systembackuphostpatharchive copies original native bytes directly
// into encrypted, create-only controller custody. It supplies NO authorization,
// physical writer hold, evidence registration or PreparedCoverage implementation.
// The actual Installer/B/D maintenance factory must authenticate the source,
// dedicated evidence provider and custody before invoking this lower-level IO.
package systembackuphostpatharchive

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	backup "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/staging"
	ev "clawreef/internal/systembackupevidence"
)

var ErrArchive = errors.New("original hostPath encrypted archive is unavailable or unbound")
var pinPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Binding is association DATA, not proof of a hold or permission. Its exact
// bytes become AEAD AAD; the original authenticated maintenance owner must load
// and recheck the actual reservation, source closure and provider identities.
// No future backup task, BootstrapGrant or task DEK participates here.
type Binding struct {
	Installation, ServerUUID, Database, MaintenanceID          string
	Generation                                                 uint64
	WriterCensusSHA256, HoldRevision                           string
	SourceIdentitySHA256, EvidenceProviderSHA256               string
	CustodyIdentitySHA256                                      string
	SourceHostPath, SourcePVUID, SourceClaimUID, SourceNodeUID string
}

// NativeStream is a pinned native component invocation. Neither its paths nor
// preparation JSON are authority; authenticated original discovery supplies
// them. There is no arbitrary argument list, shell, plaintext file or env secret.
type NativeStream struct {
	PythonFile, PythonSHA256 string
	ScriptFile, ScriptSHA256 string
	PlanFile, PlanSHA256     string
	MaxFiles, MaxSeconds     int
	MaxBytes                 int64
}

type archiveHeader struct {
	Version     string
	Binding     Binding
	Native      NativeStream
	EvidenceKey ev.KeyRef
	WrappedDEK  []byte
}

// LocalArchive is only a verified encrypted local copy. Private construction
// prevents replacing its pinned inode/bytes through this API. It is NOT an
// independently retained provider version or coverage/writer/history receipt.
// Original D custody journal must retain this file and ownership across restart;
// a failed/unknown call must resolve its create-only file, never overwrite it.
type LocalArchive struct {
	file    *os.File
	receipt staging.Receipt
	header  []byte
}

func (a *LocalArchive) Receipt() staging.Receipt {
	if a == nil || a.file == nil {
		return staging.Receipt{}
	}
	return a.receipt
}

// AssociationHeader returns the exact public wrapped-key/AAD association that
// is durably embedded in the ciphertext file. It confers no authority.
func (a *LocalArchive) AssociationHeader() []byte {
	if a == nil || a.file == nil {
		return nil
	}
	return bytes.Clone(a.header)
}

func (a *LocalArchive) Close() error {
	if a == nil || a.file == nil {
		return ErrArchive
	}
	err := a.file.Close()
	a.file = nil
	return err
}

// CopyCiphertext exports the SAME pinned ciphertext inode after a full hash
// pass. Original independent archive provider must enforce fixed-version,
// retention/custody and authenticated readback; this method grants none of it.
func (a *LocalArchive) CopyCiphertext(ctx context.Context, dst io.Writer) error {
	if a == nil || a.file == nil || ctx == nil || ctx.Err() != nil || dst == nil {
		return ErrArchive
	}
	if _, err := a.file.Seek(0, io.SeekStart); err != nil {
		return ErrArchive
	}
	h := sha256.New()
	n, err := io.Copy(h, &contextReader{ctx, a.file})
	if err != nil || n != a.receipt.Size || hex.EncodeToString(h.Sum(nil)) != a.receipt.SHA256 {
		return ErrArchive
	}
	if _, err = a.file.Seek(0, io.SeekStart); err != nil {
		return ErrArchive
	}
	n, err = io.Copy(dst, &contextReader{ctx, a.file})
	if err != nil || n != a.receipt.Size {
		return ErrArchive
	}
	return ctx.Err()
}

func pinnedFile(path, expected string, limit int64, private bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !pinPattern.MatchString(expected) {
		return ErrArchive
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return ErrArchive
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > limit ||
		before.Mode().Perm()&0022 != 0 || private && before.Mode().Perm()&0077 != 0 {
		return ErrArchive
	}
	f, err := os.Open(path)
	if err != nil {
		return ErrArchive
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(before, actual) {
		return ErrArchive
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil || n != before.Size() || hex.EncodeToString(h.Sum(nil)) != expected {
		return ErrArchive
	}
	return nil
}

func (n NativeStream) check(ctx context.Context) error {
	_, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil || n.MaxFiles <= 0 || n.MaxBytes <= 0 || n.MaxSeconds < 1 ||
		n.MaxSeconds > 600 ||
		pinnedFile(n.PythonFile, n.PythonSHA256, 128<<20, false) != nil ||
		pinnedFile(n.ScriptFile, n.ScriptSHA256, 1<<20, false) != nil ||
		pinnedFile(n.PlanFile, n.PlanSHA256, 1<<20, true) != nil {
		return ErrArchive
	}
	return nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

// encryptNative waits for native SUCCESS before exposing EOF to Encrypt. A
// failing child can emit valid-looking tar bytes; CloseWithError prevents those
// bytes receiving an authenticated final frame. No child diagnostics escape.
func encryptNative(ctx context.Context, dst io.Writer, key, aad []byte, n NativeStream) error {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	r, w := io.Pipe()
	defer r.Close()
	done := make(chan error, 1)
	go func() {
		cmd := exec.CommandContext(child, n.PythonFile, "-I", "-B", n.ScriptFile, "stream",
			"--plan-file", n.PlanFile, "--plan-sha256", n.PlanSHA256,
			"--max-files", strconv.Itoa(n.MaxFiles), "--max-bytes", strconv.FormatInt(n.MaxBytes, 10),
			"--max-seconds", strconv.Itoa(n.MaxSeconds))
		cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, w, io.Discard
		cmd.WaitDelay = 5 * time.Second
		err := cmd.Run()
		if err != nil {
			err = ErrArchive
		}
		w.CloseWithError(err)
		done <- err
	}()
	err := backup.Encrypt(ctx, dst, r, key, aad)
	if err != nil {
		cancel()
		r.CloseWithError(err)
	}
	if nativeErr := <-done; err != nil || nativeErr != nil || ctx.Err() != nil {
		return ErrArchive
	}
	return nil
}

// CreateEncryptedLocal copies under an ALREADY authenticated original hold and
// provider action. Only concrete dedicated evidence TransitKeys are accepted;
// no supplied plaintext task DEK, generic allow-all Keys, key creation/export,
// new grant, SQL update or S3 permission can be introduced through this API.
// This low-level API intentionally cannot attest the actual B/Installer holder.
// Until that concrete factory and independent archive readback are wired, it
// MUST NOT be exposed as a production admission or first-enable entrypoint.
func CreateEncryptedLocal(ctx context.Context, custody *os.Root, name string, b Binding,
	n NativeStream, evidenceKeys *ev.TransitKeys, evidenceKey ev.KeyRef) (*LocalArchive, error) {
	if ctx == nil || custody == nil || evidenceKeys == nil || b.Installation == "" || b.ServerUUID == "" ||
		b.Database == "" || b.MaintenanceID == "" || b.Generation == 0 || b.HoldRevision == "" ||
		b.SourceHostPath == "" || b.SourcePVUID == "" || b.SourceClaimUID == "" || b.SourceNodeUID == "" ||
		!pinPattern.MatchString(b.WriterCensusSHA256) || !pinPattern.MatchString(b.SourceIdentitySHA256) ||
		!pinPattern.MatchString(b.EvidenceProviderSHA256) || !pinPattern.MatchString(b.CustodyIdentitySHA256) ||
		n.check(ctx) != nil {
		return nil, ErrArchive
	}
	deadline, _ := ctx.Deadline()
	if time.Until(deadline) < time.Duration(n.MaxSeconds)*time.Second {
		return nil, ErrArchive
	}
	planRaw, err := os.ReadFile(n.PlanFile)
	var plan struct{ Root, Profile string }
	planHash := sha256.Sum256(planRaw)
	if err != nil || hex.EncodeToString(planHash[:]) != n.PlanSHA256 ||
		json.Unmarshal(planRaw, &plan) != nil || plan.Profile != "original-minio-hostpath-native-raw-cut.v1" ||
		plan.Root != b.SourceHostPath || !filepath.IsAbs(plan.Root) || filepath.Clean(plan.Root) != plan.Root {
		return nil, ErrArchive
	}
	custodyPath, err := filepath.EvalSymlinks(custody.Name())
	if err != nil {
		return nil, ErrArchive
	}
	relative, err := filepath.Rel(plan.Root, custodyPath)
	if err != nil || relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return nil, ErrArchive
	}
	info, err := custody.Stat(".")
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrArchive
	}
	key := make([]byte, 32)
	defer clear(key)
	if _, err = rand.Read(key); err != nil {
		return nil, ErrArchive
	}
	borrow := bytes.Clone(key)
	defer clear(borrow)
	wrapped, err := evidenceKeys.Wrap(ctx, evidenceKey, borrow)
	if err != nil || !bytes.Equal(borrow, key) {
		return nil, ErrArchive
	}
	clear(borrow)
	readKey, err := evidenceKeys.Unwrap(ctx, evidenceKey, wrapped)
	defer clear(readKey)
	if err != nil || !bytes.Equal(readKey, key) {
		return nil, ErrArchive
	}
	header, err := json.Marshal(archiveHeader{"original-minio-hostpath-encrypted-copy.v1", b, n, evidenceKey, wrapped})
	if err != nil || len(header) > 16384 || n.check(ctx) != nil {
		return nil, ErrArchive
	}
	// Original D journals this exact association/header BEFORE independent
	// provider publication. The header is public wrapped-key/binding metadata;
	// it is also AEAD AAD and cannot be silently rebound to another reservation.
	receipt, err := staging.WriteUnpublishedFile(ctx, custody, name, func(dst io.Writer) error {
		prefix := make([]byte, 16)
		copy(prefix, []byte("CMHPARCH0001"))
		binary.BigEndian.PutUint32(prefix[12:], uint32(len(header)))
		if _, err := io.Copy(dst, bytes.NewReader(append(prefix, header...))); err != nil {
			return ErrArchive
		}
		if err := encryptNative(ctx, dst, key, header, n); err != nil {
			return err
		}
		return n.check(ctx)
	})
	if err != nil {
		return nil, ErrArchive
	}
	f, err := staging.OpenFile(ctx, custody, receipt)
	if err != nil {
		return nil, ErrArchive
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	prefix := make([]byte, 16+len(header))
	if _, err = io.ReadFull(f, prefix); err != nil || !bytes.Equal(prefix[16:], header) ||
		!bytes.Equal(prefix[:12], []byte("CMHPARCH0001")) || binary.BigEndian.Uint32(prefix[12:16]) != uint32(len(header)) {
		return nil, ErrArchive
	}
	// Full authenticated readback of the same durable ciphertext inode.
	if err = backup.Decrypt(ctx, io.Discard, f, readKey, header); err != nil {
		return nil, ErrArchive
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil || ctx.Err() != nil {
		return nil, ErrArchive
	}
	ok = true
	return &LocalArchive{file: f, receipt: receipt, header: bytes.Clone(header)}, nil
}
