package systembackuphostpatharchive

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"sync/atomic"
	"time"

	backup "clawreef/internal/systembackup"
	ev "clawreef/internal/systembackupevidence"
)

// PipeGrant is a PRIVATE anonymous-pipe message from the actual authenticated
// original parent. It is not an HTTP request, persisted grant or evidence.
// The child has a single exact evidence-unwrap credential, not a task DEK.
type PipeGrant struct {
	Version, File, HeaderSHA256, OperationID, NativePlanSHA256 string
	Receipt                                                    stagingReceipt
	Identity                                                   FileIdentity
	Transit                                                    ev.TransitConfig
	Credential                                                 ev.TransitCredential
	Until                                                      time.Time
	Challenge, Authenticator                                   []byte
}

type stagingReceipt struct {
	Name   string
	Size   int64
	SHA256 string
}

type FileIdentity struct{ Device, Inode, UID uint64 }

// ReaderReceipt only describes actual byte/decryption readback. It supplies no
// physical writer, history, access-isolation, retention or coverage assertion.
type ReaderReceipt struct {
	Version, OperationID, NativePlanSHA256, HeaderSHA256 string
	CiphertextSHA256, PlaintextSHA256                    string
	CiphertextBytes, PlaintextBytes                      int64
	Identity                                             FileIdentity
	PID                                                  int
	Challenge, Authentication                            []byte
}

func fileIdentity(info os.FileInfo) (FileIdentity, error) {
	value := reflect.ValueOf(info.Sys())
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return FileIdentity{}, ErrArchive
	}
	fields := []string{"Dev", "Ino", "Uid", "Nlink"}
	values := make([]uint64, len(fields))
	for n, name := range fields {
		f := value.FieldByName(name)
		if !f.IsValid() || !f.CanUint() {
			return FileIdentity{}, ErrArchive
		}
		values[n] = f.Uint()
	}
	if values[3] != 1 {
		return FileIdentity{}, ErrArchive
	}
	return FileIdentity{values[0], values[1], values[2]}, nil
}

// IndependentIdentity is read from the actual pinned producer file descriptor,
// never reconstructed from a caller filename or serialized receipt.
func (a *LocalArchive) IndependentIdentity() (FileIdentity, error) {
	if a == nil || a.file == nil {
		return FileIdentity{}, ErrArchive
	}
	info, err := a.file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != a.receipt.Size {
		return FileIdentity{}, ErrArchive
	}
	return fileIdentity(info)
}

// NewPipeGrant binds read-only child access to the SAME actual local producer.
// Original Installer owner must supply the already authorized unwrap credential
// and actual pinned child executable; this function grants neither authority.
func (a *LocalArchive) NewPipeGrant(file, operation, plan string, transit ev.TransitConfig,
	credential ev.TransitCredential, until time.Time, challenge, authenticator []byte) (PipeGrant, error) {
	identity, err := a.IndependentIdentity()
	if err != nil || len(challenge) != 32 || len(authenticator) != 32 || !time.Now().Before(until) ||
		credential.Operation != ev.TransitUnwrap || credential.Key != transit.Key || credential.Installation != transit.Installation {
		return PipeGrant{}, ErrArchive
	}
	h := sha256.Sum256(a.header)
	return PipeGrant{Version: "original-custody-independent-read.v1", File: file, HeaderSHA256: hex.EncodeToString(h[:]),
		OperationID: operation, NativePlanSHA256: plan, Receipt: stagingReceipt{a.receipt.Name, a.receipt.Size, a.receipt.SHA256},
		Identity: identity, Transit: transit, Credential: credential, Until: until,
		Challenge: bytes.Clone(challenge), Authenticator: bytes.Clone(authenticator)}, nil
}

type oneReadCredential struct {
	grant PipeGrant
	used  atomic.Bool
}

func (c *oneReadCredential) Resolve(ctx context.Context, key ev.KeyRef, operation ev.TransitOperation) (ev.TransitCredential, error) {
	if ctx.Err() != nil || operation != ev.TransitUnwrap || key != c.grant.Transit.Key ||
		!c.used.CompareAndSwap(false, true) || !time.Now().Before(c.grant.Credential.ExpiresAt) {
		return ev.TransitCredential{}, ErrArchive
	}
	out := c.grant.Credential
	out.Secret = bytes.Clone(out.Secret)
	return out, nil
}

type hashCountWriter struct {
	w io.Writer
	n int64
}

func (w *hashCountWriter) Write(raw []byte) (int, error) {
	n, err := w.w.Write(raw)
	w.n += int64(n)
	return n, err
}

// VerifyPipeGrant performs real independent readonly open, inode validation,
// exact whole ciphertext SHA/EOF and native dedicated-provider unwrap followed
// by authenticated complete decryption. No source plaintext escapes this call.
func VerifyPipeGrant(g PipeGrant) (ReaderReceipt, error) {
	defer clear(g.Credential.Secret)
	defer clear(g.Authenticator)
	if g.Version != "original-custody-independent-read.v1" || len(g.Challenge) != 32 || len(g.Authenticator) != 32 ||
		!time.Now().Before(g.Until) || g.Until.After(time.Now().Add(2*time.Minute)) ||
		g.Credential.Operation != ev.TransitUnwrap || g.Credential.Key != g.Transit.Key || g.Credential.Installation != g.Transit.Installation {
		return ReaderReceipt{}, ErrArchive
	}
	ctx, cancel := context.WithDeadline(context.Background(), g.Until)
	defer cancel()
	before, err := os.Lstat(g.File)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0400 || before.Size() != g.Receipt.Size {
		return ReaderReceipt{}, ErrArchive
	}
	f, err := os.Open(g.File)
	if err != nil {
		return ReaderReceipt{}, ErrArchive
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(before, actual) {
		return ReaderReceipt{}, ErrArchive
	}
	identity, err := fileIdentity(actual)
	if err != nil || identity != g.Identity {
		return ReaderReceipt{}, ErrArchive
	}
	cipherHash := sha256.New()
	counter := &hashCountWriter{w: cipherHash}
	reader := io.TeeReader(&contextReader{ctx, f}, counter)
	prefix := make([]byte, 16)
	if _, err = io.ReadFull(reader, prefix); err != nil || !bytes.Equal(prefix[:12], []byte("CMHPARCH0001")) {
		return ReaderReceipt{}, ErrArchive
	}
	size := binary.BigEndian.Uint32(prefix[12:])
	if size == 0 || size > 16384 {
		return ReaderReceipt{}, ErrArchive
	}
	header := make([]byte, size)
	if _, err = io.ReadFull(reader, header); err != nil {
		return ReaderReceipt{}, ErrArchive
	}
	h := sha256.Sum256(header)
	var original archiveHeader
	if hex.EncodeToString(h[:]) != g.HeaderSHA256 || json.Unmarshal(header, &original) != nil ||
		original.Version != "original-minio-hostpath-encrypted-copy.v1" || original.EvidenceKey != g.Transit.Key ||
		original.Binding.Installation != g.Transit.Installation || original.Binding.MaintenanceID != g.OperationID ||
		original.Native.PlanSHA256 != g.NativePlanSHA256 {
		return ReaderReceipt{}, ErrArchive
	}
	credentials := &oneReadCredential{grant: g}
	keys, err := ev.NewTransitKeys(g.Transit, credentials)
	if err != nil {
		return ReaderReceipt{}, ErrArchive
	}
	defer keys.Close()
	key, err := keys.Unwrap(ctx, original.EvidenceKey, original.WrappedDEK)
	defer clear(key)
	if err != nil {
		return ReaderReceipt{}, ErrArchive
	}
	plainHash := sha256.New()
	plain := &hashCountWriter{w: plainHash}
	if backup.Decrypt(ctx, plain, reader, key, header) != nil || ctx.Err() != nil {
		return ReaderReceipt{}, ErrArchive
	}
	var trailing [1]byte
	if n, err := reader.Read(trailing[:]); n != 0 || err != io.EOF {
		return ReaderReceipt{}, ErrArchive
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(actual, after) || after.Size() != actual.Size() ||
		!after.ModTime().Equal(actual.ModTime()) || counter.n != g.Receipt.Size ||
		hex.EncodeToString(cipherHash.Sum(nil)) != g.Receipt.SHA256 {
		return ReaderReceipt{}, ErrArchive
	}
	out := ReaderReceipt{Version: g.Version, OperationID: g.OperationID, NativePlanSHA256: g.NativePlanSHA256,
		HeaderSHA256: g.HeaderSHA256, CiphertextSHA256: g.Receipt.SHA256, PlaintextSHA256: hex.EncodeToString(plainHash.Sum(nil)),
		CiphertextBytes: counter.n, PlaintextBytes: plain.n, Identity: identity, PID: os.Getpid(), Challenge: bytes.Clone(g.Challenge)}
	raw, err := json.Marshal(out)
	if err != nil {
		return ReaderReceipt{}, ErrArchive
	}
	mac := hmac.New(sha256.New, g.Authenticator)
	mac.Write(raw)
	out.Authentication = mac.Sum(nil)
	return out, nil
}

// AuthenticateReaderReceipt is only the private parent/child channel check;
// caller cannot use it as a coverage, native-source or authorization receipt.
func AuthenticateReaderReceipt(raw []byte, g PipeGrant, actualChildPID int) (ReaderReceipt, error) {
	var out ReaderReceipt
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || out.PID != actualChildPID || out.PID == os.Getpid() ||
		out.Version != g.Version || out.OperationID != g.OperationID || out.NativePlanSHA256 != g.NativePlanSHA256 ||
		out.HeaderSHA256 != g.HeaderSHA256 || out.CiphertextSHA256 != g.Receipt.SHA256 || out.CiphertextBytes != g.Receipt.Size ||
		out.Identity != g.Identity || !bytes.Equal(out.Challenge, g.Challenge) || !pinPattern.MatchString(out.PlaintextSHA256) {
		return ReaderReceipt{}, ErrArchive
	}
	signature := bytes.Clone(out.Authentication)
	out.Authentication = nil
	canonical, err := json.Marshal(out)
	if err != nil {
		return ReaderReceipt{}, ErrArchive
	}
	mac := hmac.New(sha256.New, g.Authenticator)
	mac.Write(canonical)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return ReaderReceipt{}, ErrArchive
	}
	out.Authentication = signature
	return out, nil
}

// RunIndependentReader accepts secrets ONLY from anonymous stdin and emits
// only bounded authenticated result metadata. Native/provider details do not
// escape on failure. The installed executable must expose this exact mode.
func RunIndependentReader() error {
	info, err := os.Stdin.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		return ErrArchive
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	defer clear(raw)
	if err != nil || len(raw) >= 1<<20 {
		return ErrArchive
	}
	var grant PipeGrant
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&grant) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrArchive
	}
	result, err := VerifyPipeGrant(grant)
	if err != nil {
		return ErrArchive
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
