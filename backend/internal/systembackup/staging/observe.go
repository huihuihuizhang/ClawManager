package staging

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
)

// SealScope is supplied from the controller's authenticated frozen Job, never
// accepted as worker authority. Custody must not be mounted into worker Pods.
type SealScope struct {
	Installation, Task, Phase, Unit, Namespace, JobName, JobUID string
	Attempt, Generation, ConfigVersion                          uint64
	ConfigSHA256, InvocationSHA256                              string
	Binding                                                     Binding
}

// Observation can only be produced by verifying a private, durable copy. It is
// a local staging seal, NOT a final artifact publication or acceptance proof.
type Observation struct {
	receipt   Receipt
	reference string
}

func (o Observation) Receipt() Receipt  { return o.receipt }
func (o Observation) Reference() string { return o.reference }

// OpenSealCustody uses a sibling of the task directories. Public worker Jobs
// mount only their exact task subPath, never this directory or the volume root.
func OpenSealCustody(parent *os.Root) (*os.Root, error) {
	if parent == nil {
		return nil, ErrFile
	}
	const name = ".controller-seals"
	if err := parent.Mkdir(name, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := parent.Lstat(name)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrFile
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	if err = syncDirectory(parent); err != nil {
		root.Close()
		return nil, err
	}
	return root, nil
}

func observedReceipt(scope SealScope, original Receipt) (Receipt, error) {
	if scope.Installation == "" || scope.Task == "" || scope.Phase != "capture" || scope.Unit == "" || scope.Namespace == "" || scope.JobName == "" || scope.JobUID == "" || scope.Attempt == 0 || scope.Generation == 0 || scope.ConfigVersion == 0 || len(scope.ConfigSHA256) != 64 || len(scope.InvocationSHA256) != 64 || scope.Binding.BackupID != scope.Task || !fileName.MatchString(original.Name) || original.Size <= 0 || len(original.SHA256) != 64 {
		return Receipt{}, ErrFile
	}
	for _, s := range []string{scope.ConfigSHA256, scope.InvocationSHA256, original.SHA256} {
		if _, err := hex.DecodeString(s); err != nil {
			return Receipt{}, ErrFile
		}
	}
	raw, err := json.Marshal(struct {
		Domain   string
		Scope    SealScope
		Original Receipt
	}{"controller-staging-seal.v1", scope, original})
	if err != nil {
		return Receipt{}, err
	}
	sum := sha256.Sum256(raw)
	return Receipt{Name: "seal-" + hex.EncodeToString(sum[:]) + ".enc", Size: original.Size, SHA256: original.SHA256}, nil
}

// SealReferenceForIntent recomputes the exact reference whose ciphertext may
// be removed. An owner must compare this with its caller's reference before it
// looks up any task or Job rows.
func SealReferenceForIntent(intent SealIntent) (string, error) {
	if intent.Schema != "controller-staging-seal-intent.v1" {
		return "", ErrFile
	}
	receipt, err := observedReceipt(intent.Scope, intent.Original)
	if err != nil {
		return "", err
	}
	return "controller-staging-seal.v1/" + receipt.Name, nil
}

// OpenObserved rehashes the exact original version on every read/restart.
// No fallback to the worker's mutable source is allowed.
func OpenObserved(ctx context.Context, custody *os.Root, scope SealScope, original Receipt) (*os.File, Observation, error) {
	receipt, err := observedReceipt(scope, original)
	if err != nil {
		return nil, Observation{}, err
	}
	f, err := OpenFile(ctx, custody, receipt)
	if err != nil {
		return nil, Observation{}, err
	}
	return f, Observation{receipt: receipt, reference: "controller-staging-seal.v1/" + receipt.Name}, nil
}

// ObserveFile copies ciphertext into exclusively owned custody, verifies both
// its exact bytes and AEAD final frame, fsyncs it, then publishes create-only.
// A retry verifies the existing version, including when the source is gone.
// The caller persists the returned reference in its original Job transaction.
// Production callers must use ObserveManaged for the shared lock and budget.
func ObserveFile(ctx context.Context, source, custody *os.Root, scope SealScope, original Receipt, key []byte, max int64) (Observation, error) {
	if max <= 0 || max > 1<<50 {
		return Observation{}, ErrFile
	}
	return observeAuthenticatedFile(ctx, source, custody, scope, original, max+(max/chunkSize+2)*64+8192, func(reader io.Reader) error { return Open(ctx, reader, io.Discard, key, scope.Binding, max) })
}

// Shared create-only copy mechanics. Only the typed CMSTG01/formal wrappers
// choose authentication; an arbitrary callback is not an exported capability.
func observeAuthenticatedFile(ctx context.Context, source, custody *os.Root, scope SealScope, original Receipt, max int64, authenticate func(io.Reader) error) (Observation, error) {
	receipt, err := observedReceipt(scope, original)
	if err != nil || ctx == nil || ctx.Err() != nil || source == nil || custody == nil || max <= 0 || max > 1<<51 || original.Size > max || authenticate == nil {
		return Observation{}, ErrFile
	}
	verify := func() (Observation, error) {
		f, o, e := OpenObserved(ctx, custody, scope, original)
		if e != nil {
			return Observation{}, e
		}
		defer f.Close()
		if e = authenticate(f); e != nil {
			return Observation{}, e
		}
		if e = syncDirectory(custody); e != nil {
			return Observation{}, e
		}
		return o, nil
	}
	if _, err = custody.Lstat(receipt.Name); err == nil {
		return verify()
	} else if !errors.Is(err, os.ErrNotExist) {
		return Observation{}, ErrFile
	}
	src, err := OpenFile(ctx, source, original)
	if err != nil {
		return Observation{}, err
	}
	defer src.Close()
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return Observation{}, err
	}
	temp := ".seal-" + hex.EncodeToString(nonce[:]) + ".partial"
	dst, err := custody.OpenFile(temp, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return Observation{}, err
	}
	defer func() { dst.Close(); custody.Remove(temp) }()
	digest := sha256.New()
	buf := make([]byte, 128<<10)
	var size int64
	for {
		if err = ctx.Err(); err != nil {
			return Observation{}, err
		}
		n, e := src.Read(buf)
		if n > 0 {
			size += int64(n)
			if size > original.Size {
				return Observation{}, ErrFile
			}
			if _, err = io.MultiWriter(dst, digest).Write(buf[:n]); err != nil {
				return Observation{}, err
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return Observation{}, e
		}
	}
	if size != original.Size || hex.EncodeToString(digest.Sum(nil)) != original.SHA256 {
		return Observation{}, ErrFile
	}
	if _, err = dst.Seek(0, io.SeekStart); err != nil {
		return Observation{}, err
	}
	if err = authenticate(dst); err != nil {
		return Observation{}, err
	}
	if err = dst.Sync(); err != nil {
		return Observation{}, err
	}
	if err = dst.Close(); err != nil {
		return Observation{}, err
	}
	if err = ctx.Err(); err != nil {
		return Observation{}, err
	}
	if err = custody.Link(temp, receipt.Name); err != nil && !errors.Is(err, os.ErrExist) {
		return Observation{}, err
	}
	if err = custody.Remove(temp); err != nil {
		return Observation{}, err
	}
	if err = custody.Chmod(receipt.Name, 0400); err != nil {
		return Observation{}, err
	}
	// The temporary bytes were authenticated above. A concurrent winner must
	// have the exact same pinned ciphertext digest/size; do not repeat a
	// single-use external unwrap just to hash identical published bytes again.
	f, observation, err := OpenObserved(ctx, custody, scope, original)
	if err != nil {
		return Observation{}, err
	}
	f.Close()
	if err = syncDirectory(custody); err != nil {
		return Observation{}, err
	}
	return observation, nil
}
