package recovery

import (
	"context"
	"io"
	"strconv"

	"clawreef/internal/systembackup/artifact"
	"clawreef/internal/systembackup/staging"
)

// An explicitly selected adapter for this repository's CMSTG01 framing. It is
// not a guess about another owner's published format and has no autodetection.
const StagingCodec = "cmstg01-adapter.v1"

type CodecEntry struct {
	Object  Object
	Binding staging.Binding
	Key     artifact.WrappedKey
}
type CodecDescriptor struct {
	Format            string
	Identity          Identity
	CaptureSHA256     string
	MaxPlaintextBytes int64
	Entries           []CodecEntry
}
type StagingAuthenticator struct {
	descriptor CodecDescriptor
	keys       artifact.Keys
}

func NewStagingAuthenticator(d CodecDescriptor, keys artifact.Keys) (*StagingAuthenticator, error) {
	if _, e := d.Identity.Matrix(); e != nil || d.Format != StagingCodec || !digest(d.CaptureSHA256) || d.MaxPlaintextBytes < 1 || d.MaxPlaintextBytes > 1<<40 || len(d.Entries) == 0 || len(d.Entries) > 100000 || keys == nil {
		return nil, ErrContract
	}
	seen := map[string]bool{}
	for _, entry := range d.Entries {
		b := entry.Binding
		if !entry.Object.valid() || seen[entry.Object.Key] || b.BackupID != d.Identity.Backup || b.Attempt != strconv.FormatInt(d.Identity.Attempt, 10) || b.CaptureContextHash != d.CaptureSHA256 || b.Path != entry.Object.Key || !validID(b.EnvelopeID) || !validID(entry.Key.Version) || len(entry.Key.Nonce) != 12 || len(entry.Key.Ciphertext) != 48 {
			return nil, ErrContract
		}
		seen[entry.Object.Key] = true
	}
	return &StagingAuthenticator{d, keys}, nil
}
func (a *StagingAuthenticator) Authenticate(ctx context.Context, m Manifest, o Object, in io.Reader) error {
	if a == nil || m.Identity != a.descriptor.Identity || m.CaptureHash != a.descriptor.CaptureSHA256 {
		return ErrContract
	}
	for _, entry := range a.descriptor.Entries {
		if entry.Object == o {
			key, e := a.keys.Unwrap(ctx, entry.Binding, entry.Key)
			if e != nil {
				return ErrUnavailable
			}
			defer clear(key)
			return staging.Open(ctx, in, io.Discard, key, entry.Binding, a.descriptor.MaxPlaintextBytes)
		}
	}
	return ErrContract
}

// Owner codecs can be registered by format. Unknown formats never fall back to
// checksum-only verification or to the CMSTG01 adapter.
type CodecFactory func(context.Context, Reference, Reader) (Authenticator, error)
type Codecs map[string]CodecFactory

func (c Codecs) Resolve(ctx context.Context, format string, descriptor Reference, store Reader) (Authenticator, error) {
	f := c[format]
	if f == nil || !descriptor.valid() || store == nil {
		return nil, ErrUnavailable
	}
	a, e := f(ctx, descriptor, store)
	if e != nil || a == nil {
		return nil, ErrUnavailable
	}
	return a, nil
}
