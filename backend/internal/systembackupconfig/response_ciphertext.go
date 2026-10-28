package systembackupconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

// OpenCiphertext exposes only the independently prepared original object. It
// is not a durable-pending receipt or provider grant. The publisher takes full
// staging custody separately and must run its real pending/claim/finish flow.
func (p ConfigMutationResponsePublication) OpenCiphertext(ctx context.Context) (io.ReadCloser, error) {
	if ctx == nil || ctx.Err() != nil || isNil(p.stage) || !time.Now().Before(p.until) {
		return nil, sec.ErrRegistrationUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, p.until)
	reader, err := p.stage.Open(ctx)
	if err != nil || isNil(reader) {
		cancel()
		if !isNil(reader) {
			reader.Close()
		}
		return nil, sec.ErrRegistrationUnavailable
	}
	m := p.binding.Manifest()
	return &configResponseCiphertextReader{reader: reader, ctx: ctx, cancel: cancel, until: p.until, size: m.ObjectSize, checksum: m.ObjectHash, hash: sha256.New()}, nil
}

type configResponseCiphertextReader struct {
	reader         io.ReadCloser
	ctx            context.Context
	cancel         context.CancelFunc
	until          time.Time
	size, count    int64
	checksum       string
	hash           hash.Hash
	failed, closed bool
}

func (r *configResponseCiphertextReader) good() bool {
	return !r.failed && r.ctx.Err() == nil && time.Now().Before(r.until)
}
func (r *configResponseCiphertextReader) complete() bool {
	return r.count == r.size && hex.EncodeToString(r.hash.Sum(nil)) == r.checksum
}
func (r *configResponseCiphertextReader) Read(dst []byte) (int, error) {
	if r.closed || !r.good() {
		r.failed = true
		return 0, sec.ErrRegistrationUnavailable
	}
	if len(dst) == 0 {
		return 0, nil
	}
	remaining := r.size - r.count
	if remaining < 0 {
		r.failed = true
		return 0, sec.ErrRegistrationUnavailable
	}
	if int64(len(dst)) > remaining+1 {
		dst = dst[:remaining+1]
	}
	n, err := r.reader.Read(dst)
	if n < 0 || n > len(dst) {
		wipe(dst)
		r.failed = true
		return 0, sec.ErrRegistrationUnavailable
	}
	r.count += int64(n)
	if n > 0 {
		r.hash.Write(dst[:n])
	}
	if !r.good() || r.count > r.size || err != nil && err != io.EOF || err == io.EOF && !r.complete() {
		wipe(dst[:n])
		r.failed = true
		return 0, sec.ErrRegistrationUnavailable
	}
	return n, err
}
func (r *configResponseCiphertextReader) Close() error {
	if r.closed {
		return sec.ErrRegistrationUnavailable
	}
	r.closed = true
	good := r.good() && r.complete()
	err := r.reader.Close()
	r.cancel()
	if !good || err != nil {
		return sec.ErrRegistrationUnavailable
	}
	return nil
}
func verifyConfigResponseCiphertext(ctx context.Context, p ConfigMutationResponsePublication) error {
	reader, err := p.OpenCiphertext(ctx)
	if err != nil {
		return sec.ErrRegistrationUnavailable
	}
	_, err = io.Copy(io.Discard, reader)
	closed := reader.Close()
	if err != nil || closed != nil {
		return sec.ErrRegistrationUnavailable
	}
	return nil
}
