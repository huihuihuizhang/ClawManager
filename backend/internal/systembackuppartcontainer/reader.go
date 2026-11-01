package systembackuppartcontainer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"

	w "clawreef/internal/systembackupwire"
)

// The checksum/size originate in authenticated manifest/index data. Version
// must be the concrete independently observed native object version. This DTO
// alone proves neither provenance nor current artifact/KEK permission.
type FixedObject struct {
	Reader          io.ReaderAt
	Version, SHA256 string
	Size            int64
}

// Inspect hashes the EXACT prefix and streamed header bytes it parses, then
// the SAME sequential payload bytes used by every member digest. An immutable
// object annotation cannot replace this requirement: mutable ReaderAt ABA must
// never let un-hashed header facts escape. No Unwrap or plaintext is used here.
func Inspect(ctx context.Context, object FixedObject, expected Scope, checkpoints map[string]string, limit, indexLimit int64) (Facts, error) {
	var zero Facts
	if ctx == nil || ctx.Err() != nil || object.Reader == nil || !fixedVersion(object.Version) || !digest.MatchString(object.SHA256) || object.Size < prefixBytes+1 || limit < 1 || limit > MaxBytes || object.Size > limit || indexLimit < 1 || indexLimit > MaxIndexBytes {
		return zero, ErrContainer
	}
	var prefix [prefixBytes]byte
	if n, err := object.Reader.ReadAt(prefix[:], 0); err != nil || n != len(prefix) || !bytes.Equal(prefix[:8], magic[:]) {
		return zero, ErrContainer
	}
	headerSize := int64(binary.BigEndian.Uint32(prefix[8:]))
	if headerSize < 1 || headerSize > indexLimit || headerSize > MaxHeaderBytes || headerSize > object.Size-prefixBytes {
		return zero, ErrContainer
	}
	whole := sha256.New()
	whole.Write(prefix[:])
	headerSource := io.TeeReader(contextReader{ctx: ctx, src: io.NewSectionReader(object.Reader, prefixBytes, headerSize)}, whole)
	header, err := readHeader(headerSource, headerSize, indexLimit)
	if err != nil {
		return zero, err
	}
	facts, err := validateHeader(header, expected, checkpoints, limit)
	if err != nil || facts.Size != object.Size-prefixBytes-headerSize {
		return zero, ErrContainer
	}
	payloadOffset := int64(prefixBytes) + headerSize
	payload := io.TeeReader(contextReader{ctx: ctx, src: io.NewSectionReader(object.Reader, payloadOffset, facts.Size)}, whole)
	for index, member := range header.Members {
		cipherHash := sha256.New()
		n, err := io.CopyN(cipherHash, payload, member.CipherBytes)
		if err != nil || n != member.CipherBytes || hex.EncodeToString(cipherHash.Sum(nil)) != member.CipherSHA256 {
			return zero, ErrContainer
		}
		envelope, err := io.ReadAll(io.LimitReader(payload, member.EnvelopeBytes))
		if err != nil || int64(len(envelope)) != member.EnvelopeBytes || checksum(envelope) != member.EnvelopeSHA256 {
			return zero, ErrContainer
		}
		if _, err = w.ParseStreamEnvelope(member.Stream, envelope); err != nil {
			return zero, ErrContainer
		}
		facts.Locations[index].ObjectVersion = object.Version
		facts.Locations[index].CipherOffset += payloadOffset
		facts.Locations[index].EnvelopeOffset += payloadOffset
	}
	var tail [1]byte
	if n, err := payload.Read(tail[:]); n != 0 || err != io.EOF {
		return zero, ErrContainer
	}
	if n, err := object.Reader.ReadAt(tail[:], object.Size); n != 0 || err != io.EOF {
		return zero, ErrContainer
	}
	if ctx.Err() != nil || hex.EncodeToString(whole.Sum(nil)) != object.SHA256 {
		return zero, ErrContainer
	}
	facts.HeaderBytes = int(headerSize)
	facts.Size = object.Size
	facts.SHA256 = object.SHA256
	return facts, nil
}
