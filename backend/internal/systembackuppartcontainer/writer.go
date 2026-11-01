package systembackuppartcontainer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"sort"

	w "clawreef/internal/systembackupwire"
)

type Input struct {
	Member     Member
	Ciphertext io.Reader
	Envelope   []byte
}

func checksum(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

type contextReader struct {
	ctx context.Context
	src io.Reader
}

type contextWriter struct {
	ctx context.Context
	dst io.Writer
}

func (w contextWriter) Write(raw []byte) (int, error) {
	if w.ctx.Err() != nil {
		return 0, w.ctx.Err()
	}
	return w.dst.Write(raw)
}

func (r contextReader) Read(dst []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, r.ctx.Err()
	}
	if len(dst) > 64<<10 {
		dst = dst[:64<<10]
	}
	n, err := r.src.Read(dst)
	if r.ctx.Err() != nil {
		return 0, r.ctx.Err()
	}
	return n, err
}

// Write creates actual deterministic container bytes. Sort order is ORIGINAL
// PartIndex, not map/name order. On failure the destination is unpublished
// partial DATA and the caller receives no complete byte facts.
func Write(ctx context.Context, dst io.Writer, scope Scope, sourceInventorySHA string, inputs []Input, checkpoints map[string]string, limit, indexLimit int64) (Facts, error) {
	var zero Facts
	if ctx == nil || ctx.Err() != nil || dst == nil || len(inputs) == 0 || len(inputs) > MaxMembers || limit < 1 || limit > MaxBytes || indexLimit < 1 || indexLimit > MaxIndexBytes {
		return zero, ErrContainer
	}
	ordered := append([]Input(nil), inputs...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Member.Index < ordered[j].Member.Index })
	header := Header{Version: Version, Scope: scope, SourceInventorySHA256: sourceInventorySHA, Members: make([]Member, 0, len(ordered))}
	var offset int64
	for index := range ordered {
		input := &ordered[index]
		member := input.Member
		if len(member.Checkpoint) == 0 || len(member.Checkpoint) > 8192 || len(input.Envelope) > maxEnvelopeBytes {
			return zero, ErrContainer
		}
		member.Checkpoint = bytes.Clone(member.Checkpoint)
		if input.Ciphertext == nil || int64(len(input.Envelope)) != member.EnvelopeBytes || checksum(input.Envelope) != member.EnvelopeSHA256 {
			return zero, ErrContainer
		}
		if _, err := w.ParseStreamEnvelope(member.Stream, input.Envelope); err != nil {
			return zero, ErrContainer
		}
		if member.CipherBytes < 1 || member.CipherBytes > limit-offset {
			return zero, ErrContainer
		}
		member.CipherOffset = offset
		offset += member.CipherBytes
		if member.EnvelopeBytes < 1 || member.EnvelopeBytes > limit-offset {
			return zero, ErrContainer
		}
		member.EnvelopeOffset = offset
		offset += member.EnvelopeBytes
		header.Members = append(header.Members, member)
	}
	facts, err := validateHeader(header, scope, checkpoints, limit)
	if err != nil {
		return zero, err
	}
	plan, err := planHeader(header, indexLimit)
	if err != nil || int64(prefixBytes)+plan.Size > limit-facts.Size {
		return zero, ErrContainer
	}
	var prefix [prefixBytes]byte
	copy(prefix[:8], magic[:])
	binary.BigEndian.PutUint32(prefix[8:], uint32(plan.Size))
	whole := sha256.New()
	output := io.MultiWriter(dst, whole)
	if _, err = io.Copy(output, contextReader{ctx: ctx, src: bytes.NewReader(prefix[:])}); err != nil {
		return zero, ErrContainer
	}
	if err = writeHeader(contextWriter{ctx: ctx, dst: output}, header, plan); err != nil {
		return zero, ErrContainer
	}
	for index, input := range ordered {
		member := header.Members[index]
		memberHash := sha256.New()
		reader := contextReader{ctx: ctx, src: input.Ciphertext}
		n, err := io.CopyN(io.MultiWriter(output, memberHash), reader, member.CipherBytes)
		if err != nil || n != member.CipherBytes || hex.EncodeToString(memberHash.Sum(nil)) != member.CipherSHA256 {
			return zero, ErrContainer
		}
		var tail [1]byte
		if n, err := reader.Read(tail[:]); n != 0 || err != io.EOF {
			return zero, ErrContainer
		}
		envelope := bytes.Clone(input.Envelope)
		if int64(len(envelope)) != member.EnvelopeBytes || checksum(envelope) != member.EnvelopeSHA256 {
			return zero, ErrContainer
		}
		if _, err = w.ParseStreamEnvelope(member.Stream, envelope); err != nil {
			return zero, ErrContainer
		}
		if _, err = io.Copy(output, contextReader{ctx: ctx, src: bytes.NewReader(envelope)}); err != nil {
			return zero, ErrContainer
		}
	}
	if ctx.Err() != nil {
		return zero, ErrContainer
	}
	facts.HeaderBytes = int(plan.Size)
	facts.Size += int64(prefixBytes) + plan.Size
	facts.SHA256 = hex.EncodeToString(whole.Sum(nil))
	for index := range facts.Locations {
		facts.Locations[index].CipherOffset += int64(prefixBytes) + plan.Size
		facts.Locations[index].EnvelopeOffset += int64(prefixBytes) + plan.Size
	}
	return facts, nil
}
