package systembackupwire

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
)

// StreamEnvelope is an exact, bounded part-local envelope bound to an already
// admitted original request. Parsing proves no AEAD, key or source authority.
type StreamEnvelope struct {
	spec    StreamSpec
	chunks  []StreamChunk
	wrapped WrappedKey
}

type streamEnvelopeJSON struct {
	Entries []struct {
		Chunks  []StreamChunk `json:"chunks"`
		Context struct {
			Installation string `json:"origin_installation_id"`
			Backup       string `json:"backup_public_id"`
			Attempt      string `json:"attempt_no"`
			Phase        string `json:"phase"`
			Part         string `json:"part"`
			Index        string `json:"part_index"`
			Envelope     string `json:"envelope_id"`
			Capture      string `json:"capture_context_hash"`
		} `json:"context"`
		DataAlgorithm  string `json:"data_algorithm"`
		EnvelopeID     string `json:"envelope_id"`
		FramingVersion string `json:"framing_version"`
		KEK            struct {
			Provider string `json:"provider"`
			Identity string `json:"identity_hash"`
			Registry string `json:"registry_version"`
			KeyID    string `json:"provider_key_id"`
			Version  string `json:"provider_version"`
		} `json:"kek"`
		WrapAlgorithm string `json:"wrap_algorithm"`
		WrappedDEK    string `json:"wrapped_dek"`
	} `json:"entries"`
	Version string `json:"schema_version"`
}

func ParseStreamEnvelope(spec StreamSpec, raw []byte) (*StreamEnvelope, error) {
	if _, err := spec.binding(); err != nil || len(raw) == 0 || len(raw) > 32<<20 {
		return nil, ErrBinding
	}
	if !boundedEnvelopeJSON(raw, spec.MaxFrames) {
		return nil, ErrBinding
	}
	var decoded streamEnvelopeJSON
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&decoded) != nil || d.Decode(new(any)) != io.EOF || decoded.Version != EnvelopeVersion || len(decoded.Entries) != 1 {
		return nil, ErrBinding
	}
	e := decoded.Entries[0]
	c, k := e.Context, e.KEK
	request := KeyRequest{Key: KeyBinding{k.Provider, k.Identity, k.Registry, k.KeyID, k.Version}, Context: KeyContext{c.Installation, c.Backup, c.Attempt, c.Phase, c.Part, c.Index, c.Envelope, c.Capture}}
	if request != spec.Request || e.EnvelopeID != c.Envelope || e.DataAlgorithm != "AES-256-GCM" || e.FramingVersion != FramingVersion || len(e.Chunks) == 0 || uint64(len(e.Chunks)) > spec.MaxFrames {
		return nil, ErrBinding
	}
	wrapped, err := base64.RawURLEncoding.Strict().DecodeString(e.WrappedDEK)
	if err != nil || len(wrapped) == 0 || len(wrapped) > 32768 {
		return nil, ErrBinding
	}
	var total int64
	seen := map[string]bool{}
	for i, chunk := range e.Chunks {
		last := i == len(e.Chunks)-1
		if chunk.Index != uint64(i) || chunk.Path != spec.Path || chunk.Final != last || chunk.Final != (chunk.PlaintextLength == 0) || chunk.PlaintextLength > ChunkSize || chunk.CiphertextLength != chunk.PlaintextLength || !digest.MatchString(chunk.SHA256) || len(chunk.Nonce) != 24 || len(chunk.Tag) != 32 || seen[chunk.Nonce] {
			return nil, ErrBinding
		}
		nonce, err := hex.DecodeString(chunk.Nonce)
		if err != nil || hex.EncodeToString(nonce) != chunk.Nonce {
			return nil, ErrBinding
		}
		tag, err := hex.DecodeString(chunk.Tag)
		if err != nil || hex.EncodeToString(tag) != chunk.Tag {
			return nil, ErrBinding
		}
		seen[chunk.Nonce] = true
		total += int64(chunk.PlaintextLength)
		if total > spec.MaxPlaintextBytes {
			return nil, ErrBinding
		}
	}
	key := WrappedKey{Request: request, Algorithm: e.WrapAlgorithm, Ciphertext: wrapped}
	// Reusing the producer's closed encoder rejects duplicate/extra fields,
	// alternative numbers, reordered chunks and noncanonical envelope bytes.
	canonical, err := (StreamSeal{spec: spec, chunks: e.Chunks, sha: "parsed"}).EnvelopeJSON(key)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, ErrBinding
	}
	return &StreamEnvelope{spec: spec, chunks: e.Chunks, wrapped: key}, nil
}

// Enforce cardinality/depth BEFORE json allocates the typed chunks slice.
// A bounded file alone would still permit millions of tiny chunk objects.
func boundedEnvelopeJSON(raw []byte, maxFrames uint64) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tokens := uint64(0)
	var value func(string, int) bool
	value = func(field string, depth int) bool {
		tokens++
		if depth > 8 || tokens > maxFrames*24+128 {
			return false
		}
		token, err := d.Token()
		if err != nil {
			return false
		}
		switch token := token.(type) {
		case string:
			return len(token) <= 65536
		case json.Delim:
			switch token {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					name, ok := key.(string)
					if err != nil || !ok || len(name) > 128 || seen[name] || len(seen) >= 16 {
						return false
					}
					seen[name] = true
					if !value(name, depth+1) {
						return false
					}
				}
				end, err := d.Token()
				return err == nil && end == json.Delim('}')
			case '[':
				limit := maxFrames
				if field == "entries" {
					limit = 1
				} else if field != "chunks" {
					return false
				}
				count := uint64(0)
				for d.More() {
					count++
					if count > limit || !value("", depth+1) {
						return false
					}
				}
				end, err := d.Token()
				return err == nil && end == json.Delim(']')
			default:
				return false
			}
		default:
			return true
		}
	}
	if !value("", 0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}

// StreamVerification is constructible only after all frames AND authenticated
// EOF have been read. It is content verification, never publication authority.
type StreamVerification struct {
	sha              string
	encrypted, plain int64
}

func (v StreamVerification) CiphertextSHA256() string { return v.sha }
func (v StreamVerification) CiphertextBytes() int64   { return v.encrypted }
func (v StreamVerification) PlaintextBytes() int64    { return v.plain }

// A frame can require several underlying reads. Recheck between every read,
// including header/payload/EOF, so an expired grant cannot start another read.
type streamContextReader struct {
	ctx context.Context
	src io.Reader
}

func (r streamContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.src.Read(p)
	if expired := r.ctx.Err(); expired != nil {
		return n, expired
	}
	return n, err
}

func (e *StreamEnvelope) authenticate(ctx context.Context, src io.Reader, key []byte) (StreamVerification, error) {
	return e.authenticateTo(ctx, src, key, io.Discard)
}

func (e *StreamEnvelope) authenticateTo(ctx context.Context, src io.Reader, key []byte, dst io.Writer) (StreamVerification, error) {
	var zero StreamVerification
	if e == nil || ctx == nil || ctx.Err() != nil || src == nil || len(key) != 32 {
		return zero, ErrStreamAuthority
	}
	src = streamContextReader{ctx, src}
	block, err := aes.NewCipher(key)
	if err != nil {
		return zero, ErrBinding
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return zero, ErrBinding
	}
	binding, err := e.spec.binding()
	if err != nil {
		return zero, err
	}
	h := sha256.New()
	var result StreamVerification
	for _, expected := range e.chunks {
		if ctx.Err() != nil {
			return zero, ctx.Err()
		}
		var header [41]byte
		if _, err = io.ReadFull(src, header[:]); err != nil || !bytes.Equal(header[:8], []byte("CMBKGC01")) || binary.BigEndian.Uint32(header[8:12]) != 41 || binary.BigEndian.Uint64(header[12:20]) != expected.Index || binary.BigEndian.Uint32(header[20:24]) != expected.PlaintextLength || binary.BigEndian.Uint32(header[24:28]) != expected.CiphertextLength || header[28] > 1 || (header[28] == 1) != expected.Final || hex.EncodeToString(header[29:41]) != expected.Nonce {
			return zero, ErrStream
		}
		// Allocation is bounded by the independently parsed <=1MiB frame size.
		frame := make([]byte, 41+int(expected.CiphertextLength)+aead.Overhead())
		copy(frame, header[:])
		if _, err = io.ReadFull(src, frame[41:]); err != nil {
			return zero, ErrStream
		}
		sum := sha256.Sum256(frame)
		if hex.EncodeToString(sum[:]) != expected.SHA256 || hex.EncodeToString(frame[len(frame)-16:]) != expected.Tag {
			return zero, ErrStream
		}
		aad, err := ChunkAAD(binding, expected.Index, expected.PlaintextLength, expected.Final)
		if err != nil {
			return zero, err
		}
		plain, err := aead.Open(nil, header[29:41], frame[41:], aad)
		if err != nil {
			return zero, ErrStream
		}
		result.plain += int64(len(plain))
		if result.plain > e.spec.MaxPlaintextBytes {
			clear(plain)
			return zero, ErrStream
		}
		n, writeErr := dst.Write(plain)
		clear(plain)
		if writeErr != nil || n != int(expected.PlaintextLength) {
			return zero, ErrStream
		}
		h.Write(frame)
		result.encrypted += int64(len(frame))
	}
	var extra [1]byte
	if _, err = io.ReadFull(src, extra[:]); err != io.EOF {
		return zero, ErrStream
	}
	if ctx.Err() != nil {
		return zero, ctx.Err()
	}
	result.sha = hex.EncodeToString(h.Sum(nil))
	return result, nil
}

// VerifyWrappedStream invokes only an independently authorized Unwrapper and
// exposes no plaintext/DEK. A provider post-use revocation discards verification.
// Invalid envelope bindings fail before any provider call.
func VerifyWrappedStream(ctx context.Context, spec StreamSpec, envelope []byte, src io.Reader, keys Unwrapper) (StreamVerification, error) {
	return inspectWrappedStream(ctx, spec, envelope, src, keys, nil)
}

// InspectWrappedStream lets a bounded, inert domain reader inspect the exact
// authenticated plaintext stream without exposing a DEK. The reader MUST NOT
// publish/mutate external state: terminal AEAD, ciphertext EOF and provider
// post-use authorization are accepted only after it returns. Early return,
// unread suffix, parser failure or revocation yields NO verification result.
// Both sides of the bounded pipe exit before the original Unwrap use ends.
func InspectWrappedStream(ctx context.Context, spec StreamSpec, envelope []byte, src io.Reader, keys Unwrapper, inspect func(io.Reader) error) (StreamVerification, error) {
	if inspect == nil {
		return StreamVerification{}, ErrStreamAuthority
	}
	return inspectWrappedStream(ctx, spec, envelope, src, keys, inspect)
}

func inspectWrappedStream(ctx context.Context, spec StreamSpec, envelope []byte, src io.Reader, keys Unwrapper, inspect func(io.Reader) error) (StreamVerification, error) {
	var zero StreamVerification
	if ctx == nil || ctx.Err() != nil {
		return zero, ErrStreamAuthority
	}
	parsed, err := ParseStreamEnvelope(spec, envelope)
	if err != nil {
		return zero, err
	}
	if keys == nil {
		return zero, ErrStreamAuthority
	}
	var result StreamVerification
	calls := 0
	err = keys.Unwrap(ctx, spec.Request, parsed.wrapped, func(key []byte) error {
		calls++
		if calls != 1 {
			return ErrStreamAuthority
		}
		var err error
		if inspect == nil {
			result, err = parsed.authenticate(ctx, src, key)
			return err
		}
		reader, writer := io.Pipe()
		done := make(chan error, 1)
		go func() {
			err := inspect(streamContextReader{ctx, reader})
			if err == nil {
				var extra [1]byte
				n, tailErr := reader.Read(extra[:])
				if n != 0 || tailErr != io.EOF {
					err = ErrStream
				}
			}
			reader.CloseWithError(ErrStream)
			done <- err
		}()
		result, err = parsed.authenticateTo(ctx, src, key, writer)
		writer.CloseWithError(err)
		parseErr := <-done
		if err == nil {
			err = parseErr
		}
		return err
	})
	if err != nil || calls != 1 || result.sha == "" {
		return zero, ErrStreamAuthority
	}
	return result, nil
}
