package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
)

var magic = []byte("SBEV0001")

type envelope struct {
	Schema   string   `json:"schema_version"`
	Identity Identity `json:"identity"`
	Key      KeyRef   `json:"key"`
	Wrapped  string   `json:"wrapped_dek_base64"`
}

func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// canonical is restricted JCS: only closed ASCII names/values and bounded
// integers from the types in this package. It is not a general JCS API.
func canonical(v any) []byte {
	raw, _ := json.Marshal(v)
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value any
	if d.Decode(&value) != nil {
		return nil
	}
	var out bytes.Buffer
	e := json.NewEncoder(&out)
	e.SetEscapeHTML(false)
	if e.Encode(value) != nil {
		return nil
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n"))
}
func aad(m Manifest, c Chunk) []byte {
	return canonical(map[string]any{"schema_version": Framing, "identity": m.Identity, "envelope_hash": m.EnvelopeHash, "chunk_index": c.Index, "plaintext_offset": c.PlainOffset, "plaintext_length": c.PlainLength})
}

// Prepared can only be created after both input passes, framing and all hashes
// succeed. A failed Prepare may leave CIPHERTEXT at dst; caller must discard it.
type Prepared struct{ manifest Manifest }

func (p Prepared) Manifest() Manifest {
	m := p.manifest
	m.Chunks = append([]Chunk(nil), m.Chunks...)
	return m
}

// Prepare uses a bounded plaintext buffer and writes only envelope/ciphertext.
// dst must be task-owned durable encrypted staging, never the remote provider.
// PersistPending must commit this manifest before any conditional remote write.
func Prepare(ctx context.Context, i Identity, key KeyRef, source Source, redactor Redactor, keys Keys, dst io.Writer) (Prepared, error) {
	if !i.valid() {
		if i.ContentSize > MaxContent {
			return Prepared{}, ErrCapacity
		}
		return Prepared{}, ErrInvalid
	}
	return prepareExternal(ctx, i, key, source, redactor, keys, dst)
}

func prepareExternal(ctx context.Context, i Identity, key KeyRef, source Source, redactor Redactor, keys Keys, dst io.Writer) (Prepared, error) {
	fail := func(e error) (Prepared, error) { return Prepared{}, e }
	if i.ContentSize > MaxContent {
		return fail(ErrCapacity)
	}
	if ctx == nil || !i.validExternal() || !key.valid() || source == nil || nilSystemAdapter(redactor) || nilSystemAdapter(keys) || nilSystemAdapter(dst) {
		return fail(ErrInvalid)
	}
	r, err := openPrepareSource(ctx, source)
	if err != nil {
		return fail(ErrUnavailable)
	}
	h := sha256.New()
	count := &countReader{r: io.LimitReader(r, i.ContentSize+1)}
	err = redactor.Validate(ctx, i, io.TeeReader(count, h))
	closeErr := r.Close()
	if ctx.Err() != nil {
		return fail(ErrUnavailable)
	}
	if err != nil {
		return fail(ErrRedaction)
	}
	if closeErr != nil || count.n != i.ContentSize || hex.EncodeToString(h.Sum(nil)) != i.ContentHash {
		return fail(ErrIntegrity)
	}
	dek := make([]byte, 32)
	defer wipe(dek)
	if _, err = rand.Read(dek); err != nil {
		return fail(ErrKey)
	}
	// Keep the AES key private. Wrap borrows a read-only copy for this call;
	// erase it immediately and again on return if an adapter retains it.
	wrapDEK := append([]byte(nil), dek...)
	defer wipe(wrapDEK)
	wrapped, err := keys.Wrap(ctx, key, wrapDEK)
	unchanged := bytes.Equal(wrapDEK, dek)
	wipe(wrapDEK)
	if ctx.Err() != nil {
		return fail(ErrUnavailable)
	}
	if err != nil || !unchanged || len(wrapped) == 0 || len(wrapped) > 4096 {
		return fail(ErrKey)
	}
	block, _ := aes.NewCipher(dek)
	gcm, _ := cipher.NewGCM(block)
	header := canonical(envelope{Framing, i, key, base64.StdEncoding.EncodeToString(wrapped)})
	if len(header) > MaxHeader {
		return fail(ErrCapacity)
	}
	m := Manifest{Identity: i, Key: key, EnvelopeHash: hash(header), HeaderSize: int64(12 + len(header))}
	prefix := make([]byte, 12)
	copy(prefix, magic)
	binary.BigEndian.PutUint32(prefix[8:], uint32(len(header)))
	objectHash := sha256.New()
	writer := io.MultiWriter(prepareWriter{ctx, dst}, objectHash)
	if err = writeAll(writer, prefix); err != nil {
		return fail(ErrUnavailable)
	}
	if err = writeAll(writer, header); err != nil {
		return fail(ErrUnavailable)
	}
	r, err = openPrepareSource(ctx, source)
	if err != nil {
		return fail(ErrUnavailable)
	}
	defer r.Close()
	plainHash := sha256.New()
	buffer := make([]byte, ChunkSize)
	defer wipe(buffer)
	noncePrefix := make([]byte, 4)
	if _, err = rand.Read(noncePrefix); err != nil {
		return fail(ErrKey)
	}
	var offset int64
	frameOffset := m.HeaderSize
	for offset < i.ContentSize {
		if ctx.Err() != nil {
			return fail(ErrUnavailable)
		}
		length := min(ChunkSize, i.ContentSize-offset)
		b := buffer[:length]
		_, err = io.ReadFull(r, b)
		if ctx.Err() != nil {
			return fail(ErrUnavailable)
		}
		if err != nil {
			return fail(ErrIntegrity)
		}
		plainHash.Write(b)
		c := Chunk{EvidenceID: i.ID, Index: int64(len(m.Chunks)), PlainOffset: offset, PlainLength: length, PlainHash: hash(b), FrameOffset: frameOffset, FrameLength: length + 28}
		nonce := make([]byte, 12)
		copy(nonce, noncePrefix)
		binary.BigEndian.PutUint64(nonce[4:], uint64(c.Index))
		sealed := gcm.Seal(nil, nonce, b, aad(m, c))
		frame := append(append([]byte(nil), nonce...), sealed...)
		c.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
		c.Tag = base64.RawURLEncoding.EncodeToString(sealed[len(sealed)-16:])
		c.CipherHash = hash(frame)
		if err = writeAll(writer, frame); err != nil {
			return fail(ErrUnavailable)
		}
		m.Chunks = append(m.Chunks, c)
		offset += length
		frameOffset += c.FrameLength
	}
	var extra [1]byte
	defer wipe(extra[:])
	n, endErr := io.ReadFull(r, extra[:])
	if ctx.Err() != nil {
		return fail(ErrUnavailable)
	}
	if n != 0 || endErr != io.EOF || hex.EncodeToString(plainHash.Sum(nil)) != i.ContentHash {
		return fail(ErrIntegrity)
	}
	// Close can report a delayed staging failure. Do not publish a Prepared
	// until both source passes have completed and closed successfully.
	closeErr = r.Close()
	if ctx.Err() != nil {
		return fail(ErrUnavailable)
	}
	if closeErr != nil {
		return fail(ErrIntegrity)
	}
	m.ObjectSize = frameOffset
	m.ObjectHash = hex.EncodeToString(objectHash.Sum(nil))
	m.ChunkRoot = hash(canonical(m.Chunks))
	if validateManifest(m) != nil {
		return fail(ErrIntegrity)
	}
	if ctx.Err() != nil {
		return fail(ErrUnavailable)
	}
	return Prepared{m}, nil
}

// Sources and staging writers are trusted synchronous adapters. Context checks
// stop subsequent I/O even when an adapter ignores cancellation during a call;
// they cannot interrupt an adapter that blocks without returning.
type prepareReader struct {
	ctx    context.Context
	source io.ReadCloser
	closed bool
}

func openPrepareSource(ctx context.Context, source Source) (*prepareReader, error) {
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	r, err := source()
	if err != nil || nilSystemAdapter(r) || ctx.Err() != nil {
		if !nilSystemAdapter(r) {
			_ = r.Close()
		}
		return nil, ErrUnavailable
	}
	return &prepareReader{ctx: ctx, source: r}, nil
}

func (r *prepareReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.source.Read(b)
	if canceled := r.ctx.Err(); canceled != nil {
		return n, canceled
	}
	return n, err
}

func (r *prepareReader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	return r.source.Close()
}

type prepareWriter struct {
	ctx context.Context
	dst io.Writer
}

func (w prepareWriter) Write(b []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := w.dst.Write(b)
	if canceled := w.ctx.Err(); canceled != nil {
		return n, canceled
	}
	return n, err
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(b []byte) (int, error) { n, e := c.r.Read(b); c.n += int64(n); return n, e }
func writeAll(w io.Writer, b []byte) error {
	n, e := w.Write(b)
	if e == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return e
}

func validateManifest(m Manifest) error {
	if !m.Identity.validExternal() || !m.Key.valid() || !digestPattern.MatchString(m.EnvelopeHash) || !digestPattern.MatchString(m.ObjectHash) || m.HeaderSize < 13 || m.HeaderSize > 12+MaxHeader || len(m.Chunks) < 1 || len(m.Chunks) > 1024 || int64(len(m.Chunks)) != (m.Identity.ContentSize+ChunkSize-1)/ChunkSize || hash(canonical(m.Chunks)) != m.ChunkRoot {
		return ErrIntegrity
	}
	var plain int64
	frame := m.HeaderSize
	nonces := map[string]bool{}
	for index, c := range m.Chunks {
		nonce, e := base64.RawURLEncoding.Strict().DecodeString(c.Nonce)
		tag, t := base64.RawURLEncoding.Strict().DecodeString(c.Tag)
		if c.EvidenceID != m.Identity.ID || c.Index != int64(index) || c.PlainOffset != plain || c.PlainLength != min(ChunkSize, m.Identity.ContentSize-plain) || c.FrameOffset != frame || c.FrameLength != c.PlainLength+28 || !digestPattern.MatchString(c.PlainHash) || !digestPattern.MatchString(c.CipherHash) || e != nil || t != nil || len(nonce) != 12 || len(tag) != 16 || base64.RawURLEncoding.EncodeToString(nonce) != c.Nonce || base64.RawURLEncoding.EncodeToString(tag) != c.Tag || nonces[c.Nonce] {
			return ErrIntegrity
		}
		nonces[c.Nonce] = true
		plain += c.PlainLength
		frame += c.FrameLength
	}
	if plain != m.Identity.ContentSize || frame != m.ObjectSize {
		return ErrIntegrity
	}
	return nil
}

// Freeze the bounded chunk index before provider/key callbacks can mutate a
// caller-owned slice. Callers must not concurrently write it during this copy.
func snapshotReadManifest(m Manifest) (Manifest, error) {
	if len(m.Chunks) < 1 || len(m.Chunks) > 1024 {
		return Manifest{}, ErrIntegrity
	}
	m.Chunks = append([]Chunk(nil), m.Chunks...)
	if validateManifest(m) != nil {
		return Manifest{}, ErrIntegrity
	}
	return m, nil
}

// ObjectReader is scoped to one registered immutable version. Range must return
// exactly length bytes or fail; Stat must establish provider SHA-256 (not ETag).
type ObjectReader interface {
	Range(context.Context, Ref, int64, int64) (io.ReadCloser, error)
}

func readExact(ctx context.Context, store ObjectReader, ref Ref, offset, length int64) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || nilSystemAdapter(store) {
		return nil, ErrUnavailable
	}
	r, e := store.Range(ctx, ref, offset, length)
	if e != nil || nilSystemAdapter(r) {
		if !nilSystemAdapter(r) {
			_ = r.Close()
		}
		return nil, ErrUnavailable
	}
	b, e := io.ReadAll(io.LimitReader(r, length+1))
	closeErr := r.Close()
	if e != nil || closeErr != nil || ctx.Err() != nil {
		wipe(b)
		return nil, ErrUnavailable
	}
	if int64(len(b)) != length {
		wipe(b)
		return nil, ErrIntegrity
	}
	return b, nil
}

func openEvidenceEnvelope(ctx context.Context, m Manifest, ref Ref, store ObjectReader, keys Keys) (cipher.AEAD, []byte, error) {
	header, e := readExact(ctx, store, ref, 0, m.HeaderSize)
	if e != nil {
		return nil, nil, e
	}
	if !bytes.Equal(header[:8], magic) || int64(binary.BigEndian.Uint32(header[8:12])) != m.HeaderSize-12 || hash(header[12:]) != m.EnvelopeHash {
		return nil, nil, ErrIntegrity
	}
	var env envelope
	if json.Unmarshal(header[12:], &env) != nil || !bytes.Equal(canonical(env), header[12:]) || env.Schema != Framing || env.Identity != m.Identity || env.Key != m.Key {
		return nil, nil, ErrIntegrity
	}
	wrapped, e := base64.StdEncoding.Strict().DecodeString(env.Wrapped)
	if e != nil || len(wrapped) < 1 || len(wrapped) > 4096 || base64.StdEncoding.EncodeToString(wrapped) != env.Wrapped {
		return nil, nil, ErrIntegrity
	}
	dek, e := keys.Unwrap(ctx, m.Key, wrapped)
	defer wipe(dek)
	if e != nil || len(dek) != 32 {
		return nil, nil, ErrKey
	}
	if ctx.Err() != nil {
		return nil, nil, ErrUnavailable
	}
	block, _ := aes.NewCipher(dek)
	gcm, _ := cipher.NewGCM(block)
	return gcm, header, nil
}

// OpenRange authenticates ALL selected frames before returning any plaintext.
// The complete chunk index/root is checked on every range, not client supplied.
func OpenRange(ctx context.Context, m Manifest, ref Ref, store ObjectReader, keys Keys, start, end int64) ([]byte, error) {
	var err error
	m, err = snapshotReadManifest(m)
	if err != nil || !ref.valid(true) {
		return nil, ErrIntegrity
	}
	if ctx == nil || ctx.Err() != nil || nilSystemAdapter(store) || nilSystemAdapter(keys) {
		return nil, ErrUnavailable
	}
	if start < 0 || end < start || end >= m.Identity.ContentSize || end-start+1 > MaxResponse {
		return nil, ErrRange
	}
	gcm, header, e := openEvidenceEnvelope(ctx, m, ref, store, keys)
	if e != nil {
		return nil, e
	}
	result := make([]byte, 0, end-start+1)
	success := false
	defer func() {
		if !success {
			wipe(result)
		}
	}()
	full := start == 0 && end == m.Identity.ContentSize-1
	objectHash := sha256.New()
	if full {
		objectHash.Write(header)
	}
	for index := start / ChunkSize; index <= end/ChunkSize; index++ {
		c := m.Chunks[index]
		frame, e := readExact(ctx, store, ref, c.FrameOffset, c.FrameLength)
		if e != nil {
			return nil, e
		}
		if hash(frame) != c.CipherHash || base64.RawURLEncoding.EncodeToString(frame[:12]) != c.Nonce || base64.RawURLEncoding.EncodeToString(frame[len(frame)-16:]) != c.Tag {
			return nil, ErrIntegrity
		}
		if full {
			objectHash.Write(frame)
		}
		plain, e := gcm.Open(nil, frame[:12], frame[12:], aad(m, c))
		if e != nil {
			return nil, ErrIntegrity
		}
		if int64(len(plain)) != c.PlainLength || hash(plain) != c.PlainHash {
			wipe(plain)
			return nil, ErrIntegrity
		}
		lo := max(start-c.PlainOffset, 0)
		hi := min(end-c.PlainOffset+1, c.PlainLength)
		result = append(result, plain[lo:hi]...)
		wipe(plain)
	}
	if full && (hash(result) != m.Identity.ContentHash || hex.EncodeToString(objectHash.Sum(nil)) != m.ObjectHash) {
		return nil, ErrIntegrity
	}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	success = true
	return result, nil
}
