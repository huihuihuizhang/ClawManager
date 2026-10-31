package systembackupwire

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

type streamVerifyUnwrapper struct {
	request     KeyRequest
	key         []byte
	calls       int
	deny, after bool
}

func (u *streamVerifyUnwrapper) Unwrap(ctx context.Context, expected KeyRequest, wrapped WrappedKey, use WithDEK) error {
	u.calls++
	if u.deny || expected != u.request || wrapped.Request != expected {
		return ErrStreamAuthority
	}
	if err := use(u.key); err != nil {
		return err
	}
	if u.after {
		return errors.New("original unwrap authority revoked")
	}
	return ctx.Err()
}

func TestStreamVerifierAuthenticatesPublishedCVector(t *testing.T) {
	raw, err := os.ReadFile("../../../contracts/system-backup/v12/public-c-crypto-v1/envelope-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Key      string `json:"test_dek_hex"`
		Envelope string `json:"envelope_json"`
		Frames   []struct {
			Frame string `json:"frame_hex"`
			Plain string `json:"plaintext_hex"`
		} `json:"frames"`
	}
	if json.Unmarshal(raw, &vector) != nil {
		t.Fatal("invalid independent C vector")
	}
	var env streamEnvelopeJSON
	if json.Unmarshal([]byte(vector.Envelope), &env) != nil || len(env.Entries) != 1 {
		t.Fatal("invalid C envelope")
	}
	e := env.Entries[0]
	c, k := e.Context, e.KEK
	request := KeyRequest{Key: KeyBinding{k.Provider, k.Identity, k.Registry, k.KeyID, k.Version}, Context: KeyContext{c.Installation, c.Backup, c.Attempt, c.Phase, c.Part, c.Index, c.Envelope, c.Capture}}
	spec := StreamSpec{Request: request, Path: "mysql/part-00001.enc", MaxPlaintextBytes: ChunkSize, MaxFrames: 2}
	key, err := hex.DecodeString(vector.Key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	var frames []byte
	plainSize := 0
	for _, f := range vector.Frames {
		b, err := hex.DecodeString(f.Frame)
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, b...)
		p, _ := hex.DecodeString(f.Plain)
		plainSize += len(p)
		clear(p)
	}
	keys := &streamVerifyUnwrapper{request: request, key: key}
	verified, err := VerifyWrappedStream(context.Background(), spec, []byte(vector.Envelope), bytes.NewReader(frames), keys)
	sum := sha256.Sum256(frames)
	if err != nil || keys.calls != 1 || verified.CiphertextSHA256() != hex.EncodeToString(sum[:]) || verified.CiphertextBytes() != int64(len(frames)) || verified.PlaintextBytes() != int64(plainSize) {
		t.Fatal("independent C vector verification failed", err)
	}
}

func TestStreamVerifierRejectsBindingTamperingMissingEOFAndRevocation(t *testing.T) {
	spec := streamFixture()
	key := bytes.Repeat([]byte{9}, 32)
	defer clear(key)
	var encrypted bytes.Buffer
	seal, err := EncryptStream(context.Background(), spec, key, &encrypted, func(w io.Writer) error { _, err := w.Write(bytes.Repeat([]byte("binary\x00"), 200000)); return err })
	if err != nil {
		t.Fatal(err)
	}
	wrapped := WrappedKey{Request: spec.Request, Algorithm: "provider-native", Ciphertext: []byte("opaque-provider-ciphertext")}
	envelope, err := seal.EnvelopeJSON(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"", "wrong-context", "wrong-key", "truncated", "trailing", "bad-tag-with-matching-hash", "missing-final", "duplicate-nonce", "unknown-envelope-field", "denied", "revoked-after-use"} {
		t.Run(fault, func(t *testing.T) {
			expected := spec
			frames := append([]byte(nil), encrypted.Bytes()...)
			env := append([]byte(nil), envelope...)
			keys := &streamVerifyUnwrapper{request: spec.Request, key: append([]byte(nil), key...)}
			chunks := seal.Chunks()
			switch fault {
			case "wrong-context":
				expected.Request.Context.AttemptNo = "2"
			case "wrong-key":
				keys.key[0]++
			case "truncated":
				frames = frames[:len(frames)-1]
			case "trailing":
				frames = append(frames, 1)
			case "bad-tag-with-matching-hash":
				length := 41 + int(chunks[0].CiphertextLength) + 16
				frames[length-1] ^= 1
				sum := sha256.Sum256(frames[:length])
				chunks[0].SHA256 = hex.EncodeToString(sum[:])
				chunks[0].Tag = hex.EncodeToString(frames[length-16 : length])
				env, _ = (StreamSeal{spec: spec, chunks: chunks, sha: "forged"}).EnvelopeJSON(wrapped)
			case "missing-final":
				chunks = chunks[:len(chunks)-1]
				env, _ = (StreamSeal{spec: spec, chunks: chunks, sha: "forged"}).EnvelopeJSON(wrapped)
			case "duplicate-nonce":
				chunks[1].Nonce = chunks[0].Nonce
				env, _ = (StreamSeal{spec: spec, chunks: chunks, sha: "forged"}).EnvelopeJSON(wrapped)
			case "unknown-envelope-field":
				env = []byte(strings.Replace(string(env), `"schema_version":`, `"unexpected":true,"schema_version":`, 1))
			case "denied":
				keys.deny = true
			case "revoked-after-use":
				keys.after = true
			}
			verified, err := VerifyWrappedStream(context.Background(), expected, env, bytes.NewReader(frames), keys)
			if fault == "" {
				if err != nil || verified.CiphertextSHA256() != seal.CiphertextSHA256() {
					t.Fatal(err)
				}
				return
			}
			if err == nil || verified != (StreamVerification{}) {
				t.Fatal("unverified stream escaped", fault, err)
			}
			if (fault == "wrong-context" || fault == "missing-final" || fault == "duplicate-nonce" || fault == "unknown-envelope-field") && keys.calls != 0 {
				t.Fatal("invalid public envelope reached provider")
			}
		})
	}
}

func TestEnvelopeChunkLimitsApplyBeforeTypedAllocation(t *testing.T) {
	for _, raw := range []string{
		`{"entries":[{},{}],"schema_version":"system-backup-envelope.v1"}`,
		`{"entries":[{"chunks":[{},{},{}]}]}`,
		`{"entries":[{"chunks":[],"chunks":[]}]}`,
		`{"entries":[{"chunks":[],"unknown_array":[1]}]}`,
	} {
		if boundedEnvelopeJSON([]byte(raw), 2) {
			t.Fatal("unbounded or duplicate JSON entered typed decoding")
		}
	}
}
