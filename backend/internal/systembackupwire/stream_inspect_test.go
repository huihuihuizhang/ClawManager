package systembackupwire

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

func TestStreamInspectionWaitsForFullAuthenticationAndOriginalPostUse(t *testing.T) {
	spec := streamFixture()
	key := bytes.Repeat([]byte{9}, 32)
	defer clear(key)
	plain := bytes.Repeat([]byte("original Skill archive\x00"), 70000)
	var encrypted bytes.Buffer
	seal, err := EncryptStream(context.Background(), spec, key, &encrypted, func(dst io.Writer) error { _, err := dst.Write(plain); return err })
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := seal.EnvelopeJSON(WrappedKey{Request: spec.Request, Algorithm: "provider-native", Ciphertext: []byte("opaque")})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "prefix-only", "parser-error", "bad-final", "ciphertext-tail", "post-use-revoked"} {
		t.Run(mode, func(t *testing.T) {
			raw := bytes.Clone(encrypted.Bytes())
			keys := &streamVerifyUnwrapper{request: spec.Request, key: key, after: mode == "post-use-revoked"}
			if mode == "bad-final" {
				raw[len(raw)-1] ^= 1
			}
			if mode == "ciphertext-tail" {
				raw = append(raw, 1)
			}
			inspected := false
			got, err := InspectWrappedStream(context.Background(), spec, envelope, bytes.NewReader(raw), keys, func(src io.Reader) error {
				inspected = true
				if mode == "prefix-only" {
					var prefix [8]byte
					_, err := io.ReadFull(src, prefix[:])
					return err
				}
				if mode == "parser-error" {
					return errors.New("untrusted parser failure")
				}
				actual, err := io.ReadAll(src)
				if err != nil {
					return err
				}
				if !bytes.Equal(actual, plain) {
					t.Error("changed authenticated plaintext")
				}
				clear(actual)
				return nil
			})
			if !inspected || keys.calls != 1 {
				t.Fatal("inspector borrowed another key or never ran")
			}
			if mode == "valid" {
				if err != nil || got.CiphertextSHA256() != seal.CiphertextSHA256() {
					t.Fatal("valid stream inspection", err)
				}
			} else if err == nil || got.CiphertextSHA256() != "" {
				t.Fatal("inert parse became verification before complete original authorization", mode, err)
			}
		})
	}
}
