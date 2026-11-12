package systembackupexecution

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

type metadataSourceCredential struct {
	Username     string `json:"username,omitempty"`
	Password     []byte `json:"password,omitempty"`
	AccessKey    string `json:"access_key,omitempty"`
	SecretKey    []byte `json:"secret_key,omitempty"`
	SessionToken []byte `json:"session_token,omitempty"`
}

// The original Redis installer emits JCS, while older metadata producers emit
// Go struct order. Accept only these two exact typed encodings. Raw-byte pin
// verification remains the caller's responsibility and is not normalized.
func decodeMetadataSourceCredential(raw []byte, out *metadataSourceCredential) error {
	refused := errors.New("source credential encoding refused")
	if out == nil || len(raw) == 0 || len(raw) > 65536 {
		return refused
	}
	var value metadataSourceCredential
	defer func() {
		clear(value.Password)
		clear(value.SecretKey)
		clear(value.SessionToken)
	}()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF {
		return refused
	}
	ordered, err := json.Marshal(value)
	if err != nil {
		return refused
	}
	defer clear(ordered)
	if !bytes.Equal(raw, ordered) {
		canonical, err := jsoncanonicalizer.Transform(ordered)
		defer clear(canonical)
		if err != nil || !bytes.Equal(raw, canonical) {
			return refused
		}
	}
	*out = value
	// Ownership of the decoded secret buffers transfers only on success.
	value.Password, value.SecretKey, value.SessionToken = nil, nil, nil
	return nil
}
