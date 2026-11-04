// Package minionative contains transport/protocol primitives, not authority or
// an installer. Callers must establish their genuine owner before invoking it.
package minionative

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net/http"

	"golang.org/x/crypto/pbkdf2"
)

var ErrNative = errors.New("fixed native transport/protocol unavailable")

// SendOnce uses a fresh, non-pooled HTTP/1 connection. Go's transport cannot
// replay an ambiguous write on a reused connection, follow redirects, or use
// HTTP/2 retry paths here. The original pinned TLS settings remain mandatory.
func SendOnce(client *http.Client, request *http.Request) (*http.Response, error) {
	if client == nil || request == nil || request.URL == nil || request.URL.Scheme != "https" || request.Context().Err() != nil {
		return nil, ErrNative
	}
	base, ok := client.Transport.(*http.Transport)
	if !ok || base.TLSClientConfig == nil || base.TLSClientConfig.InsecureSkipVerify {
		return nil, ErrNative
	}
	t := base.Clone()
	t.Proxy = nil
	t.DisableKeepAlives = true
	t.ForceAttemptHTTP2 = false
	t.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	t.TLSClientConfig = base.TLSClientConfig.Clone()
	t.TLSClientConfig.NextProtos = []string{"http/1.1"}
	c := &http.Client{Transport: t, Timeout: client.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r := request.Clone(request.Context())
	r.Close = true
	r.GetBody = nil
	response, e := c.Do(r)
	if e != nil {
		t.CloseIdleConnections()
	}
	return response, e
}

// EncryptAdminData emits MinIO madmin's supported algorithm 0x02 wire format:
// salt32, PBKDF2-SHA256/8192/AES256-GCM, nonce8, SIO 16KiB records. This is the
// exact existing native format, not the archive envelope or a new cipher.
// It is bounded to native control payloads and never performs network IO.
func EncryptAdminData(password, plain []byte) ([]byte, error) {
	var salt [32]byte
	var nonce [8]byte
	if len(password) < 8 || len(plain) > 64<<10 {
		return nil, ErrNative
	}
	if _, e := rand.Read(salt[:]); e != nil {
		return nil, e
	}
	if _, e := rand.Read(nonce[:]); e != nil {
		return nil, e
	}
	return encryptAdminData(password, plain, salt[:], nonce[:])
}

func encryptAdminData(password, plain, salt, nonce []byte) ([]byte, error) {
	if len(salt) != 32 || len(nonce) != 8 || len(plain) > 64<<10 {
		return nil, ErrNative
	}
	key := pbkdf2.Key(password, salt, 8192, 32, sha256.New)
	defer clear(key)
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	iv := make([]byte, 12)
	copy(iv, nonce)
	// SIO reserves sequence zero to bind associated data, then uses one or
	// more data records, with 0x80 only on the final complete record.
	aad := make([]byte, 1, 17)
	aad = aead.Seal(aad, iv, nil, nil)
	out := append(append(append([]byte(nil), salt...), byte(2)), nonce...)
	seq := uint32(1)
	for len(plain) > 1<<14 {
		binary.LittleEndian.PutUint32(iv[8:], seq)
		out = aead.Seal(out, iv, plain[:1<<14], aad)
		plain = plain[1<<14:]
		seq++
	}
	aad[0] = 0x80
	binary.LittleEndian.PutUint32(iv[8:], seq)
	out = aead.Seal(out, iv, plain, aad)
	return out, nil
}
