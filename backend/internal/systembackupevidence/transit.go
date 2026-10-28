package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type TransitOperation string

const (
	TransitWrap   TransitOperation = "evidence_dek_wrap"
	TransitUnwrap TransitOperation = "evidence_dek_unwrap"
)

// TransitCredential is obtained from the trusted live credential resolver,
// never from an Admin request. Secret is a fresh owned copy erased after use.
// The resolver must enforce revocation, task scope and separate wrap/unwrap ACLs.
type TransitCredential struct {
	Key          KeyRef
	Installation string
	Operation    TransitOperation
	Secret       []byte
	ExpiresAt    time.Time
}

type TransitCredentials interface {
	Resolve(context.Context, KeyRef, TransitOperation) (TransitCredential, error)
}

// TransitConfig is an immutable, admission-validated mapping of a registered
// evidence KEK ref to a pre-existing, dedicated aes256-gcm96 derived Transit
// key. It is not a claim that the remote key or its ACL has been verified.
// Tokens need update only; no create/upsert, key export or key management ACL.
type TransitConfig struct {
	Endpoint, Installation, KeyName string
	Key                             KeyRef
	KeyVersion                      uint32
	CAPEM                           []byte
	CASHA256                        string
}

type TransitKeys struct {
	client                                         *http.Client
	credentials                                    TransitCredentials
	endpoint, installation, keyName, contextBase64 string
	key                                            KeyRef
	keyVersion                                     uint32
}

// EvidenceTransitContext is the exact base64 context to pin in provider ACLs.
// It separates evidence from capture/signing and binds installation/ref/version.
func EvidenceTransitContext(installation string, key KeyRef) (string, error) {
	if !installationPattern.MatchString(installation) || !key.valid() {
		return "", ErrKey
	}
	return base64.StdEncoding.EncodeToString(canonical(map[string]any{
		"purpose": "system-backup-evidence-dek.v1", "installation_id": installation, "key": key,
	})), nil
}

func NewTransitKeys(c TransitConfig, credentials TransitCredentials) (*TransitKeys, error) {
	u, e := url.Parse(c.Endpoint)
	ctx, ce := EvidenceTransitContext(c.Installation, c.Key)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.Opaque != "" ||
		strings.ContainsAny(c.Endpoint, "?#\r\n") || ce != nil || credentials == nil || c.KeyVersion == 0 ||
		len(c.KeyName) < 1 || len(c.KeyName) > 128 || strings.Trim(c.KeyName, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" ||
		len(c.CAPEM) > 65536 || !digestPattern.MatchString(c.CASHA256) || hash(c.CAPEM) != c.CASHA256 {
		return nil, ErrKey
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.CAPEM) {
		return nil, ErrKey
	}
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		MaxIdleConnsPerHost: 4, MaxResponseHeaderBytes: 16384, DisableCompression: true,
	}
	// No environment proxy, redirect or injected caller-controlled HTTP client.
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &TransitKeys{client: client, credentials: credentials, endpoint: c.Endpoint,
		installation: c.Installation, keyName: c.KeyName, key: c.Key, keyVersion: c.KeyVersion, contextBase64: ctx}, nil
}

func (k *TransitKeys) Close() {
	if k != nil && k.client != nil {
		k.client.CloseIdleConnections()
	}
}

func (k *TransitKeys) Wrap(ctx context.Context, key KeyRef, dek []byte) ([]byte, error) {
	if k == nil || key != k.key || len(dek) != 32 {
		return nil, ErrKey
	}
	body, e := json.Marshal(struct {
		Plaintext []byte `json:"plaintext"`
		Context   string `json:"context"`
		Version   uint32 `json:"key_version"`
	}{dek, k.contextBase64, k.keyVersion})
	if e != nil {
		return nil, ErrKey
	}
	defer wipe(body)
	data, e := k.request(ctx, TransitWrap, body)
	if e != nil {
		return nil, ErrKey
	}
	defer wipeTransitFields(data)
	if len(data) < 1 || len(data) > 2 || len(data["ciphertext"]) == 0 {
		return nil, ErrKey
	}
	for name := range data {
		if name != "ciphertext" && name != "key_version" {
			return nil, ErrKey
		}
	}
	if version, ok := data["key_version"]; ok {
		var got uint32
		if json.Unmarshal(version, &got) != nil || got != k.keyVersion {
			return nil, ErrKey
		}
	}
	var wrapped string
	if json.Unmarshal(data["ciphertext"], &wrapped) != nil || !k.validCiphertext([]byte(wrapped)) {
		return nil, ErrKey
	}
	return []byte(wrapped), nil
}

func (k *TransitKeys) Unwrap(ctx context.Context, key KeyRef, wrapped []byte) ([]byte, error) {
	if k == nil || key != k.key || !k.validCiphertext(wrapped) {
		return nil, ErrKey
	}
	body, e := json.Marshal(struct {
		Ciphertext string `json:"ciphertext"`
		Context    string `json:"context"`
	}{string(wrapped), k.contextBase64})
	if e != nil {
		return nil, ErrKey
	}
	defer wipe(body)
	data, e := k.request(ctx, TransitUnwrap, body)
	if e != nil {
		return nil, ErrKey
	}
	defer wipeTransitFields(data)
	if len(data) != 1 || len(data["plaintext"]) == 0 {
		return nil, ErrKey
	}
	var dek []byte
	if json.Unmarshal(data["plaintext"], &dek) != nil || len(dek) != 32 {
		wipe(dek)
		return nil, ErrKey
	}
	encoded, _ := json.Marshal(dek)
	defer wipe(encoded)
	if !bytes.Equal(encoded, bytes.TrimSpace(data["plaintext"])) {
		wipe(dek)
		return nil, ErrKey
	}
	return dek, nil
}

func (k *TransitKeys) validCiphertext(wrapped []byte) bool {
	prefix := "vault:v" + strconv.FormatUint(uint64(k.keyVersion), 10) + ":"
	if len(wrapped) != len(prefix)+80 || !bytes.HasPrefix(wrapped, []byte(prefix)) {
		return false
	}
	encoded := wrapped[len(prefix):]
	raw := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, e := base64.StdEncoding.Strict().Decode(raw, encoded)
	defer wipe(raw)
	// aes256-gcm96 wraps one 32-byte DEK: 12-byte nonce + 32 + 16 tag.
	return e == nil && n == 60 && base64.StdEncoding.EncodeToString(raw[:n]) == string(encoded)
}

func (k *TransitKeys) request(ctx context.Context, operation TransitOperation, body []byte) (map[string]json.RawMessage, error) {
	if k.client == nil || k.credentials == nil || ctx.Err() != nil {
		return nil, ErrKey
	}
	grant, e := k.credentials.Resolve(ctx, k.key, operation)
	defer wipe(grant.Secret)
	if e != nil || grant.Key != k.key || grant.Installation != k.installation || grant.Operation != operation ||
		len(grant.Secret) < 16 || len(grant.Secret) > 4096 || !time.Now().Before(grant.ExpiresAt) {
		return nil, ErrKey
	}
	for _, b := range grant.Secret {
		if b < 33 || b > 126 {
			return nil, ErrKey
		}
	}
	ctx, cancel := context.WithDeadline(ctx, grant.ExpiresAt)
	defer cancel()
	action := "encrypt"
	if operation == TransitUnwrap {
		action = "decrypt"
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, k.endpoint+"/v1/transit/"+action+"/"+k.keyName, bytes.NewReader(body))
	if e != nil {
		return nil, ErrKey
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", string(grant.Secret))
	defer req.Header.Del("X-Vault-Token")
	res, e := k.client.Do(req)
	if e != nil {
		return nil, ErrKey
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Encoding") != "" {
		return nil, ErrKey
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, 65537))
	defer wipe(raw)
	if e != nil || len(raw) > 65536 || ctx.Err() != nil || !time.Now().Before(grant.ExpiresAt) {
		return nil, ErrKey
	}
	root, e := transitObject(raw)
	if e != nil {
		return nil, ErrKey
	}
	defer wipeTransitFields(root)
	if errors, ok := root["errors"]; ok && !bytes.Equal(bytes.TrimSpace(errors), []byte("null")) && !bytes.Equal(bytes.TrimSpace(errors), []byte("[]")) {
		return nil, ErrKey
	}
	if wrapped, ok := root["wrap_info"]; ok && !bytes.Equal(bytes.TrimSpace(wrapped), []byte("null")) {
		return nil, ErrKey
	}
	return transitObject(root["data"])
}

// Parse only one object; duplicate fields and trailing JSON are ambiguous and
// rejected. Provider metadata is ignored, never reflected or logged.
func transitObject(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, e := d.Token()
	if e != nil || token != json.Delim('{') {
		return nil, ErrKey
	}
	fields := map[string]json.RawMessage{}
	ok := false
	defer func() {
		if !ok {
			wipeTransitFields(fields)
		}
	}()
	for d.More() {
		token, e := d.Token()
		name, valid := token.(string)
		if e != nil || !valid || len(fields) >= 32 {
			return nil, ErrKey
		}
		if _, exists := fields[name]; exists {
			return nil, ErrKey
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			wipe(value)
			return nil, ErrKey
		}
		fields[name] = value
	}
	if token, e = d.Token(); e != nil || token != json.Delim('}') {
		return nil, ErrKey
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrKey
	}
	ok = true
	return fields, nil
}

func wipeTransitFields(fields map[string]json.RawMessage) {
	for _, value := range fields {
		wipe(value)
	}
}
