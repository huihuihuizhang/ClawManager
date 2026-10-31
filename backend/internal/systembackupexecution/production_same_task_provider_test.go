package systembackupexecution

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// This bounded LOCAL Transit protocol model keeps its wrapping key private to
// the provider. Original worker Generate and independent controller Unwrap use
// their real TLS clients, separate JWT roles and full original Transit context.
// It supplies no CaptureKeyJob/Unwrapper replacement or deployment assertion.
type dOriginalProvider struct {
	mu                         sync.Mutex
	wrapping                   cipher.AEAD
	controller                 map[string]string
	workers                    map[string]map[string]string
	tokens                     map[string]dOriginalProviderToken
	contexts                   map[string]bool
	generated                  map[string]bool
	workerJWTFile              string
	generateCalls, unwrapCalls int
	refuseGenerate             bool
	deniedGenerate             int
}

type dOriginalProviderToken struct {
	generate bool
	until    time.Time
	context  string
}

func newDOriginalProvider(namespace, podUID, serviceAccountUID string) *dOriginalProvider {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		panic(err)
	}
	wrapping, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return &dOriginalProvider{wrapping: wrapping, controller: map[string]string{"namespace": namespace, "pod_uid": podUID, "service_account_uid": serviceAccountUID}, workers: map[string]map[string]string{}, tokens: map[string]dOriginalProviderToken{}, contexts: map[string]bool{}, generated: map[string]bool{}}
}

func (p *dOriginalProvider) ServeHTTP(out http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	deny := func() { out.WriteHeader(http.StatusForbidden) }
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
		deny()
		return
	}
	var input map[string]json.RawMessage
	decoder := json.NewDecoder(io.LimitReader(r.Body, 65537))
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		deny()
		return
	}
	str := func(name string) string { var value string; _ = json.Unmarshal(input[name], &value); return value }
	if strings.HasPrefix(r.URL.Path, "/v1/auth/") {
		if len(input) != 2 {
			deny()
			return
		}
		generate := r.URL.Path == "/v1/auth/capture-jwt/login"
		role, policy := "controller-unwrap-role", "controller-unwrap-policy"
		identity := p.controller
		if generate {
			role, policy = "capture-generate-role", "capture-generate-policy"
			identity = p.workers[str("jwt")]
		} else if r.URL.Path != "/v1/auth/controller-jwt/login" || str("jwt") != "explicit-local-original-verifier-projected-jwt" {
			deny()
			return
		}
		if str("role") != role || identity == nil {
			deny()
			return
		}
		var random [24]byte
		if _, err := rand.Read(random[:]); err != nil {
			deny()
			return
		}
		token := base64.RawURLEncoding.EncodeToString(random[:])
		p.tokens[token] = dOriginalProviderToken{generate: generate, until: time.Now().Add(10 * time.Second), context: identity["context"]}
		metadata := map[string]string{"role": role, "namespace": identity["namespace"], "pod_uid": identity["pod_uid"], "service_account_uid": identity["service_account_uid"]}
		_ = json.NewEncoder(out).Encode(map[string]any{"auth": map[string]any{"client_token": token, "token_type": "batch", "renewable": false, "lease_duration": 10, "policies": []string{policy}, "metadata": metadata}})
		return
	}
	token, ok := p.tokens[r.Header.Get("X-Vault-Token")]
	context := str("context")
	if !ok || !time.Now().Before(token.until) || !p.contexts[context] || (token.generate && token.context != context) {
		deny()
		return
	}
	if token.generate && r.URL.Path == "/v1/transit/datakey/plaintext/original-key" {
		if len(input) != 3 || str("bits") != "256" || str("key_version") != "1" || p.generated[context] {
			deny()
			return
		}
		if p.refuseGenerate {
			p.deniedGenerate++
			deny()
			return
		}
		key := make([]byte, 32)
		defer clear(key)
		nonce := make([]byte, p.wrapping.NonceSize())
		if _, err := rand.Read(key); err != nil {
			deny()
			return
		}
		if _, err := rand.Read(nonce); err != nil {
			deny()
			return
		}
		wrapped := p.wrapping.Seal(nonce, nonce, key, []byte(context))
		p.generated[context] = true
		p.generateCalls++
		_ = json.NewEncoder(out).Encode(map[string]any{"data": map[string]any{"plaintext": key, "ciphertext": "vault:v1:" + base64.StdEncoding.EncodeToString(wrapped), "key_version": 1}})
		return
	}
	if !token.generate && r.URL.Path == "/v1/transit/decrypt/original-key" && len(input) == 2 && p.generated[context] {
		encoded := str("ciphertext")
		if !strings.HasPrefix(encoded, "vault:v1:") {
			deny()
			return
		}
		wrapped, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(encoded, "vault:v1:"))
		if err != nil || len(wrapped) != 60 {
			deny()
			return
		}
		key, err := p.wrapping.Open(nil, wrapped[:p.wrapping.NonceSize()], wrapped[p.wrapping.NonceSize():], []byte(context))
		defer clear(key)
		if err != nil || len(key) != 32 {
			deny()
			return
		}
		p.unwrapCalls++
		_ = json.NewEncoder(out).Encode(map[string]any{"data": map[string]any{"plaintext": key}})
		return
	}
	deny()
}
