package systembackupsecurity

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func configHTTPToken(t *testing.T, actor RegistrationActor) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": actor.UserID, "token_type": "access", "iat": actor.SessionIssuedAt.Unix(), "exp": actor.SessionExpiresAt.Unix()})
	signed, err := token.SignedString([]byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

type configHTTPCountingWriter struct {
	service             ConfigMutationService
	state               *mutationTestState
	calls, observations int
}

func (s *configHTTPCountingWriter) Mutate(ctx context.Context, a RegistrationActor, e, k, id string, raw []byte, p *Proof) (ConfigMutationResult, error) {
	s.calls++
	out, err := s.service.Mutate(ctx, a, e, k, id, raw, p)
	if errors.Is(err, ErrConfigCommitUnknown) {
		s.state.commitUnknown = false
	}
	return out, err
}
func (s *configHTTPCountingWriter) ObserveCommitted(ctx context.Context, a RegistrationActor, e, k, id string, raw []byte) (ConfigMutationResult, error) {
	s.observations++
	return s.service.ObserveCommitted(ctx, a, e, k, id, raw)
}
func configHTTPCall(t *testing.T, client *http.Client, url, method, token, key string, raw []byte, proof string) (int, []byte, http.Header) {
	t.Helper()
	r, err := http.NewRequest(method, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Idempotency-Key", key)
	if proof != "" {
		r.Header.Set(StrongAuthProofHeader, proof)
	}
	resp, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body, resp.Header
}
func TestConfigMutationHTTPRealTLSJWTWriterAndOriginalReplay(t *testing.T) {
	svc, actor, raw, s, _, _ := operationStoreFixture(t)
	counting := &configHTTPCountingWriter{service: svc, state: s.base}
	h, err := NewConfigMutationHTTP(svc.InstallationID, JWTRegistrationAuthenticator{Secret: []byte(strings.Repeat("s", 32))}, counting)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	defer server.Close()
	token := configHTTPToken(t, actor)
	authenticated, err := (JWTRegistrationAuthenticator{Secret: []byte(strings.Repeat("s", 32))}).Authenticate(func() *http.Request {
		r := httptest.NewRequest("PUT", ConfigMutationPath, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		return r
	}())
	if err != nil || authenticated.Session != actor.Session {
		t.Fatal("test token/session mismatch", err)
	}
	code, first, headers := configHTTPCall(t, server.Client(), server.URL+ConfigMutationPath, "PUT", token, "mutation_key_0123456789", raw, "")
	p, decodeErr := DecodeCanonicalConfigOperationResponse(first)
	if code != 200 || decodeErr != nil || p.Version != 2 || !bytes.Equal(first, s.base.data.response) || headers.Get("Cache-Control") != "no-store" {
		t.Fatal("public Operation wire/receipt mismatch", code, decodeErr)
	}
	writes, strong := len(s.base.data.writes), s.base.strongCalls
	oldProof := testProof()
	oldProof.Payload.Endpoint = ConfigUpdateEndpoint
	oldProof.Payload.IdempotencyKey = "mutation_key_0123456789"
	oldProofRaw, _ := json.Marshal(oldProof)
	code, replayed, _ := configHTTPCall(t, server.Client(), server.URL+ConfigMutationPath, "PUT", token, "mutation_key_0123456789", raw, base64.StdEncoding.EncodeToString(oldProofRaw))
	if code != 200 || !bytes.Equal(first, replayed) || len(s.base.data.writes) != writes || s.base.strongCalls != strong {
		t.Fatal("HTTP replay performed new mutation", code)
	}
	rollback, _ := json.Marshal(map[string]any{"expected_version": 2, "change_reason": nil, "rollback_from_version": 1})
	code, body, _ := configHTTPCall(t, server.Client(), server.URL+ConfigRollbackPath, "POST", token, "rollback_key_0123456789", rollback, "")
	p, decodeErr = DecodeCanonicalConfigOperationResponse(body)
	if code != 200 || decodeErr != nil || p.Endpoint != ConfigRollbackEndpoint || p.Version != 3 || len(s.base.data.rows) != 3 {
		t.Fatal("rollback HTTP wire", code, decodeErr)
	}
}

func TestConfigMutationHTTPLargeConfigKeepsFullSQLBytesAndBoundedOperation(t *testing.T) {
	svc, actor, _, s, _, _ := operationStoreFixture(t)
	var config map[string]json.RawMessage
	if json.Unmarshal(s.base.data.rows[1].CanonicalJSON(), &config) != nil {
		t.Fatal("config fixture")
	}
	var registries []BootstrapRegistryRef
	var refs []BootstrapSecretRef
	if json.Unmarshal(config["registries"], &registries) != nil || json.Unmarshal(config["references"], &refs) != nil {
		t.Fatal("fixture refs")
	}
	for i := range registries {
		if registries[i].Kind != "rbac_bindings" {
			registries[i].Version = strings.Repeat("v", 128)
		}
	}
	for i := range refs {
		refs[i].Version = strings.Repeat("r", 128)
	}
	config["registries"], _ = json.Marshal(registries)
	config["references"], _ = json.Marshal(refs)
	encoded, _ := json.Marshal(config)
	large, err := DecodeConfigValues(encoded)
	if err != nil || len(large.CanonicalJSON()) <= 8192 {
		t.Fatal("real large configuration fixture", err)
	}
	s.base.data.rows[1] = large
	raw, _ := json.Marshal(map[string]any{"expected_version": 1, "change_reason": nil, "config": json.RawMessage(large.CanonicalJSON())})
	h, err := NewConfigMutationHTTP(svc.InstallationID, JWTRegistrationAuthenticator{Secret: []byte(strings.Repeat("s", 32))}, svc)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	defer server.Close()
	code, body, _ := configHTTPCall(t, server.Client(), server.URL+ConfigMutationPath, "PUT", configHTTPToken(t, actor), "mutation_key_0123456789", raw, "")
	p, decodeErr := DecodeCanonicalConfigOperationResponse(body)
	if code != 200 || decodeErr != nil || len(body) > MaxConfigOperationResponseBytes || p.Version != 2 || !bytes.Equal(s.base.data.rows[2].CanonicalJSON(), large.CanonicalJSON()) {
		t.Fatal("large config was truncated or returned instead of Operation", code, decodeErr)
	}
}
func TestConfigMutationHTTPUnknownCommitObservesOnceWithoutRewriting(t *testing.T) {
	svc, actor, raw, s, _, _ := operationStoreFixture(t)
	s.base.commitUnknown = true
	writer := &configHTTPCountingWriter{service: svc, state: s.base}
	h, err := NewConfigMutationHTTP(svc.InstallationID, JWTRegistrationAuthenticator{Secret: []byte(strings.Repeat("s", 32))}, writer)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	defer server.Close()
	code, body, _ := configHTTPCall(t, server.Client(), server.URL+ConfigMutationPath, "PUT", configHTTPToken(t, actor), "mutation_key_0123456789", raw, "")
	if code != 200 || !bytes.Equal(body, s.base.data.response) || writer.calls != 1 || writer.observations != 1 || len(s.base.data.rows) != 2 {
		t.Fatal("unknown commit blindly repeated or lost original", code, writer.calls, writer.observations)
	}
}

type configHTTPFakeWriter struct {
	err, observeErr     error
	calls, observations int
	badBody             bool
	lastProof           *Proof
}

func (s *configHTTPFakeWriter) Mutate(_ context.Context, a RegistrationActor, e, k, _ string, raw []byte, proof *Proof) (ConfigMutationResult, error) {
	s.calls++
	s.lastProof = proof
	if s.err != nil {
		return ConfigMutationResult{}, s.err
	}
	r, err := DecodeConfigMutationRequest(e, raw)
	if err != nil {
		return ConfigMutationResult{}, err
	}
	hash, err := r.RequestHash("installation_synthetic", "admin", "42")
	if err != nil {
		return ConfigMutationResult{}, err
	}
	now := time.Now().UTC()
	body, err := CanonicalConfigOperationResponse(ConfigOperationResponsePolicy{InstallationID: "installation_synthetic", OperationPublicID: "sop_12345678-1234-1234-1234-123456789abc", Endpoint: e, IdempotencyKey: k, RequestHash: hash, ActorID: a.UserID, Version: 2, RowVersion: 1, CreatedAt: now.Add(-time.Second), StartedAt: now.Add(-time.Second), FinishedAt: now, UpdatedAt: now, DeadlineAt: now.Add(time.Minute)})
	if s.badBody {
		body = []byte(`{"schema_version":"system-backup-config.v1"}`)
	}
	return ConfigMutationResult{OperationPublicID: "sop_12345678-1234-1234-1234-123456789abc", Version: 2, HTTPStatus: 200, Response: body}, err
}
func (s *configHTTPFakeWriter) ObserveCommitted(context.Context, RegistrationActor, string, string, string, []byte) (ConfigMutationResult, error) {
	s.observations++
	return ConfigMutationResult{}, s.observeErr
}
func configHTTPUnit(t *testing.T, writer *configHTTPFakeWriter) (*ConfigMutationHTTP, *http.Request) {
	t.Helper()
	_, actor, raw, s, _ := mutationTransactionFixture(t)
	now := time.Now().UTC()
	actor.SessionIssuedAt = now.Add(-time.Minute)
	actor.SessionExpiresAt = now.Add(time.Hour)
	s.now = now
	h, err := NewConfigMutationHTTP("installation_synthetic", JWTRegistrationAuthenticator{Secret: []byte(strings.Repeat("s", 32))}, writer)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("PUT", ConfigMutationPath, bytes.NewReader(raw))
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Authorization", "Bearer "+configHTTPToken(t, actor))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", "mutation_key_0123456789")
	return h, r
}
func TestConfigMutationHTTPRejectsInvalidTransportBeforeService(t *testing.T) {
	for _, name := range []string{"plaintext", "unauthenticated", "wrong-method", "unknown-path", "query", "empty-query", "encoding", "duplicate-content-type", "duplicate-key", "bad-key", "duplicate-proof", "bad-proof", "invalid-body", "oversized"} {
		t.Run(name, func(t *testing.T) {
			writer := &configHTTPFakeWriter{}
			h, r := configHTTPUnit(t, writer)
			want := 400
			switch name {
			case "plaintext":
				r.TLS = nil
				want = 426
			case "unauthenticated":
				r.Header.Del("Authorization")
				want = 401
			case "wrong-method":
				r.Method = "POST"
				want = 405
			case "unknown-path":
				r.URL.Path += "/other"
				want = 404
			case "query":
				r.URL.RawQuery = "actor_id=7"
			case "empty-query":
				r.URL.ForceQuery = true
			case "encoding":
				r.Header.Set("Content-Encoding", "gzip")
			case "duplicate-content-type":
				r.Header.Add("Content-Type", "application/json")
			case "duplicate-key":
				r.Header.Add("Idempotency-Key", "another_key_0123456789")
			case "bad-key":
				r.Header.Set("Idempotency-Key", "bad")
			case "duplicate-proof":
				r.Header.Add(StrongAuthProofHeader, "a")
				r.Header.Add(StrongAuthProofHeader, "b")
			case "bad-proof":
				r.Header.Set(StrongAuthProofHeader, "private-invalid")
			case "invalid-body":
				r.Body = io.NopCloser(strings.NewReader(`{"config":null}`))
			case "oversized":
				r.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", 262145)))
				want = 413
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want || writer.calls != 0 || strings.Contains(w.Body.String(), "private-invalid") {
				t.Fatal("invalid transport reached writer/leaked", name, w.Code)
			}
		})
	}
}
func TestConfigMutationHTTPClosedErrorsAndInvalidSuccessNeverLeak(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
		code   string
	}{{"validation", ErrConfigMutation, 400, "validation_failed"}, {"permission", ErrRegistrationPermission, 403, "permission_denied"}, {"version", ErrConfigVersionConflict, 409, "version_conflict"}, {"idempotency", ErrRegistrationConflict, 409, "idempotency_conflict"}, {"expired", ErrConfigIdempotencyExpired, 410, "idempotency_expired"}, {"unknown", ErrConfigCommitUnknown, 503, "not_ready"}, {"private", errors.New("PRIVATE SQL password"), 503, "not_ready"}, {"unknown-auth-code", &VerificationError{Code: FailureCode("PRIVATE invented")}, 503, "not_ready"}}
	for _, code := range []FailureCode{FailureRequired, FailureInvalid, FailureInvalidIssuer, FailureExpired, FailureReplayed} {
		cases = append(cases, struct {
			name   string
			err    error
			status int
			code   string
		}{string(code), fmt.Errorf("PRIVATE wrapper: %w", &VerificationError{Code: code}), 401, string(code)})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writer := &configHTTPFakeWriter{err: tc.err, observeErr: ErrRegistrationUnavailable}
			h, r := configHTTPUnit(t, writer)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			var body map[string]any
			if json.Unmarshal(w.Body.Bytes(), &body) != nil || w.Code != tc.status || body["code"] != tc.code || strings.Contains(w.Body.String(), "PRIVATE") {
				t.Fatal("error boundary", w.Code, w.Body.String())
			}
			if tc.name == "unknown" && (writer.calls != 1 || writer.observations != 1) {
				t.Fatal("unknown commit replayed write")
			}
		})
	}
	writer := &configHTTPFakeWriter{badBody: true}
	h, r := configHTTPUnit(t, writer)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatal("ConfigResource returned as public Operation")
	}
}
func TestConfigMutationHTTPExpiredProofRepresentationCanReachReceiptReplay(t *testing.T) {
	writer := &configHTTPFakeWriter{}
	h, r := configHTTPUnit(t, writer)
	proof := testProof()
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set(StrongAuthProofHeader, base64.StdEncoding.EncodeToString(raw))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || writer.lastProof == nil || writer.calls != 1 {
		t.Fatal("representation parser rejected old proof before receipt lookup", w.Code)
	}
}
