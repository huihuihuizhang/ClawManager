package systembackupsecurity

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fixedRegistrationAuth struct {
	actor RegistrationActor
	err   error
}

func (a fixedRegistrationAuth) Authenticate(*http.Request) (RegistrationActor, error) {
	return a.actor, a.err
}

func TestHTTPRegistrationCommitsAndReplaysWithoutProof(t *testing.T) {
	svc, actor, body, proof, state := registrationFixture(t)
	handler := ProviderRegistrationHTTP{Auth: fixedRegistrationAuth{actor: actor}, Service: svc}
	var registration ProviderProofRegistration
	_ = json.Unmarshal(body, &registration)
	call := func(encoded string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", ProviderRegistrationPath, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", registration.IdempotencyKey)
		if encoded != "" {
			r.Header.Set(StrongAuthProofHeader, encoded)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	raw, _ := json.Marshal(proof)
	w := call(base64.StdEncoding.EncodeToString(raw))
	if w.Code != 201 || state.commits != 1 || !strings.HasPrefix(w.Header().Get("Location"), "/api/v1/admin/system-backup-operations/sop_") {
		t.Fatalf("status=%d commits=%d body=%s", w.Code, state.commits, w.Body)
	}
	first := w.Body.String()
	state.now = state.now.Add(time.Hour)
	w = call("")
	if w.Code != 201 || w.Body.String() != first || len(state.committed) != 5 {
		t.Fatal("HTTP replay duplicated transaction", w.Code)
	}
	state.denied = true
	w = call("")
	if w.Code != 403 {
		t.Fatal("revoked actor replayed", w.Code)
	}
}
func TestHTTPRejectsMalformedAndAmbiguousTransportBeforeTransaction(t *testing.T) {
	for _, name := range []string{"missing-idempotency", "duplicate-idempotency", "duplicate-proof", "wrong-media", "oversize", "bad-proof", "unauthenticated"} {
		t.Run(name, func(t *testing.T) {
			svc, actor, body, proof, state := registrationFixture(t)
			var reg ProviderProofRegistration
			json.Unmarshal(body, &reg)
			auth := fixedRegistrationAuth{actor: actor}
			if name == "unauthenticated" {
				auth.err = ErrRegistrationPermission
			}
			if name == "oversize" {
				body = bytes.Repeat([]byte(" "), 16385)
			}
			r := httptest.NewRequest("POST", ProviderRegistrationPath, bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Idempotency-Key", reg.IdempotencyKey)
			raw, _ := json.Marshal(proof)
			r.Header.Set(StrongAuthProofHeader, base64.StdEncoding.EncodeToString(raw))
			switch name {
			case "missing-idempotency":
				r.Header.Del("Idempotency-Key")
			case "duplicate-idempotency":
				r.Header.Add("Idempotency-Key", reg.IdempotencyKey)
			case "duplicate-proof":
				r.Header.Add(StrongAuthProofHeader, r.Header.Get(StrongAuthProofHeader))
			case "wrong-media":
				r.Header.Set("Content-Type", "text/plain")
			case "bad-proof":
				r.Header.Set(StrongAuthProofHeader, "bad")
			}
			w := httptest.NewRecorder()
			ProviderRegistrationHTTP{Auth: auth, Service: svc}.ServeHTTP(w, r)
			if w.Code < 400 || state.commits != 0 || len(state.committed) != 0 {
				t.Fatal("invalid transport reached commit", w.Code)
			}
		})
	}
}
func TestHTTPCommitUnknownIsNotCreated(t *testing.T) {
	svc, actor, body, proof, state := registrationFixture(t)
	state.commitUnknown = true
	var reg ProviderProofRegistration
	json.Unmarshal(body, &reg)
	raw, _ := json.Marshal(proof)
	r := httptest.NewRequest("POST", ProviderRegistrationPath, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", reg.IdempotencyKey)
	r.Header.Set(StrongAuthProofHeader, base64.StdEncoding.EncodeToString(raw))
	w := httptest.NewRecorder()
	ProviderRegistrationHTTP{Auth: fixedRegistrationAuth{actor: actor}, Service: svc}.ServeHTTP(w, r)
	if w.Code != 503 || w.Header().Get("Location") != "" || !strings.Contains(w.Body.String(), "provider_registration_commit_unknown") || strings.Contains(w.Body.String(), "PRIVATE") {
		t.Fatal("uncertain commit exposed", w.Code, w.Body)
	}
}
func TestRegistrationJWTAndHTTPSBoundary(t *testing.T) {
	key := []byte(strings.Repeat("s", 32))
	now := time.Now()
	claims := jwt.MapClaims{"user_id": 42, "token_type": "access", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	r := httptest.NewRequest("POST", strongAuthBase+"/enroll", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	auth := JWTRegistrationAuthenticator{Secret: key}
	a, err := auth.Authenticate(r)
	if err != nil || a.UserID != 42 || a.Subject != "user:42" || a.Session == token || len(a.Session) != 64 {
		t.Fatal("JWT binding failed", err)
	}
	refresh := jwt.MapClaims{"user_id": 42, "token_type": "refresh", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	token, _ = jwt.NewWithClaims(jwt.SigningMethodHS256, refresh).SignedString(key)
	r.Header.Set("Authorization", "Bearer "+token)
	if _, err = auth.Authenticate(r); err == nil {
		t.Fatal("refresh token accepted")
	}
	w := httptest.NewRecorder()
	RegistrationAPI{}.ServeHTTP(w, r)
	if w.Code != 426 {
		t.Fatal("unencrypted credential API accepted")
	}
	r.TLS = &tls.ConnectionState{}
	w = httptest.NewRecorder()
	RegistrationAPI{}.ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatal("missing authentication accepted")
	}
}
