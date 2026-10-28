package systembackupsecurity

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

type registrationContractFailure struct{ err error }

func (s registrationContractFailure) Register(context.Context, RegistrationActor, []byte, Proof) (ProviderRegistrationResult, error) {
	return ProviderRegistrationResult{}, s.err
}

func registrationContractPolicy(t *testing.T) (map[string]int, map[string]bool) {
	t.Helper()
	read := func(name string, target any) {
		raw, err := os.ReadFile("../../../contracts/system-backup/v12/" + name)
		if err != nil || json.Unmarshal(raw, target) != nil {
			t.Fatal("cannot load authoritative operation error policy", err)
		}
	}
	var policy struct {
		Errors []struct {
			Code string `json:"code"`
			HTTP int    `json:"http_status"`
		} `json:"error_status_map"`
	}
	var profiles struct {
		Profiles []struct {
			ID    string   `json:"profile_id"`
			Codes []string `json:"codes"`
		} `json:"profiles"`
	}
	read("admin-operation-policy.json", &policy)
	read("admin-operation-errors.json", &profiles)
	statuses, allowed := map[string]int{}, map[string]bool{}
	for _, e := range policy.Errors {
		statuses[e.Code] = e.HTTP
	}
	for _, p := range profiles.Profiles {
		if p.ID == "provider_proof" {
			for _, code := range p.Codes {
				allowed[code] = true
			}
		}
	}
	if len(statuses) == 0 || len(allowed) == 0 {
		t.Fatal("operation error contracts are empty")
	}
	return statuses, allowed
}

func TestRegistrationContractErrorCodesAndStatusesMatchMachinePolicy(t *testing.T) {
	statuses, allowed := registrationContractPolicy(t)
	var nilAuth *VerificationError
	var nilProvider *ProviderProofError
	cases := []struct {
		name, wire string
		err        error
	}{
		{"provider-validation", "validation_failed", &ProviderProofError{Code: ProviderValidationFailed}},
		{"provider-signature", "signature_invalid", &ProviderProofError{Code: ProviderSignatureInvalid}},
		{"provider-checksum", "checksum_mismatch", &ProviderProofError{Code: ProviderChecksumMismatch}},
		{"provider-version", "version_conflict", &ProviderProofError{Code: ProviderVersionConflict}},
		{"provider-unknown", "signature_invalid", &ProviderProofError{Code: "PRIVATE provider error"}},
		{"permission", "permission_denied", ErrRegistrationPermission},
		{"idempotency", "idempotency_conflict", ErrRegistrationConflict},
		{"unavailable", "not_ready", ErrRegistrationUnavailable},
		{"storage", "not_ready", ErrProviderEvidenceStorage},
		{"unknown-commit", "not_ready", ErrRegistrationCommitUnknown},
		{"unclassified", "internal_error", errors.New("PRIVATE adapter error")},
		{"unknown-auth-code", "internal_error", &VerificationError{Code: "PRIVATE auth code", err: errors.New("PRIVATE cause")}},
		{"nil-auth", "not_ready", nilAuth},
		{"nil-provider", "not_ready", nilProvider},
	}
	for _, code := range []FailureCode{FailureRequired, FailureInvalid, FailureInvalidIssuer, FailureExpired, FailureReplayed} {
		cases = append(cases, struct {
			name, wire string
			err        error
		}{string(code), string(code), &VerificationError{Code: code, err: errors.New("PRIVATE cause")}})
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, actor, body, _, _ := registrationFixture(t)
			var input ProviderProofRegistration
			if json.Unmarshal(body, &input) != nil {
				t.Fatal("synthetic request")
			}
			r := httptest.NewRequest("POST", ProviderRegistrationPath, bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Idempotency-Key", input.IdempotencyKey)
			w := httptest.NewRecorder()
			ProviderRegistrationHTTP{Auth: fixedRegistrationAuth{actor: actor}, Service: registrationContractFailure{test.err}}.ServeHTTP(w, r)
			var response struct {
				Code string `json:"code"`
			}
			if json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Code != test.wire || !allowed[response.Code] || w.Code != statuses[response.Code] || strings.Contains(w.Body.String(), "PRIVATE") || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("runtime HTTP error diverges from machine policy", w.Code, response.Code)
			}
		})
	}
}

func TestRegistrationContractMissingProofPreservesCommittedReplay(t *testing.T) {
	svc, actor, body, proof, state := registrationFixture(t)
	var input ProviderProofRegistration
	if json.Unmarshal(body, &input) != nil {
		t.Fatal("synthetic request")
	}
	h := ProviderRegistrationHTTP{Auth: fixedRegistrationAuth{actor: actor}, Service: svc}
	call := func(encoded string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", ProviderRegistrationPath, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", input.IdempotencyKey)
		if encoded != "" {
			r.Header.Set(StrongAuthProofHeader, encoded)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := call("")
	if w.Code != 401 || !strings.Contains(w.Body.String(), `"code":"strong_auth_required"`) || state.commits != 0 || len(state.committed) != 0 || state.loads != 0 {
		t.Fatal("fresh missing proof was not required before nonce/material work", w.Code)
	}
	raw, _ := json.Marshal(proof)
	first := call(base64.StdEncoding.EncodeToString(raw))
	if first.Code != 201 {
		t.Fatal("fresh denied call consumed idempotency or altered valid request", first.Code)
	}
	writes := len(state.committed)
	replay := call("")
	if replay.Code != 201 || !bytes.Equal(first.Body.Bytes(), replay.Body.Bytes()) || len(state.committed) != writes {
		t.Fatal("committed replay incorrectly required a fresh proof")
	}
}

func TestRegistrationContractMalformedProofIsValidationFailure(t *testing.T) {
	for _, name := range []string{"invalid-header", "duplicate-header"} {
		t.Run(name, func(t *testing.T) {
			svc, actor, body, _, state := registrationFixture(t)
			var input ProviderProofRegistration
			_ = json.Unmarshal(body, &input)
			r := httptest.NewRequest("POST", ProviderRegistrationPath, bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Idempotency-Key", input.IdempotencyKey)
			r.Header.Set(StrongAuthProofHeader, "not-a-proof")
			if name == "duplicate-header" {
				r.Header.Add(StrongAuthProofHeader, "not-a-proof")
			}
			w := httptest.NewRecorder()
			ProviderRegistrationHTTP{Auth: fixedRegistrationAuth{actor: actor}, Service: svc}.ServeHTTP(w, r)
			if w.Code != 400 || !strings.Contains(w.Body.String(), `"code":"validation_failed"`) || state.commits != 0 || state.authorizations != 0 {
				t.Fatal("malformed transport became authentication failure or reached authority", w.Code)
			}
		})
	}
}

func TestRegistrationContractConfigMutationMissingProofIsRequired(t *testing.T) {
	svc, actor, raw, state, _ := mutationTransactionFixture(t)
	state.extraRisk.SecurityBoundary = true
	result, err := svc.Mutate(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "contract-missing-proof", raw, nil)
	var auth *VerificationError
	if !errors.As(err, &auth) || auth == nil || auth.Code != FailureRequired || state.commits != 0 || state.data.active != 1 || len(state.data.rows) != 1 || len(state.data.writes) != 0 || len(result.Response) != 0 {
		t.Fatal("missing mutation proof was misclassified or changed state", err)
	}
}

func TestRegistrationContractTOTPFailureReturnsAuthenticationStatus(t *testing.T) {
	f := newConfigProofFixture(t, ConfigUpdateEndpoint)
	body, _ := json.Marshal(map[string]any{"password": f.password + "-wrong", "code": f.code(), "endpoint": ConfigUpdateEndpoint, "idempotency_key": "config_mfa_key_0123456789", "request": json.RawMessage(f.request.CanonicalJSON())})
	r := httptest.NewRequest("POST", "https://control.example"+strongAuthBase+"/proof", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+f.token)
	w := httptest.NewRecorder()
	(RegistrationAPI{Registration: ProviderRegistrationHTTP{Auth: JWTRegistrationAuthenticator{Secret: f.jwtSecret}}, TOTP: f.svc}).ServeHTTP(w, r)
	if w.Code != 401 || !strings.Contains(w.Body.String(), `"code":"strong_auth_invalid"`) || strings.Contains(w.Body.String(), f.password) || strings.Contains(w.Body.String(), "header_value") {
		t.Fatal("failed credentials returned the wrong status or a proof", w.Code)
	}
}
