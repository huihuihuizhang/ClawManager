package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

type registrationBoundaryCase struct {
	name   string
	err    error
	status int
	code   string
}

func registrationBoundaryCases() []registrationBoundaryCase {
	var auth *VerificationError
	var provider *ProviderProofError
	cases := []registrationBoundaryCase{
		{"nil-auth", auth, 503, "provider_registration_unavailable"},
		{"wrapped-nil-auth", fmt.Errorf("PRIVATE wrapper: %w", auth), 503, "provider_registration_unavailable"},
		{"nil-provider", provider, 503, "provider_registration_unavailable"},
		{"private-ordinary", errors.New("PRIVATE password token nonce"), 503, "provider_registration_unavailable"},
		{"permission", fmt.Errorf("PRIVATE wrapper: %w", ErrRegistrationPermission), 403, "permission_denied"},
	}
	for _, code := range []FailureCode{FailureRequired, FailureInvalid, FailureInvalidIssuer, FailureExpired, FailureReplayed} {
		status := 401
		for _, wrapped := range []bool{false, true} {
			var err error = &VerificationError{Code: code, err: errors.New("PRIVATE password token nonce")}
			if wrapped {
				err = fmt.Errorf("PRIVATE wrapper: %w", err)
			}
			cases = append(cases, registrationBoundaryCase{fmt.Sprintf("%s-wrapped-%t", code, wrapped), err, status, string(code)})
		}
	}
	for _, code := range []FailureCode{"", "PRIVATE password token nonce", FailureCode(strings.Repeat("x", 65536)), FailureCode(string([]byte{0xff}))} {
		cases = append(cases, registrationBoundaryCase{fmt.Sprintf("unknown-code-%d", len(code)), &VerificationError{Code: code, err: errors.New("PRIVATE cause")}, 503, "provider_registration_unavailable"})
	}
	return cases
}

func TestRegistrationErrorBoundaryOnlyExportsClosedCodes(t *testing.T) {
	for _, test := range registrationBoundaryCases() {
		t.Run(test.name, func(t *testing.T) {
			mapped := registrationBoundaryError(test.err)
			if mapped == nil || strings.Contains(mapped.Error(), "PRIVATE") || len(mapped.Error()) > 128 {
				t.Fatal("adapter code/cause escaped failure boundary")
			}
			status, code := registrationHTTPError(mapped)
			if status != test.status || code != test.code {
				t.Fatal("closed error mapping changed", status, code)
			}
			if strings.HasPrefix(test.name, "unknown-code") || test.name == "nil-auth" || test.name == "wrapped-nil-auth" || test.name == "nil-provider" {
				if mapped != ErrRegistrationUnavailable {
					t.Fatal("unclassified adapter error was trusted")
				}
			}
			// The HTTP boundary must also tolerate a raw typed-nil error, before
			// a transaction adapter has had an opportunity to sanitize it.
			if strings.Contains(test.name, "nil") {
				if status, code = registrationHTTPError(test.err); status != 503 || code != "provider_registration_unavailable" {
					t.Fatal("typed-nil reached public error mapping")
				}
			}
		})
	}
}

type registrationBoundaryAuthority struct {
	RegistrationAuthority
	err error
}

func (a registrationBoundaryAuthority) Authorize(context.Context, *sql.Tx, RegistrationActor, ProviderProofTarget, RegistrationConfig) error {
	return a.err
}

func TestRegistrationErrorBoundaryRealHTTPNeverCommits(t *testing.T) {
	for _, test := range registrationBoundaryCases() {
		t.Run(test.name, func(t *testing.T) {
			svc, actor, body, _, state := registrationFixture(t)
			svc.Authority = registrationBoundaryAuthority{svc.Authority, test.err}
			var registration ProviderProofRegistration
			if json.Unmarshal(body, &registration) != nil {
				t.Fatal("invalid synthetic registration")
			}
			r := httptest.NewRequest("POST", ProviderRegistrationPath, bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Idempotency-Key", registration.IdempotencyKey)
			w := httptest.NewRecorder()
			ProviderRegistrationHTTP{Auth: fixedRegistrationAuth{actor: actor}, Service: svc}.ServeHTTP(w, r)
			if w.Code != test.status || state.commits != 0 || len(state.committed) != 0 || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "PRIVATE") {
				t.Fatal("untrusted failure committed or escaped HTTP", w.Code)
			}
			var result struct {
				Code    string            `json:"code"`
				Message string            `json:"message"`
				Details map[string]string `json:"details"`
			}
			if json.Unmarshal(w.Body.Bytes(), &result) != nil {
				t.Fatal("failure was not JSON")
			}
			if test.status == 503 {
				if result.Code != "not_ready" || result.Message != "not_ready" || result.Details["reason"] != test.code || w.Header().Get("Retry-After") != "1" {
					t.Fatal("unavailable wire contract changed")
				}
			} else if result.Code != test.code || result.Message != test.code {
				t.Fatal("legitimate failure classification changed")
			}
		})
	}
}

func TestRegistrationTypedNilVerificationSupportsErrorTraversal(t *testing.T) {
	var auth *VerificationError
	if auth.Error() != string(FailureInvalid) || auth.Unwrap() != nil || errors.Is(auth, ErrRegistrationPermission) {
		t.Fatal("typed-nil error traversal was not safe")
	}
	var got *VerificationError
	if !errors.As(fmt.Errorf("PRIVATE wrapper: %w", auth), &got) || got != nil {
		t.Fatal("typed-nil wrapper fixture is not exercising errors.As")
	}
}
