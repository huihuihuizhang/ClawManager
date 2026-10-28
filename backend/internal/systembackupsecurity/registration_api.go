package systembackupsecurity

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTRegistrationAuthenticator consumes the application's existing access
// token, but requires exp/iat, HS256 and a configured production-strength key.
// The session identifier is a digest, never the bearer token itself.
type JWTRegistrationAuthenticator struct{ Secret []byte }

func (a JWTRegistrationAuthenticator) Authenticate(r *http.Request) (RegistrationActor, error) {
	empty := RegistrationActor{}
	if len(a.Secret) < 32 || len(r.Header.Values("Authorization")) != 1 {
		return empty, ErrRegistrationPermission
	}
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") || len(header) > 8192 {
		return empty, ErrRegistrationPermission
	}
	token := strings.TrimPrefix(header, "Bearer ")
	var claims struct {
		UserID    int64  `json:"user_id"`
		TokenType string `json:"token_type"`
		jwt.RegisteredClaims
	}
	parsed, err := jwt.ParseWithClaims(token, &claims, func(*jwt.Token) (any, error) { return a.Secret, nil }, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || !parsed.Valid || claims.UserID <= 0 || claims.TokenType != "access" || claims.IssuedAt == nil || claims.ExpiresAt == nil || !claims.ExpiresAt.After(claims.IssuedAt.Time) {
		return empty, ErrRegistrationPermission
	}
	return RegistrationActor{UserID: claims.UserID, Subject: "user:" + strconv.FormatInt(claims.UserID, 10), Session: registrationHash(token), SessionExpiresAt: claims.ExpiresAt.Time, SessionIssuedAt: claims.IssuedAt.Time}, nil
}

const strongAuthBase = "/api/v1/admin/system-backup-strong-auth"
const ProviderObservationPath = "/api/v1/admin/system-backup-provider-observations"

type RegistrationAPI struct {
	Registration         ProviderRegistrationHTTP
	TOTP                 SQLTOTPService
	Attestation          ProviderAttestationService
	AuthorizeObservation func(context.Context, RegistrationActor, ProviderProofTarget) error
	DownloadProofTargets SensitiveDownloadProofTargets
}

func (a RegistrationAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Never trust X-Forwarded-Proto. Deploy with TLS to this listener; a trusted
	// ingress may forward TLS but cannot assert actor/session identity.
	if r.TLS == nil {
		http.Error(w, "HTTPS required", http.StatusUpgradeRequired)
		return
	}
	if r.URL.Path == ProviderRegistrationPath {
		a.Registration.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	id, _ := registrationID("")
	fail := func(status int, code string) {
		var details any
		switch code {
		case "provider_registration_unavailable", "provider_registration_commit_unknown":
			details = map[string]string{"reason": code}
			code = "not_ready"
		case "strong_auth_rate_limited":
			code = "rate_limited"
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": code, "message": code, "details": details, "request_id": id})
	}
	if r.URL.Path != ProviderObservationPath && r.URL.Path != strongAuthBase+"/enroll" && r.URL.Path != strongAuthBase+"/confirm" && r.URL.Path != strongAuthBase+"/proof" {
		fail(404, "not_found")
		return
	}
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		fail(405, "validation_failed")
		return
	}
	if a.Registration.Auth == nil {
		fail(503, "provider_registration_unavailable")
		return
	}
	actor, err := a.Registration.Auth.Authenticate(r)
	if err != nil {
		fail(401, "authentication_required")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || r.URL.RawQuery != "" || r.Header.Get("Content-Encoding") != "" {
		fail(400, "validation_failed")
		return
	}
	bodyLimit := int64(24 * 1024)
	if r.URL.Path == strongAuthBase+"/proof" {
		// A full config request may itself occupy 256 KiB. Bound the extra
		// password/code/selector wrapper separately; the decoder limits request.
		bodyLimit = 262144 + 8192
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, bodyLimit))
	if err != nil {
		fail(413, "payload_too_large")
		return
	}
	var fields map[string]json.RawMessage
	if !json.Valid(raw) || !providerJSONUnicode(raw) || !providerUniqueJSON(json.NewDecoder(bytes.NewReader(raw))) || json.Unmarshal(raw, &fields) != nil {
		fail(400, "validation_failed")
		return
	}
	if r.URL.Path == ProviderObservationPath {
		var target ProviderProofTarget
		var version int64
		var tf map[string]json.RawMessage
		if !providerFieldSet(fields, "target", "expected_row_version") || json.Unmarshal(fields["target"], &tf) != nil || !providerFieldSet(tf, "target_type", "target_public_id") || json.Unmarshal(fields["target"], &target) != nil || json.Unmarshal(fields["expected_row_version"], &version) != nil || version < 1 {
			fail(400, "validation_failed")
			return
		}
		if a.AuthorizeObservation == nil || a.AuthorizeObservation(r.Context(), actor, target) != nil {
			fail(403, "permission_denied")
			return
		}
		proof, err := a.Attestation.Attest(r.Context(), target, version)
		if err != nil {
			status, code := registrationHTTPError(err)
			fail(status, code)
			return
		}
		_ = json.NewEncoder(w).Encode(proof)
		return
	}
	var password, code string
	if json.Unmarshal(fields["password"], &password) != nil || len(password) == 0 || len(password) > 1024 {
		fail(400, "validation_failed")
		return
	}
	switch r.URL.Path {
	case strongAuthBase + "/enroll":
		if !providerFieldSet(fields, "password") {
			fail(400, "validation_failed")
			return
		}
		uri, err := a.TOTP.BeginEnrollment(r.Context(), actor, password)
		if err != nil {
			failTOTP(fail, err)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"enrollment_uri": uri})
		return
	case strongAuthBase + "/confirm", strongAuthBase + "/proof":
		if json.Unmarshal(fields["code"], &code) != nil || !normalizedCode(code) {
			fail(400, "validation_failed")
			return
		}
		var request *ProviderProofRegistration
		var configRequest *ConfigMutationRequest
		var downloadRequest *SensitiveDownloadProofSelector
		var configKey string
		if r.URL.Path == strongAuthBase+"/proof" {
			if _, config := fields["endpoint"]; config {
				var endpoint string
				if !providerFieldSet(fields, "password", "code", "endpoint", "idempotency_key", "request") || json.Unmarshal(fields["endpoint"], &endpoint) != nil || json.Unmarshal(fields["idempotency_key"], &configKey) != nil || !validIdempotencyKey(configKey) {
					fail(400, "validation_failed")
					return
				}
				if endpoint == SensitiveDownloadEndpoint {
					decoded, err := DecodeSensitiveDownloadProofSelector(fields["request"])
					if err != nil {
						fail(400, "validation_failed")
						return
					}
					downloadRequest = &decoded
				} else {
					decoded, err := DecodeConfigMutationRequest(endpoint, fields["request"])
					if err != nil {
						fail(400, "validation_failed")
						return
					}
					configRequest = &decoded
				}
			} else {
				if !providerFieldSet(fields, "password", "code", "request") {
					fail(400, "validation_failed")
					return
				}
				decoded, err := DecodeProviderProofRegistration(fields["request"])
				if err != nil {
					fail(400, "validation_failed")
					return
				}
				request = &decoded
			}
		} else if !providerFieldSet(fields, "password", "code") {
			fail(400, "validation_failed")
			return
		}
		var proof Proof
		if downloadRequest != nil {
			proof, err = a.TOTP.VerifySensitiveDownloadAndIssue(r.Context(), actor, password, code, *downloadRequest, configKey, a.DownloadProofTargets)
		} else if configRequest != nil {
			proof, err = a.TOTP.VerifyConfigMutationAndIssue(r.Context(), actor, password, code, *configRequest, configKey)
		} else {
			proof, err = a.TOTP.VerifyAndIssue(r.Context(), actor, password, code, request)
		}
		if err != nil {
			failTOTP(fail, err)
			return
		}
		if request == nil && configRequest == nil && downloadRequest == nil {
			_ = json.NewEncoder(w).Encode(map[string]bool{"confirmed": true})
			return
		}
		encoded, _ := json.Marshal(proof)
		_ = json.NewEncoder(w).Encode(map[string]string{"header_name": StrongAuthProofHeader, "header_value": base64.StdEncoding.EncodeToString(encoded)})
		return
	default:
		fail(404, "not_found")
	}
}
func failTOTP(f func(int, string), err error) {
	switch err {
	case ErrTOTPRateLimited:
		f(429, "strong_auth_rate_limited")
	case ErrRegistrationPermission:
		f(403, "permission_denied")
	case ErrTOTPRejected:
		f(401, "strong_auth_invalid")
	default:
		status, code := registrationHTTPError(err)
		f(status, code)
	}
}

// HTTPS servers should use these timeouts and a bounded header budget.
func RegistrationHTTPServer(address string, api RegistrationAPI) *http.Server {
	return &http.Server{Addr: address, Handler: api, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 * 1024}
}
