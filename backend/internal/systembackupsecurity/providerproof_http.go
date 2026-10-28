package systembackupsecurity

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
)

const ProviderRegistrationPath = "/api/v1/admin/system-backup-provider-proofs"
const StrongAuthProofHeader = "X-Strong-Auth-Proof"

type RegistrationHTTPAuthenticator interface {
	Authenticate(*http.Request) (RegistrationActor, error)
}
type ProviderRegistrar interface {
	Register(context.Context, RegistrationActor, []byte, Proof) (ProviderRegistrationResult, error)
}

// ProviderRegistrationHTTP is mounted at the contract path by the application.
// Authentication is server-owned. No actor, session, registry or binding is
// accepted from the body or forwarded identity headers.
type ProviderRegistrationHTTP struct {
	Auth    RegistrationHTTPAuthenticator
	Service ProviderRegistrar
}

func (h ProviderRegistrationHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	requestID, err := registrationID("")
	if err != nil {
		w.WriteHeader(503)
		return
	}
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
		_ = json.NewEncoder(w).Encode(map[string]any{"code": code, "message": code, "details": details, "request_id": requestID})
	}
	if r.URL.Path != ProviderRegistrationPath {
		fail(404, "not_found")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		fail(405, "validation_failed")
		return
	}
	if h.Auth == nil || h.Service == nil {
		fail(503, "provider_registration_unavailable")
		return
	}
	actor, err := h.Auth.Authenticate(r)
	if err != nil || actor.UserID <= 0 || actor.Subject == "" || actor.Session == "" {
		fail(401, "authentication_required")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || r.URL.RawQuery != "" || r.Header.Get("Content-Encoding") != "" {
		fail(400, "validation_failed")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16*1024))
	if err != nil {
		var size *http.MaxBytesError
		if errors.As(err, &size) {
			fail(413, "payload_too_large")
		} else {
			fail(400, "validation_failed")
		}
		return
	}
	decoded, err := DecodeProviderProofRegistration(raw)
	if err != nil || len(r.Header.Values("Idempotency-Key")) != 1 || r.Header.Get("Idempotency-Key") != decoded.IdempotencyKey {
		fail(400, "validation_failed")
		return
	}
	var proof Proof
	headers := r.Header.Values(StrongAuthProofHeader)
	if len(headers) > 1 {
		fail(400, "validation_failed")
		return
	}
	if len(headers) == 1 {
		proof, err = DecodeStrongAuthHeader(headers[0])
		if err != nil {
			fail(400, "validation_failed")
			return
		}
	}
	// A missing proof is passed through so an authenticated committed retry can
	// return its original result even after the old proof has expired.
	result, err := h.Service.Register(r.Context(), actor, raw, proof)
	if err != nil {
		status, code := registrationHTTPError(err)
		if status == 503 {
			w.Header().Set("Retry-After", "1")
		}
		fail(status, code)
		return
	}
	if result.HTTPStatus != 201 || result.OperationPublicID == "" || result.EvidencePublicID == "" {
		fail(503, "provider_registration_unavailable")
		return
	}
	w.Header().Set("Location", "/api/v1/admin/system-backup-operations/"+result.OperationPublicID)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(result)
}

// A bounded canonical padded-base64 transport keeps JSON out of intermediary
// header parsing. Payload nullability follows the existing proof contract.
func DecodeStrongAuthHeader(encoded string) (Proof, error) {
	var p Proof
	bad := func() (Proof, error) { return Proof{}, &VerificationError{Code: FailureInvalid} }
	if len(encoded) == 0 || len(encoded) > 16384 {
		return bad()
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != encoded || !json.Valid(raw) || !providerJSONUnicode(raw) {
		return bad()
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if !providerUniqueJSON(d) {
		return bad()
	}
	var root, payload, sig map[string]json.RawMessage
	if json.Unmarshal(raw, &root) != nil || !providerFieldSet(root, "schema_version", "payload", "signature") || json.Unmarshal(root["payload"], &payload) != nil || !providerFieldSet(payload, "issuer", "audience", "subject", "session", "auth_time", "expires_at", "method", "nonce", "endpoint", "request_hash", "idempotency_key", "acr", "amr") || json.Unmarshal(root["signature"], &sig) != nil || !providerFieldSet(sig, "format", "algorithm", "key_id", "key_version", "domain_separator", "protected_header", "value") {
		return bad()
	}
	if json.Unmarshal(raw, &p) != nil {
		return bad()
	}
	if p.SchemaVersion != ProofSchemaVersion {
		return bad()
	}
	if _, err = CanonicalPayload(p.Payload); err != nil {
		return bad()
	}
	return p, nil
}

func registrationHTTPError(err error) (int, string) {
	var p *ProviderProofError
	var a *VerificationError
	switch {
	case err == ErrSensitiveDownloadRequest:
		return 400, "validation_failed"
	case errors.Is(err, ErrRegistrationPermission):
		return 403, "permission_denied"
	case errors.Is(err, ErrRegistrationConflict):
		return 409, "idempotency_conflict"
	case errors.Is(err, ErrRegistrationCommitUnknown):
		return 503, "provider_registration_commit_unknown"
	case errors.Is(err, ErrRegistrationUnavailable), errors.Is(err, ErrProviderEvidenceStorage):
		return 503, "provider_registration_unavailable"
	case errors.As(err, &p):
		if p == nil {
			return 503, "provider_registration_unavailable"
		}
		if p.Code == ProviderValidationFailed {
			return 400, p.Error()
		}
		return 409, p.Error()
	case errors.As(err, &a):
		if a == nil {
			return 503, "provider_registration_unavailable"
		}
		switch a.Code {
		case FailureRequired, FailureInvalid, FailureInvalidIssuer, FailureExpired, FailureReplayed:
			return 401, string(a.Code)
		}
	}
	return 500, "internal_error"
}
