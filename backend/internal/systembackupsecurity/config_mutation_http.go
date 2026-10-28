package systembackupsecurity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
)

const ConfigMutationPath = "/api/v1/admin/system-backup-config"
const ConfigRollbackPath = ConfigMutationPath + "/rollback"

type ConfigMutationWriter interface {
	Mutate(context.Context, RegistrationActor, string, string, string, []byte, *Proof) (ConfigMutationResult, error)
	ObserveCommitted(context.Context, RegistrationActor, string, string, string, []byte) (ConfigMutationResult, error)
}

// Candidate transport only. Construction does not mount a route, create
// runtime adapters, grant permission or enable a production writer.
type ConfigMutationHTTP struct {
	installation string
	auth         RegistrationHTTPAuthenticator
	service      ConfigMutationWriter
}

func NewConfigMutationHTTP(installation string, auth RegistrationHTTPAuthenticator, service ConfigMutationWriter) (*ConfigMutationHTTP, error) {
	if !configMutationInstallation.MatchString(installation) || nilConfigMutationBoundary(auth) || nilConfigMutationBoundary(service) {
		return nil, ErrRegistrationUnavailable
	}
	return &ConfigMutationHTTP{installation, auth, service}, nil
}
func (h *ConfigMutationHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	id, err := registrationID("")
	if err != nil {
		w.WriteHeader(503)
		return
	}
	fail := func(status int, code, reason string) {
		var details any
		if reason != "" {
			details = map[string]string{"reason": reason}
		}
		if status == 503 {
			w.Header().Set("Retry-After", "1")
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": code, "message": code, "details": details, "request_id": id})
	}
	endpoint, method := "", ""
	switch r.URL.Path {
	case ConfigMutationPath:
		endpoint, method = ConfigUpdateEndpoint, http.MethodPut
	case ConfigRollbackPath:
		endpoint, method = ConfigRollbackEndpoint, http.MethodPost
	default:
		fail(404, "not_found", "")
		return
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		fail(405, "validation_failed", "")
		return
	}
	if r.TLS == nil {
		fail(http.StatusUpgradeRequired, "validation_failed", "")
		return
	}
	if h == nil || nilConfigMutationBoundary(h.auth) || nilConfigMutationBoundary(h.service) {
		fail(503, "not_ready", "config_mutation_unavailable")
		return
	}
	actor, err := h.auth.Authenticate(r)
	if err != nil || actor.UserID < 1 || actor.Subject == "" || actor.Session == "" {
		fail(401, "authentication_required", "")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(r.Header.Values("Content-Type")) != 1 || len(r.Header.Values("Content-Encoding")) != 0 || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || len(r.Header.Values("Idempotency-Key")) != 1 || !validIdempotencyKey(r.Header.Get("Idempotency-Key")) {
		fail(400, "validation_failed", "")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 262144))
	if err != nil {
		var size *http.MaxBytesError
		if errors.As(err, &size) {
			fail(413, "payload_too_large", "")
		} else {
			fail(400, "validation_failed", "")
		}
		return
	}
	request, err := DecodeConfigMutationRequest(endpoint, raw)
	if err != nil {
		fail(400, "validation_failed", "")
		return
	}
	var proof *Proof
	headers := r.Header.Values(StrongAuthProofHeader)
	if len(headers) > 1 {
		fail(400, "validation_failed", "")
		return
	}
	if len(headers) == 1 {
		decoded, err := DecodeStrongAuthHeader(headers[0])
		if err != nil {
			fail(400, "validation_failed", "")
			return
		}
		proof = &decoded
	}
	key := r.Header.Get("Idempotency-Key")
	result, err := h.service.Mutate(r.Context(), actor, endpoint, key, id, raw, proof)
	if errors.Is(err, ErrConfigCommitUnknown) {
		// Observe once under current authority. Never repeat Mutate on an
		// uncertain commit, and never invent a new proof/idempotency key.
		observed, observeErr := h.service.ObserveCommitted(r.Context(), actor, endpoint, key, id, raw)
		if observeErr == nil {
			result, err = observed, nil
		} else if errors.Is(observeErr, ErrRegistrationPermission) {
			err = observeErr
		}
	}
	if err != nil {
		status, code, reason := configMutationHTTPError(err)
		fail(status, code, reason)
		return
	}
	policy, err := DecodeCanonicalConfigOperationResponse(result.Response)
	hash, hashErr := request.RequestHash(h.installation, "admin", strconv.FormatInt(actor.UserID, 10))
	if err != nil || hashErr != nil || result.HTTPStatus != 200 || policy.InstallationID != h.installation || policy.OperationPublicID != result.OperationPublicID || policy.Version != result.Version || policy.ActorID != actor.UserID || policy.Endpoint != endpoint || policy.IdempotencyKey != key || policy.RequestHash != hash {
		fail(503, "not_ready", "config_mutation_unavailable")
		return
	}
	w.Header().Set("Location", "/api/v1/admin/system-backup-operations/"+result.OperationPublicID)
	w.Header().Set("Content-Length", strconv.Itoa(len(result.Response)))
	w.WriteHeader(200)
	_, _ = w.Write(result.Response)
}
func configMutationHTTPError(err error) (int, string, string) {
	var auth *VerificationError
	switch {
	case errors.Is(err, ErrRegistrationPermission):
		return 403, "permission_denied", ""
	case errors.Is(err, ErrConfigVersionConflict):
		return 409, "version_conflict", ""
	case errors.Is(err, ErrRegistrationConflict):
		return 409, "idempotency_conflict", ""
	case errors.Is(err, ErrConfigIdempotencyExpired):
		return 410, "idempotency_expired", ""
	case errors.Is(err, ErrConfigMutation):
		return 400, "validation_failed", ""
	case errors.Is(err, ErrConfigCommitUnknown):
		return 503, "not_ready", "config_commit_unknown"
	case errors.As(err, &auth):
		if auth != nil {
			switch auth.Code {
			case FailureRequired, FailureInvalid, FailureInvalidIssuer, FailureExpired, FailureReplayed:
				return 401, string(auth.Code), ""
			}
		}
	}
	return 503, "not_ready", "config_mutation_unavailable"
}
