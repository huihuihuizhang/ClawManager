package systembackupevidence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

// Built only from deployment-owned concrete admission/result/SQL authorities.
// No callback can substitute an already-claimed legacy row for atomic Admit.
type admittedDownloadHandler struct {
	admission *DownloadAdmissionService
	authority *SQLDownloadAuthority
	results   *SQLDownloadResults
	service   Service
	public    Handler
}

func newAdmittedDownloadHandler(admission *DownloadAdmissionService, a *SQLDownloadAuthority, results *SQLDownloadResults, service Service, public Handler) (*admittedDownloadHandler, error) {
	if admission == nil || a == nil || results == nil || nilSystemAdapter(service.Store) || nilSystemAdapter(service.Keys) || service.Failure == nil {
		return nil, ErrDownloadAdmissionNotReady
	}
	r, s := admission.registry, a.c.Registry
	if r.DB != s.DB || r.Installation != s.Installation || r.ServerUUID != s.ServerUUID || r.Database != s.Database || !bytes.Equal(admission.secret, a.c.JWTSecret) || results.c.Registry.DB != r.DB || results.c.Registry.Installation != r.Installation || results.c.Registry.ServerUUID != r.ServerUUID || results.c.Registry.Database != r.Database {
		return nil, ErrDownloadAdmissionNotReady
	}
	public.publicOnly = true
	return &admittedDownloadHandler{admission, a, results, service, public}, nil
}

func admittedDownloadHTTPError(err error) (int, string) {
	var proof *sec.VerificationError
	switch {
	case errors.Is(err, ErrDownloadAdmissionKeyConflict), errors.Is(err, sec.ErrRegistrationConflict):
		return 409, "idempotency_conflict"
	case errors.Is(err, ErrDownloadAdmissionKeyExpired):
		return 410, "idempotency_expired"
	case errors.Is(err, ErrAuth):
		return 401, "authentication_required"
	case errors.Is(err, ErrDenied), errors.Is(err, sec.ErrRegistrationPermission):
		return 403, "permission_denied"
	case errors.Is(err, ErrInvalid), errors.Is(err, sec.ErrSensitiveDownloadRequest):
		return 400, "validation_failed"
	case errors.Is(err, ErrRange):
		return 416, "range_not_satisfiable"
	case errors.Is(err, ErrConflict):
		return 409, "version_conflict"
	case errors.Is(err, ErrState):
		return 409, "state_conflict"
	case errors.Is(err, ErrNotFound):
		return 404, "not_found"
	case errors.Is(err, ErrUnavailable), errors.Is(err, ErrKey):
		return 503, "artifact_unavailable"
	case errors.Is(err, ErrCapacity):
		return 422, "capacity_exceeded"
	case errors.Is(err, ErrAudit), errors.Is(err, ErrIntegrity):
		return 500, "internal_error"
	case errors.As(err, &proof):
		if proof != nil {
			switch proof.Code {
			case sec.FailureRequired, sec.FailureInvalid, sec.FailureInvalidIssuer, sec.FailureExpired, sec.FailureReplayed:
				return 401, string(proof.Code)
			}
		}
	}
	return 503, "not_ready"
}

func writeAdmittedDownloadError(w http.ResponseWriter, err error) {
	status, code := admittedDownloadHTTPError(err)
	w.Header().Del("X-System-Backup-Operation-Id")
	w.Header().Del("Content-Length")
	for _, name := range []string{"ETag", "Content-Range", "Accept-Ranges", "Content-Disposition"} {
		w.Header().Del(name)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": code})
}

func (h *admittedDownloadHandler) finish(c *CommittedDownloadAdmission, o DownloadResultObservation) {
	ctx, cancel := context.WithTimeout(downloadFailureContext(c), 5*time.Second)
	err := h.results.Finish(ctx, c, o)
	cancel()
	if err != nil {
		// Use a fresh non-canceled budget: neither a disconnected client nor the
		// failed result transaction may silence the mandatory durable sink.
		failureCtx, stop := context.WithTimeout(downloadFailureContext(c), 5*time.Second)
		defer stop()
		h.service.Failure(failureCtx, c.record.Manifest.Identity.ID, "download_result_audit_or_release_failed")
	}
}

// net/http represents an empty native HTTP/2 GET with a non-nil Body. Verify
// EOF before SQL admission rather than trusting Content-Length or the Body's
// concrete type. A peer leaving a zero-length stream open cannot hold this
// read indefinitely. The normalized clone is never reused as a body reader.
func normalizeEmptyDownloadBody(w http.ResponseWriter, r *http.Request) error {
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 {
		return ErrInvalid
	}
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	controller := http.NewResponseController(w)
	until := time.Now().Add(time.Second)
	if bound, ok := r.Context().Deadline(); ok && bound.Before(until) {
		until = bound
	}
	if r.Context().Err() != nil || !time.Now().Before(until) {
		return ErrInvalid
	}
	if controller.SetReadDeadline(until) != nil {
		return ErrDownloadAdmissionNotReady
	}
	var one [1]byte
	n, err := r.Body.Read(one[:])
	if controller.SetReadDeadline(time.Time{}) != nil {
		return ErrDownloadAdmissionNotReady
	}
	if n != 0 || err != io.EOF || len(r.Trailer) != 0 || r.Context().Err() != nil || !time.Now().Before(until) {
		return ErrInvalid
	}
	return nil
}

func (h *admittedDownloadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if h == nil || r == nil || r.URL == nil {
		writeAdmittedDownloadError(w, ErrDownloadAdmissionNotReady)
		return
	}
	if r.TLS == nil {
		writeAdmittedDownloadError(w, ErrAuth)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := normalizeEmptyDownloadBody(w, r); err != nil {
		writeAdmittedDownloadError(w, err)
		return
	}
	request := r.Clone(r.Context())
	request.Body = http.NoBody
	c, err := h.admission.admit(request, true)
	if errors.Is(err, errDownloadAdmissionPublic) {
		h.public.ServeHTTP(w, request)
		return
	}
	if err != nil {
		writeAdmittedDownloadError(w, err)
		return
	}
	observation := DownloadResultObservation{Outcome: "rejected"}
	defer func() { h.finish(c, observation) }()
	ctx, cancel, err := h.authority.BindCommittedDownload(request.Context(), c)
	if err != nil {
		writeAdmittedDownloadError(w, err)
		return
	}
	defer cancel()
	if err = h.authority.CheckCommittedDownload(ctx, c); err != nil {
		writeAdmittedDownloadError(w, err)
		return
	}
	record := c.Record()
	info, err := h.service.Store.Stat(ctx, record.Ref)
	if err != nil {
		writeAdmittedDownloadError(w, boundary(err))
		return
	}
	if !matchObject(record, info) {
		writeAdmittedDownloadError(w, ErrIntegrity)
		return
	}
	start, end, partial := c.Range()
	data, err := OpenRange(ctx, record.Manifest, record.Ref, h.service.Store, h.service.Keys, start, end)
	defer wipe(data)
	if err != nil {
		writeAdmittedDownloadError(w, boundary(err))
		return
	}
	if int64(len(data)) != end-start+1 {
		writeAdmittedDownloadError(w, ErrIntegrity)
		return
	}
	// Native HTTP/1 and HTTP/2 response writers support this. Unknown wrappers
	// must expose Unwrap or SetWriteDeadline; silently unbounded writes fail.
	if err = http.NewResponseController(w).SetWriteDeadline(c.localDeadline); err != nil {
		writeAdmittedDownloadError(w, ErrDownloadAdmissionNotReady)
		return
	}
	// Keep the original deadline through the independent result transaction
	// and net/http's final flush. Write may only copy a small body into the
	// server buffer; clearing now could release it after the original limit.
	// The native server owns connection/stream deadline cleanup.
	w.Header().Set("Content-Type", record.Manifest.Identity.Media)
	w.Header().Set("Content-Disposition", `attachment; filename="evidence.bin"`)
	w.Header().Set("ETag", `"`+record.Manifest.Identity.ContentHash+`"`)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("X-System-Backup-Operation-Id", c.OperationPublicID())
	status := http.StatusOK
	if partial {
		status = http.StatusPartialContent
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, record.Manifest.Identity.ContentSize))
	}
	if err = h.authority.CheckCommittedDownload(ctx, c); err != nil {
		writeAdmittedDownloadError(w, err)
		return
	}
	observation.Outcome = "interrupted"
	w.WriteHeader(status)
	// Header emission may block or cancel the request. Never append JSON once
	// committed, and recheck immediately before the first plaintext write.
	if err = h.authority.CheckCommittedDownload(ctx, c); err != nil {
		return
	}
	n, writeErr := w.Write(data)
	if n >= 0 && n <= len(data) {
		observation.BytesWritten = int64(n)
	}
	if writeErr == nil && n == len(data) {
		observation.Outcome = "local_write_complete"
	}
}
