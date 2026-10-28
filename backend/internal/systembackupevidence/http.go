package systembackupevidence

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const Path = "/api/v1/admin/system-backup-evidence/"

type Authenticator interface {
	Authenticate(*http.Request) (Actor, error)
}

// BoundDownloadAuthenticator carries a cryptographically authenticated session
// to provider/key authorization. Its checks run outside Registry transactions,
// after the claim commits and again before sending any plaintext.
type BoundDownloadAuthenticator interface {
	Authenticator
	AuthenticateContext(*http.Request) (context.Context, Actor, error)
	AuthorizeDownload(context.Context, Actor, Record) error
}

// SensitiveDownloadAuthenticator must verify a fresh, exact-request second
// factor in the same locked transaction as the download claim and audit intent.
// Its implementation owns durable nonce consumption; ordinary JWT/RBAC is not
// sufficient. The handler denies sensitive evidence without this boundary.
type SensitiveDownloadAuthenticator interface {
	AuthorizeSensitiveDownload(context.Context, *http.Request, Actor, Record, int64, int64, Locked) error
}
type Handler struct {
	Service Service
	Auth    Authenticator
	// Runtime's legacy path handles only public/internal rows. Check the
	// classification under the actual lock, before claim/audit effects.
	publicOnly bool
}

func parseRange(value string, size int64) (int64, int64, bool, error) {
	if value == "" {
		if size > MaxResponse {
			return 0, 0, false, ErrRange
		}
		return 0, size - 1, false, nil
	}
	if len(value) > 100 || !strings.HasPrefix(value, "bytes=") || strings.ContainsAny(value, ", \t\r\n") {
		return 0, 0, false, ErrRange
	}
	parts := strings.Split(strings.TrimPrefix(value, "bytes="), "-")
	if len(parts) != 2 {
		return 0, 0, false, ErrRange
	}
	decimal := func(s string) (int64, error) {
		if s == "" || strings.Trim(s, "0123456789") != "" {
			return 0, ErrRange
		}
		return strconv.ParseInt(s, 10, 64)
	}
	var start, end int64
	var e error
	if parts[0] == "" {
		suffix, err := decimal(parts[1])
		if err != nil || suffix <= 0 {
			return 0, 0, false, ErrRange
		}
		start = max(size-suffix, 0)
		end = size - 1
	} else {
		start, e = decimal(parts[0])
		if e != nil {
			return 0, 0, false, ErrRange
		}
		end = size - 1
		if parts[1] != "" {
			end, e = decimal(parts[1])
			if e != nil {
				return 0, 0, false, ErrRange
			}
			end = min(end, size-1)
		}
	}
	if start < 0 || start >= size || end < start || end-start+1 > MaxResponse {
		return 0, 0, false, ErrRange
	}
	return start, end, true, nil
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", `attachment; filename="evidence.bin"`)
	fail := func(err error) {
		status := 503
		switch err {
		case ErrInvalid:
			status = 400
		case ErrAuth:
			status = 401
		case ErrDenied:
			status = 403
		case ErrNotFound:
			status = 404
		case ErrState, ErrConflict, ErrIntegrity:
			status = 409
		case ErrRange:
			status = 416
		case ErrAudit:
			status = 500
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": err.Error(), "message": err.Error()})
	}
	if r.TLS == nil {
		fail(ErrAuth)
		return
	}
	if r.Method != "GET" {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(405)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, Path)
	if !strings.HasPrefix(r.URL.Path, Path) || !idPattern.MatchString(id) || r.URL.RawQuery != "" {
		fail(ErrInvalid)
		return
	}
	s := h.Service
	if h.Auth == nil || s.Registry == nil || s.Store == nil || s.Keys == nil || s.Failure == nil {
		fail(ErrUnavailable)
		return
	}
	requestContext := r.Context()
	var actor Actor
	var e error
	bound, boundAuth := h.Auth.(BoundDownloadAuthenticator)
	if boundAuth {
		requestContext, actor, e = bound.AuthenticateContext(r)
	} else {
		actor, e = h.Auth.Authenticate(r)
	}
	if e != nil || requestContext == nil || actor.ID == "" || actor.Session == "" {
		fail(ErrAuth)
		return
	}
	ctx, cancel := context.WithTimeout(requestContext, 20*time.Second)
	defer cancel()
	claim, e := claimID()
	if e != nil {
		fail(e)
		return
	}
	var record Record
	var start, end int64
	var partial, sensitive bool
	e = s.Registry.WithLocked(ctx, id, func(tx Locked) error {
		record = tx.Record()
		now := tx.Time()
		if record.Manifest.Identity.ID != id {
			return ErrIntegrity
		}
		if h.publicOnly && !oneOf(record.Manifest.Identity.Classification, "public", "internal") {
			return ErrDownloadAdmissionNotReady
		}
		permission := permissions(record.Manifest.Identity.Classification)
		if permission == nil {
			return ErrIntegrity
		}
		if e := tx.Authorize(ctx, actor, permission); e != nil {
			return boundary(e)
		}
		switch record.State {
		case "deleted":
			return ErrNotFound
		case "deleting", "delete_failed":
			return ErrUnavailable
		case "ready":
		default:
			return ErrState
		}
		if !validRecord(record) || !record.Ref.valid(true) {
			return ErrIntegrity
		}
		if record.Manifest.Identity.Type == "job_log_chunk" && !now.Before(record.ExpiresAt) {
			return ErrNotFound
		}
		if record.Claim != "" && record.ClaimUntil.After(now) {
			return ErrConflict
		}
		var err error
		if len(r.Header.Values("Range")) > 1 {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", record.Manifest.Identity.ContentSize))
			return ErrRange
		}
		start, end, partial, err = parseRange(r.Header.Get("Range"), record.Manifest.Identity.ContentSize)
		if err != nil {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", record.Manifest.Identity.ContentSize))
			return err
		}
		sensitive = oneOf(record.Manifest.Identity.Classification, "confidential", "sensitive")
		if sensitive {
			if e := tx.Audit(ctx, Audit{ID: claim, Action: "evidence.download.intent", EvidenceID: id, ActorID: actor.ID, Start: start, End: end}); e != nil {
				return ErrAudit
			}
		}
		record.Claim = claim
		record.ClaimUntil = now.Add(30 * time.Second)
		record.RowVersion++
		if e := tx.Save(ctx, record); e != nil {
			return e
		}
		if sensitive {
			stepUp, ok := h.Auth.(SensitiveDownloadAuthenticator)
			if !ok {
				return ErrAuth
			}
			if e := stepUp.AuthorizeSensitiveDownload(ctx, r, actor, record, start, end, tx); e != nil {
				return boundary(e)
			}
		}
		return nil
	})
	if e != nil {
		fail(boundary(e))
		return
	}
	ctx = withEvidenceAccess(ctx, "download", record)
	if boundAuth {
		e = bound.AuthorizeDownload(ctx, actor, record)
	}
	var info ObjectInfo
	if e == nil {
		info, e = s.Store.Stat(ctx, record.Ref)
	}
	if e == nil && !matchObject(record, info) {
		e = ErrIntegrity
	}
	var data []byte
	if e == nil {
		data, e = OpenRange(ctx, record.Manifest, record.Ref, s.Store, s.Keys, start, end)
	}
	defer wipe(data)
	if e == nil {
		e = s.Registry.WithLocked(ctx, id, func(tx Locked) error {
			current := tx.Record()
			if current.RowVersion != record.RowVersion || current.Claim != claim || !current.ClaimUntil.After(tx.Time()) || current.State != "ready" || hash(canonical(current.Manifest)) != hash(canonical(record.Manifest)) || current.Ref != record.Ref {
				return ErrConflict
			}
			return tx.Authorize(ctx, actor, permissions(current.Manifest.Identity.Classification))
		})
	}
	if e == nil && boundAuth {
		e = bound.AuthorizeDownload(ctx, actor, record)
	}
	if e != nil {
		s.finishDownload(claim, id, actor, record.RowVersion, sensitive, "rejected", record)
		s.reportDownloadFailure(ctx, id, boundary(e).Error())
		fail(boundary(e))
		return
	}
	w.Header().Set("Content-Type", record.Manifest.Identity.Media)
	w.Header().Set("ETag", `"`+record.Manifest.Identity.ContentHash+`"`)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	if partial {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, record.Manifest.Identity.ContentSize))
		w.WriteHeader(206)
	} else {
		w.WriteHeader(200)
	}
	n, writeErr := w.Write(data)
	outcome := "sent"
	if writeErr != nil || n != len(data) {
		outcome = "interrupted"
	}
	s.finishDownload(claim, id, actor, record.RowVersion, sensitive, outcome, record)
}

// Failure persistence gets its own deadline even when the request or result
// transaction has expired. Values retain the original correlation; this context
// is never reused for SQL authorization or provider access.
func (s Service) reportDownloadFailure(parent context.Context, id, code string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
	defer cancel()
	s.Failure(ctx, id, code)
}

func (s Service) finishDownload(claim, id string, actor Actor, version int64, sensitive bool, outcome string, original Record) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !sensitive {
		if finisher, ok := s.Registry.(interface {
			finishPublicDownload(context.Context, Record) (bool, error)
		}); ok {
			if handled, err := finisher.finishPublicDownload(ctx, original); handled {
				if err != nil {
					s.reportDownloadFailure(ctx, id, "download_audit_or_release_failed")
				}
				return
			}
		}
	}
	e := s.Registry.WithLocked(ctx, id, func(tx Locked) error {
		r := tx.Record()
		if r.RowVersion != version || r.Claim != claim {
			return ErrConflict
		}
		if sensitive {
			if e := tx.Audit(ctx, Audit{ID: claim, Action: "evidence.download.result", EvidenceID: id, ActorID: actor.ID, Outcome: outcome}); e != nil {
				return ErrAudit
			}
		}
		r.Claim = ""
		r.ClaimUntil = time.Time{}
		r.RowVersion++
		return tx.Save(ctx, r)
	})
	if e != nil {
		s.reportDownloadFailure(ctx, id, "download_audit_or_release_failed")
	}
}
