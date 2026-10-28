package systembackupevidence

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"regexp"
	"strings"
	"time"
)

type Actor struct{ ID, Session string }
type Audit struct {
	ID, Action, EvidenceID, ActorID, Outcome string
	Start, End                               int64
}

// Locked is a transaction-scoped control-plane capability. Record/Time,
// authorization, owner/reference checks, audit and Save MUST share one DB
// transaction. Save is row-version CAS; WithLocked commits only on nil error.
// Implementations must lock current references and disallow new references to
// deleting/deleted rows. No reference/permission facts come from API input.
type Locked interface {
	Record() Record
	Time() time.Time
	Authorize(context.Context, Actor, []string) error
	Audit(context.Context, Audit) error
	Save(context.Context, Record) error
	// Deletable proves owner terminal, no owner/retry/report/health/promotion/
	// hold/read-lease references, and required control metadata retention.
	Deletable(context.Context) error
}
type Registry interface {
	WithLocked(context.Context, string, func(Locked) error) error
	// PersistPending atomically validates task ownership/deadline, redaction
	// policy, retention and capacity, then INSERTs record + all chunks. It may
	// not allow replacing a previously registered public ID or staged bytes.
	PersistPending(context.Context, Record) error
}

type ObjectInfo struct {
	Version, SHA256 string
	Size            int64
}
type Absence struct {
	Authoritative bool
	Version       string
}

// Store is a trusted C-owned provider adapter. It must bind endpoint/root/CA
// and scoped identities out of band. Put is exact-key conditional create, with
// body SHA256, content-length and expiry; no listing, unversioned delete or URI
// accepted from an Admin. Ordinary 404 cannot produce Authoritative absence.
type Store interface {
	ObjectReader
	Stat(context.Context, Ref) (ObjectInfo, error)
	Put(context.Context, Ref, io.Reader, ObjectInfo, time.Time) error
	Delete(context.Context, Ref, ObjectInfo) error
	Absent(context.Context, Ref) (Absence, error)
}

type Service struct {
	Registry Registry
	Store    Store
	Keys     Keys
	// Failure persists a bounded degradation/reconciliation signal when a
	// post-response audit or remote result cannot be saved. Mandatory in HTTP.
	Failure func(context.Context, string, string)
}

func safeKey(s string) bool {
	if len(s) == 0 || len(s) > 1024 || !regexp.MustCompile(`^[A-Za-z0-9._/-]+$`).MatchString(s) || strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}
func keyFor(root string, i Identity) (string, error) {
	key := strings.TrimSuffix(root, "/") + "/" + i.Installation + "/" + i.OwnerType + "/" + i.OwnerID + "/" + i.ID + "/" + i.ContentHash + ".bin"
	if !safeKey(root) || !i.validExternal() || !safeKey(key) {
		return "", ErrInvalid
	}
	return key, nil
}
func claimID() (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", ErrUnavailable
	}
	return "aev_" + hex.EncodeToString(b), nil
}
func validRecord(r Record) bool {
	return validateManifest(r.Manifest) == nil && r.Ref.valid(false) && r.RowVersion >= 1 && !r.CreatedAt.IsZero() && r.ExpiresAt.After(r.CreatedAt) && r.OwnerDeadline.After(r.CreatedAt)
}
func matchObject(r Record, o ObjectInfo) bool {
	return o.Version != "" && o.Version != "null" && len(o.Version) <= 256 && o.SHA256 == r.Manifest.ObjectHash && o.Size == r.Manifest.ObjectSize && (r.Ref.ImmutableVersion == "" || r.Ref.ImmutableVersion == o.Version)
}
func permissions(c string) []string {
	switch c {
	case "public", "internal":
		return []string{"system_backup.read"}
	case "confidential":
		return []string{"system_backup.read", "system_backup.operate"}
	case "sensitive":
		return []string{"system_backup.read", "system_backup.security_configure"}
	}
	return nil
}

// Register registers immutable ciphertext intent only. Caller must supply
// configuration-derived retention; the registry rechecks it against locked
// owner/config. All classifications are encrypted, including public/internal.
func (s Service) Register(ctx context.Context, p Prepared, root string, ref Ref, created, expires, protected, deadline time.Time) error {
	m := p.Manifest()
	key, e := keyFor(root, m.Identity)
	if e != nil || s.Registry == nil || ref.ImmutableVersion != "" {
		return ErrInvalid
	}
	ref.RelativeKey = key
	r := Record{Manifest: m, Ref: ref, State: "pending", Failure: "none", RowVersion: 1, CreatedAt: created, ExpiresAt: expires, ProtectedUntil: protected, OwnerDeadline: deadline}
	if !validRecord(r) {
		return ErrInvalid
	}
	return boundaryOrNil(s.Registry.PersistPending(ctx, r))
}
func boundaryOrNil(e error) error {
	if e == nil {
		return nil
	}
	return boundary(e)
}

// Publish uses the original ciphertext staging (not a fresh encryption). A
// claim is committed before any external write. Lost write results converge
// using exact immutable Stat; failures never manufacture absence or readiness.
func (s Service) Publish(ctx context.Context, id string, staged Source) error {
	if s.Registry == nil || s.Store == nil || !idPattern.MatchString(id) {
		return ErrInvalid
	}
	claim, e := claimID()
	if e != nil {
		return e
	}
	var r Record
	e = s.Registry.WithLocked(ctx, id, func(tx Locked) error {
		r = tx.Record()
		now := tx.Time()
		if !validRecord(r) || r.Manifest.Identity.ID != id {
			return ErrIntegrity
		}
		if !oneOf(r.State, "pending", "write_unknown") {
			return ErrState
		}
		if r.Claim != "" && r.ClaimUntil.After(now) {
			return ErrConflict
		}
		r.Claim = claim
		r.ClaimUntil = now.Add(30 * time.Second)
		r.RowVersion++
		return tx.Save(ctx, r)
	})
	if e != nil {
		return boundary(e)
	}
	ctx = withEvidenceAccess(ctx, "task", r)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	info, statErr := s.Store.Stat(ctx, r.Ref)
	if statErr == nil {
		return s.writeResult(ctx, r, info, nil)
	}
	// Reissue only on an authoritative exact-key absence, with original bytes
	// and a DB-checked live owner deadline. Unknown absence stays recoverable.
	absent, ae := s.Store.Absent(ctx, r.Ref)
	var writeAllowed bool
	e = s.Registry.WithLocked(ctx, id, func(tx Locked) error {
		current := tx.Record()
		now := tx.Time()
		if current.RowVersion != r.RowVersion || current.Claim != claim || !current.ClaimUntil.After(now) {
			return ErrConflict
		}
		writeAllowed = now.Before(current.OwnerDeadline)
		return nil
	})
	if e != nil {
		return boundary(e)
	}
	if ae != nil || !absent.Authoritative || !writeAllowed || staged == nil {
		return s.writeResult(ctx, r, ObjectInfo{}, ErrUnavailable)
	}
	reader, e := staged()
	if e != nil || reader == nil {
		return s.writeResult(ctx, r, ObjectInfo{}, ErrUnavailable)
	}
	defer reader.Close()
	// The provider verifies exact hash/length before accepting conditional PUT.
	e = s.Store.Put(ctx, r.Ref, reader, ObjectInfo{SHA256: r.Manifest.ObjectHash, Size: r.Manifest.ObjectSize}, r.OwnerDeadline)
	info, statErr = s.Store.Stat(ctx, r.Ref)
	if statErr == nil {
		return s.writeResult(ctx, r, info, nil)
	}
	if e == ErrIntegrity || e == ErrDenied {
		return s.writeResult(ctx, r, ObjectInfo{}, e)
	}
	return s.writeResult(ctx, r, ObjectInfo{}, ErrUnavailable)
}
func (s Service) writeResult(ctx context.Context, claimed Record, info ObjectInfo, result error) error {
	if result == nil && !matchObject(claimed, info) {
		result = ErrIntegrity
	}
	e := s.Registry.WithLocked(ctx, claimed.Manifest.Identity.ID, func(tx Locked) error {
		r := tx.Record()
		if r.RowVersion != claimed.RowVersion || r.Claim != claimed.Claim || !r.ClaimUntil.After(tx.Time()) {
			return ErrConflict
		}
		switch result {
		case nil:
			r.State = "ready"
			r.Failure = "none"
			r.Ref.ImmutableVersion = info.Version
		case ErrIntegrity:
			r.State = "write_failed"
			r.Failure = "checksum_mismatch"
		case ErrDenied:
			r.State = "write_failed"
			r.Failure = "permission_denied"
		default:
			r.State = "write_unknown"
			r.Failure = "provider_unavailable"
		}
		r.Claim = ""
		r.ClaimUntil = time.Time{}
		r.RowVersion++
		return tx.Save(ctx, r)
	})
	if e != nil {
		return boundary(e)
	}
	return result
}

// GC handles a bounded caller-selected batch (IDs from D's expiry scanner).
// Each candidate takes an atomic reference/retention check before deleting.
// Missing/failed provider proofs leave durable delete_failed + typed ref.
func (s Service) GC(ctx context.Context, ids []string) []error {
	if len(ids) > 100 {
		return []error{ErrCapacity}
	}
	results := make([]error, len(ids))
	for i, id := range ids {
		results[i] = s.collect(ctx, id)
	}
	return results
}
func (s Service) collect(ctx context.Context, id string) error {
	if s.Registry == nil || s.Store == nil || !idPattern.MatchString(id) {
		return ErrInvalid
	}
	claim, e := claimID()
	if e != nil {
		return e
	}
	var r Record
	e = s.Registry.WithLocked(ctx, id, func(tx Locked) error {
		r = tx.Record()
		now := tx.Time()
		if r.State == "deleted" && r.Manifest.Identity.ID == id {
			return nil
		}
		if !validRecord(r) || r.Manifest.Identity.ID != id {
			return ErrIntegrity
		}
		if !oneOf(r.State, "ready", "delete_failed", "deleting", "write_failed") {
			return ErrState
		}
		if now.Before(r.ExpiresAt) || now.Before(r.ProtectedUntil) || r.Claim != "" && r.ClaimUntil.After(now) {
			return ErrConflict
		}
		if e := tx.Deletable(ctx); e != nil {
			return boundary(e)
		}
		// write_failed may describe a mismatching object. Never delete it or
		// claim absence using its untrusted observed version.
		if r.State == "write_failed" {
			return ErrState
		}
		if !r.Ref.valid(true) {
			return ErrIntegrity
		}
		r.State = "deleting"
		r.Failure = "none"
		r.Claim = claim
		r.ClaimUntil = now.Add(30 * time.Second)
		r.RowVersion++
		if e := tx.Audit(ctx, Audit{ID: claim, Action: "evidence.gc.intent", EvidenceID: id}); e != nil {
			return ErrAudit
		}
		return tx.Save(ctx, r)
	})
	if e != nil {
		return boundary(e)
	}
	if r.State == "deleted" {
		return nil
	}
	ctx = withEvidenceAccess(ctx, "gc", r)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	info, readErr := s.Store.Stat(ctx, r.Ref)
	result := readErr
	if readErr == nil {
		if !matchObject(r, info) {
			result = ErrIntegrity
		} else {
			result = s.Store.Delete(ctx, r.Ref, info)
		}
	}
	absence, absenceErr := s.Store.Absent(ctx, r.Ref)
	if absenceErr == nil && absence.Authoritative && absence.Version == r.Ref.ImmutableVersion && result != ErrIntegrity {
		result = nil
	} else if result == nil {
		result = ErrUnavailable
	}
	e = s.Registry.WithLocked(ctx, id, func(tx Locked) error {
		current := tx.Record()
		if current.RowVersion != r.RowVersion || current.Claim != claim || !current.ClaimUntil.After(tx.Time()) {
			return ErrConflict
		}
		if result == nil {
			// Recheck references and retention before discarding immutable refs.
			// Provider latency may overlap a hold or control-plane policy change.
			if tx.Time().Before(current.ExpiresAt) || tx.Time().Before(current.ProtectedUntil) {
				return ErrConflict
			}
			if e := tx.Deletable(ctx); e != nil {
				return boundary(e)
			}
			current.State = "deleted"
			current.Failure = "none"
			current.Ref = Ref{}
			current.Manifest.Chunks = nil
		} else {
			current.State = "delete_failed"
			current.Failure = "provider_unavailable"
			if result == ErrIntegrity {
				current.Failure = "checksum_mismatch"
			}
			if result == ErrDenied {
				current.Failure = "permission_denied"
			}
		}
		current.Claim = ""
		current.ClaimUntil = time.Time{}
		current.RowVersion++
		outcome := "deleted"
		if result != nil {
			outcome = "delete_failed"
		}
		if e := tx.Audit(ctx, Audit{ID: claim, Action: "evidence.gc.result", EvidenceID: id, Outcome: outcome}); e != nil {
			return ErrAudit
		}
		return tx.Save(ctx, current)
	})
	if e != nil {
		return boundary(e)
	}
	return boundaryOrNil(result)
}
