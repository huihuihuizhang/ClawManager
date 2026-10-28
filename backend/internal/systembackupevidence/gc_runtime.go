package systembackupevidence

import (
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// GCRuntimeConfig is trusted deployment admission for one evidence_gc operation.
// It requires the real SQLPolicy, durable Failure sink and C-owned authoritative
// absence verifier. Neither a DELETE response nor 404 substitutes for proof.
type GCRuntimeConfig struct {
	Authority GCAuthorityConfig
	S3        S3STSConfig
	Absence   S3AbsenceVerifier
	Failure   func(context.Context, string, string)
}

type GCRuntime struct {
	authority *SQLGCAuthority
	sts       *S3STSCredentials
	store     *S3Store
	service   Service
	journal   *gcFailureJournal
	closed    atomic.Bool
}

func NewGCRuntime(c GCRuntimeConfig) (*GCRuntime, error) {
	s, a := c.S3.Store, c.Authority
	if nilSystemAdapter(c.Absence) || c.Failure == nil || s.Installation != a.Registry.Installation || s.Identity != a.Store.Identity || s.Version != a.Store.Version || s.Root != a.Root || c.S3.Issuer != a.Issuer || c.S3.Audience != a.Audience {
		return nil, ErrInvalid
	}
	authority, err := NewSQLGCAuthority(a)
	if err != nil {
		return nil, err
	}
	r := &GCRuntime{authority: authority}
	r.sts, err = NewS3STSCredentials(c.S3, authority)
	if err != nil {
		r.Close()
		return nil, err
	}
	r.store, err = NewS3Store(s, r.sts, GCAbsenceVerifier{Authority: authority, Verifier: c.Absence})
	if err != nil {
		r.Close()
		return nil, err
	}
	r.service = Service{Registry: gcRegistry{authority}, Store: gcDeleteStore{r.store}, Failure: c.Failure}
	return r, nil
}

func (r *GCRuntime) AuthenticateRequest(req *http.Request) (context.Context, error) {
	if r == nil || r.closed.Load() || r.journal != nil && r.journal.check() != nil {
		return nil, ErrUnavailable
	}
	return r.authority.AuthenticateRequest(req)
}

// GC handles at most 100 caller-selected hints within one 30-second batch.
// Every candidate revalidates current operation, references and retention. The
// host owns scheduling and operation claim lifecycle; no background goroutine
// or new system operation is manufactured by this runtime.
func (r *GCRuntime) GC(ctx context.Context, ids []string) []error {
	if r == nil || r.closed.Load() || ctx == nil {
		return []error{ErrUnavailable}
	}
	if len(ids) > 100 {
		return []error{ErrCapacity}
	}
	// Keep selected hints and failure associations stable across callbacks.
	// Callers must still avoid concurrent mutation while this copy is made.
	ids = append([]string(nil), ids...)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if r.journal != nil {
		return r.journaledGC(ctx, ids)
	}
	results := r.service.GC(ctx, ids)
	// Persist bounded reconciliation signals even when work was cancelled.
	// One shared budget bounds all callbacks for this batch.
	failureCtx, failureCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer failureCancel()
	for n, err := range results {
		if err != nil && err != ErrConflict && err != ErrState && idPattern.MatchString(ids[n]) && failureCtx.Err() == nil {
			r.service.Failure(failureCtx, ids[n], "evidence_incomplete")
		}
	}
	return results
}

// Drain worker requests before closing. The caller's database remains open.
func (r *GCRuntime) Close() {
	if r != nil && !r.closed.Swap(true) {
		r.store.Close()
		r.sts.Close()
		if r.journal != nil {
			r.journal.storage.Close()
		}
	}
}

type gcDeleteStore struct{ *S3Store }

func (gcDeleteStore) Put(context.Context, Ref, io.Reader, ObjectInfo, time.Time) error {
	return ErrDenied
}
func (gcDeleteStore) Range(context.Context, Ref, int64, int64) (io.ReadCloser, error) {
	return nil, ErrDenied
}
