package systembackupevidence

import (
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// DownloadRuntimeConfig is deployment-owned. Registry.Policy and Failure must
// be real control-plane implementations; no default policy or static token is
// substituted. This constructor does not create providers, routes or identities.
type DownloadRuntimeConfig struct {
	Authority DownloadAuthorityConfig
	S3        S3STSConfig
	Transit   []DownloadTransitConfig
	Failure   func(context.Context, string, string)
	Admission *DownloadAdmissionService
	Results   *SQLDownloadResults
}

// DownloadRuntime is ready to mount at Path on the existing TLS Admin server.
// All provider/key operations use the same SQLDownloadAuthority. The host must
// drain requests before Close, and supply the existing authoritative SQLPolicy.
type DownloadRuntime struct {
	handler   Handler
	admitted  *admittedDownloadHandler
	authority *SQLDownloadAuthority
	sts       *S3STSCredentials
	store     *S3Store
	keys      *DownloadTransit
	journal   *DownloadFailureJournal
	closed    atomic.Bool
}

func NewDownloadRuntime(c DownloadRuntimeConfig) (*DownloadRuntime, error) {
	s, a := c.S3.Store, c.Authority
	if c.Failure == nil || s.Installation != a.Registry.Installation || s.Identity != a.Store.Identity || s.Version != a.Store.Version || s.Root != a.Root || c.S3.Issuer != a.Issuer || c.S3.Audience != a.Audience {
		return nil, ErrInvalid
	}
	authority, err := NewSQLDownloadAuthority(a)
	if err != nil {
		return nil, err
	}
	r := &DownloadRuntime{authority: authority}
	fail := func(err error) (*DownloadRuntime, error) { r.Close(); return nil, err }
	r.sts, err = NewS3STSCredentials(c.S3, authority)
	if err != nil {
		return fail(err)
	}
	// Download cannot invoke absence verification. This explicit denying
	// verifier is not a proof or a fallback for write/GC workflows.
	r.store, err = NewS3Store(s, r.sts, downloadNoAbsence{})
	if err != nil {
		return fail(err)
	}
	r.keys, err = NewDownloadTransit(authority, c.Transit)
	if err != nil {
		return fail(err)
	}
	r.handler = Handler{Auth: authority, Service: Service{Registry: a.Registry, Store: downloadReadStore{r.store}, Keys: r.keys, Failure: c.Failure}, publicOnly: true}
	if c.Admission != nil || c.Results != nil {
		r.admitted, err = newAdmittedDownloadHandler(c.Admission, authority, c.Results, r.handler.Service, r.handler)
		if err != nil {
			return fail(err)
		}
	}
	return r, nil
}

func (r *DownloadRuntime) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if r == nil || r.closed.Load() || r.journal != nil && r.journal.Check() != nil {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, `{"code":"artifact_unavailable","message":"artifact_unavailable"}`)
		return
	}
	if r.admitted != nil {
		r.admitted.ServeHTTP(w, req)
		return
	}
	r.handler.ServeHTTP(w, req)
}
func (r *DownloadRuntime) Close() {
	if r != nil && !r.closed.Swap(true) {
		r.keys.Close()
		r.store.Close()
		r.sts.Close()
		if r.authority != nil {
			wipe(r.authority.c.JWTSecret)
		}
		if r.journal != nil {
			r.journal.Close()
		}
	}
}

type downloadNoAbsence struct{}

func (downloadNoAbsence) VerifyAbsent(context.Context, S3AbsenceRequest) (S3AbsenceProof, error) {
	return S3AbsenceProof{}, ErrDenied
}

type downloadReadStore struct{ *S3Store }

func (downloadReadStore) Put(context.Context, Ref, io.Reader, ObjectInfo, time.Time) error {
	return ErrDenied
}
func (downloadReadStore) Delete(context.Context, Ref, ObjectInfo) error { return ErrDenied }
func (downloadReadStore) Absent(context.Context, Ref) (Absence, error)  { return Absence{}, ErrDenied }
