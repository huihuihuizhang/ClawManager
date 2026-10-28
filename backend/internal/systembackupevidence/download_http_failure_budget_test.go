package systembackupevidence

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type downloadBudgetFailStore struct {
	*testStore
	cancel context.CancelFunc
	seen   context.Context
	calls  int
}

func (s *downloadBudgetFailStore) Stat(ctx context.Context, _ Ref) (ObjectInfo, error) {
	s.calls++
	s.seen = ctx
	if s.cancel != nil {
		s.cancel()
	}
	return ObjectInfo{}, errors.New("private provider address and credential")
}

func downloadBudgetRequest(ctx context.Context, id string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, Path+id, nil).WithContext(ctx)
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Range", "bytes=0-15")
	return r
}

func checkDownloadFailureBudget(t *testing.T, ctx context.Context) {
	t.Helper()
	if ctx.Err() != nil {
		t.Error("failure sink inherited cancellation or exhausted result budget")
	}
	until, ok := ctx.Deadline()
	if remaining := time.Until(until); !ok || remaining <= 0 || remaining > 5*time.Second || ctx.Done() == nil {
		t.Error("failure sink lacks an independent finite five-second budget")
	}
}

func TestDownloadHTTPFailureIndependentBudget(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		name := "live_request"
		if canceled {
			name = "canceled_provider_request"
		}
		t.Run(name, func(t *testing.T) {
			s, m, store, _, _ := serviceFixture(t)
			j := failureJournalFixture(t)
			ref := journalReference()
			base := context.WithValue(context.Background(), downloadFailureReferenceKey{}, ref)
			requestCtx, cancel := context.WithCancel(base)
			defer cancel()
			provider := &downloadBudgetFailStore{testStore: store}
			if canceled {
				provider.cancel = cancel
			}
			s.Store = provider
			var auditCtx context.Context
			calls := 0
			s.Failure = func(ctx context.Context, id, code string) {
				calls++
				auditCtx = ctx
				checkDownloadFailureBudget(t, ctx)
				if got, ok := DownloadFailureReferenceFrom(ctx); !ok || got != ref {
					t.Error("original failure correlation lost")
				}
				if id != m.r.Manifest.Identity.ID || code != ErrUnavailable.Error() {
					t.Error("failure identity or closed error code changed")
				}
				if err := j.Append(ctx, id, code); err != nil {
					t.Error("independent failure journal write rejected", err)
				}
			}
			w := httptest.NewRecorder()
			Handler{Service: s, Auth: testAuth{}}.ServeHTTP(w, downloadBudgetRequest(requestCtx, m.r.Manifest.Identity.ID))
			if calls != 1 || auditCtx == nil || auditCtx.Err() != context.Canceled {
				t.Error("failure callback count or completed budget cleanup")
			}
			if w.Code != 503 || strings.Contains(w.Body.String(), "private") || w.Header().Get("ETag") != "" || store.reads != 0 || provider.calls != 1 {
				t.Error("provider failure changed rejection or exposed plaintext/private cause")
			}
			if provider.seen == auditCtx || provider.seen == nil || (canceled && provider.seen.Err() == nil) {
				t.Error("failure budget escaped into provider authorization")
			}
			if m.r.Claim != "" || len(m.audits) != 2 || m.audits[1].Outcome != "rejected" {
				t.Error("original result audit or claim release changed")
			}
			data, err := os.ReadFile(j.config.Path)
			var entry recoveryAuditJournalEntry
			if err != nil || json.Unmarshal(data, &entry) != nil || entry.Download == nil || entry.Download.Reference == nil || *entry.Download.Reference != ref || j.Check() != nil {
				t.Error("durable failure record or original correlation missing")
			}
		})
	}
}

func TestDownloadHTTPFailureJournalQueueDeadline(t *testing.T) {
	s, m, store, _, _ := serviceFixture(t)
	j := failureJournalFixture(t)
	j.journal.mu.Lock()
	var once sync.Once
	unlock := func() { once.Do(j.journal.mu.Unlock) }
	defer unlock()
	requestCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Store = &downloadBudgetFailStore{testStore: store, cancel: cancel}
	var auditCtx context.Context
	var appendErr error
	calls := 0
	s.Failure = func(ctx context.Context, id, code string) {
		calls++
		auditCtx = ctx
		appendErr = j.Append(ctx, id, code)
	}
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		Handler{Service: s, Auth: testAuth{}}.ServeHTTP(w, downloadBudgetRequest(requestCtx, m.r.Manifest.Identity.ID))
	}()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		// The counterfactual must also release and join its owned handler.
		unlock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("handler did not finish after releasing journal writer")
		}
		t.Fatal("download failure waited beyond its journal queue budget")
	}
	unlock()
	if calls != 1 || auditCtx == nil || auditCtx.Err() != context.DeadlineExceeded || appendErr != ErrUnavailable || !j.journal.poisoned.Load() || j.Check() == nil {
		t.Error("expired queue failed to return and latch durable failure")
	}
	if w.Code != 503 || store.reads != 0 || strings.Contains(w.Body.String(), "private") {
		t.Error("failed audit restored download or leaked private cause")
	}
	data, err := os.ReadFile(j.config.Path)
	if err != nil || len(data) != 0 || j.Append(context.Background(), m.r.Manifest.Identity.ID, ErrUnavailable.Error()) != ErrUnavailable {
		t.Error("timed-out report wrote later or restored journal readiness")
	}
}

type downloadBudgetTimedOutRegistry struct{ *memoryRegistry }

func (r downloadBudgetTimedOutRegistry) WithLocked(ctx context.Context, _ string, _ func(Locked) error) error {
	<-ctx.Done()
	return ctx.Err()
}

type downloadBudgetPublicResultRegistry struct{ *memoryRegistry }

func (r downloadBudgetPublicResultRegistry) finishPublicDownload(context.Context, Record) (bool, error) {
	return true, errors.New("private SQL result failure")
}

func TestDownloadResultFailureIndependentBudget(t *testing.T) {
	for _, name := range []string{"expired_result_transaction", "public_result_failure"} {
		t.Run(name, func(t *testing.T) {
			s, m, store, _, _ := serviceFixture(t)
			j := failureJournalFixture(t)
			sensitive := name == "expired_result_transaction"
			if sensitive {
				s.Registry = downloadBudgetTimedOutRegistry{m}
			} else {
				s.Registry = downloadBudgetPublicResultRegistry{m}
			}
			calls := 0
			var auditCtx context.Context
			s.Failure = func(ctx context.Context, id, code string) {
				calls++
				auditCtx = ctx
				checkDownloadFailureBudget(t, ctx)
				if code != "download_audit_or_release_failed" || id != m.r.Manifest.Identity.ID {
					t.Error("result failure code or identity changed")
				}
				if err := j.Append(ctx, id, code); err != nil {
					t.Error("failed result transaction silenced durable failure sink", err)
				}
			}
			before := m.r
			s.finishDownload("claim", m.r.Manifest.Identity.ID, Actor{"admin", "session"}, m.r.RowVersion, sensitive, "interrupted", m.r)
			if calls != 1 || auditCtx == nil || auditCtx.Err() != context.Canceled || j.Check() != nil {
				t.Error("result failure did not receive and release a fresh audit budget")
			}
			if m.r.RowVersion != before.RowVersion || m.r.Claim != before.Claim || store.reads != 0 || len(m.audits) != 0 {
				t.Error("failed result changed original facts or retried provider effects")
			}
			data, err := os.ReadFile(j.config.Path)
			var entry recoveryAuditJournalEntry
			if err != nil || json.Unmarshal(data, &entry) != nil || entry.Download == nil || entry.Download.Code != "download_audit_or_release_failed" {
				t.Error("result failure durable record missing")
			}
		})
	}
}
