package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/systembackup/worker"
)

// Root-validated R2 prefix, integrated for root's real SQL/RPC validation.
// This adds one old/new pair inside ONE original database key-check RPC after
// its original key-begin. There is no extra key window, task, source shortcut,
// provider operation or bypass of the production downstream authorizer.
type originalPrefixRPCQueryKey struct{}
type originalPrefixRPCQueryScope struct {
	mu       sync.Mutex
	current  *originalPrefixRPCQueries
	deadline time.Time
	bounded  bool
}

func (s *originalPrefixRPCQueryScope) observe(ctx context.Context, query string) {
	s.mu.Lock()
	current := s.current
	s.mu.Unlock()
	if current == nil {
		return
	}
	deadline, bounded := ctx.Deadline()
	current.observe(query, bounded == s.bounded && deadline.Equal(s.deadline))
}

func (s *originalPrefixRPCQueryScope) selectQueries(current *originalPrefixRPCQueries) {
	s.mu.Lock()
	s.current = current
	s.mu.Unlock()
}

type originalPrefixRPCQueries struct {
	mu                    sync.Mutex
	total, prefix         uint64
	changedPrefixDeadline bool
}

func (p *originalPrefixRPCQueries) observe(query string, originalDeadline bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.total++
	if strings.Contains(query, "FROM (SELECT engine FROM system_backup_v2_engine_bindings") {
		p.prefix++
		p.changedPrefixDeadline = p.changedPrefixDeadline || !originalDeadline
	}
}
func (p *originalPrefixRPCQueries) snapshot() (uint64, uint64, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.total, p.prefix, p.changedPrefixDeadline
}

type originalPrefixRPCComparison struct {
	owner                                                      *PublicJobOwner
	t                                                          *testing.T
	afterBegin, chosen                                         atomic.Bool
	mu                                                         sync.Mutex
	beginInvocation, beginPoint                                string
	beginUntil                                                 time.Time
	paired                                                     bool
	failure                                                    string
	beforeQueries, afterQueries, beforePrefixes, afterPrefixes uint64
	beforeNanos, afterNanos                                    int64
}

func (p *originalPrefixRPCComparison) authorizeWithNext(ctx context.Context, peer string, request worker.ControlRequest, next worker.Authorizer) (worker.Lease, error) {
	database := request.Invocation.Request.Database != nil && request.Invocation.ProviderKey != nil && request.Invocation.FormalCapture != nil
	p.mu.Lock()
	sameKeyBegin := p.beginInvocation == request.InvocationSHA256 && p.beginPoint == request.Point && !p.beginUntil.IsZero()
	beginUntil := p.beginUntil
	p.mu.Unlock()
	if !database || request.Action != "key-check" || !p.afterBegin.Load() || !sameKeyBegin || !p.chosen.CompareAndSwap(false, true) {
		lease, err := next.Authorize(ctx, peer, request)
		if database && request.Action == "key-begin" && err == nil && lease.KeyUse != nil && lease.KeyUse.State == "using" {
			p.mu.Lock()
			if p.beginInvocation == "" {
				p.beginInvocation, p.beginPoint, p.beginUntil = request.InvocationSHA256, request.Point, lease.KeyUse.Until
			}
			p.mu.Unlock()
			p.afterBegin.Store(true)
		}
		return lease, err
	}
	beforeCount, afterCount := &originalPrefixRPCQueries{}, &originalPrefixRPCQueries{}
	deadline, bounded := ctx.Deadline()
	queries := &originalPrefixRPCQueryScope{current: beforeCount, deadline: deadline, bounded: bounded}
	// BOTH complete implementations receive this exact same request context.
	// Its parent is the original authenticated HTTP context, with the original
	// deadline/cancellation and bound Pod. Only diagnostic query counters differ.
	pairedCtx := context.WithValue(ctx, originalPrefixRPCQueryKey{}, queries)
	pairedDeadline, pairedBounded := pairedCtx.Deadline()
	originalPod, podOK := boundPod(ctx)
	pairedPod, pairedPodOK := boundPod(pairedCtx)
	if pairedBounded != bounded || !pairedDeadline.Equal(deadline) || pairedCtx.Done() != ctx.Done() || !podOK || !pairedPodOK || originalPod != pairedPod {
		p.recordFailure("original_request_context_changed")
		return worker.Lease{}, errors.New("original control RPC context was changed")
	}
	started := time.Now()
	before, err := p.owner.authorizeOriginalControl(pairedCtx, peer, request, false)
	beforeNanos := time.Since(started).Nanoseconds()
	defer before.Clear()
	if err != nil {
		p.recordFailure("original_authorize_refused")
		return worker.Lease{}, err
	}
	queries.selectQueries(afterCount)
	started = time.Now()
	after, err := next.Authorize(pairedCtx, peer, request)
	afterNanos := time.Since(started).Nanoseconds()
	if err != nil {
		after.Clear()
		p.recordFailure("candidate_authorize_refused")
		return worker.Lease{}, err
	}
	want, wantErr := json.Marshal(before)
	got, gotErr := json.Marshal(after)
	if wantErr != nil || gotErr != nil || !bytes.Equal(want, got) || before.KeyUse == nil || before.KeyUse.State != "using" || after.KeyUse == nil || !before.KeyUse.Until.Equal(beginUntil) || !after.KeyUse.Until.Equal(beginUntil) || !before.ExpiresAt.Equal(after.ExpiresAt) {
		after.Clear()
		p.recordFailure("original_lease_identity_or_until_changed")
		return worker.Lease{}, errors.New("original control RPC differential changed original lease")
	}
	bq, bp, oldDeadlineChanged := beforeCount.snapshot()
	aq, ap, newDeadlineChanged := afterCount.snapshot()
	if bp != 0 || ap < 3 || aq >= bq || oldDeadlineChanged || newDeadlineChanged {
		after.Clear()
		p.recordFailure("missing_fresh_path_or_query_reduction")
		return worker.Lease{}, errors.New("original control RPC differential did not execute fresh prefix reduction")
	}
	p.mu.Lock()
	p.paired = true
	p.beforeQueries, p.afterQueries, p.beforePrefixes, p.afterPrefixes = bq, aq, bp, ap
	p.beforeNanos, p.afterNanos = beforeNanos, afterNanos
	p.mu.Unlock()
	p.t.Logf("same-RPC original/candidate Authorize DATA old_queries=%d new_queries=%d old_prefixes=%d new_fresh_prefixes=%d old_elapsed_ns=%d new_elapsed_ns=%d same_request_context=true original_deadline_unchanged=true original_until_unchanged=true original_window_extended=false", bq, aq, bp, ap, beforeNanos, afterNanos)
	return after, nil
}
func (p *originalPrefixRPCComparison) recordFailure(stage string) {
	p.mu.Lock()
	p.failure = stage
	p.mu.Unlock()
	p.t.Log("same-RPC original prefix differential refused", stage)
}

// Only the original fixture's ROOT control endpoint is wrapped. WorkloadIdentity
// still performs the original TokenReview/Pod/SA checks; ControlHandler still
// verifies the original mTLS peer and decodes the same request. The concrete
// production deploymentControlAuthorizer remains the downstream delegate.
// All non-root routes and the nil-option path use the original handler intact.
func serveDOriginalControlWithAuthorizer(f *dOriginalSixPartTask, options dOriginalSixPartFixtureOptions, w http.ResponseWriter, r *http.Request) {
	if options.WrapOriginalControlAuthorizer == nil || r.URL.Path != "/" {
		f.service.controlHandler().ServeHTTP(w, r)
		return
	}
	o := f.service.Runtime.Owner
	next := options.WrapOriginalControlAuthorizer(deploymentControlAuthorizer{service: f.service, owner: o})
	if next == nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	handler := WorkloadIdentity{Client: o.Client, Namespace: o.Namespace, ServiceAccount: o.Security.ServiceAccountName, ServiceAccountUID: o.Security.ServiceAccountUID, Next: worker.ControlHandler{Authorizer: next}}
	handler.ServeHTTP(w, r)
}

// This is the complete ORIGINAL capture fixture with one extra diagnostic pair.
// It does not certify final publication or installed provider authority. The
// original thirty-second callback budget remains strict, including this pair.
func TestOriginalHeldPrefixSameRPCControlDifferentialMySQL(t *testing.T) {
	// The explicit description protocol requires a finite process allowance.
	// Model the same 4 GiB Go process limit as the existing description and
	// publication fixtures; production startup validates the real limit itself.
	previousMemory := debug.SetMemoryLimit(4 << 30)
	defer debug.SetMemoryLimit(previousMemory)
	var pair *originalPrefixRPCComparison
	options := dOriginalSixPartFixtureOptions{CaptureDescription: true}
	options.AfterOwnerReady = func(_ context.Context, _ *testing.T, f *dOriginalSixPartTask) error {
		pair = &originalPrefixRPCComparison{owner: f.owner, t: t}
		return nil
	}
	options.WrapOriginalControlAuthorizer = func(next worker.Authorizer) worker.Authorizer {
		// One immutable production downstream per wrapper is used only on its
		// synchronous handler call; concurrent requests share diagnostic counters,
		// never replace the delegate retained by another request.
		return originalPrefixRPCDelegate{pair: pair, next: next}
	}
	options.ControlBeforeQuery = func(ctx context.Context, query string) error {
		if observed, ok := ctx.Value(originalPrefixRPCQueryKey{}).(*originalPrefixRPCQueryScope); ok && observed != nil {
			observed.observe(ctx, query)
		}
		return nil
	}
	runDOriginalSixPartCaptureWithOptions(t, false, true, options, nil)
	if pair == nil {
		t.Fatal("original owner comparison not composed")
	}
	pair.mu.Lock()
	defer pair.mu.Unlock()
	if !pair.paired || pair.failure != "" {
		t.Fatal("missing actual same-RPC current authority comparison", pair.failure)
	}
}

type originalPrefixRPCDelegate struct {
	pair *originalPrefixRPCComparison
	next worker.Authorizer
}

func (d originalPrefixRPCDelegate) Authorize(ctx context.Context, peer string, request worker.ControlRequest) (worker.Lease, error) {
	if d.pair == nil || d.next == nil {
		return worker.Lease{}, worker.ErrExecution
	}
	return d.pair.authorizeWithNext(ctx, peer, request, d.next)
}
