package worker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	k "clawreef/internal/systembackupkms"
	w "clawreef/internal/systembackupwire"
)

var keyUseHash = regexp.MustCompile(`^[a-f0-9]{64}$`)
var keyUseNonce = regexp.MustCompile(`^[a-f0-9]{32}$`)
var keyUseName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// KeyUseLease is a public observation on the ORIGINAL Job row, not a bearer
// grant. Every request still requires mTLS, TokenReview and the original SQL
// claim/fence and live Job. No provider credential or DEK travels this channel.
type KeyUseLease struct {
	Identity        k.JobIdentity `json:"identity"`
	Access          k.Access      `json:"access"`
	AuthoritySHA256 string        `json:"authority_sha256"`
	Nonce           string        `json:"nonce"`
	Until           time.Time     `json:"until"`
	State           string        `json:"state"`
}

func validKeyUseRequest(r ControlRequest) bool {
	a := r.Invocation.ProviderKey
	if a == nil || a.Operation != k.Generate || !strings.HasPrefix(r.Invocation.Request.Operation, "capture-") || r.Result != nil {
		return false
	}
	if _, e := k.TransitContext(a.Request); e != nil {
		return false
	}
	u, e := url.Parse(a.Endpoint)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || strings.ContainsAny(a.Endpoint, "?#\r\n") || !keyUseName.MatchString(a.KeyName) {
		return false
	}
	b, c := r.Invocation.Request.Binding, a.Request.Context
	if c.BackupPublicID != b.BackupID || c.AttemptNo != b.Attempt || c.Phase != "capture" || c.Part != b.Path || c.PartIndex != strconv.FormatUint(uint64(b.PartIndex), 10) || c.EnvelopeID != b.EnvelopeID || c.CaptureContextHash != b.CaptureContextHash {
		return false
	}
	if r.Action == "candidate" {
		return keyUseNonce.MatchString(r.Point) && ValidateFormalCaptureResult(r.Invocation, r.Candidate)
	}
	if r.Candidate != nil {
		return false
	}
	switch r.Action {
	case "ready":
		return r.Point == ""
	case "key-reserve", "key-check", "key-begin", "key-end":
		return keyUseNonce.MatchString(r.Point)
	}
	return false // never fall back to functional acquire/complete or restore
}

func validKeyUseLease(l Lease, r ControlRequest) bool {
	v := l.KeyUse
	if r.Action == "ready" {
		return v == nil && len(l.DEK) == 0 && l.Database == nil && l.CandidateSHA256 == ""
	}
	if v == nil || len(l.DEK) != 0 || l.Database != nil || v.Access != *r.Invocation.ProviderKey || v.Nonce != r.Point || !v.Until.Equal(l.ExpiresAt) || !keyUseHash.MatchString(v.AuthoritySHA256) {
		return false
	}
	i := v.Identity
	if i.Namespace == "" || i.PodUID == "" || i.ServiceAccountUID == "" || i.JobUID == "" || i.InvocationSHA256 != r.InvocationSHA256 || !keyUseHash.MatchString(i.ExecutionGrantSHA256) {
		return false
	}
	if r.Action == "candidate" {
		return v.State == "finished" && l.CandidateSHA256 == FormalCandidateSHA256(r.Invocation, r.Candidate) && keyUseHash.MatchString(l.CandidateSHA256)
	}
	if l.CandidateSHA256 != "" {
		return false
	}
	switch r.Action {
	case "key-reserve":
		return v.State == "reserved"
	case "key-begin":
		return v.State == "using"
	case "key-end":
		return v.State == "finished"
	case "key-check":
		return v.State == "reserved" || v.State == "using" || v.State == "finished"
	}
	return false
}

// OriginalKeyAuthority is composed IN the original Job. Reserve is persisted
// before provider I/O; begin is linearized against Revoke on the original Job
// row. Revoke stops new admission, while StopJob/Stopped (not the revoked flag)
// proves that an already admitted local callback has ended. This is a bounded
// use window, not a SQL transaction held over network/streaming capture.
type OriginalKeyAuthority struct {
	client     *ControlClient
	invocation Invocation
	lease      KeyUseLease
	mu         sync.Mutex
	failed     bool
	used       bool
	delivery   k.DeliveredProviderPermit
}

func NewOriginalKeyAuthority(ctx context.Context, client *ControlClient, invocation Invocation) (*OriginalKeyAuthority, error) {
	if ctx == nil || ctx.Err() != nil || client == nil || invocation.ProviderKey == nil {
		return nil, ErrExecution
	}
	// Copy all nested mutable invocation fields; later caller mutation cannot
	// redirect a previously admitted use or silently change its identity.
	raw, e := json.Marshal(invocation)
	var frozen Invocation
	if e != nil || json.Unmarshal(raw, &frozen) != nil {
		return nil, ErrExecution
	}
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		return nil, ErrExecution
	}
	hash, _ := frozen.Hash()
	request := ControlRequest{Invocation: frozen, InvocationSHA256: hash, Action: "key-reserve", Point: hex.EncodeToString(nonce)}
	var l Lease
	dynamic := frozen.FormalCapture != nil && frozen.FormalCapture.PermitDelivery != nil
	if dynamic {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, frozen.Request.Deadline)
		defer cancel()
	}
	for tries := 0; ; tries++ {
		l, e = client.send(ctx, request)
		if !dynamic || !errors.Is(e, ErrNotReady) || tries >= 2 || ctx.Err() != nil {
			break
		}
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			e = ctx.Err()
		case <-timer.C:
		}
		if ctx.Err() != nil {
			break
		}
	}
	defer l.Clear()
	if e != nil || l.KeyUse == nil {
		if errors.Is(e, ErrNotReady) {
			return nil, k.ErrUnknown
		}
		return nil, ErrExecution
	}
	result := &OriginalKeyAuthority{client: client, invocation: frozen, lease: *l.KeyUse}
	if dynamic {
		if l.ProviderPermit == nil {
			return nil, ErrExecution
		}
		result.delivery = k.DeliveredProviderPermit{Payload: bytes.Clone(l.ProviderPermit.Payload), Signature: bytes.Clone(l.ProviderPermit.Signature)}
	}
	return result, nil
}

func (a *OriginalKeyAuthority) Identity() k.JobIdentity {
	if a == nil {
		return k.JobIdentity{}
	}
	return a.lease.Identity
}
func (a *OriginalKeyAuthority) ValidUntil() time.Time {
	if a == nil {
		return time.Time{}
	}
	return a.lease.Until
}
func (a *OriginalKeyAuthority) check(ctx context.Context, access k.Access, action string) error {
	if a.failed || ctx == nil || ctx.Err() != nil || access != a.lease.Access || !time.Now().Before(a.lease.Until) {
		a.failed = true
		return k.ErrPermission
	}
	l, e := a.client.send(ctx, ControlRequest{Invocation: a.invocation, InvocationSHA256: a.lease.Identity.InvocationSHA256, Action: action, Point: a.lease.Nonce})
	defer l.Clear()
	if e != nil || l.KeyUse == nil {
		a.failed = true
		if (action == "key-begin" || action == "key-end") && errors.Is(e, ErrNotReady) {
			return k.ErrUnknown
		}
		return k.ErrPermission
	}
	got, expected := *l.KeyUse, a.lease
	got.State, expected.State = "", ""
	if got != expected {
		a.failed = true
		return k.ErrPermission
	}
	return nil
}
func (a *OriginalKeyAuthority) Recheck(ctx context.Context, access k.Access) error {
	if a == nil {
		return k.ErrPermission
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.check(ctx, access, "key-check")
}
func (a *OriginalKeyAuthority) WithUse(ctx context.Context, access k.Access, use func() error) error {
	if a == nil || use == nil {
		return k.ErrPermission
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.used {
		return k.ErrPermission
	}
	if e := a.check(ctx, access, "key-begin"); e != nil {
		return e
	}
	a.used = true
	if e := use(); e != nil {
		a.failed = true
		return e
	}
	return a.check(ctx, access, "key-end")
}

// NewCaptureKeyJob is B's production constructor on the existing mTLS control
// client. Missing frozen C metadata is rejected; it never derives staging keys.
func NewCaptureKeyJob(ctx context.Context, client *ControlClient, invocation Invocation, config k.Config, permit k.PermitMount) (*CaptureKeyJob, error) {
	if invocation.FormalCapture != nil && invocation.FormalCapture.PermitDelivery != nil {
		return nil, ErrExecution
	}
	access := invocation.ProviderKey
	// Reject an incompatible admitted mapping before reserving the original
	// Job's single-use key window. NewCaptureJob repeats the binding check at
	// provider use; this early check avoids consuming the original reservation
	// for a wrong installation, key or exact version.
	if access == nil || access.Operation != k.Generate || access.Endpoint != config.Endpoint || access.KeyName != config.KeyName || access.Request.Key != config.Key || access.Request.Context.InstallationID != config.InstallationID {
		return nil, ErrExecution
	}
	a, e := NewOriginalKeyAuthority(ctx, client, invocation)
	if e != nil {
		return nil, e
	}
	job, e := k.NewCaptureJob(ctx, config, permit, a, a.lease.Access.Request)
	if e != nil {
		return nil, e
	}
	return &CaptureKeyJob{job: job, until: job.ValidUntil(), original: a, access: *access}, nil
}

// The delivered bytes come ONLY from the original authenticated reserve ACK.
// Callers supply the previously frozen issuer/delegation pin, never a permit.
func NewDeliveredCaptureKeyJob(ctx context.Context, client *ControlClient, invocation Invocation, config k.Config, pin k.PermitDeliveryPin) (*CaptureKeyJob, error) {
	access := invocation.ProviderKey
	if invocation.FormalCapture == nil || invocation.FormalCapture.PermitDelivery == nil || !samePermitDeliveryPin(pin, *invocation.FormalCapture.PermitDelivery) || access == nil || access.Operation != k.Generate || access.Endpoint != config.Endpoint || access.KeyName != config.KeyName || access.Request.Key != config.Key || access.Request.Context.InstallationID != config.InstallationID {
		return nil, ErrExecution
	}
	original, err := NewOriginalKeyAuthority(ctx, client, invocation)
	if err != nil {
		return nil, err
	}
	job, err := k.NewDeliveredCaptureJob(ctx, config, pin, original.delivery, original, access.Request)
	if err != nil {
		return nil, err
	}
	return &CaptureKeyJob{job: job, until: job.ValidUntil(), original: original, access: *access}, nil
}

// CaptureKeyJob exposes the original shortest deadline to the streaming writer.
// The callback must cooperate with cancellation and never retain the DEK. It
// writes only unpublished output; an error means that output cannot be accepted.
type CaptureKeyJob struct {
	job      *k.CaptureJob
	until    time.Time
	original *OriginalKeyAuthority
	access   k.Access
}

// Recheck uses the SAME original Job/nonce after local candidate writes. It
// cannot renew the use window or mint a second provider operation.
func (j *CaptureKeyJob) Recheck(ctx context.Context) error {
	if j == nil || j.original == nil || ctx == nil || !time.Now().Before(j.until) {
		return ErrNotReady
	}
	return j.original.Recheck(ctx, j.access)
}

// recheckDuringUse uses the SAME authenticated key-check protocol without
// reacquiring OriginalKeyAuthority.mu: WithUse holds that mutex while invoking
// the synchronous producer. It accepts only the original immutable "using"
// lease, never reserves/begins/extends use or accepts a finished callback.
func (j *CaptureKeyJob) recheckDuringUse(ctx context.Context) error {
	if j == nil || j.original == nil || j.original.client == nil || j.original.failed || ctx == nil || ctx.Err() != nil || !time.Now().Before(j.until) || j.access != j.original.lease.Access {
		return ErrNotReady
	}
	a := j.original
	l, e := a.client.send(ctx, ControlRequest{Invocation: a.invocation, InvocationSHA256: a.lease.Identity.InvocationSHA256, Action: "key-check", Point: a.lease.Nonce})
	defer l.Clear()
	if e != nil || l.KeyUse == nil || l.KeyUse.State != "using" {
		return ErrNotReady
	}
	got, want := *l.KeyUse, a.lease
	got.State, want.State = "", ""
	if got != want {
		return ErrNotReady
	}
	return nil
}

func (j *CaptureKeyJob) WithDEK(ctx context.Context, use func(context.Context, []byte) error) (w.WrappedKey, error) {
	if j == nil || ctx == nil || use == nil {
		return w.WrappedKey{}, ErrExecution
	}
	ctx, cancel := context.WithDeadline(ctx, j.until)
	defer cancel()
	return j.job.WithDEK(ctx, func(dek []byte) error { return use(ctx, dek) })
}
func (j *CaptureKeyJob) Close() {
	if j != nil {
		j.job.Close()
	}
}

var _ k.OriginalJobAuthority = (*OriginalKeyAuthority)(nil)
