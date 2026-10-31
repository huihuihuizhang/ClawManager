package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	k "clawreef/internal/systembackupkms"
	w "clawreef/internal/systembackupwire"
)

type scopedKeyUseFixture struct {
	inner    *candidateContentUnwrapper
	original []byte
	identity FormalVerifierIdentity
	closes   int
	mutate   bool
	until    time.Time
}

func (f *scopedKeyUseFixture) Identity() FormalVerifierIdentity { return f.identity }
func (f *scopedKeyUseFixture) ValidUntil() time.Time            { return f.until }
func (f *scopedKeyUseFixture) Recheck(_ context.Context, s FormalCandidateReadScope) error {
	raw, _ := json.Marshal(s)
	if f.closes != 0 || !bytes.Equal(raw, f.original) {
		return w.ErrStreamAuthority
	}
	if f.mutate {
		s.Invocation.ProviderKey.Request.Context.BackupPublicID = "mutating-callback"
	}
	return nil
}
func (f *scopedKeyUseFixture) Unwrap(ctx context.Context, expected w.KeyRequest, wrapped w.WrappedKey, use w.WithDEK) error {
	return f.inner.Unwrap(ctx, expected, wrapped, use)
}
func (f *scopedKeyUseFixture) Close() { f.closes++ }

func TestFormalKeyFactoryScopesEachOriginalTaskAndVerifierWorkload(t *testing.T) {
	_, _, seal, i, candidate, inner := formalObserverFixture(t)
	a, j, _ := resultEvidenceFixture()
	a.ConfigSHA256 = seal.ConfigSHA256
	a.DeadlineAt = i.Request.Deadline
	scope := FormalCandidateReadScope{Authority: a, Job: j, Invocation: i, Candidate: candidate, CapturePod: BoundPod{Namespace: j.Namespace, Name: "capture", UID: "capture-pod", ServiceAccountUID: "capture-sa"}, CaptureGrantSHA256: strings.Repeat("a", 64)}
	identity := FormalVerifierIdentity{Namespace: "verification", PodName: "controller-pod", PodUID: "verifier-pod", ServiceAccountName: "controller", ServiceAccountUID: "verifier-sa", OwnerKind: "Deployment", OwnerUID: "controller-deployment", GrantSHA256: strings.Repeat("f", 64)}
	for _, fault := range []string{"", "task", "attempt", "config", "source-pod", "source-sa", "verifier-pod", "verifier-sa", "verifier-job", "capture-grant", "factory-error", "callback-mutation", "zero-deadline", "expired"} {
		t.Run(fault, func(t *testing.T) {
			changed, _ := cloneFormalReadScope(scope)
			raw, _ := json.Marshal(scope)
			use := &scopedKeyUseFixture{inner: inner, original: raw, identity: identity, until: i.Request.Deadline}
			switch fault {
			case "zero-deadline":
				use.until = time.Time{}
			case "expired":
				use.until = time.Now().Add(-time.Second)
			case "task":
				changed.Authority.TaskPublicID = "sbk_other"
			case "attempt":
				changed.Authority.AttemptNo++
			case "config":
				changed.Authority.ConfigSHA256 = strings.Repeat("b", 64)
			case "source-pod":
				changed.CapturePod.UID = "other"
			case "source-sa":
				changed.CapturePod.ServiceAccountUID = "other"
			case "verifier-pod":
				use.identity.PodUID = scope.CapturePod.UID
			case "verifier-sa":
				use.identity.ServiceAccountUID = scope.CapturePod.ServiceAccountUID
			case "verifier-job":
				use.identity.OwnerUID = scope.Job.UID
			case "capture-grant":
				use.identity.GrantSHA256 = scope.CaptureGrantSHA256
			case "callback-mutation":
				use.mutate = true
			}
			opens := 0
			factory := func(_ context.Context, s FormalCandidateReadScope) (FormalCandidateKeyUse, error) {
				opens++
				access, err := s.ExpectedUnwrapAccess()
				if err != nil || access.Operation != k.Unwrap || access.Request != i.ProviderKey.Request {
					t.Fatal("factory borrowed Generate or foreign context")
				}
				if fault == "factory-error" {
					return use, w.ErrStreamAuthority
				}
				if fault == "callback-mutation" {
					s.Invocation.ProviderKey.Request.Context.BackupPublicID = "mutating-factory"
				}
				return use, nil
			}
			keys, err := openFormalCandidateKeys(context.Background(), factory, changed)
			valid := fault == "" || fault == "callback-mutation"
			if (err == nil) != valid {
				t.Fatal("wrong scoped factory outcome", err)
			}
			if fault == "task" || fault == "attempt" {
				if opens != 0 {
					t.Fatal("foreign task reached key factory")
				}
				return
			}
			if !valid {
				if use.closes != 1 {
					t.Fatal("failed scope leaked key capability", use.closes)
				}
				return
			}
			request := i.ProviderKey.Request
			if !keys.ValidUntil().Equal(i.Request.Deadline) {
				t.Fatal("factory lost original bounded deadline")
			}
			wrapped := w.WrappedKey{Request: request, Algorithm: "provider-native", Ciphertext: []byte("opaque")}
			before := inner.calls
			if err = keys.Unwrap(context.Background(), request, wrapped, func(key []byte) error {
				if len(key) != 32 {
					t.Fatal("bad fixture key")
				}
				return nil
			}); err != nil {
				t.Fatal("original unwrap failed", err)
			}
			foreign := request
			foreign.Context.AttemptNo = "4"
			wrapped.Request = foreign
			if err = keys.Unwrap(context.Background(), foreign, wrapped, func([]byte) error { t.Fatal("foreign unwrap callback"); return nil }); err == nil {
				t.Fatal("scoped key reused by other attempt")
			}
			if inner.calls != before+1 {
				t.Fatal("foreign request reached provider")
			}
			use.until = use.until.Add(time.Minute)
			if err = keys.Unwrap(context.Background(), request, w.WrappedKey{Request: request}, func([]byte) error { t.Fatal("extended grant reached callback"); return nil }); err == nil {
				t.Fatal("factory changed deadline after original authorization")
			}
			keys.Close()
			if use.closes != 1 {
				t.Fatal("scoped keys not closed")
			}
			if err = keys.Unwrap(context.Background(), request, w.WrappedKey{Request: request}, func([]byte) error { return nil }); err == nil {
				t.Fatal("closed key use replayed")
			}
		})
	}
}
