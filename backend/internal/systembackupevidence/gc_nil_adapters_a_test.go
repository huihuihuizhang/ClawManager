package systembackupevidence

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A nil receiver can implement the verifier interface without panicking.
// The wrapper must reject it itself, before SQL or a provider callback.
type aGCTypedNilVerifier struct{}

func (*aGCTypedNilVerifier) VerifyAbsent(_ context.Context, request S3AbsenceRequest) (S3AbsenceProof, error) {
	now := time.Now().UTC()
	return S3AbsenceProof{Request: request, ObservedAt: now, ExpiresAt: now.Add(time.Second)}, nil
}

func aGCNilVerifiers() map[string]S3AbsenceVerifier {
	return map[string]S3AbsenceVerifier{
		"interface_nil": nil,
		"pointer_nil":   (*aGCTypedNilVerifier)(nil),
		"function_nil":  s3AbsenceFunc(nil),
	}
}

func TestAGCAuthorityRejectsNilPolicy(t *testing.T) {
	for _, mode := range []string{"interface_nil", "pointer_nil"} {
		t.Run(mode, func(t *testing.T) {
			f := newGCFixture(t)
			c := f.c
			c.Registry.Policy = nil
			if mode == "pointer_nil" {
				c.Registry.Policy = (*gcTestPolicy)(nil)
			}
			a, err := NewSQLGCAuthority(c)
			if a != nil || err != ErrInvalid || f.base.db.begins != 0 {
				t.Fatal("missing GC policy was accepted or reached SQL", err)
			}
		})
	}
}

func TestAGCRuntimeRejectsNilAbsence(t *testing.T) {
	for mode, verifier := range aGCNilVerifiers() {
		t.Run(mode, func(t *testing.T) {
			x := newGCRuntimeFixture(t, "ok")
			c := x.c
			c.Absence = verifier
			r, err := NewGCRuntime(c)
			if r != nil {
				r.Close()
			}
			if r != nil || err != ErrInvalid || x.db.begins != 0 || x.exchanges.Load() != 0 || x.heads.Load() != 0 || x.deletes.Load() != 0 || x.proofs.Load() != 0 {
				t.Fatal("missing absence verifier was accepted or reached SQL/provider", err)
			}
		})
	}
}

func TestAGCAbsenceRejectsNilVerifierBeforeSQL(t *testing.T) {
	for mode, verifier := range aGCNilVerifiers() {
		t.Run(mode, func(t *testing.T) {
			f := newGCFixture(t)
			v := GCAbsenceVerifier{Authority: f.a, Verifier: verifier}
			// The old function-nil path panics. Keep that counterexample a
			// normal test failure so every other dependency case still runs.
			defer func() {
				if recover() != nil {
					t.Error("nil verifier was invoked instead of rejected")
				}
			}()
			proof, err := v.VerifyAbsent(f.ctx, S3AbsenceRequest{Ref: f.record.Ref, Challenge: strings.Repeat("f", 64)})
			if err != ErrDenied || proof != (S3AbsenceProof{}) || f.base.db.begins != 0 || f.base.db.commits != 0 || f.policy.deletableChecks != 0 {
				t.Fatal("missing verifier was accepted or reached SQL/provider", err)
			}
		})
	}
}
