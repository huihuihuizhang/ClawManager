package systembackupsecurity

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSensitiveDownloadNonceUseOriginalProofAndSharedSingleAttempt(t *testing.T) {
	d, tx, v := downloadNonceFixture(t)
	s, err := LockSensitiveDownloadNonceScope(context.Background(), tx, d.identity, "installation_test")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.LockCandidates(context.Background(), tx, v); err != nil {
		t.Fatal(err)
	}
	calls := 0
	if err = s.UseLockedCandidates(context.Background(), tx, v, func(c NonceHMACCandidate) error {
		calls++
		if c != v.ActiveNonce() {
			t.Fatal("replaced active candidate")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = s.RecheckUsedCandidates(context.Background(), tx, v); err != nil {
		t.Fatal(err)
	}
	copyScope := *s
	if copyScope.UseLockedCandidates(context.Background(), tx, v, func(NonceHMACCandidate) error { calls++; return nil }) == nil || calls != 1 {
		t.Fatal("copied scope performed second use")
	}
	if s.RecheckUsedCandidates(context.Background(), tx, v) == nil {
		t.Fatal("failed repeated use did not invalidate original scope")
	}
	if d.writes != 0 || d.commits != 0 || d.rollbacks != 0 {
		t.Fatal("scope pretended to consume/commit")
	}
}

func TestSensitiveDownloadNonceUseFailuresCannotRecover(t *testing.T) {
	for _, name := range []string{"before_candidate_locks", "nil_writer", "foreign_tx", "different_proof", "writer_error", "writer_cancellation", "writer_clock_backwards", "writer_expiry"} {
		t.Run(name, func(t *testing.T) {
			d, tx, v := downloadNonceFixture(t)
			s, err := LockSensitiveDownloadNonceScope(context.Background(), tx, d.identity, "installation_test")
			if err != nil {
				t.Fatal(err)
			}
			if name != "before_candidate_locks" {
				if err = s.LockCandidates(context.Background(), tx, v); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			writer := func(NonceHMACCandidate) error {
				calls++
				switch name {
				case "writer_error":
					return errors.New("synthetic write error")
				case "writer_cancellation":
					cancel()
				case "writer_clock_backwards":
					d.now = d.now.Add(-time.Microsecond)
				case "writer_expiry":
					d.now = d.now.Add(time.Hour)
				}
				return nil
			}
			borrowed := tx
			switch name {
			case "nil_writer":
				writer = nil
			case "foreign_tx":
				_, borrowed, _ = downloadNonceFixture(t)
			case "different_proof":
				v.maxAge += time.Second
			}
			if s.UseLockedCandidates(ctx, borrowed, v, writer) == nil {
				t.Fatal("invalid use accepted")
			}
			before := calls
			copyScope := *s
			if copyScope.UseLockedCandidates(context.Background(), tx, v, func(NonceHMACCandidate) error { calls++; return nil }) == nil || calls != before {
				t.Fatal("failed scope recovered")
			}
			if s.RecheckUsedCandidates(context.Background(), tx, v) == nil {
				t.Fatal("failed use passed final check")
			}
		})
	}
}
