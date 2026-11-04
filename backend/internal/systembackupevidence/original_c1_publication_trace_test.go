package systembackupevidence

import (
	"context"
	"io"
	"testing"
	"time"
)

// Test diagnostics only. Every operation delegates to the SAME actual store
// from the production constructor. No operation, result or authority is faked;
// no credentials, JWTs, wrapped keys or body bytes enter test output.
type originalC1TraceStore struct {
	systemPublicationStore
	t *testing.T
}

func (s *originalC1TraceStore) Stat(ctx context.Context, r Ref) (ObjectInfo, error) {
	o, e := s.systemPublicationStore.Stat(ctx, r)
	s.t.Logf("original native store Stat: %v", e)
	return o, e
}
func (s *originalC1TraceStore) Absent(ctx context.Context, r Ref) (Absence, error) {
	o, e := s.systemPublicationStore.Absent(ctx, r)
	s.t.Logf("original native store Absent: %v", e)
	return o, e
}
func (s *originalC1TraceStore) Put(ctx context.Context, r Ref, b io.Reader, o ObjectInfo, d time.Time) error {
	e := s.systemPublicationStore.Put(ctx, r, b, o, d)
	s.t.Logf("original native store Put: %v", e)
	return e
}

func logOriginalC1PublicationFailure(t *testing.T, g *OriginalC1OwnerChannel, v SystemSTSProfileVerifier, p *SystemPublisher) {
	profile, ok := v.(*originalC1ChannelProfile)
	if !ok {
		return
	}
	profile.mu.Lock()
	failed, scopes, probed := profile.failed, len(profile.scopes), len(profile.probed)
	profile.mu.Unlock()
	g.mu.Lock()
	sessions := len(g.sessions)
	g.mu.Unlock()
	t.Logf("original native channel diagnostics: profileFailed=%t registeredScopes=%d nativeSessions=%d probed=%d", failed, scopes, sessions, probed)
	if p.nativeVerifier != nil {
		p.nativeVerifier.mu.Lock()
		t.Logf("original native verifier diagnostics: used=%t bound=%t failed=%t", p.nativeVerifier.used, p.nativeVerifier.bound, p.nativeVerifier.failed)
		p.nativeVerifier.mu.Unlock()
	}
}
