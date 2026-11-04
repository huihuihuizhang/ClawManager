package systembackupevidence

import (
	"bytes"
	"context"
	"time"
)

// OriginalC1BackingStoreSource is created only by the running native owner
// channel AFTER authenticated upstream TLS/versioning and real workload reads.
// No caller can construct it from a replacement S3Config or JSON. It retains
// durable original backing coordinates; loopback TLS is a transport only.
type OriginalC1BackingStoreSource struct {
	origin     *OriginalC1BackingStoreSource
	channel    *OriginalC1OwnerChannel
	store      S3Config
	observedAt time.Time
}

func (*OriginalC1BackingStoreSource) MarshalJSON() ([]byte, error) { return nil, ErrDenied }

func (g *OriginalC1OwnerChannel) BackingStoreSource() *OriginalC1BackingStoreSource {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.backing == nil {
		return nil
	}
	return g.backing
}

// OriginalStore exposes comparison DATA from this concrete native source for
// the original installer to sign into the pre-capture association. Authority
// consumers must retain the opaque source, not reinterpret this DTO as proof.
// It performs no network/SQL and can be used in the original locked readback.
func (s *OriginalC1BackingStoreSource) OriginalStore() (S3Config, time.Time, error) {
	if s == nil || s.origin != s || s.channel == nil || s.channel.backing != s || s.observedAt.IsZero() {
		return S3Config{}, time.Time{}, ErrDenied
	}
	c := s.store
	c.CAPEM = bytes.Clone(c.CAPEM)
	return c, s.observedAt, nil
}

// CurrentOriginalOwner is deliberately BEFORE SQL locks. Later source guards
// compare only the original immutable opaque source and already-held SQL rows.
func (s *OriginalC1BackingStoreSource) CurrentOriginalOwner(ctx context.Context) error {
	if _, _, e := s.OriginalStore(); e != nil {
		return e
	}
	return s.channel.currentWorkload(ctx)
}

// OriginalChannel exposes the actual bounded transport paired with this same
// source, solely so the enrolled owner can sign the pre-capture association.
func (s *OriginalC1BackingStoreSource) OriginalChannel() (S3STSConfig, string, error) {
	if _, _, err := s.OriginalStore(); err != nil {
		return S3STSConfig{}, "", err
	}
	s.channel.mu.Lock()
	closed := s.channel.closed
	s.channel.mu.Unlock()
	if closed || s.channel.ctx.Err() != nil {
		return S3STSConfig{}, "", ErrDenied
	}
	c, profile := s.channel.Config()
	return c, profile, nil
}
