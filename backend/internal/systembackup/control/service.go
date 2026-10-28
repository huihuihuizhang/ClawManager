package control

import (
	"context"
	"errors"
	"time"
)

// Service runs profile health, normal task reconciliation and read-only
// finalization reconciliation independently. Claims are authoritative in SQL;
// this host does not treat an in-process mutex as cluster leadership.
type Service struct {
	Controller   Controller
	Store        SQLStore
	Publisher    Publisher
	PollInterval time.Duration
	ProbeTimeout time.Duration
	// OnError receives fixed codes only, never provider errors or credentials.
	OnError func(string)
}

func (s Service) Run(ctx context.Context) error {
	c := s.Controller
	if s.Store.DB == nil || c.Executor == nil || c.Store == nil || !identifier.MatchString(c.Owner) || c.Lease < 3*time.Second || c.Lease > time.Minute || c.RecoveryTimeout <= 0 || c.RecoveryTimeout > 10*time.Minute || s.PollInterval < 100*time.Millisecond || s.PollInterval > time.Minute || s.ProbeTimeout < time.Second || s.ProbeTimeout > 10*time.Second {
		return ErrInvalid
	}
	// The same SQL store must own admission, claims, resources and publication.
	sqlStore, ok := c.Store.(SQLStore)
	if !ok || sqlStore.DB != s.Store.DB || s.Publisher.Store.DB != s.Store.DB {
		return ErrInvalid
	}
	run, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{}, 2)
	go func() { defer func() { done <- struct{}{} }(); s.profiles(run) }()
	go func() { defer func() { done <- struct{}{} }(); s.finalizations(run) }()
	defer func() { cancel(); <-done; <-done }()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		e := c.RunOnce(run)
		if e != nil && !errors.Is(e, ErrNotFound) && run.Err() == nil {
			s.report("task_reconcile_failed")
		}
		if !waitPoll(run, s.PollInterval) {
			return ctx.Err()
		}
	}
}
func (s Service) report(code string) {
	if s.OnError != nil {
		s.OnError(code)
	}
}
func waitPoll(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
func (s Service) profiles(ctx context.Context) {
	for ctx.Err() == nil {
		probe, cancel := context.WithTimeout(ctx, s.ProbeTimeout)
		profiles, e := s.Controller.Executor.Profiles(probe)
		if e == nil {
			e = s.Store.PublishProfiles(probe, profiles, 30*time.Second)
		}
		cancel()
		if e != nil && ctx.Err() == nil {
			s.report("profile_probe_failed")
		}
		// A failed probe never refreshes last-known-good readiness. It expires.
		if !waitPoll(ctx, 10*time.Second) {
			return
		}
	}
}
func (s Service) finalizations(ctx context.Context) {
	for ctx.Err() == nil {
		t, e := s.Store.ClaimFinalization(ctx, s.Controller.Owner, s.Controller.Lease)
		if e == nil {
			e = s.resolve(ctx, t)
		}
		if e != nil && !errors.Is(e, ErrNotFound) && ctx.Err() == nil {
			s.report("publication_reconcile_pending")
		}
		if !waitPoll(ctx, s.PollInterval) {
			return
		}
	}
}
func (s Service) resolve(ctx context.Context, t Task) error {
	// Artifact hashing can exceed one claim interval. Renew with the ORIGINAL
	// generation and cancel immediately on failure, never using a new takeover.
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(s.Controller.Lease / 3)
		defer ticker.Stop()
		for {
			select {
			case <-work.Done():
				return
			case <-ticker.C:
				if _, e := s.Store.Renew(work, t, s.Controller.Lease); e != nil {
					cancel()
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-done }()
	bounded, stop := context.WithTimeout(work, 10*time.Minute)
	defer stop()
	publicationErr := ErrNotFound
	if resolver, ok := s.Controller.Executor.(PublicationResolver); ok {
		publicationErr = resolver.ResolvePublication(bounded, t)
	}
	if errors.Is(publicationErr, ErrNotFound) {
		publicationErr = s.Publisher.Reconcile(bounded, t)
	}
	if publicationErr != nil {
		return publicationErr
	}
	recovery, finish := context.WithTimeout(work, s.Controller.RecoveryTimeout)
	e := s.Controller.Executor.Recover(recovery, t)
	finish()
	if e != nil {
		return e
	}
	current, e := s.Store.Get(work, t.ID)
	if e != nil {
		return e
	}
	if current.Owner != t.Owner || current.Generation != t.Generation || current.Status != "finalization_unknown" {
		return ErrFence
	}
	_, e = s.Store.Advance(work, current, "succeeded", "")
	return e
}
