// Package mutation lets detached business work participate in the shared gate.
// Configure once before services start. Disabled installations retain behavior.
package mutation

import (
	"clawreef/internal/backupgate"
	"context"
	"errors"
	"sync/atomic"
	"time"
)

type Gate interface {
	Enter(context.Context, string) (func() error, error)
}

// ContextGate may cancel cooperative work after admission is lost. Its release
// still belongs to the writer after all children and cleanup have exited.
type ContextGate interface {
	EnterContext(context.Context, string) (context.Context, func() error, error)
}

func EnterContext(ctx context.Context, name string) (context.Context, func() error, error) {
	if ctx == nil || ctx.Err() != nil {
		return ctx, nil, context.Canceled
	}
	h := configured.Load()
	if h != nil && h.gate != nil {
		if g, ok := h.gate.(ContextGate); ok {
			child, release, err := g.EnterContext(ctx, name)
			if err == nil && (child == nil || release == nil) {
				if release != nil {
					_ = release()
				}
				return ctx, nil, errors.New("backup mutation context capability missing")
			}
			return child, release, err
		}
	}
	release, err := Enter(ctx, name)
	return ctx, release, err
}

type holder struct{ gate Gate }

var configured atomic.Pointer[holder]

func Configure(g Gate) { configured.Store(&holder{g}) }
func Enter(ctx context.Context, name string) (func() error, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, context.Canceled
	}
	h := configured.Load()
	if h == nil || h.gate == nil {
		// Team's existing work boundary is the default authority. A missing
		// optional v2 registry must not bypass a configured legacy backup gate.
		release, err := backupgate.HoldWorkUnit(ctx, name)
		if err != nil {
			return nil, err
		}
		return func() error { release(); return nil }, nil
	}
	release, err := h.gate.Enter(ctx, name)
	if err == nil && release == nil {
		return nil, errors.New("backup mutation release capability missing")
	}
	return release, err
}

// Wait is for once-only detached work: defer the work until admission reopens,
// rather than silently dropping it. Recurring workers use Enter and retry on
// their next tick. Never call Wait inside an already-held parent permit.
func Wait(ctx context.Context, name string) (func() error, error) {
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		release, e := Enter(ctx, name)
		if e == nil {
			return release, nil
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
