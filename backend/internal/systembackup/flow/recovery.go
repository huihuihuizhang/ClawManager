package flow

import (
	"context"
	"errors"
)

type PauseRecord struct {
	WriterID string
	Original State
}

// PendingPauses reads the authoritative persisted intent list, including a
// stop whose ACK was never saved. It must not be rebuilt from current DB power
// status: that loses which writers were running before the interrupted task.
type RecoveryJournal interface {
	PendingPauses(context.Context, Identity) ([]PauseRecord, error)
	CheckRecoveryFence(context.Context, Identity, string, State) error
	Resumed(context.Context, Identity, string) error
}

// RecoverSource is used by controller/watchdog takeover under a fresh recovery
// lease. The caller supplies a bounded context; no collector, backup restore,
// source rediscovery or implicit ownership takeover is performed here.
func RecoverSource(ctx context.Context, id Identity, j RecoveryJournal, writers []Writer) error {
	if _, ok := ctx.Deadline(); !ok || j == nil || id.Task == "" || id.Attempt == "" || id.Phase == "" || id.Generation <= 0 {
		return ErrNotReady
	}
	byID := map[string]Writer{}
	for _, w := range writers {
		if w == nil || w.ID() == "" || byID[w.ID()] != nil {
			return ErrNotReady
		}
		byID[w.ID()] = w
	}
	intents, err := j.PendingPauses(ctx, id)
	if err != nil || len(intents) > 10_000 {
		return ErrJournal
	}
	seen := map[string]bool{}
	// Validate the whole recovery inventory before any source mutation.
	for _, p := range intents {
		if seen[p.WriterID] || byID[p.WriterID] == nil || p.Original.UID == "" || p.Original.Generation <= 0 {
			return ErrJournal
		}
		seen[p.WriterID] = true
	}
	var result error
	for idx := len(intents) - 1; idx >= 0; idx-- {
		p := intents[idx]
		if ctx.Err() != nil {
			return errors.Join(result, ErrResume, ctx.Err())
		}
		if j.CheckRecoveryFence(ctx, id, p.WriterID, p.Original) != nil {
			result = errors.Join(result, ErrJournal, ErrResume)
			continue
		}
		if byID[p.WriterID].Resume(ctx, p.Original) != nil {
			result = errors.Join(result, ErrResume)
			continue
		}
		if j.Resumed(ctx, id, p.WriterID) != nil {
			result = errors.Join(result, ErrJournal, ErrResume)
		}
	}
	return result
}
