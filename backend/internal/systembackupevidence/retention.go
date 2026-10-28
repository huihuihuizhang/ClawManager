package systembackupevidence

import "time"

// Retention is read from the locked owner's immutable config snapshot. The
// control-plane policy must still check live references, capacity and holds.
type Retention struct {
	Artifact, Evidence, Logs, Control time.Duration
}

func (p Retention) valid() bool {
	return p.Artifact >= 24*time.Hour && p.Artifact <= 365*24*time.Hour &&
		p.Evidence >= p.Artifact && p.Evidence <= 365*24*time.Hour &&
		p.Logs >= time.Hour && p.Logs <= 30*24*time.Hour &&
		p.Control >= 30*24*time.Hour && p.Control <= 5*365*24*time.Hour &&
		p.Control >= p.Evidence && p.Control >= p.Logs
}

// Check rejects shortened payload retention and job logs promoted into
// correctness evidence. A zero hold is permitted; actual references always
// block GC through Locked.Deletable, including references with no fixed end.
func (p Retention) Check(r Record, correctnessReference bool) error {
	if !p.valid() || r.CreatedAt.IsZero() {
		return ErrInvalid
	}
	retention := p.Evidence
	if r.Manifest.Identity.Type == "job_log_chunk" {
		if correctnessReference || r.Manifest.Identity.ContentSize > ChunkSize {
			return ErrInvalid
		}
		retention = p.Logs
		if !r.ExpiresAt.Equal(r.CreatedAt.Add(retention)) {
			return ErrInvalid
		}
	}
	if r.ExpiresAt.Before(r.CreatedAt.Add(retention)) {
		return ErrInvalid
	}
	return nil
}

// TombstoneUntil gives only the minimum control-metadata cutoff; an unresolved
// owner/reference/retry or permanent retention rule can require longer. GC in
// this package never deletes the tombstone itself.
func (p Retention) TombstoneUntil(created time.Time) (time.Time, error) {
	if !p.valid() || created.IsZero() {
		return time.Time{}, ErrInvalid
	}
	return created.Add(p.Control), nil
}
