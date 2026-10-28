package profile

import (
	"context"
	"io"
	"os"
	"strings"

	"clawreef/internal/systembackup/artifact"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/staging"
)

func (d *Driver) workBuddyUID() bool {
	return d.Config.WorkBuddy != nil && d.Config.WorkBuddy.Layout == domain.WorkBuddyUIDV1
}

// The bundle is signature-checked by the caller (or consists of the current
// fenced capture receipts). Unwrap + receipt + AEAD checks precede SQL decoding.
func (d *Driver) databaseSnapshot(ctx context.Context, root *os.Root, b artifact.Bundle) (domain.Snapshot, error) {
	for _, part := range b.Parts {
		if part.ID != "database" {
			continue
		}
		key, e := d.Keys.Unwrap(ctx, part.Binding, part.Key)
		if e != nil {
			return domain.Snapshot{}, e
		}
		defer clear(key)
		f, e := staging.OpenFile(ctx, root, part.Receipt)
		if e != nil {
			return domain.Snapshot{}, e
		}
		defer f.Close()
		var s domain.Snapshot
		e = staging.ConsumeCompressed(ctx, f, key, part.Binding, 32<<20, 32<<20, func(r io.Reader) error {
			var e error
			s, e = domain.Decode(r, domain.Limits{MaxRows: 1_000_000, MaxBytes: 32 << 20})
			return e
		})
		if e != nil {
			clearSnapshot(s)
			return domain.Snapshot{}, e
		}
		return s, nil
	}
	return domain.Snapshot{}, ErrProfile
}

func clearSnapshot(s domain.Snapshot) {
	for _, t := range s.Tables {
		for _, r := range t.Rows {
			for _, c := range r {
				clear(c.Bytes)
			}
		}
	}
}

func bindWorkBuddyIdentity(s domain.Snapshot, w *work) error {
	if w.Invocation.Request.RuntimePolicy == nil || w.Invocation.Request.RuntimePolicy.Runtime.Type != "workbuddy" {
		return nil
	}
	expected, e := domain.WorkBuddyUIDForInstance(s, strings.TrimPrefix(w.PartID, "instance-"))
	if e != nil {
		return e
	}
	w.Invocation.Request.WorkBuddyIdentity = &expected
	return nil
}

// A source identity change between discovery and the writer fence invalidates
// the backup. Do not publish SQL and file parts from different UID generations.
func (d *Driver) validateWorkBuddyCapture(ctx context.Context, root *os.Root, b artifact.Bundle, p plan) error {
	if !d.workBuddyUID() {
		return nil
	}
	s, e := d.databaseSnapshot(ctx, root, b)
	if e != nil {
		return e
	}
	defer clearSnapshot(s)
	for _, w := range p.Work {
		if w.Invocation.Request.RuntimePolicy == nil || w.Invocation.Request.RuntimePolicy.Runtime.Type != "workbuddy" {
			continue
		}
		frozen := w.Invocation.Request.WorkBuddyIdentity
		if e = bindWorkBuddyIdentity(s, &w); e != nil || frozen == nil || !jsonEqual(frozen, w.Invocation.Request.WorkBuddyIdentity) {
			return ErrProfile
		}
	}
	return nil
}
