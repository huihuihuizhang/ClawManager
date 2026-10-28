package recovery

import (
	"bytes"
	"context"
	"encoding/json"
)

type ScanState struct {
	Snapshot                       Snapshot
	Cursor, LastKey, RollingSHA256 string
	Page, Count                    int64
	Complete                       bool
	PageSHA256                     string
}
type ScanPage struct {
	Page                   Page
	PreviousSHA256, SHA256 string
}
type ScannedRecord struct {
	Key    string
	Object Object
	Record Record
	Signed json.RawMessage
}
type ScanJournal interface {
	Load(context.Context, string) (ScanState, error)
	Start(context.Context, string, Snapshot) (ScanState, error)
	// Page records and cursor/rolling hash CAS commit together. Finish must
	// recompute the inventory hash/count in the SAME consistent transaction.
	CommitPage(context.Context, string, ScanState, ScanState, ScanPage, []ScannedRecord) error
	Finish(context.Context, string, ScanState) error
}
type Scanner struct {
	Source  Discovery
	Trust   Trust
	Journal ScanJournal
	Now     func() int64
}

func emptyRolling() string                  { return Hash([]byte("clawmanager/catalog-inventory/v1")) }
func roll(previous string, o Object) string { b, _ := Marshal([]any{previous, o}); return Hash(b) }
func pageHash(previous string, p Page) string {
	b, _ := Marshal([]any{"catalog-page.v1", previous, p})
	return Hash(b)
}

// Step processes one bounded page. Resume uses the same immutable provider
// snapshot/cursor and never starts a replacement scan under the same ID.
func (s Scanner) Step(ctx context.Context, id string, deadline int64) (bool, error) {
	if !validID(id) || s.Source == nil || s.Journal == nil || s.Now == nil || deadline <= s.Now() {
		return false, ErrContract
	}
	state, e := s.Journal.Load(ctx, id)
	if e != nil {
		return false, e
	}
	if state.Snapshot.ID == "" {
		snapshot, e := s.Source.Begin(ctx, deadline)
		if e != nil {
			return false, ErrUnavailable
		}
		if !validID(snapshot.ID) || !snapshot.Root.valid() || snapshot.Mode != "provider_snapshot" && snapshot.Mode != "inventory_manifest" || snapshot.Count < 0 || snapshot.Count > 100000 || !digest(snapshot.RecordsSHA256) || snapshot.ExpiresAt < deadline {
			return false, ErrContract
		}
		state, e = s.Journal.Start(ctx, id, snapshot)
		if e != nil {
			return false, e
		}
	}
	if state.Complete {
		return true, nil
	}
	if state.Snapshot.ExpiresAt < s.Now() {
		return false, ErrUnavailable
	}
	// The EOF page may have committed while the Finish response was lost.
	// Resume finalization without fetching cursor="" as a new first page.
	if state.Count == state.Snapshot.Count && state.RollingSHA256 == state.Snapshot.RecordsSHA256 {
		if e := s.Journal.Finish(ctx, id, state); e != nil {
			return false, e
		}
		return true, nil
	}
	page, e := s.Source.Page(ctx, state.Snapshot, state.Cursor, state.Page)
	if e != nil {
		return false, ErrUnavailable
	}
	if page.SnapshotID != state.Snapshot.ID || page.Number != state.Page || page.Cursor != state.Cursor || len(page.Objects) > 1000 || page.Next != "" && (page.Next == state.Cursor || len(page.Objects) == 0) {
		return false, ErrContract
	}
	next := state
	if next.RollingSHA256 == "" {
		next.RollingSHA256 = emptyRolling()
	}
	records := []ScannedRecord{}
	for _, o := range page.Objects {
		if !o.valid() || o.Key <= next.LastKey || next.Count >= state.Snapshot.Count {
			return false, ErrContract
		}
		b, e := readObject(ctx, s.Source, o)
		if e != nil {
			return false, e
		}
		var r Record
		if _, e = s.Trust.Open(b, CatalogPurpose, &r); e != nil {
			return false, e
		}
		key, e := r.Key()
		if e != nil || key != o.Key {
			return false, ErrContract
		}
		next.LastKey = key
		next.Count++
		next.RollingSHA256 = roll(next.RollingSHA256, o)
		records = append(records, ScannedRecord{key, o, r, append(json.RawMessage(nil), b...)})
	}
	next.Page++
	next.Cursor = page.Next
	next.PageSHA256 = pageHash(state.PageSHA256, page)
	receipt := ScanPage{page, state.PageSHA256, next.PageSHA256}
	if page.Next == "" && (next.Count != state.Snapshot.Count || next.RollingSHA256 != state.Snapshot.RecordsSHA256) {
		return false, ErrConflict
	}
	if e = s.Journal.CommitPage(ctx, id, state, next, receipt, records); e != nil {
		return false, e
	}
	if page.Next == "" {
		if e = s.Journal.Finish(ctx, id, next); e != nil {
			return false, e
		}
		return true, nil
	}
	return false, nil
}
func same(a, b any) bool {
	x, e := Marshal(a)
	y, f := Marshal(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}

// ValidatePages checks the durable cursor/checksum chain against the exact
// signed-record inventory in the same transaction as scan completion.
func ValidatePages(state ScanState, pages []ScanPage, records []ScannedRecord) error {
	if int64(len(pages)) != state.Page || len(pages) == 0 || state.Cursor != "" {
		return ErrConflict
	}
	previous, cursor, offset := "", "", 0
	for n, receipt := range pages {
		p := receipt.Page
		if p.SnapshotID != state.Snapshot.ID || p.Number != int64(n) || p.Cursor != cursor || receipt.PreviousSHA256 != previous || receipt.SHA256 != pageHash(previous, p) || len(p.Objects) > 1000 {
			return ErrConflict
		}
		if n < len(pages)-1 && (p.Next == "" || p.Next == p.Cursor || len(p.Objects) == 0) {
			return ErrConflict
		}
		for _, o := range p.Objects {
			if offset >= len(records) || records[offset].Object != o {
				return ErrConflict
			}
			offset++
		}
		previous, cursor = receipt.SHA256, p.Next
	}
	if offset != len(records) || cursor != "" || previous != state.PageSHA256 {
		return ErrConflict
	}
	return nil
}

// ValidateInventory is shared by persistent scan journals at the final commit.
// It checks count/hash and every tombstone link, including across page borders.
func ValidateInventory(state ScanState, records []ScannedRecord, trust Trust) error {
	if int64(len(records)) != state.Count || state.Count != state.Snapshot.Count {
		return ErrConflict
	}
	rolling, last := emptyRolling(), ""
	registrations := map[string]ScannedRecord{}
	for _, r := range records {
		var signed Record
		if int64(len(r.Signed)) != r.Object.Size || Hash(r.Signed) != r.Object.SHA256 {
			return ErrConflict
		}
		if _, e := trust.Open(r.Signed, CatalogPurpose, &signed); e != nil || !same(signed, r.Record) {
			return ErrConflict
		}
		key, e := r.Record.Key()
		if e != nil || key != r.Key || r.Object.Key != key || key <= last {
			return ErrConflict
		}
		last = key
		rolling = roll(rolling, r.Object)
		if r.Record.Registration != nil {
			registrations[r.Record.ID] = r
		}
	}
	if rolling != state.RollingSHA256 || rolling != state.Snapshot.RecordsSHA256 {
		return ErrConflict
	}
	for _, r := range records {
		if d := r.Record.Deletion; d != nil {
			parent, ok := registrations[d.RegistrationID]
			if !ok || parent.Object.SHA256 != d.RegistrationSHA256 || parent.Record.Registration.Locator != d.Locator || parent.Record.Registration.Core != d.Core {
				return ErrConflict
			}
		}
	}
	return nil
}
