package systembackupevidence

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"time"

	pd "clawreef/internal/systembackupproducer"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// BootstrapOriginalEvidenceEntry is immutable comparison data from the
// independently authenticated original mapping. Constructor consistency is
// not authorization. Expected must belong to its original signed selection;
// no caller Manifest or a healthy result creates provider/read permission.
type BootstrapOriginalEvidenceEntry struct {
	Record   Record
	Channel  ProducerEvidenceChannel
	Expected pd.EvidenceBinding
}
type BootstrapOriginalEvidenceSource struct {
	entries []BootstrapOriginalEvidenceEntry
}
type BootstrapOriginalEvidenceLock struct {
	origin *BootstrapOriginalEvidenceLock
	source *BootstrapOriginalEvidenceSource
	ctx    context.Context
	tx     pd.BootstrapSQL
	facts  []pd.ResultEvidence
	rows   []systemPendingStored
	failed bool
}

func NewBootstrapOriginalEvidenceSource(entries []BootstrapOriginalEvidenceEntry) (*BootstrapOriginalEvidenceSource, error) {
	if len(entries) == 0 || len(entries) > 20 {
		return nil, ErrDenied
	}
	raw, e := json.Marshal(entries)
	var owned []BootstrapOriginalEvidenceEntry
	if e != nil || len(raw) > 8<<20 || json.Unmarshal(raw, &owned) != nil {
		return nil, ErrDenied
	}
	sort.Slice(owned, func(i, j int) bool {
		return owned[i].Record.Manifest.Identity.ID < owned[j].Record.Manifest.Identity.ID
	})
	for i, entry := range owned {
		r := entry.Record
		if r.State != "ready" || r.Failure != "none" || r.RowVersion < 1 || r.Claim != "" || !r.ClaimUntil.IsZero() || r.Manifest.Identity.OwnerType != "system" || r.Manifest.Identity.Type != "capability_snapshot" || r.Manifest.Identity.Media != "application/json" || r.Manifest.Identity.ContentSize > MaxCapabilityContent || MatchProducerBinding(r, entry.Channel, entry.Expected) != nil || i > 0 && owned[i-1].Record.Manifest.Identity.ID == r.Manifest.Identity.ID {
			return nil, ErrDenied
		}
	}
	return &BootstrapOriginalEvidenceSource{entries: owned}, nil
}
func (*BootstrapOriginalEvidenceSource) MarshalJSON() ([]byte, error) { return nil, ErrDenied }
func (*BootstrapOriginalEvidenceLock) MarshalJSON() ([]byte, error)   { return nil, ErrDenied }

// ComparisonBytes/BindingSHA256 are public source comparison data only. Their
// exact bytes must be selected by the authenticated original mapping issuer.
func (s *BootstrapOriginalEvidenceSource) ComparisonBytes() ([]byte, error) {
	if s == nil {
		return nil, ErrDenied
	}
	raw, e := json.Marshal(s.entries)
	if e != nil {
		return nil, ErrDenied
	}
	// Producer CanonicalJSON is a typed C1 binary frame, not JSON. The signed
	// source file uses the same strict JCS bytes as the installation issuer.
	return jsoncanonicalizer.Transform(raw)
}
func (s *BootstrapOriginalEvidenceSource) BindingSHA256() (string, error) {
	raw, e := s.ComparisonBytes()
	if e != nil {
		return "", e
	}
	return hash(raw), nil
}
func (s *BootstrapOriginalEvidenceSource) ExpectedBindings() ([]pd.EvidenceBinding, error) {
	if s == nil {
		return nil, ErrDenied
	}
	out := make([]pd.EvidenceBinding, 0, len(s.entries))
	for _, entry := range s.entries {
		expected := entry.Expected
		if expected.ImmutableVersion != nil {
			value := *expected.ImmutableVersion
			expected.ImmutableVersion = &value
		}
		out = append(out, expected)
	}
	return out, nil
}

func (s *BootstrapOriginalEvidenceSource) read(ctx context.Context, view pd.BootstrapReadSQL) ([]pd.ResultEvidence, []systemPendingStored, error) {
	if s == nil || len(s.entries) == 0 || nilSystemAdapter(ctx) || ctx.Err() != nil || nilSystemAdapter(view) {
		return nil, nil, ErrDenied
	}
	before, e := view.SampleTime(ctx)
	if e != nil {
		return nil, nil, ErrDenied
	}
	facts := make([]pd.ResultEvidence, 0, len(s.entries))
	rows := make([]systemPendingStored, 0, len(s.entries))
	for _, entry := range s.entries {
		r := entry.Record
		if before.Before(r.CreatedAt) || !before.Before(r.ExpiresAt) || !before.Before(r.ProtectedUntil) || entry.Expected.ImmutableVersion == nil {
			return nil, nil, ErrDenied
		}
		// Reuse D's complete immutable projection, exact object version, mutable
		// state/claim checks and complete ordered chunk read. No LIMIT or manifest
		// hash-only shortcut replaces registry/chunk correspondence.
		row, found, e := loadSystemPublication(ctx, view, r, string(*entry.Expected.ImmutableVersion))
		if e != nil || !found || row.State != "ready" || row.Failure != "none" || row.Version != r.RowVersion || row.Claim.Valid || row.ClaimUntil.Valid || MatchProducerBinding(r, entry.Channel, entry.Expected) != nil {
			return nil, nil, ErrDenied
		}
		expected := entry.Expected
		version := *expected.ImmutableVersion
		expected.ImmutableVersion = &version
		facts = append(facts, pd.ResultEvidence{Evidence: expected, RowVersion: pd.Counter(strconv.FormatInt(row.Version, 10)), State: row.State, Failure: row.Failure, RetentionExpiresAt: systemPublicationTimestamp(r.ExpiresAt), ProtectedUntil: systemPublicationTimestamp(r.ProtectedUntil)})
		rows = append(rows, row)
	}
	after, e := view.SampleTime(ctx)
	if e != nil || after.Before(before) {
		return nil, nil, ErrDenied
	}
	for _, entry := range s.entries {
		if !after.Before(entry.Record.ExpiresAt) || !after.Before(entry.Record.ProtectedUntil) {
			return nil, nil, ErrDenied
		}
	}
	return facts, rows, nil
}
func (s *BootstrapOriginalEvidenceSource) Lock(ctx context.Context, tx pd.BootstrapSQL) (*BootstrapOriginalEvidenceLock, []pd.ResultEvidence, error) {
	if !pd.SameBootstrapTransaction(tx, tx) {
		return nil, nil, ErrDenied
	}
	facts, rows, e := s.read(ctx, tx)
	if e != nil {
		return nil, nil, e
	}
	// Detach pointers before returning public comparison facts to the caller.
	raw, e := json.Marshal(facts)
	var owned []pd.ResultEvidence
	if e != nil || json.Unmarshal(raw, &owned) != nil {
		return nil, nil, ErrDenied
	}
	guard := &BootstrapOriginalEvidenceLock{source: s, ctx: ctx, tx: tx, facts: owned, rows: rows}
	guard.origin = guard
	return guard, facts, nil
}
func (g *BootstrapOriginalEvidenceLock) Recheck(ctx context.Context, view pd.BootstrapReadSQL) error {
	if g == nil {
		return ErrDenied
	}
	fail := func() error { g.failed = true; return ErrDenied }
	if g.origin != g || g.failed || ctx == nil || g.ctx == nil || !reflect.ValueOf(ctx).Comparable() || ctx != g.ctx || ctx.Err() != nil || !pd.SameBootstrapTransaction(g.tx, view) {
		if g.origin != nil {
			g.origin.failed = true
		}
		return fail()
	}
	facts, rows, e := g.source.read(ctx, view)
	if e != nil || !reflect.DeepEqual(facts, g.facts) || !reflect.DeepEqual(rows, g.rows) {
		return fail()
	}
	return nil
}

// Deadline is the existing original registry retention/protection minimum.
// It is not a refreshed observation or a new grant/window.
func (s *BootstrapOriginalEvidenceSource) Deadline() *pd.Timestamp {
	if s == nil || len(s.entries) == 0 {
		return nil
	}
	end := time.Time{}
	for _, entry := range s.entries {
		for _, limit := range []time.Time{entry.Record.ExpiresAt, entry.Record.ProtectedUntil} {
			if end.IsZero() || limit.Before(end) {
				end = limit
			}
		}
	}
	stamp := systemPublicationTimestamp(end)
	return &stamp
}
