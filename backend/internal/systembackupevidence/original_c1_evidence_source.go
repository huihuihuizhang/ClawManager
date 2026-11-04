package systembackupevidence

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// Source observations are data. Only the private original producer state plus
// independent original committed SQL readback authenticates their provenance.
// Manifest.Key remains a genuine retained key reference, never inline metadata.
type OriginalC1EvidenceFacts struct {
	KeySource                         OriginalC1KeySource
	Record                            Record
	Channel                           ProducerEvidenceChannel
	Domain                            pd.DomainRecord
	Grant                             pd.GrantRecord
	Run                               pd.RunRecord
	History                           pd.HistoricalBindingRecord
	Target                            pd.TargetRecord
	Receipt                           pd.ReceiptRecord
	References                        []pd.ReferenceRecord
	Commands                          []pd.CommandReceiptRecord
	NativePublication                 SystemPublicationProof
	NativeStore                       S3Config
	EvidenceRowID, EvidenceRowVersion int64
	ObservedAt                        time.Time
}

// No caller DTO/receipt/hash constructor. A failed/rolled-back transaction can
// leave staged source DATA only; ReadCommitted MUST find the exact original
// result and evidence/chunks before exposing any authenticated source facts.
type OriginalC1EvidenceSource struct {
	mu             sync.Mutex
	origin         *OriginalC1EvidenceSource
	publication    *NativeSystemPublicationVerifier
	original       systemPublicationOriginal
	channel        ProducerEvidenceChannel
	keySource      OriginalC1KeySource
	commands       *pd.OriginalCommandSource
	backing        *OriginalC1BackingStoreSource
	ctx            context.Context
	facts          OriginalC1EvidenceFacts
	stored         systemPendingStored
	staged, failed bool
}

func (*OriginalC1EvidenceSource) MarshalJSON() ([]byte, error) { return nil, ErrDenied }

// Guard data only, explicitly NOT evidence of a Result COMMIT. The concrete
// mixed source reader uses it to acquire complete C1 ranges in original order,
// then MUST call ReadCommitted in that same source transaction for every run.
func (s *OriginalC1EvidenceSource) OriginalGuardData(ctx context.Context) (OriginalC1EvidenceFacts, error) {
	var zero OriginalC1EvidenceFacts
	if s == nil {
		return zero, ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.origin != s || s.failed || !s.staged || !sameRelayContext(ctx, s.ctx) || ctx.Err() != nil {
		return zero, ErrDenied
	}
	raw, e := json.Marshal(s.facts)
	if e != nil || json.Unmarshal(raw, &zero) != nil {
		return OriginalC1EvidenceFacts{}, ErrDenied
	}
	commands, e := s.commands.OriginalCommittedData()
	if e != nil {
		return OriginalC1EvidenceFacts{}, ErrDenied
	}
	zero.Commands = commands
	hold, e := pd.OriginalPendingHoldData(zero.History)
	if e != nil {
		return OriginalC1EvidenceFacts{}, ErrDenied
	}
	zero.References = append(zero.References, hold)
	return zero, nil
}

// D's real ResultsService must receive THIS environment before CommitResult.
// The caller retains the source and later passes the opaque object to the
// original installer mixed-source reader. It cannot manufacture source facts.
func NewTrackedSystemResultEnvironment(a SystemResultAuthority, p Prepared, c ProducerEvidenceChannel, h pd.HistoricalBindingRecord, publisher *SystemPublisher) (*SystemResultEnvironment, *OriginalC1EvidenceSource, error) {
	// The original direct provider constructor remains available. A temporary
	// loopback transport must use the concrete backing-source entry below.
	return newTrackedSystemResultEnvironment(a, p, c, h, publisher, nil)
}

func NewTrackedSystemResultEnvironmentWithBacking(ctx context.Context, a SystemResultAuthority, p Prepared, c ProducerEvidenceChannel, h pd.HistoricalBindingRecord, publisher *SystemPublisher, backing *OriginalC1BackingStoreSource) (*SystemResultEnvironment, *OriginalC1EvidenceSource, error) {
	if backing == nil || backing.CurrentOriginalOwner(ctx) != nil || publisher == nil || publisher.sts == nil {
		return nil, nil, ErrDenied
	}
	profile, ok := publisher.sts.verifier.(*originalC1ChannelProfile)
	if !ok || profile.gateway == nil || profile.gateway.BackingStoreSource() != backing {
		return nil, nil, ErrDenied
	}
	transport, _, err := backing.OriginalChannel()
	transport.CAPEM, transport.Store.CAPEM = nil, nil
	if err != nil || !reflect.DeepEqual(transport, publisher.sts.c.STS) || !sameRelayContext(ctx, profile.ctx) {
		return nil, nil, ErrDenied
	}
	return newTrackedSystemResultEnvironment(a, p, c, h, publisher, backing)
}

func newTrackedSystemResultEnvironment(a SystemResultAuthority, p Prepared, c ProducerEvidenceChannel, h pd.HistoricalBindingRecord, publisher *SystemPublisher, backing *OriginalC1BackingStoreSource) (*SystemResultEnvironment, *OriginalC1EvidenceSource, error) {
	keySource, keyErr := originalC1KeySource(p)
	if keyErr != nil {
		return nil, nil, ErrDenied
	}
	e, err := NewSystemResultEnvironment(a, p, c, h)
	if err != nil || publisher == nil || publisher.nativeVerifier == nil || publisher.closed.Load() {
		return nil, nil, ErrDenied
	}
	if publisher.sts == nil {
		return nil, nil, ErrDenied
	}
	u, parseErr := url.Parse(publisher.sts.c.STS.Store.Endpoint)
	if parseErr != nil || u.Hostname() == "" {
		return nil, nil, ErrDenied
	}
	ip := net.ParseIP(u.Hostname())
	if backing == nil && (strings.EqualFold(u.Hostname(), "localhost") || ip != nil && ip.IsLoopback()) {
		return nil, nil, ErrDenied
	}
	v := publisher.nativeVerifier
	preparation, ok := p.transitSource.preparer.authority.(*systemExecutionAuthority)
	if !ok || preparation == nil {
		return nil, nil, ErrDenied
	}
	wrapCalls, ok := preparation.calls.(systemDCalls)
	if !ok {
		return nil, nil, ErrDenied
	}
	v.mu.Lock()
	valid := v.origin == v && !v.closed && !v.failed && v.sts == publisher.sts && v.sts != nil && v.sts.original.historyHash == e.original.historyHash && reflect.DeepEqual(v.sts.original.record, e.original.record)
	var publicationCalls systemDPublicationCalls
	callsOK := false
	if v.sts != nil {
		publicationCalls, callsOK = v.sts.calls.(systemDPublicationCalls)
	}
	v.mu.Unlock()
	if !valid || !callsOK || publicationCalls.handle != wrapCalls.handle {
		return nil, nil, ErrDenied
	}
	commands, err := publicationCalls.execution.OriginalCommandSource(publicationCalls.handle)
	if err != nil {
		return nil, nil, ErrDenied
	}
	wrapCommands, err := wrapCalls.execution.OriginalCommandSource(wrapCalls.handle)
	if err != nil || wrapCommands != commands {
		return nil, nil, ErrDenied
	}
	s := &OriginalC1EvidenceSource{publication: v, original: e.original, channel: c, keySource: keySource, commands: commands}
	s.backing = backing
	s.origin = s
	e.source = s
	return e, s, nil
}

func (s *OriginalC1EvidenceSource) stageOriginalResult(ctx context.Context, write *pd.Transaction, read pd.ReadSQL, b pd.ResultBinding, f pd.ResultFacts, row systemPendingStored, now time.Time) error {
	if s == nil {
		return ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fail := func() error { s.failed = true; return ErrDenied }
	if s.origin != s || s.failed || s.staged || ctx == nil || ctx.Err() != nil || !pd.SameGuardedTransaction(write, read) || f.Replayed || f.Receipt == nil || f.Grant == nil || f.Run == nil || f.History == nil || f.Target == nil || f.Evidence == nil || f.Projection == nil || f.Projection.Mode != "candidate" || f.Run.State != "committed" || row.State != "ready" || row.Failure != "none" || row.Claim.Valid || row.ClaimUntil.Valid || !s.original.historyMatches(*f.History) {
		return fail()
	}
	v := s.publication
	if v == nil || v.sts == nil {
		return fail()
	}
	v.mu.Lock()
	proof := v.proof
	nativeStore := v.sts.c.STS.Store
	nativeStore.CAPEM = nil
	valid := v.origin == v && !v.closed && !v.failed && v.used && v.bound && proof.State == "ready" && proof.Request.RunID == b.Request.RunID && proof.Request.Scope == b.Request.Scope && proof.Request.Claim.EvidenceID == b.Request.Evidence.EvidenceID && proof.Object.Version != "" && b.Request.Evidence.ImmutableVersion != nil && proof.Object.Version == string(*b.Request.Evidence.ImmutableVersion) && proof.Object.SHA256 == s.original.record.Manifest.ObjectHash && proof.Object.Size == s.original.record.Manifest.ObjectSize
	v.mu.Unlock()
	if s.backing != nil {
		upstream, observed, e := s.backing.OriginalStore()
		if e != nil || observed.After(now) || upstream.Identity != nativeStore.Identity || upstream.Version != nativeStore.Version || upstream.Installation != nativeStore.Installation || upstream.Bucket != nativeStore.Bucket || upstream.Root != nativeStore.Root {
			return fail()
		}
		upstream.CAPEM = nil
		nativeStore = upstream
	}
	if !valid || now.Before(proof.ObservedAt) || now.Before(s.original.record.CreatedAt) || !now.Before(s.original.record.ExpiresAt) || f.Receipt.RequestHash == "" || !reflect.DeepEqual(f.Receipt.Request, b.Request) {
		return fail()
	}
	r := s.original.copyRecord()
	r.State = "ready"
	r.Failure = "none"
	r.Ref.ImmutableVersion = proof.Object.Version
	r.RowVersion = row.Version
	facts := OriginalC1EvidenceFacts{KeySource: s.keySource, Record: r, Channel: s.channel, Domain: f.Domain, Grant: *f.Grant, Run: *f.Run, History: *f.History, Target: *f.Target, Receipt: *f.Receipt, References: f.References, NativePublication: proof, EvidenceRowID: row.ID, EvidenceRowVersion: row.Version, ObservedAt: now}
	facts.NativeStore = nativeStore
	raw, err := json.Marshal(facts)
	if err != nil || json.Unmarshal(raw, &s.facts) != nil {
		return fail()
	}
	s.ctx = ctx
	s.stored = row
	s.staged = true
	return nil
}

// Recheck committed original rows in a caller-owned RR source transaction.
// The caller authenticates original installer/Plan/db identity and owns locking
// order/completion. No commit, provider IO, renewal or source signing occurs.
// Exact guards also run after rolled-back/unknown Result attempts: absent or
// different receipt/run/target/history/evidence/chunks means refusal.
func (s *OriginalC1EvidenceSource) ReadCommitted(ctx context.Context, tx *sql.Tx) (OriginalC1EvidenceFacts, error) {
	var zero OriginalC1EvidenceFacts
	if s == nil {
		return zero, ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.origin != s || s.failed || !s.staged || tx == nil || !sameRelayContext(ctx, s.ctx) || ctx.Err() != nil {
		return zero, ErrDenied
	}
	f := s.facts
	var server, database string
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)").Scan(&server, &database, &now) != nil || server != string(f.History.Scope.ServerUUID) || database != string(f.History.Scope.Database) || now.Before(f.ObservedAt) || !now.Before(f.Record.ExpiresAt) || !now.Before(f.Record.ProtectedUntil) {
		return zero, ErrDenied
	}
	check := func(key pd.RecordKey, want any, out any) bool {
		found, e := pd.ReadOriginalSharedRecord(ctx, tx, f.History.Scope, key, out)
		return e == nil && found && reflect.DeepEqual(want, out)
	}
	var domain pd.DomainRecord
	var grant pd.GrantRecord
	var run pd.RunRecord
	var history pd.HistoricalBindingRecord
	var target pd.TargetRecord
	var receipt pd.ReceiptRecord
	if !check(pd.RecordKey{}, &f.Domain, &domain) || !check(pd.RecordKey{ID: f.Grant.GrantID}, &f.Grant, &grant) || !check(pd.RecordKey{ID: f.Run.RunID}, &f.Run, &run) || !check(pd.RecordKey{EvidenceID: f.History.Evidence.EvidenceID}, &f.History, &history) || !check(pd.RecordKey{Hash: f.Target.TargetHash}, &f.Target, &target) || !check(pd.RecordKey{Hash: f.Receipt.ReceiptKeyHash}, &f.Receipt, &receipt) {
		return zero, ErrIntegrity
	}
	for _, ref := range f.References {
		var actual pd.ReferenceRecord
		if !check(pd.RecordKey{EvidenceID: ref.EvidenceID, ReferenceKind: ref.ReferenceKind, Hash: ref.ReferenceKeyHash}, &ref, &actual) {
			return zero, ErrIntegrity
		}
	}
	commands, commandErr := s.commands.ReadOriginal(ctx, tx)
	if commandErr != nil {
		return zero, ErrIntegrity
	}
	f.Commands = commands
	hold, holdErr := pd.ReadOriginalPendingHold(ctx, tx, f.History)
	if holdErr != nil {
		return zero, ErrIntegrity
	}
	f.References = append(f.References, hold)
	// The original row loader rechecks every original immutable projection and
	// complete chunk nonce/tag/hash/offset list against the genuine Prepared.
	row, found, e := loadSystemPublication(ctx, tx, s.original.record, f.Record.Ref.ImmutableVersion)
	if e != nil || !found || !reflect.DeepEqual(row, s.stored) || row.ID != f.EvidenceRowID || row.Version != f.EvidenceRowVersion || row.State != "ready" || row.Failure != "none" || row.Claim.Valid || row.ClaimUntil.Valid {
		return zero, ErrIntegrity
	}
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || now.Before(f.ObservedAt) || !now.Before(f.Record.ExpiresAt) || !now.Before(f.Record.ProtectedUntil) || ctx.Err() != nil {
		return zero, ErrDenied
	}
	raw, e := json.Marshal(f)
	if e != nil || json.Unmarshal(raw, &zero) != nil {
		return OriginalC1EvidenceFacts{}, ErrDenied
	}
	return zero, nil
}
