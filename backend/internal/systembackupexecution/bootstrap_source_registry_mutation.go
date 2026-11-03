package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
	sec "clawreef/internal/systembackupsecurity"
)

// Separate mutation observation contract. The same four-slot source is reused
// only for native reads; no bootstrap check/OfflineBootstrapGrant authorizes a
// write. A's actual mutation session/RBAC/strong-auth/nonce/KEK remains required.
type BootstrapSourceRegistryEnableOnlyMutation struct {
	owner   *BootstrapSourceRegistryTerminalResource
	mapping install.BootstrapTerminalFiles
	mu      sync.Mutex
	pending map[context.Context]*sourceRegistryMutationObservation
}

func NewBootstrapSourceRegistryEnableOnlyMutation(source *BootstrapSourceRegistryTerminalResource, mapping install.BootstrapTerminalFiles) (*BootstrapSourceRegistryEnableOnlyMutation, error) {
	if source == nil || source.capture == nil || source.nativeFiles == nil || !validBootstrapNativeFiles(*source.nativeFiles) || !formalCandidateDigest(mapping.MappingSHA256) {
		return nil, install.ErrInstall
	}
	for _, path := range []string{mapping.MappingFile, mapping.SignatureFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, install.ErrInstall
		}
	}
	if _, err := source.BindingSHA256(); err != nil {
		return nil, install.ErrInstall
	}
	return &BootstrapSourceRegistryEnableOnlyMutation{owner: source, mapping: mapping, pending: map[context.Context]*sourceRegistryMutationObservation{}}, nil
}

func (*BootstrapSourceRegistryEnableOnlyMutation) MarshalJSON() ([]byte, error) {
	return nil, install.ErrInstall
}

func sourceRegistryMutationSlot(slot string) bool {
	switch slot {
	case "registry:parts", "registry:redis_sources", "registry:secret_allowlist", "registry:source_writers":
		return true
	}
	return false
}

func (v *BootstrapSourceRegistryEnableOnlyMutation) Prepare(ctx context.Context, in sec.ConfigMutationResourceInput) (sec.ConfigMutationResourceObservation, error) {
	if v == nil || v.owner == nil || !minioTerminalContext(ctx, ctx) {
		return nil, install.ErrInstall
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	current, proposed := in.Configs()
	if existing := v.pending[ctx]; existing != nil {
		if sec.ValidateEnableOnlyConfigMutation(in) != nil || !sourceRegistryMutationSlot(in.Slot()) || existing.current != current.SHA256() || existing.proposed != proposed.SHA256() || existing.actor != in.Actor() || existing.installation != in.InstallationID() || existing.slots[in.Slot()] || existing.failed.Load() || existing.samePairs(in) != nil {
			return nil, existing.fail()
		}
		existing.slots[in.Slot()] = true
		return existing, nil
	}
	if sec.ValidateEnableOnlyConfigMutation(in) != nil || !sourceRegistryMutationSlot(in.Slot()) || len(v.pending) >= 64 {
		return nil, install.ErrInstall
	}
	observation, err := v.prepare(ctx, in)
	if err != nil {
		// Preserve failed preparation for this request too. Another alias cannot
		// start a second observation and manufacture a later native deadline.
		failed := &sourceRegistryMutationObservation{ctx: ctx, slots: map[string]bool{}, current: current.SHA256(), proposed: proposed.SHA256(), actor: in.Actor(), installation: in.InstallationID()}
		failed.origin = failed
		failed.failed.Store(true)
		v.pending[ctx] = failed
		context.AfterFunc(ctx, func() { v.mu.Lock(); delete(v.pending, ctx); v.mu.Unlock() })
		return nil, install.ErrInstall
	}
	observation.slots[in.Slot()] = true
	v.pending[ctx] = observation
	context.AfterFunc(ctx, func() { observation.failed.Store(true); v.mu.Lock(); delete(v.pending, ctx); v.mu.Unlock() })
	return observation, nil
}

func (v *BootstrapSourceRegistryEnableOnlyMutation) prepare(ctx context.Context, in sec.ConfigMutationResourceInput) (*sourceRegistryMutationObservation, error) {
	started := time.Now().UTC().Truncate(time.Microsecond)
	until := started.Add(30 * time.Second)
	if deadline, ok := ctx.Deadline(); !ok {
		return nil, install.ErrInstall
	} else if deadline.Before(until) {
		until = deadline
	}
	binding, err := v.owner.BindingSHA256()
	if err != nil {
		return nil, install.ErrInstall
	}
	source, err := v.owner.capture.PrepareSourceRegistryEnableOnlyRead(ctx, in, v.owner.files, v.mapping, binding)
	if err != nil {
		return nil, install.ErrInstall
	}
	read, err := source.NativeReadSource(ctx)
	if err != nil {
		return nil, install.ErrInstall
	}
	record, err := read.Association()
	if err != nil {
		return nil, install.ErrInstall
	}
	current, proposed := in.Configs()
	o := &sourceRegistryMutationObservation{ctx: ctx, source: source, current: current.SHA256(), proposed: proposed.SHA256(), actor: in.Actor(), installation: in.InstallationID(), slots: map[string]bool{}, pairs: map[string]sec.ConfigMutationRegistryPair{}, pins: map[string]install.BootstrapSourceFilePin{"parts": record.Source.PartsRegistry, "source_writers": record.Source.SourceWritersRegistry, "redis_sources": v.owner.nativeFiles.RedisSources, "secret_allowlist": v.owner.nativeFiles.SecretAllowlist}}
	o.origin = o
	o.started, o.until = started, until
	if end := source.ValidUntil(); end.Before(o.until) {
		o.until = end
	}
	if !time.Now().Before(o.until) {
		return nil, install.ErrInstall
	}
	if in.InstallationID() != record.Target.InstallationID {
		return nil, install.ErrInstall
	}
	for kind, pin := range o.pins {
		pair, ok := in.RegistryPair(kind)
		if !ok || pair.Current != pair.Proposed || pair.Current.Kind != kind || pair.Current.SHA256 != pin.SHA256 || !bytes.Equal(pair.CurrentJSON, pair.ProposedJSON) || hash(pair.CurrentJSON) != pin.SHA256 {
			return nil, install.ErrInstall
		}
		o.pairs[kind] = pair
	}
	// Do not invoke the bootstrap terminal/check. This is a new independent
	// observation, using only its actual original native-read source.
	reader, err := newBootstrapSourceRegistryReader(ctx, read)
	if err != nil {
		return nil, install.ErrInstall
	}
	defer reader.Close()
	// Narrow real native requests to the mutation's ORIGINAL earliest start,
	// rather than renewing at the reader's later construction time.
	physical, cancel := context.WithDeadline(reader.physical, o.until)
	defer cancel()
	reader.physical = physical
	facts, err := reader.collectBootstrapSourceFacts()
	if err != nil || reader.matchSourceRegistries(facts) != nil {
		return nil, install.ErrInstall
	}
	redis := o.pairs["redis_sources"]
	want, err := reader.redisSourceRegistry(redis.Current.Version, facts)
	var actual bootstrapRedisSourceRegistry
	if err != nil || strictBootstrapSourceJSON(redis.CurrentJSON, &actual) != nil || !reflect.DeepEqual(actual, want) {
		return nil, install.ErrInstall
	}
	if _, err := reader.selectedSecretPolicy(v.owner.nativeFiles.SecretAllowlist, o.pairs["secret_allowlist"].Current.Version, facts); err != nil {
		return nil, install.ErrInstall
	}
	_, readUntil, err := reader.access.Bounds(ctx)
	if err != nil {
		return nil, install.ErrInstall
	}
	if readUntil.Before(o.until) {
		o.until = readUntil
	}
	if o.samePairs(in) != nil || !o.started.Before(o.until) || o.local(ctx) != nil || !time.Now().Before(o.until) {
		return nil, install.ErrInstall
	}
	return o, nil
}

type sourceRegistryMutationObservation struct {
	mu                                sync.Mutex
	origin                            *sourceRegistryMutationObservation
	failed                            atomic.Bool
	ctx                               context.Context
	source                            *install.BootstrapSourceRegistryMutationRead
	current, proposed, installation   string
	actor                             sec.RegistrationActor
	pairs                             map[string]sec.ConfigMutationRegistryPair
	pins                              map[string]install.BootstrapSourceFilePin
	slots                             map[string]bool
	started, until, floor, inputFloor time.Time
	tx                                *sql.Tx
}

func (*sourceRegistryMutationObservation) MarshalJSON() ([]byte, error) {
	return nil, install.ErrInstall
}
func (*sourceRegistryMutationObservation) Risk() sec.ConfigMutationRisk {
	return sec.ConfigMutationRisk{SecurityBoundary: true}
}
func (o *sourceRegistryMutationObservation) fail() error {
	if o != nil {
		o.failed.Store(true)
		if o.origin != nil {
			o.origin.failed.Store(true)
		}
	}
	return install.ErrInstall
}
func (o *sourceRegistryMutationObservation) ValidUntil() time.Time {
	if o == nil {
		return time.Time{}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.origin != o || o.failed.Load() {
		_ = o.fail()
		return time.Time{}
	}
	return o.until
}
func (o *sourceRegistryMutationObservation) samePairs(in sec.ConfigMutationResourceInput) error {
	for kind, original := range o.pairs {
		pair, ok := in.RegistryPair(kind)
		if !ok || pair.Current != original.Current || pair.Proposed != original.Proposed || !bytes.Equal(pair.CurrentJSON, original.CurrentJSON) || !bytes.Equal(pair.ProposedJSON, original.ProposedJSON) {
			return o.fail()
		}
	}
	return nil
}
func (o *sourceRegistryMutationObservation) local(ctx context.Context) error {
	if o == nil || o.origin != o || o.failed.Load() || !minioTerminalContext(ctx, o.ctx) || o.source == nil || time.Now().Before(o.started) || !time.Now().Before(o.until) {
		return o.fail()
	}
	for kind, pin := range o.pins {
		raw, err := readBootstrapNativeRegistryPin(pin)
		if err != nil || !bytes.Equal(raw, o.pairs[kind].CurrentJSON) {
			clear(raw)
			return o.fail()
		}
		clear(raw)
	}
	if ctx.Err() != nil || !time.Now().Before(o.until) {
		return o.fail()
	}
	return nil
}

func (o *sourceRegistryMutationObservation) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if o == nil {
		return install.ErrInstall
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if tx == nil || o.tx != nil && o.tx != tx || now.IsZero() || !o.inputFloor.IsZero() && now.Before(o.inputFloor) || now.Before(o.started) || !now.Before(o.until) || o.local(ctx) != nil || o.source.Recheck(ctx, tx, now) != nil {
		return o.fail()
	}
	if until := o.source.ValidUntil(); until.Before(o.until) {
		o.until = until
	}
	// These are the exact four original/proposed registry pins. No provider I/O
	// under mutation SQL; the LAST delivered SQL sample follows all local tails.
	if o.local(ctx) != nil {
		return o.fail()
	}
	var tail time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&tail) != nil || tail.Before(now) || tail.Before(o.started) || !o.floor.IsZero() && tail.Before(o.floor) || !tail.Before(o.until) || ctx.Err() != nil || !time.Now().Before(o.until) {
		return o.fail()
	}
	o.tx = tx
	o.floor = tail
	o.inputFloor = now
	return nil
}

var _ sec.ConfigMutationResourceValidator = (*BootstrapSourceRegistryEnableOnlyMutation)(nil)
var _ sec.ConfigMutationResourceObservation = (*sourceRegistryMutationObservation)(nil)
