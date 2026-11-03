package systembackupinstallationowner

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

// OriginalSignerFirstEnableScope checks DATA only. The independently signed
// original resource sources, live native observers and current SQL checks
// below remain mandatory. It grants no session/config/write authority.
func OriginalSignerFirstEnableScope(current, proposed sec.ConfigValues, originalSHA string, wanted []sec.BootstrapSecretRef) bool {
	if current.Enabled() || !proposed.Enabled() || current.SHA256() != originalSHA || len(wanted) != 3 {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(current.CanonicalJSON(), &fields) != nil {
		return false
	}
	fields["enabled"] = json.RawMessage("true")
	raw, e := canonical(fields)
	if e != nil || !bytes.Equal(raw, proposed.CanonicalJSON()) {
		return false
	}
	seen := map[string]bool{}
	for _, ref := range wanted {
		if seen[ref.Purpose] || ref.Purpose != "capture_signing" && ref.Purpose != "acceptance_signing" && ref.Purpose != "catalog_signing" {
			return false
		}
		seen[ref.Purpose] = true
		foundCurrent, foundProposed := 0, 0
		for _, v := range current.References() {
			if v == ref {
				foundCurrent++
			}
		}
		for _, v := range proposed.References() {
			if v == ref {
				foundProposed++
			}
		}
		if foundCurrent != 1 || foundProposed != 1 {
			return false
		}
	}
	return len(seen) == 3
}

type signerMutationTokenPin struct{ path, sha string }
type signerMutationSnapshot struct {
	capture ownerLedgerState
	signers [2]SigningResourceCAS
	until   time.Time
}
type originalSignerMutationObservation struct {
	mu                 sync.Mutex
	origin             *originalSignerMutationObservation
	ctx                context.Context
	capture            *CaptureSigningValidator
	resources          *SigningResources
	auth               *AuthenticatedRecord
	grants             [2]SigningResourceGrant
	raws, signatures   [2][]byte
	captureObservation *signingObservation
	observations       [2]*ObservedSigningResource
	tokens             []signerMutationTokenPin
	expected           signerMutationSnapshot
	started, until     time.Time
	lastSQL            time.Time
	tx                 *sql.Tx
	failed             atomic.Bool
}

func (*originalSignerMutationObservation) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrRegistrationUnavailable
}
func (s *originalSignerMutationObservation) fail() error {
	if s != nil {
		s.failed.Store(true)
		if s.origin != nil {
			s.origin.failed.Store(true)
		}
	}
	return sec.ErrRegistrationUnavailable
}

func originalSignerSourceScope(auth *AuthenticatedRecord, resources *SigningResources, grants [2]SigningResourceGrant) bool {
	if auth == nil || resources == nil {
		return false
	}
	r := auth.record
	for n, g := range grants {
		pin := resources.inputs[n].Pin
		if g.Target != r.Target || g.Actor != r.Actor || g.ConfigSHA256 != r.ConfigSHA256 || g.BootstrapGrantSHA256 != r.GrantSHA256 || g.EnrollmentID != r.EnrollmentID || g.EnrollmentRevision != r.EnrollmentRevision || g.IssuerID != r.IssuerID || !bytes.Equal(pin.Issuer, auth.pin.Issuer) || !reflect.DeepEqual(g.Histories, r.Histories) {
			return false
		}
		captureFound := false
		for _, binding := range g.Bindings {
			if binding.Purpose == "capture_certificate" {
				captureFound = binding == r.Binding
			}
		}
		if !captureFound {
			return false
		}
	}
	x, y := grants[0], grants[1]
	return x.PlanSHA256 == y.PlanSHA256 && x.EnrollmentDocumentSHA256 == y.EnrollmentDocumentSHA256 && x.SigningMaterialSHA256 == y.SigningMaterialSHA256 && x.SigningMaterialRevision == y.SigningMaterialRevision && reflect.DeepEqual(x.Bindings, y.Bindings) && reflect.DeepEqual(x.Histories, y.Histories)
}

func (s *originalSignerMutationObservation) captureTokens() error {
	transports := []*CaptureSigningObserver{s.capture.observer, s.resources.inputs[0].Observer.transport, s.resources.inputs[1].Observer.transport}
	for _, transport := range transports {
		if transport == nil {
			return s.fail()
		}
		for _, item := range []struct{ path, expected string }{{transport.cfg.ObserverTokenFile, transport.cfg.ObserverTokenSHA256}, {transport.cfg.RuntimeJWTFile, ""}} {
			raw, e := privateToken(item.path)
			if e != nil {
				return s.fail()
			}
			sha := digest(raw)
			clear(raw)
			if item.expected != "" && sha != item.expected {
				return s.fail()
			}
			s.tokens = append(s.tokens, signerMutationTokenPin{item.path, sha})
		}
	}
	return nil
}
func (s *originalSignerMutationObservation) local(ctx context.Context) error {
	if s == nil || s.origin != s || s.failed.Load() || !sameContext(ctx, s.ctx) || ctx.Err() != nil {
		return s.fail()
	}
	auth, e := s.capture.files.read(s.capture.pin)
	if e != nil || !bytes.Equal(auth.raw, s.auth.raw) || !bytes.Equal(auth.signature, s.auth.signature) {
		return s.fail()
	}
	for n, in := range s.resources.inputs {
		raw, e := localFile(in.Files.RecordFile, 262144)
		sig, f := localFile(in.Files.SignatureFile, 64)
		if e != nil || f != nil || !bytes.Equal(raw, s.raws[n]) || !bytes.Equal(sig, s.signatures[n]) || CheckSigningResourceMaterial(ctx, in.Material, s.grants[n]) != nil {
			return s.fail()
		}
	}
	for _, pin := range s.tokens {
		raw, e := privateToken(pin.path)
		if e != nil {
			return s.fail()
		}
		same := digest(raw) == pin.sha
		clear(raw)
		if !same {
			return s.fail()
		}
	}
	return nil
}

// The fixed mode is ONLY the already-authoritative time supplied by the real
// ConfigMutation resolver. Before its SQL prefix, separate read transactions
// sample their own SQL clock with a local monotonic/failure floor.
type signerMutationSQLRead struct {
	*sql.Tx
	fixed  *time.Time
	last   time.Time
	failed bool
}

func (q *signerMutationSQLRead) SampleTime(ctx context.Context) (time.Time, error) {
	if q == nil || q.Tx == nil || q.failed || ctx == nil || ctx.Err() != nil {
		return time.Time{}, ErrOwner
	}
	var now time.Time
	if q.fixed != nil {
		now = *q.fixed
	} else if e := q.Tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now); e != nil {
		q.failed = true
		return time.Time{}, ErrOwner
	}
	if !validTime(now) || now.Before(q.last) {
		q.failed = true
		return time.Time{}, ErrOwner
	}
	q.last = now
	return now, nil
}

var _ pd.BootstrapReadSQL = (*signerMutationSQLRead)(nil)

func (s *originalSignerMutationObservation) snapshot(ctx context.Context, q pd.BootstrapReadSQL) (signerMutationSnapshot, error) {
	var out signerMutationSnapshot
	before, e := q.SampleTime(ctx)
	if e != nil {
		return out, e
	}
	out.capture, e = readOwnerLedger(ctx, q, s.auth, before)
	if e != nil {
		return out, e
	}
	// Retain the actual original capture-head expiry as well as record expiry.
	var raw, sig []byte
	if q.QueryRowContext(ctx, `SELECT signed_head,signature FROM system_backup_installation_owner_heads WHERE installation_id=? AND enrollment_id=? FOR SHARE`, s.auth.pin.InstallationID, s.auth.pin.EnrollmentID).Scan(&raw, &sig) != nil {
		return out, ErrOwner
	}
	head, e := verifyHead(raw, sig, s.auth.pin)
	if e != nil || digest(raw) != out.capture.headHash || before.Before(head.NotBefore) || !before.Before(head.Until) {
		return out, ErrOwner
	}
	out.until = minimum(s.auth.record.Until, head.Until)
	for n, in := range s.resources.inputs {
		current, e := ReadSigningResourceCandidate(ctx, q, in.Pin)
		if e != nil || current.RequireCurrent(before) != nil || !bytes.Equal(current.raw, s.raws[n]) || !bytes.Equal(current.signature, s.signatures[n]) {
			return out, ErrOwner
		}
		out.signers[n] = current.cas
		out.until = minimum(out.until, minimum(current.grant.Until, current.head.Until))
	}
	after, e := q.SampleTime(ctx)
	if e != nil || after.Before(before) || !after.Before(out.until) || ctx.Err() != nil {
		return out, ErrOwner
	}
	return out, nil
}
func (s *originalSignerMutationObservation) readOutsidePrefix(ctx context.Context, db *sql.DB) (signerMutationSnapshot, error) {
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		return signerMutationSnapshot{}, e
	}
	defer tx.Rollback()
	return s.snapshot(ctx, &signerMutationSQLRead{Tx: tx})
}

// This is a NEW mutation-resource check of independently installed original
// sources. It never calls bootstrap Prepare/Authorize/LockReferences, never
// signs a config, and never imports or creates a native/SQL authority record.
// Actual config write/session/RBAC/strong-auth/nonce/deployment/KEK authority
// must remain in the real A/D mutation service around this observation.
func PrepareOriginalSignerMutationResources(ctx context.Context, db *sql.DB, capture *CaptureSigningValidator, resources *SigningResources, input sec.ConfigMutationResourceInput) (sec.ConfigMutationResourceObservation, error) {
	if db == nil || capture == nil || capture.observer == nil || resources == nil || !sameContext(ctx, ctx) || ctx.Err() != nil {
		return nil, sec.ErrRegistrationUnavailable
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, sec.ErrRegistrationUnavailable
	}
	s := &originalSignerMutationObservation{ctx: ctx, capture: capture, resources: resources, started: time.Now().UTC().Truncate(time.Microsecond)}
	s.origin = s
	auth, e := capture.files.read(capture.pin)
	if e != nil {
		return nil, s.fail()
	}
	s.auth = auth
	wanted := []sec.BootstrapSecretRef{auth.record.Reference}
	for n, in := range resources.inputs {
		raw, e := localFile(in.Files.RecordFile, 262144)
		sig, f := localFile(in.Files.SignatureFile, 64)
		grant, g := InspectSigningResourceGrant(raw, sig, in.Pin)
		if e != nil || f != nil || g != nil || CheckSigningResourceMaterial(ctx, in.Material, grant) != nil {
			return nil, s.fail()
		}
		s.grants[n], s.raws[n], s.signatures[n] = grant, raw, sig
		wanted = append(wanted, grant.Reference)
	}
	current, proposed := input.Configs()
	slot := input.Slot()
	if slot != "reference:capture_signing" && slot != "reference:acceptance_signing" && slot != "reference:catalog_signing" || input.InstallationID() != auth.record.Target.InstallationID || input.Actor().UserID != auth.record.Actor.UserID || !originalSignerSourceScope(auth, resources, s.grants) || !OriginalSignerFirstEnableScope(current, proposed, auth.record.ConfigSHA256, wanted) || s.captureTokens() != nil {
		return nil, s.fail()
	}
	deadline := minimum(s.started.Add(25*time.Second), minimum(auth.record.Until, auth.record.Probe.Until))
	for _, grant := range s.grants {
		deadline = minimum(deadline, grant.Until)
	}
	end, _ := ctx.Deadline()
	deadline = minimum(deadline, end.UTC().Truncate(time.Microsecond))
	if !s.started.Before(deadline) {
		return nil, s.fail()
	}
	active, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	before, e := s.readOutsidePrefix(active, db)
	if e != nil {
		return nil, s.fail()
	}
	s.captureObservation, e = capture.observer.observe(active, auth)
	if e != nil || s.captureObservation == nil || s.captureObservation.owner != capture.observer || s.captureObservation.recordHash != capture.pin.RecordSHA256 || len(s.captureObservation.probeSignature) != 64 {
		return nil, s.fail()
	}
	deadline = minimum(deadline, s.captureObservation.until)
	for n, in := range resources.inputs {
		observation, e := in.Observer.ObserveSigningResource(active, s.raws[n], s.signatures[n], in.Pin)
		if e != nil || observation == nil || observation.owner != in.Observer || observation.grantSHA256 != in.Pin.GrantSHA256 || !sameContext(observation.ctx, active) || len(observation.signature) != 64 {
			return nil, s.fail()
		}
		s.observations[n] = observation
		_, originalUntil, windowErr := observation.Window()
		if windowErr != nil {
			return nil, s.fail()
		}
		deadline = minimum(deadline, originalUntil)
	}
	after, e := s.readOutsidePrefix(active, db)
	if e != nil || before != after || s.local(ctx) != nil || !time.Now().Before(deadline) {
		return nil, s.fail()
	}
	deadline = minimum(deadline, after.until)
	if !time.Now().Before(deadline) {
		return nil, s.fail()
	}
	s.expected, s.until = after, deadline
	return s, nil
}

func (s *originalSignerMutationObservation) Risk() sec.ConfigMutationRisk {
	if s == nil || s.origin != s || s.failed.Load() {
		return sec.ConfigMutationRisk{SecurityBoundary: true, ProtectionReduction: true}
	}
	return sec.ConfigMutationRisk{}
}
func (s *originalSignerMutationObservation) ValidUntil() time.Time {
	if s == nil || s.origin != s || s.failed.Load() {
		return time.Time{}
	}
	return s.until
}
func (s *originalSignerMutationObservation) Recheck(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if s == nil {
		return sec.ErrRegistrationUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.origin != s || s.failed.Load() || !sameContext(ctx, s.ctx) || ctx.Err() != nil || tx == nil || s.tx != nil && s.tx != tx || !validTime(now) || now.Before(s.started) || now.Before(s.lastSQL) || !now.Before(s.until) || !time.Now().Before(s.until) || s.local(ctx) != nil {
		return s.fail()
	}
	for _, observation := range s.observations {
		if observation == nil || !observation.pinsCurrent() || now.Before(observation.observed) || !now.Before(observation.until) {
			return s.fail()
		}
	}
	if s.captureObservation == nil || now.Before(s.captureObservation.observed) || !now.Before(s.captureObservation.until) {
		return s.fail()
	}
	s.tx = tx
	actual, e := s.snapshot(ctx, &signerMutationSQLRead{Tx: tx, fixed: &now})
	if e != nil || actual != s.expected || ctx.Err() != nil || !time.Now().Before(s.until) {
		return s.fail()
	}
	s.lastSQL = now
	return nil
}

var _ sec.ConfigMutationResourceObservation = (*originalSignerMutationObservation)(nil)
