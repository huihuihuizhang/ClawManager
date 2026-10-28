package systembackupproducer

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (p *bootstrapConsumptionPolicy) lock(ctx context.Context, key RecordKey, out any) error {
	l, err := p.tx.LockRecord(ctx, key, out)
	if err != nil {
		return err
	}
	if !l.Found() {
		return ErrGuardRequired
	}
	p.locks = append(p.locks, l)
	return nil
}

func (p *bootstrapConsumptionPolicy) lockCandidates(ctx context.Context) error {
	// Alias relationships stay in the request/hash. Deduplicating identical SQL
	// primary keys here only avoids acquiring one lock twice, never authenticates
	// an alias. Conflicting requests under one receipt key are rejected.
	selected := map[Hash]BootstrapCandidateSelection{}
	keys := []Hash{}
	for _, c := range p.request.Candidates {
		d, err := ResultHashes(c.Request)
		if err != nil {
			return err
		}
		if prior, ok := selected[d.Key]; ok {
			if !reflect.DeepEqual(prior.Request, c.Request) || prior.ResultVersion != c.ResultVersion {
				return ErrConflict
			}
		} else {
			selected[d.Key] = c
			keys = append(keys, d.Key)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, key := range keys {
		c := selected[key]
		d, _ := ResultHashes(c.Request)
		var receipt ReceiptRecord
		if err := p.lock(ctx, RecordKey{Hash: key}, &receipt); err != nil {
			return err
		}
		if receipt.RequestHash != d.Request || receipt.ResultVersion != c.ResultVersion || !reflect.DeepEqual(receipt.Request, c.Request) {
			return ErrConflict
		}
		p.facts.Candidates = append(p.facts.Candidates, ResultFacts{Domain: detached(p.facts.Domain), Receipt: &receipt})
	}
	grants := map[ID]GrantRecord{}
	runs := map[ID]RunRecord{}
	histories := map[EvidenceID]HistoricalBindingRecord{}
	for _, f := range p.facts.Candidates {
		r := f.Receipt.Request
		grants[r.GrantID] = GrantRecord{}
		runs[r.RunID] = RunRecord{}
		histories[r.Evidence.EvidenceID] = HistoricalBindingRecord{}
	}
	grantIDs := make([]ID, 0, len(grants))
	for key := range grants {
		grantIDs = append(grantIDs, key)
	}
	sort.Slice(grantIDs, func(i, j int) bool { return grantIDs[i] < grantIDs[j] })
	for _, key := range grantIDs {
		var g GrantRecord
		if err := p.lock(ctx, RecordKey{ID: key}, &g); err != nil {
			return err
		}
		grants[key] = g
	}
	runIDs := make([]ID, 0, len(runs))
	for key := range runs {
		runIDs = append(runIDs, key)
	}
	sort.Slice(runIDs, func(i, j int) bool { return runIDs[i] < runIDs[j] })
	for _, key := range runIDs {
		var r RunRecord
		if err := p.lock(ctx, RecordKey{ID: key}, &r); err != nil {
			return err
		}
		runs[key] = r
	}
	evidenceIDs := make([]EvidenceID, 0, len(histories))
	for key := range histories {
		evidenceIDs = append(evidenceIDs, key)
	}
	sort.Slice(evidenceIDs, func(i, j int) bool { return evidenceIDs[i] < evidenceIDs[j] })
	for _, key := range evidenceIDs {
		var h HistoricalBindingRecord
		if err := p.lock(ctx, RecordKey{EvidenceID: key}, &h); err != nil {
			return err
		}
		histories[key] = h
	}
	for i := range p.facts.Candidates {
		f := &p.facts.Candidates[i]
		r := f.Receipt.Request
		g, run, h := grants[r.GrantID], runs[r.RunID], histories[r.Evidence.EvidenceID]
		d := p.facts.Domain
		digests, _ := ResultHashes(r)
		pendingEvidence := r.Evidence
		pendingEvidence.ImmutableVersion = nil
		// GrantVersion is deliberately absent: ReceiptRecord never persisted the
		// original execution snapshot. Capture CURRENT locked rows for final guard.
		if g.State != "active" || g.Generation != r.GrantGeneration || g.DomainEpoch != d.Epoch || r.DomainEpoch != d.Epoch || g.IssuerIdentityHash != d.IssuerIdentityHash || !reflect.DeepEqual(g.Admission, d.Admission) || !reflect.DeepEqual(r.Admission, d.Admission) || !reflect.DeepEqual(g.Target, r.Target) || g.Purpose != r.Purpose || run.State != "committed" || run.GrantID != g.GrantID || run.GrantGeneration != g.Generation || run.TargetHash != digests.Target || run.TargetGeneration != r.TargetGeneration || run.InputHash != r.InputHash || run.EvidenceID != r.Evidence.EvidenceID || run.ObservedAt == nil || run.ObservationExpiresAt == nil || *run.ObservedAt != r.ObservedAt || *run.ObservationExpiresAt != r.ObservationExpiresAt || h.RunID != run.RunID || h.GrantID != g.GrantID || h.GrantGeneration != g.Generation || h.DomainEpoch != d.Epoch || !reflect.DeepEqual(h.Admission, d.Admission) || h.TargetHash != digests.Target || h.InputHash != r.InputHash || h.OwnerWriteExpiresAt != run.OwnerWriteExpiresAt || h.ObservedAt != r.ObservedAt || h.ObservationExpiresAt != r.ObservationExpiresAt || !reflect.DeepEqual(h.Evidence, pendingEvidence) || !validObjectVersion(r.Evidence.ImmutableVersion) {
			return ErrConflict
		}
		f.Grant, f.Run, f.History = &g, &run, &h
	}
	return nil
}

func (p *bootstrapConsumptionPolicy) lockTargets(ctx context.Context) error {
	targets := map[Hash]TargetRecord{}
	for _, f := range p.facts.Candidates {
		d, _ := ResultHashes(f.Receipt.Request)
		targets[d.Target] = TargetRecord{}
	}
	keys := make([]Hash, 0, len(targets))
	for key := range targets {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, key := range keys {
		var target TargetRecord
		if err := p.lock(ctx, RecordKey{Hash: key}, &target); err != nil {
			return err
		}
		targets[key] = target
	}
	for i := range p.facts.Candidates {
		f := &p.facts.Candidates[i]
		r := f.Receipt.Request
		digests, _ := ResultHashes(r)
		target := targets[digests.Target]
		if !reflect.DeepEqual(target.Target, r.Target) || target.Generation != r.TargetGeneration || target.CurrentRunID != r.RunID || target.ResultVersion != ZeroCounter(f.Receipt.ResultVersion) {
			return ErrConflict
		}
		f.Target = &target
	}
	return nil
}

func (p *bootstrapConsumptionPolicy) lockReferences(ctx context.Context) error {
	type refKey struct {
		evidence EvidenceID
		kind     string
		hash     Hash
	}
	refs := map[refKey]ReferenceRecord{}
	perCandidate := make([][]refKey, len(p.facts.Candidates))
	for i, f := range p.facts.Candidates {
		d, _ := ResultHashes(f.Receipt.Request)
		hold, err := pendingReferenceHash(*f.History)
		if err != nil {
			return err
		}
		keys := []refKey{{f.Receipt.Request.Evidence.EvidenceID, "bootstrap_candidate", d.Key}, {f.Receipt.Request.Evidence.EvidenceID, "producer_receipt", d.Key}, {f.Receipt.Request.Evidence.EvidenceID, "hold", hold}}
		perCandidate[i] = keys
		for _, key := range keys {
			refs[key] = ReferenceRecord{}
		}
	}
	keys := make([]refKey, 0, len(refs))
	for key := range refs {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.evidence != b.evidence {
			return a.evidence < b.evidence
		}
		if a.kind != b.kind {
			return a.kind < b.kind
		}
		return a.hash < b.hash
	})
	for _, key := range keys {
		var ref ReferenceRecord
		if err := p.lock(ctx, RecordKey{EvidenceID: key.evidence, ReferenceKind: key.kind, Hash: key.hash}, &ref); err != nil {
			return err
		}
		refs[key] = ref
	}
	for i := range p.facts.Candidates {
		f := &p.facts.Candidates[i]
		for _, key := range perCandidate[i] {
			ref := refs[key]
			until := f.History.RetentionExpiresAt
			if key.kind == "producer_receipt" {
				until = f.Receipt.RetentionExpiresAt
			}
			if ref.ProtectedUntil != until || key.kind == "hold" && ref.CreatedAt != f.History.CreatedAt {
				return ErrConflict
			}
			f.References = append(f.References, ref)
		}
	}
	return nil
}

func (p *bootstrapConsumptionPolicy) write(ctx context.Context, tx *Transaction) error {
	if tx != p.tx {
		return ErrGuardRequired
	}
	if p.facts.Replayed {
		if err := p.captureBootstrapRows(ctx); err != nil {
			return err
		}
		return p.finishCallbacks(ctx, tx)
	}
	env, r := p.authority.Session, p.request
	if err := env.AuditIntent(ctx, tx, detached(r), detached(p.facts)); err != nil {
		return err
	}
	// Present the evidence batch in public-ID order independent of request order.
	sort.Slice(p.facts.Candidates, func(i, j int) bool {
		return p.facts.Candidates[i].Receipt.Request.Evidence.EvidenceID < p.facts.Candidates[j].Receipt.Request.Evidence.EvidenceID
	})
	evidence, err := env.LockEvidence(ctx, tx, detached(r), detached(p.facts))
	if err != nil {
		return err
	}
	if len(evidence) != len(p.facts.Candidates) {
		return ErrGuardRequired
	}
	for i := range evidence {
		f := &p.facts.Candidates[i]
		e := detached(evidence[i])
		request := f.Receipt.Request
		if validateTyped(reflect.ValueOf(e)) != nil || !reflect.DeepEqual(e.Evidence, request.Evidence) || e.RowVersion != request.ExpectedEvidenceVersion || e.State != "ready" || e.Failure != "none" || e.ClaimOwner != nil || e.ClaimExpiresAt != nil || e.RetentionExpiresAt < f.Receipt.RetentionExpiresAt || e.ProtectedUntil < f.Receipt.RetentionExpiresAt || e.RetentionExpiresAt < f.History.RetentionExpiresAt || e.ProtectedUntil < f.History.RetentionExpiresAt {
			return ErrGuardRequired
		}
		f.Evidence = &e
		if err = p.captureEvidence(ctx, *f); err != nil {
			return err
		}
	}
	now, err := tx.SampleTime(ctx)
	if err != nil {
		return err
	}
	closed := detached(p.facts.Domain)
	closed.Epoch, err = nextCounter(closed.Epoch)
	if err != nil {
		return err
	}
	closed.RowVersion, err = nextCounter(closed.RowVersion)
	if err != nil {
		return err
	}
	closed.State = "closed"
	closed.UpdatedAt = Timestamp(now.Format(timeLayout))
	if err = tx.ReplaceRecord(ctx, p.domainLock, &closed); err != nil {
		return err
	}
	p.closed = closed
	p.facts.Write, err = env.WriteBootstrap(ctx, tx, detached(r), detached(p.facts), p.operationID(), p.hash, now)
	if err != nil {
		return err
	}
	if p.facts.Write.IntentAuditID <= 0 || p.facts.Write.ResultAuditID <= 0 || p.facts.Write.IntentAuditID == p.facts.Write.ResultAuditID {
		return ErrGuardRequired
	}
	if err = p.captureBootstrapRows(ctx); err != nil {
		return err
	}
	return p.finishCallbacks(ctx, tx)
}

// All delegated source checks finish within Work, before the SQL-only fixed
// FinalGuard. Close every public write capability first: even a retained write
// pointer cannot mutate while read-only source checks run. The private view may
// use the original shared clock and already-held rows; exact controlled local
// file rechecks belong here, never provider/TLS calls or refreshed observations.
func (p *bootstrapConsumptionPolicy) finishCallbacks(ctx context.Context, tx *Transaction) error {
	if tx != p.tx || p.callbacksComplete {
		return ErrGuardRequired
	}
	if err := tx.close(); err != nil {
		return err
	}
	now, err := tx.sampleGuardTime(ctx, true)
	if err != nil {
		return err
	}
	if err = checkTime(ctx, p.plan, now); err != nil {
		return err
	}
	var readFailure error
	view := &bootstrapReadView{state: &bootstrapReadState{open: true, read: readSQL{tx: tx.tx, fault: &readFailure}, tx: tx}}
	defer view.close() // Also seal retained reads if a trusted callback panics.
	err = p.authority.Session.Recheck(ctx, view, detached(p.request), detached(p.facts), now)
	view.close()
	if err != nil {
		return err
	}
	if readFailure != nil {
		return readFailure
	}
	if err = tx.failure(); err != nil {
		return err
	}
	now, err = tx.sampleGuardTime(ctx, true)
	if err != nil {
		return err
	}
	if err = checkTime(ctx, p.plan, now); err != nil {
		return err
	}
	p.callbacksComplete = true
	return nil
}

func (p *bootstrapConsumptionPolicy) Recheck(ctx context.Context, read ReadSQL, scope Scope, plan GuardPlan, now time.Time) error {
	if scope != p.request.Scope || plan.BindingHash != p.hash || !p.callbacksComplete {
		return ErrGuardRequired
	}
	// No adapter callbacks, files, network or mutation in this fixed FinalGuard.
	// Every SQL key/range was already locked before Work.
	var err error
	for _, lock := range p.locks {
		if err = p.verifyRecord(ctx, read, lock); err != nil {
			return err
		}
	}
	if err = p.verifySnapshots(ctx, read); err != nil {
		return err
	}
	return p.verifyBootstrap(ctx, read)
}

func (p *bootstrapConsumptionPolicy) verifyRecord(ctx context.Context, read ReadSQL, lock *LockedRecord) error {
	s := lock.definition
	columns := recordColumns(s)
	keys := recordPrimary(s)
	conditions := make([]string, len(keys))
	for i, key := range keys {
		conditions[i] = key + " = ?"
	}
	q := "SELECT " + strings.Join(columns, ",") + " FROM " + s.table + " WHERE " + strings.Join(conditions, " AND ") + " FOR UPDATE"
	rows, err := read.QueryContext(ctx, q, lock.keyValues...)
	if err != nil {
		return ErrUnavailable
	}
	defer rows.Close()
	if !rows.Next() {
		return ErrConflict
	}
	cell := make([]any, len(columns))
	dest := make([]any, len(cell))
	for i := range cell {
		dest[i] = &cell[i]
	}
	if rows.Scan(dest...) != nil {
		return ErrUnavailable
	}
	expected := lock.row
	if lock == p.domainLock && !p.facts.Replayed {
		expected, err = EncodeStoredRecord(&p.closed)
		if err != nil {
			return err
		}
	}
	for i, key := range columns {
		if !sameStoredValue(expected.Columns[key], cell[i]) {
			return ErrConflict
		}
	}
	if rows.Next() {
		return ErrConflict
	}
	if rows.Err() != nil || rows.Close() != nil {
		return ErrUnavailable
	}
	return nil
}

func (p *bootstrapConsumptionPolicy) verifyBootstrap(ctx context.Context, read ReadSQL) error {
	r := p.request
	var configHash, matrix string
	var version int64
	var enabled bool
	if err := read.QueryRowContext(ctx, `SELECT c.config_sha256,s.active_config_version,c.enabled,s.matrix_key FROM system_backup_v2_installation_state s JOIN system_backup_v2_configs c ON c.origin_installation_id=s.origin_installation_id AND c.version=s.active_config_version WHERE s.origin_installation_id=? FOR UPDATE`, string(r.Scope.Installation)).Scan(&configHash, &version, &enabled, &matrix); err != nil {
		return ErrUnavailable
	}
	if configHash != string(r.ConfigHash) || version != 1 || enabled || matrix != r.MatrixKey {
		return ErrConflict
	}
	var op BootstrapOperation
	if err := read.QueryRowContext(ctx, `SELECT public_id,result_config_version,request_hash,status,http_status FROM system_backup_v2_operations WHERE origin_installation_id=? AND actor_type='admin' AND actor_id=? AND endpoint=? AND idempotency_key=? FOR UPDATE`, string(r.Scope.Installation), string(r.ActorID), r.Endpoint, r.IdempotencyKey).Scan(&op.PublicID, &op.Version, &op.RequestHash, &op.Status, &op.HTTPStatus); err != nil {
		return ErrUnavailable
	}
	if op.PublicID != p.operationID() || op.Version != 1 || op.RequestHash != p.hash || op.Status != "succeeded" || op.HTTPStatus != 201 {
		return ErrConflict
	}
	var username, role, provider string
	var active bool
	actor, err := r.ActorID.SQLInt64()
	if err != nil {
		return err
	}
	if err = read.QueryRowContext(ctx, "SELECT username,role,is_active,auth_provider FROM users WHERE id=? FOR UPDATE", actor).Scan(&username, &role, &active, &provider); err != nil {
		return ErrUnavailable
	}
	if username != r.Username || role != "admin" || !active || provider != "local" {
		return ErrGuardRequired
	}
	if p.facts.Replayed {
		return nil
	}
	for i, id := range []int64{p.facts.Write.IntentAuditID, p.facts.Write.ResultAuditID} {
		var user int64
		var action, resource string
		var raw []byte
		if err = read.QueryRowContext(ctx, "SELECT user_id,action,resource_type,details FROM audit_logs WHERE id=? FOR UPDATE", id).Scan(&user, &action, &resource, &raw); err != nil {
			return ErrUnavailable
		}
		expectedAction := "system_backup.config_bootstrap.intent"
		if i == 1 {
			expectedAction = "system_backup.config_bootstrap.result"
		}
		var details map[string]json.RawMessage
		if user != actor || action != expectedAction || resource != "system_backup" || json.Unmarshal(raw, &details) != nil || len(details) != 6 {
			return ErrConflict
		}
		want := map[string]string{"operation_public_id": p.operationID(), "installation_id": string(r.Scope.Installation), "config_sha256": string(r.ConfigHash), "request_hash": string(p.hash), "authorization": "offline_bootstrap"}
		for key, value := range want {
			var found string
			if json.Unmarshal(details[key], &found) != nil || found != value {
				return ErrConflict
			}
		}
		if string(details["config_version"]) != strconv.Itoa(1) {
			return ErrConflict
		}
	}
	return nil
}
