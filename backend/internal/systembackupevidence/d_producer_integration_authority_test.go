package systembackupevidence

import (
	"context"
	"database/sql/driver"
	"reflect"
	"strings"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// Test-only identity/evaluator/host/reference authority. Requests are compared
// to fixture inputs, not authenticated by hashing caller-supplied data. These
// doubles deliberately do not claim production ACL or provider verification.
type dIntegrationCommand struct{ f *dIntegrationFixture }

func (a *dIntegrationCommand) Prepare(_ context.Context, r pd.CommandRequest) (pd.PreparedCommand, error) {
	if !reflect.DeepEqual(r, a.f.command) {
		return pd.PreparedCommand{}, pd.ErrGuardRequired
	}
	sample := a.f.sample()
	return pd.PreparedCommand{Session: a, CapacityObservedAt: &sample}, nil
}
func (*dIntegrationCommand) LockInstallation(context.Context, pd.SQL, pd.CommandRequest) error {
	return nil
}
func (a *dIntegrationCommand) Authenticate(_ context.Context, _ pd.SQL, r pd.CommandRequest, _ pd.DomainRecord) (pd.CommandAdmission, error) {
	h, e := pd.CommandHashes(a.f.command)
	if e != nil {
		return pd.CommandAdmission{}, e
	}
	return pd.CommandAdmission{RequestHash: h.Request, IdentityHash: a.f.command.ActorIdentityHash, Deadlines: []time.Time{a.f.until}, Management: true, HistoricalReceiptRead: true, ReceiptRetentionUntil: a.f.history.RetentionExpiresAt, AdditionalCost: "65536"}, nil
}
func (*dIntegrationCommand) LockHosts(context.Context, pd.SQL, pd.CommandRequest) error { return nil }
func (*dIntegrationCommand) LockReferences(context.Context, pd.SQL, pd.CommandRequest) error {
	return nil
}
func (*dIntegrationCommand) Reserve(context.Context, pd.SQL, pd.CommandRequest, uint64) error {
	return nil
}
func (*dIntegrationCommand) Audit(context.Context, pd.SQL, pd.CommandRequest, string) error {
	return nil
}
func (a *dIntegrationCommand) Recheck(ctx context.Context, tx pd.ReadSQL, _ pd.CommandRequest, f pd.CommandFacts, _ time.Time) error {
	records := []any{&f.Domain, &f.Receipt, f.Target}
	for i := range f.Grants {
		records = append(records, &f.Grants[i])
	}
	for i := range f.Runs {
		records = append(records, &f.Runs[i])
	}
	return a.f.check(ctx, tx, records...)
}

type dIntegrationExecution struct{ f *dIntegrationFixture }

func (a *dIntegrationExecution) PrepareExecution(_ context.Context, b pd.ExecutionBinding) (pd.PreparedExecution, error) {
	publication := (b.Call.Purpose == "sts" || b.Call.Purpose == "publish") && b.Claim != nil && b.Call.PolicyHash == a.f.policy && b.Call.EvidenceID == a.f.history.Evidence.EvidenceID && b.Observation == nil
	preparation := (b.Call.Purpose == "content_read" || b.Call.Purpose == "wrap") && b.Claim == nil && b.Call.PolicyHash == a.f.policy && b.Call.EvidenceID == a.f.history.Evidence.EvidenceID && b.Observation == nil
	probe := b.Call == a.f.probe && b.Observation != nil && reflect.DeepEqual(*b.Observation, a.f.observation) || b.Call == a.f.probe && b.Observation == nil
	if (!publication && !preparation && !probe) || b.Subject != a.f.command.ActorIdentityHash {
		return pd.PreparedExecution{}, pd.ErrGuardRequired
	}
	sample := a.f.sample()
	return pd.PreparedExecution{Session: a, CapacityObservedAt: &sample}, nil
}
func (*dIntegrationExecution) LockInstallation(context.Context, pd.SQL, pd.ExecutionBinding) error {
	return nil
}
func (a *dIntegrationExecution) Authenticate(_ context.Context, _ pd.SQL, b pd.ExecutionBinding, _ pd.DomainRecord) (pd.ExecutionAdmission, error) {
	h, e := pd.ExecutionBindingHash(b)
	if e != nil {
		return pd.ExecutionAdmission{}, e
	}
	out := pd.ExecutionAdmission{RequestHash: h, IdentityHash: a.f.command.ActorIdentityHash, IdentityVersionHash: a.f.policy, IdentityExpiresAt: systemExecutionStamp(a.f.until), AdditionalCost: "0"}
	if b.Observation != nil {
		out.AdditionalCost = "65536"
		out.AuthenticatedAttestationHash = &a.f.observation.AttestationHash
		out.ObservedNotBefore = &a.f.observation.ObservedAt
		out.ObservationExpiresNotAfter = &a.f.observation.ExpiresAt
	}
	return out, nil
}
func (*dIntegrationExecution) LockHost(context.Context, pd.SQL, pd.ExecutionBinding, pd.GrantRecord) error {
	return nil
}
func (a *dIntegrationExecution) LockReferences(_ context.Context, _ pd.SQL, b pd.ExecutionBinding, _ pd.ExecutionFacts) (pd.ReferenceApproval, error) {
	h, e := pd.ExecutionBindingHash(b)
	return a.f.refs(h), e
}
func (*dIntegrationExecution) Reserve(context.Context, pd.SQL, pd.ExecutionBinding, uint64) error {
	return nil
}
func (*dIntegrationExecution) Audit(context.Context, pd.SQL, pd.ExecutionBinding, string) error {
	return nil
}
func (*dIntegrationExecution) LockEvidence(context.Context, pd.SQL, pd.ExecutionBinding, pd.ExecutionFacts) (pd.CallEvidence, error) {
	return pd.CallEvidence{}, pd.ErrGuardRequired
}
func (a *dIntegrationExecution) Recheck(ctx context.Context, tx pd.ReadSQL, _ pd.ExecutionBinding, f pd.ExecutionFacts, _ time.Time) error {
	if err := a.f.check(ctx, tx, &f.Domain, &f.Grant, &f.Run, &f.Target); err != nil {
		return err
	}
	if a.f.fail == "preparation_insert_at_guard" {
		a.f.d.row = map[string]driver.Value{"id": int64(41), "public_id": string(f.Run.EvidenceID)}
	}
	if a.f.executionRecheckHook != nil {
		a.f.executionRecheckHook()
	}
	return nil
}

type dIntegrationPending struct {
	systemPendingTestAuthority
	f *dIntegrationFixture
}

func (a *dIntegrationPending) PreparePendingAuthority(_ context.Context, b pd.PendingBinding, _ Record) (SystemPendingAuthoritySession, *time.Time, error) {
	if !reflect.DeepEqual(b.Request, a.f.pendingRequest) {
		return nil, nil, pd.ErrGuardRequired
	}
	sample := a.f.sample()
	return a, &sample, nil
}
func (a *dIntegrationPending) Authenticate(_ context.Context, _ pd.SQL, b pd.PendingBinding, _ pd.DomainRecord) (pd.PendingAdmission, error) {
	h, e := pd.PendingBindingHash(b)
	if e != nil {
		return pd.PendingAdmission{}, e
	}
	history, e := pd.PendingHistoryHash(a.f.history)
	return pd.PendingAdmission{RequestHash: h, IdentityHash: a.f.command.ActorIdentityHash, IdentityExpiresAt: systemExecutionStamp(a.f.until), DependencyExpiresAt: systemExecutionStamp(a.f.until), PolicyHash: a.f.policy, PreparedHistoryHash: history, AdditionalCost: "65536", ReadExisting: true}, e
}
func (a *dIntegrationPending) Audit(ctx context.Context, tx pd.SQL, _ pd.PendingBinding, stage string) error {
	return a.f.audit(ctx, tx, "pending", stage)
}
func (a *dIntegrationPending) Recheck(ctx context.Context, tx pd.ReadSQL, _ pd.PendingBinding, f pd.PendingFacts, _ time.Time) error {
	if a.f.fail == "pending_guard" {
		return pd.ErrGuardRequired
	}
	return a.f.check(ctx, tx, &f.Domain, &f.Grant, &f.Run, &f.Target, &f.History, &f.Reference)
}

type dIntegrationClaim struct {
	systemClaimTestAuthority
	f *dIntegrationFixture
}

func (a *dIntegrationClaim) PrepareClaimAuthority(_ context.Context, b pd.ClaimRequestBinding, _ bool, _ Record) (SystemClaimAuthoritySession, *time.Time, error) {
	if b.Request != a.f.claimRequest {
		return nil, nil, pd.ErrGuardRequired
	}
	sample := a.f.sample()
	return a, &sample, nil
}
func (a *dIntegrationClaim) Authenticate(_ context.Context, _ pd.SQL, b pd.ClaimRequestBinding, _ pd.DomainRecord, _ bool) (pd.ClaimAdmission, error) {
	h, e := pd.ClaimRequestHash(b)
	return pd.ClaimAdmission{RequestHash: h, IdentityHash: a.f.command.ActorIdentityHash, IdentityExpiresAt: systemExecutionStamp(a.f.until), ExpiresNotAfter: a.f.claimRequest.ExpiresAt, AdditionalCost: "65536", ReadbackAllowed: true}, e
}
func (a *dIntegrationClaim) LockReferences(_ context.Context, _ pd.SQL, b pd.ClaimRequestBinding, _ pd.ClaimFacts) (pd.ReferenceApproval, error) {
	h, e := pd.ClaimRequestHash(b)
	return a.f.refs(h), e
}
func (a *dIntegrationClaim) Audit(ctx context.Context, tx pd.SQL, _ pd.ClaimRequestBinding, stage string) error {
	return a.f.audit(ctx, tx, "claim", stage)
}
func (a *dIntegrationClaim) Recheck(ctx context.Context, tx pd.ReadSQL, _ pd.ClaimRequestBinding, f pd.ClaimFacts, _ time.Time) error {
	if a.f.fail == "claim_guard" {
		return pd.ErrGuardRequired
	}
	return a.f.check(ctx, tx, &f.Domain, &f.Grant, &f.Run, &f.Target, &f.History, &f.Reference)
}

type dIntegrationFinish struct {
	systemFinishTestAuthority
	f *dIntegrationFixture
}

func (a *dIntegrationFinish) PrepareFinishAuthority(_ context.Context, b pd.FinishBinding, _ Record) (SystemFinishAuthoritySession, *time.Time, error) {
	if a.f.acceptPublishedFinish {
		version := pd.Text("Exact.Version/1")
		if b.Request.State != "ready" || b.Request.ProofHash != pd.Hash(strings.Repeat("e", 64)) || b.Request.ObjectHash != a.f.history.Evidence.ObjectHash || b.Request.ObjectBytes != a.f.history.Evidence.ObjectBytes || b.Request.ImmutableVersion == nil || *b.Request.ImmutableVersion != version {
			return nil, nil, pd.ErrGuardRequired
		}
		a.f.finishRequest = b.Request
		if !a.f.realDB {
			a.f.d.now = time.Now().UTC().Truncate(time.Microsecond)
		}
	}
	if !reflect.DeepEqual(b.Request, a.f.finishRequest) {
		return nil, nil, pd.ErrGuardRequired
	}
	sample := a.f.sample()
	return a, &sample, nil
}
func (a *dIntegrationFinish) Authenticate(_ context.Context, _ pd.SQL, b pd.FinishBinding, _ pd.DomainRecord) (pd.FinishAdmission, error) {
	h, e := pd.FinishBindingHash(b)
	return pd.FinishAdmission{RequestHash: h, IdentityHash: a.f.command.ActorIdentityHash, VerifiedProofHash: a.f.finishRequest.ProofHash, IdentityExpiresAt: systemExecutionStamp(a.f.until), ProofExpiresAt: systemExecutionStamp(a.f.until), AdditionalCost: "65536"}, e
}
func (a *dIntegrationFinish) LockReferences(_ context.Context, _ pd.SQL, b pd.FinishBinding, _ pd.FinishFacts) (pd.ReferenceApproval, error) {
	h, e := pd.FinishBindingHash(b)
	return a.f.refs(h), e
}
func (a *dIntegrationFinish) Audit(ctx context.Context, tx pd.SQL, _ pd.FinishBinding, stage string) error {
	return a.f.audit(ctx, tx, "finish", stage)
}
func (a *dIntegrationFinish) Recheck(ctx context.Context, tx pd.ReadSQL, _ pd.FinishBinding, f pd.FinishFacts, _ time.Time) error {
	if a.f.fail == "finish_guard" {
		return pd.ErrGuardRequired
	}
	return a.f.check(ctx, tx, &f.Domain, &f.Grant, &f.Run, &f.Target, &f.History, &f.Reference)
}

type dIntegrationResult struct {
	systemResultTestAuthority
	f *dIntegrationFixture
}

func (a *dIntegrationResult) PrepareResultAuthority(_ context.Context, b pd.ResultBinding, _ Record) (SystemResultAuthoritySession, *time.Time, error) {
	if !reflect.DeepEqual(b.Request, a.f.resultRequest) {
		return nil, nil, pd.ErrGuardRequired
	}
	sample := a.f.sample()
	return a, &sample, nil
}
func (a *dIntegrationResult) Authenticate(_ context.Context, _ pd.SQL, b pd.ResultBinding, _ pd.DomainRecord) (pd.ResultAdmission, error) {
	h, e := pd.ResultBindingHash(b)
	if e != nil {
		return pd.ResultAdmission{}, e
	}
	dig, e := pd.ResultHashes(a.f.resultRequest)
	return pd.ResultAdmission{BindingHash: h, IdentityHash: a.f.command.ActorIdentityHash, VerifiedRequestHash: dig.Request, IdentityExpiresAt: systemExecutionStamp(a.f.until), DependencyExpiresAt: systemExecutionStamp(a.f.until), ReceiptRetentionUntil: a.f.history.RetentionExpiresAt, AdditionalCost: "65536", ReadReceipt: a.f.readReceipt}, e
}
func (a *dIntegrationResult) LockProjectionReferences(_ context.Context, _ pd.SQL, b pd.ResultBinding, f pd.ResultFacts) (pd.ResultProjection, error) {
	h, e := pd.ResultBindingHash(b)
	return pd.ResultProjection{BindingHash: h, TargetHash: f.Target.TargetHash, MappingHash: a.f.policy, Mode: "candidate"}, e
}
func (a *dIntegrationResult) Audit(ctx context.Context, tx pd.SQL, _ pd.ResultBinding, stage string) error {
	return a.f.audit(ctx, tx, "result", stage)
}
func (a *dIntegrationResult) Recheck(ctx context.Context, tx pd.ReadSQL, _ pd.ResultBinding, f pd.ResultFacts, _ time.Time) error {
	if a.f.fail == "result_guard" {
		return pd.ErrGuardRequired
	}
	if f.Replayed {
		return a.f.check(ctx, tx, &f.Domain, f.Receipt)
	}
	if e := a.f.check(ctx, tx, &f.Domain, f.Grant, f.Run, f.Target, f.History, f.Receipt); e != nil {
		return e
	}
	for i := range f.References {
		if e := a.f.check(ctx, tx, &f.References[i]); e != nil {
			return e
		}
	}
	return nil
}
