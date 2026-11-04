package install

import (
	"bytes"
	ev "clawreef/internal/systembackupevidence"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// OriginalC1SigningProduction is NOT a DTO/selection authority. Retain it in
// the original complete invocation through the mixed-source/17-stage adoption
// reader. Only ReadCommitted can establish the actual original Result COMMIT.
type OriginalC1SigningProduction struct {
	head1              *OriginalC1Head1Receipt
	committedAt        pd.Timestamp
	children           []*OriginalC1SigningProduction
	channel            *ev.OriginalC1OwnerChannel
	origin             *OriginalC1SigningProduction
	ctx                context.Context
	run                *originalC1Run
	selections         []pd.BootstrapCandidateSelection
	mapping, signature BootstrapSourceFilePin
}

func (*OriginalC1SigningProduction) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (p *OriginalC1SigningProduction) OriginalSource(ctx context.Context) (*ev.OriginalC1EvidenceSource, error) {
	if p == nil || p.origin != p || p.run == nil || p.run.source == nil || !consumerSameContext(ctx, p.ctx) || ctx.Err() != nil {
		return nil, ErrInstall
	}
	return p.run.source, nil
}
func (p *OriginalC1SigningProduction) ReadCommitted(ctx context.Context, tx *sql.Tx) ([]pd.BootstrapCandidateSelection, error) {
	source, err := p.OriginalSource(ctx)
	if err != nil {
		return nil, err
	}
	facts, err := source.ReadCommitted(ctx, tx)
	if err != nil || facts.Receipt.RequestHash == "" || !reflect.DeepEqual(facts.Receipt.Request, p.run.result) {
		return nil, ErrInstall
	}
	return append([]pd.BootstrapCandidateSelection(nil), p.selections...), nil
}

// Close drains publication before wiping ciphertext; it never deletes an
// object/key/ref, releases a source hold, cancels a run or declares recovery.
func (p *OriginalC1SigningProduction) Close() {
	if p == nil || p.run == nil {
		return
	}
	for _, child := range p.children {
		child.Close()
	}
	if p.run.publisher != nil {
		p.run.publisher.Close()
	}
	if p.channel != nil {
		p.channel.Close()
	}
	clear(p.run.ciphertext)
	p.run.ciphertext = nil
}

type OriginalC1SigningPipelineInputs struct {
	SigningMaterial, WrapMaterial, STSJWT, AuthenticationJWT BootstrapSourceFilePin
	AuthenticationAudience                                   string
	ControllerDeployment, ControllerPod                      string
	Capacity                                                 sec.CapacityCollectorConfig
	OutputDirectory                                          string
}

func c1random(prefix string) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw), nil
}
func c1evidenceID() (pd.EvidenceID, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	s := hex.EncodeToString(b)
	return pd.EvidenceID("sev_" + s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]), nil
}

// Actual production method chain. All services and opaque values are kept in
// THIS original Go invocation; no intermediate JSON reconstructs a handle,
// Prepared, claim or result source. Other reference groups must supply their
// own actual native observations before complete20 encoding/first capture.
func (p *OriginalC1Production) ProduceOriginalC1Signing(ctx context.Context, capacityDB *sql.DB, channel *ev.OriginalC1OwnerChannel, in OriginalC1SigningPipelineInputs, password, issuerPrivate []byte) (_ *OriginalC1SigningProduction, resultErr error) {
	if !p.live(ctx) || capacityDB == nil || channel == nil || p.backing == nil || channel.BackingStoreSource() != p.backing || privateDirectory(in.OutputDirectory) != nil || in.Capacity.Validate() != nil {
		return nil, ErrInstall
	}
	native, err := p.newSigningObservation(ctx, in.SigningMaterial, in.ControllerDeployment, in.ControllerPod)
	if err != nil {
		return nil, err
	}
	return p.produceOriginalC1Observed(ctx, capacityDB, channel, in, native, password, issuerPrivate)
}

// Only private native constructors can reach this shared actual D/A chain.
func (p *OriginalC1Production) produceOriginalC1Observed(ctx context.Context, capacityDB *sql.DB, channel *ev.OriginalC1OwnerChannel, in OriginalC1SigningPipelineInputs, native *originalC1NativeObservation, password, issuerPrivate []byte) (_ *OriginalC1SigningProduction, resultErr error) {
	if !p.live(ctx) || native == nil || native.parent != p || native.local(ctx) != nil || capacityDB == nil || channel == nil || channel.BackingStoreSource() != p.backing || privateDirectory(in.OutputDirectory) != nil {
		return nil, ErrInstall
	}
	i := p.operator.installer
	raw, err := readBootstrapSourcePin(in.WrapMaterial, 262144)
	var wrap OriginalC1EvidenceMaterial
	if err != nil || decodeExact(raw, &wrap) != nil || !sameC1Actor(wrap.Binding, native.actor) || wrap.Transit.Transit.KeyName == "" {
		return nil, ErrInstall
	}
	// Independent native original issuer query authenticates exact signed
	// retained files + live Pod/role/key/context; it never reissues this material.
	verified, err := i.QueryOriginalC1EvidenceMaterial(ctx, password, p.enrollment, wrap.Source.OutputDirectory)
	if err != nil || verified.Material != in.WrapMaterial {
		return nil, ErrInstall
	}
	authJWT, err := readBootstrapSourcePin(in.AuthenticationJWT, 16384)
	if err != nil {
		return nil, ErrInstall
	}
	clear(authJWT)
	stsJWT, err := readBootstrapSourcePin(in.STSJWT, 16384)
	if err != nil {
		return nil, ErrInstall
	}
	clear(stsJWT)
	config, providerHash := channel.Config()
	if in.AuthenticationAudience == "" || in.AuthenticationAudience == config.Audience || in.AuthenticationAudience == wrap.Transit.Audience || in.AuthenticationJWT.File == in.STSJWT.File || wrap.Transit.TokenFile == in.AuthenticationJWT.File || wrap.Transit.TokenFile == in.STSJWT.File {
		return nil, ErrInstall
	}
	// Preserve the shortest ORIGINAL material deadline; callbacks never renew it.
	if wrap.Until.Before(native.until) {
		native.until = wrap.Until
	}
	if !time.Now().Before(native.until) {
		return nil, ErrInstall
	}
	r := &originalC1Run{stsJWT: in.STSJWT, authenticationJWT: in.AuthenticationJWT, authenticationAudience: in.AuthenticationAudience, parent: p, ctx: ctx, capacityDB: capacityDB, capacity: in.Capacity, native: native, until: native.until}
	success := false
	defer func() {
		if !success {
			r.failed = true
		}
		if resultErr != nil && r.publisher != nil {
			r.publisher.Close()
		}
	}()
	grant, err := c1random("c1-grant-")
	if err != nil {
		return nil, err
	}
	runID, err := c1random("c1-run-")
	if err != nil {
		return nil, err
	}
	requestKey, err := c1random("c1-request-")
	if err != nil {
		return nil, err
	}
	evidenceID, err := c1evidenceID()
	if err != nil {
		return nil, err
	}
	input := hash(c1wire(struct{ Version, Domain, Native, Wrap string }{"original-c1-native-group-input.v1", p.profileSHA, native.originalNativeSource().SHA256, in.WrapMaterial.SHA256}))
	lease := c1stamp(r.until)
	r.command = pd.CommandRequest{SchemaVersion: "system-backup-producer-command.c1", Scope: p.domain.Scope, ActorIdentityHash: native.subject, Command: "acquire", RequestKey: pd.RequestKey(requestKey), Target: native.target, ExpectedDomainEpoch: p.domain.Epoch, ExpectedTargetGeneration: "0", Next: &pd.CommandNext{GrantID: pd.ID(grant), GrantGeneration: "1", RunID: pd.ID(runID), EvidenceID: evidenceID, SubjectIdentityHash: native.subject, IssuerIdentityHash: p.domain.IssuerIdentityHash, Host: native.host, Admission: p.domain.Admission, Purpose: "dependency_check", InputHash: pd.Hash(input), AuthorizationExpiresAt: c1stamp(r.until), OwnerWriteExpiresAt: c1stamp(r.until)}, LeaseExpiresAt: &lease}
	if _, err := pd.CommandHashes(r.command); err != nil {
		return nil, err
	}
	// Record exact command BEFORE dispatch; unknown cannot call acquire again.
	if writeNewFiles(in.OutputDirectory, map[string][]byte{"original-c1.command.json": c1wire(r.command)}) != nil {
		return nil, ErrInstall
	}
	r.lifecycle, err = pd.NewLifecycle(i.db, p.domain.Scope, &originalC1CommandEnvironment{r})
	if err != nil {
		return nil, err
	}
	command, err := r.lifecycle.Execute(ctx, r.command, nil)
	if err != nil || command.Handle == nil || command.Replayed {
		return nil, errors.Join(ErrInstall, err)
	}
	r.handle, r.commandReceipt = command.Handle, command.Receipt
	r.calls = &originalC1ExecutionSwitch{raw: &originalC1ExecutionAuthority{r}}
	r.execution, err = pd.NewExecution(r.lifecycle, r.calls)
	if err != nil {
		return nil, err
	}
	probeBudget := time.Now().Add(20 * time.Second)
	if r.until.Before(probeBudget) {
		probeBudget = r.until
	}
	r.probe, err = r.execution.BeginCall(ctx, r.handle, pd.CallRequest{Purpose: "probe", EvidenceID: evidenceID, RefIdentityHash: native.target.IdentityHash, RefVersion: native.target.RefVersion, PolicyHash: pd.Hash(native.policy), BudgetUntil: c1stamp(probeBudget)}, nil)
	if err != nil {
		return nil, err
	}
	if err = native.observe(ctx, r.probe, runID); err != nil {
		return nil, err
	}
	r.until = native.until
	r.observation = pd.ObservationRequest{ExpectedRunVersion: r.probe.View().Facts.Run.RowVersion, ObservedAt: c1stamp(native.started), ExpiresAt: c1stamp(native.until), AttestationHash: pd.Hash(native.attestation)}
	observed, err := r.execution.BindObservation(ctx, r.handle, r.probe, r.observation)
	if err != nil {
		return nil, err
	}
	identity := native.identity(string(evidenceID))
	r.preparation = ev.SystemExecutionPreparationPolicy{Scope: p.domain.Scope, RunID: pd.ID(runID), InputHash: input, EvaluatorProfileHash: string(native.target.EvaluatorProfileHash), SubjectIdentityHash: string(native.subject), IssuerIdentityHash: string(p.domain.IssuerIdentityHash), Identity: identity, Content: native.contentPolicy(identity), Wrap: wrap.Transit, AuthenticationAudience: in.AuthenticationAudience, AuthenticationTokenFile: in.AuthenticationJWT.File}
	r.calls.preparation, err = ev.NewSystemPreparationCallEnvironment(r.calls.raw, r.preparation)
	if err != nil {
		return nil, err
	}
	preparer, err := ev.NewSystemExecutionPreparer(ctx, r.execution, r.handle, r.preparation)
	if err != nil {
		return nil, err
	}
	var encrypted bytes.Buffer
	r.prepared, err = preparer.Prepare(ctx, identity, c1bodySource(native.body), &encrypted)
	preparer.Close()
	if err != nil {
		return nil, err
	}
	r.ciphertext = bytes.Clone(encrypted.Bytes())
	clear(encrypted.Bytes())
	evidence, err := r.prepared.PendingProducerBinding(p.channel)
	if err != nil {
		return nil, err
	}
	relative := strings.TrimSuffix(p.channel.Root, "/") + "/" + identity.Installation + "/" + identity.OwnerType + "/" + identity.OwnerID + "/" + identity.ID + "/" + identity.ContentHash + ".bin"
	if pd.Hash(hash([]byte(relative))) != evidence.RelativeKeyHash {
		return nil, ErrInstall
	}
	created := time.Now().UTC().Truncate(time.Microsecond)
	r.history = pd.HistoricalBindingRecord{Scope: p.domain.Scope, RunID: pd.ID(runID), GrantID: pd.ID(grant), GrantGeneration: "1", DomainEpoch: p.domain.Epoch, Admission: p.domain.Admission, TargetHash: r.probe.View().Facts.Run.TargetHash, InputHash: pd.Hash(input), Evidence: evidence, RelativeKey: pd.RelativeKey(relative), OwnerWriteExpiresAt: r.command.Next.OwnerWriteExpiresAt, ObservedAt: r.observation.ObservedAt, ObservationExpiresAt: r.observation.ExpiresAt, RetentionExpiresAt: c1stamp(native.retention), RetentionPolicyHash: pd.Hash(hash([]byte("original-c1-30day-retained-key-evidence.v1"))), CreatedAt: c1stamp(created)}
	r.pending = pd.PendingRequest{History: r.history, ExpectedRunVersion: observed.RunVersion, PolicyHash: pd.Hash(native.policy), BudgetUntil: c1stamp(r.until)}
	pendingEnv, err := ev.NewSystemPendingEnvironment(&originalC1PendingAuthority{r}, r.prepared, p.channel, r.history)
	if err != nil {
		return nil, err
	}
	pending, err := pd.NewPending(r.execution, pendingEnv)
	if err != nil {
		return nil, err
	}
	if _, err = pending.AdmitPending(ctx, r.handle, r.pending); err != nil {
		return nil, err
	}
	r.calls.publication, err = ev.NewSystemPublicationCallEnvironment(r.calls.raw, r.prepared, p.channel, r.history)
	if err != nil {
		return nil, err
	}
	r.publication = ev.SystemSTSPolicy{History: r.history, Channel: p.channel, STS: config, SubjectIdentityHash: string(native.subject), IssuerIdentityHash: string(p.domain.IssuerIdentityHash), Subject: "system:serviceaccount:" + native.actor.Namespace + ":" + native.actor.ServiceAccountName, TokenFile: in.STSJWT.File, AuthenticationAudience: in.AuthenticationAudience, AuthenticationTokenFile: in.AuthenticationJWT.File, ProviderProfileHash: providerHash}
	nonce, err := c1random("c1-claim-")
	if err != nil {
		return nil, err
	}
	claimUntil := time.Now().Add(30 * time.Second)
	if r.until.Before(claimUntil) {
		claimUntil = r.until
	}
	r.claimRequest = pd.ClaimRequest{EvidenceID: evidenceID, ExpectedEvidenceVersion: "1", Nonce: pd.ID(nonce), ExpiresAt: c1stamp(claimUntil), PolicyHash: pd.Hash(ev.SystemSTSPolicyHash(r.publication)), RefsVersionHash: pd.Hash(native.referenceHash), BudgetUntil: c1stamp(r.until)}
	claimEnv, err := ev.NewSystemClaimEnvironment(&originalC1ClaimAuthority{r}, r.prepared, p.channel, r.history)
	if err != nil {
		return nil, err
	}
	publication, err := pd.NewPublication(r.execution, claimEnv)
	if err != nil {
		return nil, err
	}
	r.claim, err = publication.ClaimPublication(ctx, r.handle, r.claimRequest)
	if errors.Is(err, pd.ErrCommitUnknown) {
		r.claim, err = publication.ReadPublicationClaim(ctx, r.handle, r.claimRequest)
	}
	if err != nil {
		return nil, err
	}
	profile, absence, err := channel.NewProfileVerifier(ctx, r.execution, r.handle, r.claim, r.prepared, r.publication)
	if err != nil {
		return nil, err
	}
	r.publisher, err = ev.NewVerifiedSystemPublisher(ctx, r.execution, r.handle, r.claim, r.prepared, r.publication, profile, absence, &originalC1FinishAuthority{r})
	if err != nil {
		return nil, err
	}
	finished, err := r.publisher.Publish(ctx, c1bodySource(r.ciphertext))
	if err != nil || finished.State != "ready" || finished.ImmutableVersion == nil {
		return nil, errors.Join(ErrInstall, err)
	}
	evidence.ImmutableVersion = finished.ImmutableVersion
	r.result = pd.ResultRequest{SchemaVersion: "system-backup-producer-result.c1", Scope: p.domain.Scope, GrantID: pd.ID(grant), GrantGeneration: "1", RunID: pd.ID(runID), DomainEpoch: p.domain.Epoch, Admission: p.domain.Admission, Purpose: "dependency_check", Target: native.target, InputHash: pd.Hash(input), RequestKey: pd.RequestKey(requestKey), TargetGeneration: command.Receipt.Outcome.TargetGeneration, ExpectedResultVersion: "0", Evidence: evidence, ExpectedEvidenceVersion: finished.EvidenceVersion, ObservedAt: r.observation.ObservedAt, ObservationExpiresAt: r.observation.ExpiresAt, Results: native.results}
	resultEnv, source, err := ev.NewTrackedSystemResultEnvironmentWithBacking(ctx, &originalC1ResultAuthority{r}, r.prepared, p.channel, r.history, r.publisher, p.backing)
	if err != nil {
		return nil, err
	}
	r.source = source
	results, err := pd.NewResults(r.execution, resultEnv)
	if err != nil {
		return nil, err
	}
	committed, err := results.CommitResult(ctx, r.handle, r.result)
	if err != nil && !errors.Is(err, pd.ErrCommitUnknown) {
		return nil, err
	}
	// Actual independent transaction readback also resolves a lost COMMIT reply;
	// absence/rollback cannot become a signing mapping or source result.
	tx, err := i.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, err
	}
	facts, readErr := source.ReadCommitted(ctx, tx)
	rollbackErr := tx.Rollback()
	if readErr != nil || rollbackErr != nil {
		return nil, errors.Join(ErrInstall, readErr, rollbackErr)
	}
	if committed.Receipt.RequestHash != "" && committed.Receipt.RequestHash != facts.Receipt.RequestHash {
		return nil, ErrInstall
	}
	sourceRaw, err := canonical(struct {
		Version, Domain, Native string
		Request                 pd.ResultRequest
		References              []sec.BootstrapSecretRef
	}{"original-c1-native-group-mapping.v1", p.profileSHA, native.originalNativeSource().SHA256, r.result, native.references})
	if err != nil {
		return nil, err
	}
	issuer, err := p.operator.privateKey(issuerPrivate)
	if err != nil {
		return nil, err
	}
	defer clear(issuer)
	signature := ed25519.Sign(issuer, append([]byte("original-c1-native-group-mapping.v1\x00"), sourceRaw...))
	if writeNewFiles(in.OutputDirectory, map[string][]byte{"original-c1.mapping.json": sourceRaw, "original-c1.mapping.signature": signature}) != nil {
		return nil, ErrInstall
	}
	batch := &OriginalC1SigningProduction{committedAt: facts.Receipt.CommittedAt, ctx: ctx, run: r, mapping: BootstrapSourceFilePin{File: filepath.Join(in.OutputDirectory, "original-c1.mapping.json"), SHA256: hash(sourceRaw)}, signature: BootstrapSourceFilePin{File: filepath.Join(in.OutputDirectory, "original-c1.mapping.signature"), SHA256: hash(signature)}}
	for _, ref := range native.references {
		mapping := hash(c1wire(struct{ Source, Purpose, Identity, Version string }{hash(sourceRaw), ref.Purpose, ref.IdentityHash, ref.Version}))
		batch.selections = append(batch.selections, pd.BootstrapCandidateSelection{Purpose: ref.Purpose, ReferenceIdentityHash: pd.Hash(ref.IdentityHash), ReferenceVersion: pd.RefVersion(ref.Version), MappingHash: pd.Hash(mapping), Request: r.result, ResultVersion: facts.Receipt.ResultVersion})
	}
	batch.origin = batch
	success = true
	return batch, nil
}
