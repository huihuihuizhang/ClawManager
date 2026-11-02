package systembackupkekadapter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strconv"
	"time"

	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
	sec "clawreef/internal/systembackupsecurity"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type ProviderPermitIssuerConfig struct {
	Capabilities       *SQLProviderCapabilityPreparation
	Binding            reg.Binding
	InstallationIssuer ed25519.PublicKey
	Authority          c.SQLExecutionAuthority
	Records            c.SQLExecutionRecords
	Kubernetes         kubernetes.Interface
	Workload           ControllerVerifierWorkload
	CaptureGrantSHA256 string
	GrantMount         ProviderPermitIssuerGrantMount
	SigningKeyFile     string
}

type ProviderPermitIssueScope struct {
	Input          d.Input
	Job            d.JobBinding
	Invocation     worker.Invocation
	WorkerIdentity kms.JobIdentity
	WorkerPodName  string
}

type ProviderPermitIssuer struct{ cfg ProviderPermitIssuerConfig }

func NewProviderPermitIssuer(cfg ProviderPermitIssuerConfig) (*ProviderPermitIssuer, error) {
	keys, ok := cfg.Records.Keys.(*c.PinnedExecutionIdentity)
	_, bare := cfg.Authority.Authorization.(*c.PinnedExecutionIdentity)
	if cfg.Capabilities == nil || cfg.Authority.DB == nil || cfg.Capabilities.db != cfg.Authority.DB || cfg.Records.Authority.DB != cfg.Authority.DB || cfg.Authority.InstallationID != cfg.Binding.InstallationID || cfg.Capabilities.installation != cfg.Binding.InstallationID || !cfg.Authority.DeploymentEnabled || cfg.Authority.ApplicationScope == "" || cfg.Records.Authority.ApplicationScope != cfg.Authority.ApplicationScope || bare || nilSource(cfg.Authority.Authorization) || !reflect.DeepEqual(cfg.Authority.Authorization, cfg.Records.Authority.Authorization) || !ok || keys == nil || keys.GrantSHA256() != cfg.CaptureGrantSHA256 || len(cfg.InstallationIssuer) != ed25519.PublicKeySize || nilSource(cfg.Kubernetes) || !filepath.IsAbs(cfg.SigningKeyFile) || cfg.SigningKeyFile == cfg.GrantMount.File {
		return nil, kms.ErrPermission
	}
	cfg.InstallationIssuer = bytes.Clone(cfg.InstallationIssuer)
	cfg.GrantMount.Issuer = bytes.Clone(cfg.GrantMount.Issuer)
	cfg.Binding.GenerateRef.RawJSON = bytes.Clone(cfg.Binding.GenerateRef.RawJSON)
	cfg.Binding.UnwrapRef.RawJSON = bytes.Clone(cfg.Binding.UnwrapRef.RawJSON)
	g, err := readPermitIssuerGrant(context.Background(), cfg)
	if err != nil {
		return nil, err
	}
	key, err := readPermitSigningKey(cfg.SigningKeyFile, g.SigningPublicKey)
	clear(key)
	if err != nil {
		return nil, err
	}
	return &ProviderPermitIssuer{cfg: cfg}, nil
}

type PreparedProviderPermitIssue struct {
	issuer             *ProviderPermitIssuer
	scope              ProviderPermitIssueScope
	grant              ProviderPermitIssuerGrant
	grantProof         *authenticatedPermitIssuerGrant
	capability         *sqlPreparedCapability
	mapping            OriginalRecord
	mappingRaw         []byte
	mappingSignature   []byte
	mappingIssuer      ed25519.PublicKey
	planHash, specHash string
	until              time.Time
	id                 string
	lease              *worker.KeyUseLease
	original           *c.OriginalCapturePlan
}

// Prepare authenticates original frozen source/real controller and worker on
// the original SQL/K8s chain OUTSIDE transaction locks. Only original owner pins
// delegate signing; request DTOs, artifact signers and the identity CA cannot.
func (i *ProviderPermitIssuer) Prepare(ctx context.Context, scope ProviderPermitIssueScope) (*PreparedProviderPermitIssue, error) {
	return i.prepare(ctx, scope, nil)
}

// PrepareOriginal reuses only this request's controller-authenticated history.
// Current workload, owner grant, capability, mapping and Stage checks remain.
func (i *ProviderPermitIssuer) PrepareOriginal(ctx context.Context, scope ProviderPermitIssueScope, original *c.OriginalCapturePlan) (*PreparedProviderPermitIssue, error) {
	if original == nil {
		return nil, kms.ErrPermission
	}
	return i.prepare(ctx, scope, original)
}

func (i *ProviderPermitIssuer) prepare(ctx context.Context, scope ProviderPermitIssueScope, original *c.OriginalCapturePlan) (*PreparedProviderPermitIssue, error) {
	if i == nil || ctx == nil || ctx.Err() != nil || scope.Invocation.FormalCapture == nil || scope.Invocation.ProviderKey == nil || !worker.ValidateRecordedInvocation(scope.Invocation) {
		return nil, kms.ErrPermission
	}
	raw, err := json.Marshal(scope)
	if err != nil || len(raw) > 4<<20 {
		return nil, kms.ErrPermission
	}
	var frozen ProviderPermitIssueScope
	err = json.Unmarshal(raw, &frozen)
	clear(raw)
	if err != nil {
		return nil, kms.ErrPermission
	}
	scope = frozen
	grantProof, err := authenticatePermitIssuerGrant(ctx, i.cfg)
	if err != nil || checkControllerWorkload(ctx, i.cfg.Kubernetes, i.cfg.Workload) != nil {
		return nil, kms.ErrPermission
	}
	g := grantProof.grant
	a, identity := scope.Input.Authority, scope.WorkerIdentity
	invocationHash, err := scope.Invocation.Hash()
	access := *scope.Invocation.ProviderKey
	if err != nil || a.InstallationID != i.cfg.Binding.InstallationID || a.TaskType != "backup" || a.Phase != "capture" || a.ClaimOwner != g.Workload.ControllerOwner || a.ConfigVersion != g.Workload.ConfigVersion || a.ConfigSHA256 != g.Workload.ConfigSHA256 || identity.InvocationSHA256 != invocationHash || identity.ExecutionGrantSHA256 != i.cfg.CaptureGrantSHA256 || identity.Namespace != g.WorkerNamespace || identity.Namespace != scope.Job.Namespace || identity.JobUID != scope.Job.UID || identity.ServiceAccountUID != g.WorkerServiceAccountUID || identity.PodUID == "" || scope.WorkerPodName == "" || access.Operation != kms.Generate || access.Endpoint != i.cfg.Binding.Provider.Endpoint || access.KeyName != i.cfg.Binding.Provider.KeyName || access.Request.Key != i.cfg.Binding.Key || access.Request.Context.InstallationID != a.InstallationID || access.Request.Context.BackupPublicID != a.TaskPublicID || access.Request.Context.AttemptNo != strconv.FormatUint(a.AttemptNo, 10) {
		return nil, kms.ErrPermission
	}
	if _, err = kms.TransitContext(access.Request); err != nil {
		return nil, err
	}
	pod, err := i.cfg.Kubernetes.CoreV1().Pods(identity.Namespace).Get(ctx, scope.WorkerPodName, metav1.GetOptions{})
	if err != nil || string(pod.UID) != identity.PodUID || pod.DeletionTimestamp != nil || pod.Status.Phase != "Running" || pod.Spec.ServiceAccountName != g.WorkerServiceAccountName || len(pod.OwnerReferences) != 1 {
		return nil, kms.ErrPermission
	}
	owner := pod.OwnerReferences[0]
	if owner.Controller == nil || !*owner.Controller || owner.APIVersion != "batch/v1" || owner.Kind != "Job" || string(owner.UID) != identity.JobUID || owner.Name != scope.Job.Name {
		return nil, kms.ErrPermission
	}
	job, err := i.cfg.Kubernetes.BatchV1().Jobs(scope.Job.Namespace).Get(ctx, scope.Job.Name, metav1.GetOptions{})
	if err != nil || string(job.UID) != identity.JobUID || job.DeletionTimestamp != nil {
		return nil, kms.ErrPermission
	}
	sa, err := i.cfg.Kubernetes.CoreV1().ServiceAccounts(identity.Namespace).Get(ctx, g.WorkerServiceAccountName, metav1.GetOptions{})
	if err != nil || string(sa.UID) != identity.ServiceAccountUID || sa.DeletionTimestamp != nil {
		return nil, kms.ErrPermission
	}
	var planHash, specHash string
	if original != nil {
		planHash, specHash, err = original.MatchPart(ctx, i.cfg.Records, scope.Input, scope.Job, scope.Invocation)
	} else {
		planHash, specHash, err = loadOriginalCandidatePlan(ctx, i.cfg.Records, ControllerVerifierCandidate{Input: scope.Input, Job: scope.Job, Invocation: scope.Invocation})
	}
	if err != nil {
		return nil, err
	}
	capability, err := i.cfg.Capabilities.prepareOperation(ctx, i.cfg.Binding, kms.Generate)
	if err != nil || !reflect.DeepEqual(capability.record.Facts.Permission, g.GeneratePermission) {
		return nil, kms.ErrPermission
	}
	mappingRaw, mappingSig, err := (SQLOriginalReader{DB: i.cfg.Authority.DB}).ReadOriginal(ctx, a.InstallationID, i.cfg.Binding.ConfigRef)
	if err != nil {
		return nil, kms.ErrPermission
	}
	mapping, err := decodeOwnerRecord(mappingRaw, mappingSig, i.cfg.InstallationIssuer)
	now := time.Now()
	if err != nil || !reflect.DeepEqual(mapping.Binding, i.cfg.Binding) || mapping.GenerateRevoked || now.Before(mapping.NotBefore) || !now.Before(mapping.Until) {
		return nil, kms.ErrPermission
	}
	until := g.Until
	for _, end := range []time.Time{capability.ValidUntil(), mapping.Until, a.DeadlineAt} {
		if end.Before(until) {
			until = end
		}
	}
	until = until.UTC().Truncate(time.Microsecond)
	return &PreparedProviderPermitIssue{issuer: i, scope: scope, grant: g, grantProof: grantProof, capability: capability, mapping: mapping, mappingRaw: bytes.Clone(mappingRaw), mappingSignature: bytes.Clone(mappingSig), mappingIssuer: bytes.Clone(i.cfg.InstallationIssuer), planHash: planHash, specHash: specHash, until: until, original: original}, nil
}

func (p *PreparedProviderPermitIssue) ValidUntil() time.Time {
	if p == nil {
		return time.Time{}
	}
	return p.until
}

const issuedPermitQuery = `SELECT inline_payload,content_checksum,content_size_bytes,expires_at FROM system_backup_v2_evidence WHERE public_id=? AND owner_target_type='backup' AND owner_target_public_id=? AND evidence_type='diagnostic' AND storage_state='inline' AND observed_health='healthy' AND encryption='none'`

// Stage is called at the END of the caller's ORIGINAL key-use transaction,
// after its domain/Job/candidate/observation locks, before that owner's Commit.
// It never commits and exposes no uncommitted signed payload to its caller.
func (p *PreparedProviderPermitIssue) Stage(ctx context.Context, tx *sql.Tx, lease worker.KeyUseLease, action string) error {
	return p.stage(ctx, tx, lease, action, nil)
}

// StageOriginal repeats CURRENT authority checks using the exact original
// context/transaction/store/input guard whose locks the caller still holds.
// All provider/registry checks and the original final clock checks remain.
func (p *PreparedProviderPermitIssue) StageOriginal(ctx context.Context, tx *sql.Tx, lease worker.KeyUseLease, action string, original *c.ExecutionAuthorityGuard) error {
	if original == nil {
		return kms.ErrPermission
	}
	err := p.stage(ctx, tx, lease, action, original)
	if err != nil {
		original.Invalidate()
	}
	return err
}

func (p *PreparedProviderPermitIssue) stage(ctx context.Context, tx *sql.Tx, lease worker.KeyUseLease, action string, original *c.ExecutionAuthorityGuard) (resultErr error) {
	cost := startProviderPermitTimer(ctx, "Stage")
	defer func() { cost.finish(resultErr != nil) }()
	segment := startProviderPermitTimer(ctx, "Stage.Entry")
	defer func() { segment.finish(resultErr != nil) }()
	next := func(label string) {
		segment.finish(false)
		segment = startProviderPermitTimer(ctx, label)
	}
	if p == nil || ctx == nil || ctx.Err() != nil || tx == nil || lease.Identity != p.scope.WorkerIdentity || lease.Access != *p.scope.Invocation.ProviderKey || lease.Nonce == "" || len(lease.Nonce) != 32 || !authorityHash.MatchString(lease.Nonce+lease.Nonce) || !time.Now().Before(lease.Until) || lease.Until.After(p.until) || !lease.Until.Equal(lease.Until.Truncate(time.Microsecond)) || (lease.State != "reserved" && lease.State != "using" && lease.State != "finished") {
		return kms.ErrPermission
	}
	next("Stage.OriginalPlan")
	if p.original != nil && p.original.RecheckTx(ctx, tx, p.issuer.cfg.Records, p.scope.Input) != nil {
		return kms.ErrPermission
	}
	switch action {
	case "key-reserve":
		if lease.State != "reserved" {
			return kms.ErrPermission
		}
	case "key-begin":
		if lease.State != "using" {
			return kms.ErrPermission
		}
	case "key-end", "candidate":
		if lease.State != "finished" {
			return kms.ErrPermission
		}
	case "key-check":
	default:
		return kms.ErrPermission
	}
	a := p.scope.Input.Authority
	cfg := p.issuer.cfg
	next("Stage.Guard")
	guard := original
	var err error
	if guard == nil {
		guard, err = cfg.Authority.Bind(ctx, tx, a)
	} else {
		err = guard.RecheckOriginal(ctx, tx, cfg.Authority, a)
	}
	if err != nil || lease.Until.After(guard.ValidUntil()) {
		return kms.ErrPermission
	}
	next("Stage.OriginalRows")
	var account, server, database string
	if tx.QueryRowContext(ctx, "SELECT CURRENT_USER(),@@server_uuid,DATABASE()").Scan(&account, &server, &database) != nil || account != p.grant.DatabaseAccount || server != p.grant.Database.ServerUUID || database != p.grant.Database.Database {
		return kms.ErrPermission
	}
	var planHash, specHash string
	var keyUse []byte
	j := p.scope.Job
	if tx.QueryRowContext(ctx, `SELECT payload_sha256 FROM system_backup_v2_execution_records WHERE origin_installation_id=? AND task_public_id=? AND attempt_no=? AND phase='capture' AND record_kind='plan' FOR SHARE`, a.InstallationID, a.TaskPublicID, a.AttemptNo).Scan(&planHash) != nil || planHash != p.planHash {
		return kms.ErrPermission
	}
	if tx.QueryRowContext(ctx, `SELECT key_use_json,request_sha256 FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND attempt_no=? AND phase='capture' AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND observed_uid=? AND revoked=FALSE AND stopped_at IS NULL AND lifecycle='ready' FOR SHARE`, a.TaskPublicID, a.AttemptNo, j.Namespace, j.Name, j.UID).Scan(&keyUse, &specHash) != nil || specHash != p.specHash {
		return kms.ErrPermission
	}
	expected, _ := json.Marshal(lease)
	if !bytes.Equal(expected, keyUse) {
		return kms.ErrPermission
	}
	authorityRaw, _ := json.Marshal(a)
	sum := sha256.Sum256(authorityRaw)
	if lease.AuthoritySHA256 != hex.EncodeToString(sum[:]) {
		return kms.ErrPermission
	}
	identityRaw, _ := json.Marshal(struct {
		Authority d.Authority
		Job       d.JobBinding
		Nonce     string
	}{a, j, lease.Nonce})
	idHash := sha256.Sum256(identityRaw)
	id := "sev_apermit_" + hex.EncodeToString(idHash[:])
	next("Stage.Delivery")
	var raw []byte
	var checksum string
	var size uint64
	var expires time.Time
	err = tx.QueryRowContext(ctx, issuedPermitQuery+" FOR SHARE", id, a.TaskPublicID).Scan(&raw, &checksum, &size, &expires)
	newPermit := errors.Is(err, sql.ErrNoRows)
	if err != nil && !newPermit {
		return kms.ErrPermission
	}
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil {
		return kms.ErrPermission
	}
	if newPermit {
		if lease.State != "reserved" || action != "key-reserve" {
			return kms.ErrPermission
		}
		context64, err := kms.TransitContext(lease.Access.Request)
		if err != nil {
			return err
		}
		identityFile, err := workerJWTIdentityPath(p.grant.WorkerJWTIdentityFile, lease.Identity.PodUID)
		if err != nil {
			return err
		}
		payload := kms.DeliveredPermitPayload{Version: kms.PermitDeliveryVersion, IssuerGrantSHA256: cfg.GrantMount.SHA256, Nonce: lease.Nonce, Request: lease.Access.Request, Permit: kms.ProviderPermit{Version: "system-backup-provider-permit.v1", Identity: lease.Identity, Operation: kms.Generate, Endpoint: lease.Access.Endpoint, KeyName: lease.Access.KeyName, ContextBase64: context64, NotBefore: now, ExpiresAt: lease.Until, JWT: kms.JWTIdentityGrant{Mount: p.grant.GeneratePermission.AuthMount, Role: p.grant.GeneratePermission.Role, Policy: p.grant.GeneratePermission.Policy, IdentityFile: identityFile}}}
		payloadRaw, _ := json.Marshal(payload)
		key, err := readPermitSigningKey(cfg.SigningKeyFile, p.grant.SigningPublicKey)
		if err != nil {
			return err
		}
		signature := ed25519.Sign(key, append([]byte(kms.PermitDeliveryDomain), payloadRaw...))
		clear(key)
		raw, err = json.Marshal(kms.DeliveredProviderPermit{Payload: payloadRaw, Signature: signature})
		if err != nil || len(raw) > 8192 {
			return kms.ErrPermission
		}
		h := sha256.Sum256(raw)
		checksum = hex.EncodeToString(h[:])
		size = uint64(len(raw))
		expires = lease.Until
		if cfg.Records.CapacityReportFile != "" {
			var capacity int64
			if tx.QueryRowContext(ctx, `SELECT control_metadata_capacity_bytes FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=?`, a.InstallationID, a.ConfigVersion).Scan(&capacity) != nil || (sec.RegistrationCapacity{ReportFile: cfg.Records.CapacityReportFile}).ReserveExecutionPayload(ctx, tx, capacity, len(raw)) != nil {
				return kms.ErrPermission
			}
		}
	}
	if _, err = p.authenticateDelivery(raw, checksum, size, expires, lease, now); err != nil {
		return err
	}
	next("Stage.RegistryBind")
	bound, locked, err := (reg.SQLStore{}).Bind(ctx, tx, a.InstallationID)
	if err != nil {
		return kms.ErrPermission
	}
	next("Stage.RegistryRecheck")
	if p.recheck(ctx, tx, guard, bound, locked, now) != nil {
		return kms.ErrPermission
	}
	// The first full recheck above acquired both exact provider rows in the
	// existing capability -> issuer-file -> mapping order. Only subsequent
	// checks in THIS original transaction may batch their CURRENT row reads.
	providerRows := &heldProviderPermitRows{ctx: ctx, tx: tx, issue: p, guard: guard, authority: a, capability: p.capability, source: p.capability.pin.Source, mapping: cfg.Binding.ConfigRef}
	if newPermit {
		if _, err = tx.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at) VALUES (?,'backup',?,'diagnostic','inline',?,?,?,'application/json','none','internal','healthy',?)`, id, a.TaskPublicID, raw, checksum, size, expires); err != nil {
			return kms.ErrPermission
		}
	}
	next("Stage.RegistryChange")
	// The original key-reserve is retained BEFORE permission can leave this
	// transaction. Begin/finished/candidate never prove external absence: once
	// provider I/O can have occurred, keep this member unknown until an original
	// artifact/cleanup owner later proves its actual lifecycle.
	fingerprint, err := reg.BindingFingerprint(cfg.Binding)
	if err != nil {
		return kms.ErrPermission
	}
	lifecycleHash := sha256.Sum256(expected)
	lifecycle := reg.SourceRecord{SourceID: "original-public-capture-key-use.v1", RecordID: id, RecordVersion: "v1", ContentSHA256: hex.EncodeToString(lifecycleHash[:])}
	state := reg.ReferencePlanned
	if action != "key-reserve" {
		state = reg.ReferenceUnknown
	}
	r := reg.Reference{Partition: reg.InflightAndUnknownWrites, State: state, SourceRecordID: id, SourceRecordVersion: "v1", BackupPublicID: a.TaskPublicID, AttemptNo: strconv.FormatUint(a.AttemptNo, 10), EnvelopeID: lease.Access.Request.Context.EnvelopeID, Key: cfg.Binding.Key, BindingSHA256: fingerprint, MappingSource: p.mapping.Source, ExpectedRequestSource: reg.SourceRecord{SourceID: "original-frozen-execution-plan.v1", RecordID: "plan:" + a.TaskPublicID + ":" + strconv.FormatUint(a.AttemptNo, 10), RecordVersion: p.planHash, ContentSHA256: p.planHash}, LifecycleSource: lifecycle}
	// The first Bind read and locked every reference plus the installation
	// fence in THIS transaction. An exactly identical reference makes the
	// original registry mutation below a no-op; it cannot advance that fence.
	// Keep every mutation/recheck call, but avoid rereading the same locked
	// snapshot on every key-check when no facts changed. No authority or data
	// snapshot is reused across requests or transactions.
	unchanged := false
	for _, existing := range locked.Facts().References {
		if reflect.DeepEqual(existing, r) {
			unchanged = true
			break
		}
	}
	change := &issuedPermitReferenceChange{issue: p, tx: tx, guard: guard, bound: bound, locked: locked, reference: r, until: lease.Until, providerRows: providerRows}
	if state == reg.ReferencePlanned {
		err = bound.RetainPlanned(ctx, change)
	} else {
		err = bound.MarkUnknown(ctx, change)
	}
	if err != nil {
		return kms.ErrPermission
	}
	// A changed source advances this SAME locked fence. Refresh its derived
	// snapshot in that case, retaining all original business/source locks.
	if !unchanged {
		bound, locked, err = (reg.SQLStore{}).Bind(ctx, tx, a.InstallationID)
		if err != nil {
			return kms.ErrPermission
		}
	}
	next("Stage.RegistryTail")
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || p.recheckRows(ctx, tx, guard, bound, locked, now, providerRows) != nil {
		return kms.ErrPermission
	}
	p.id = id
	copied := lease
	p.lease = &copied
	return nil
}

type issuedPermitReferenceChange struct {
	issue        *PreparedProviderPermitIssue
	tx           *sql.Tx
	guard        *c.ExecutionAuthorityGuard
	bound        *reg.Bound
	locked       reg.LockedSnapshot
	reference    reg.Reference
	until        time.Time
	providerRows *heldProviderPermitRows
}

func (p *issuedPermitReferenceChange) Reference() reg.Reference { return p.reference }
func (p *issuedPermitReferenceChange) Source() reg.SourceRecord { return p.reference.LifecycleSource }
func (p *issuedPermitReferenceChange) ExpectedEpoch() uint64    { return p.locked.Facts().Epoch }
func (p *issuedPermitReferenceChange) ValidUntil() time.Time    { return p.until }
func (p *issuedPermitReferenceChange) Recheck(ctx context.Context, view reg.SQLReadView, locked reg.LockedSnapshot, now time.Time) error {
	if view != p.tx || !reg.SameSnapshotFacts(locked.Facts(), p.locked.Facts()) || !now.Before(p.until) {
		return kms.ErrPermission
	}
	return p.issue.recheckRows(ctx, p.tx, p.guard, p.bound, locked, now, p.providerRows)
}

func (p *PreparedProviderPermitIssue) recheck(ctx context.Context, tx *sql.Tx, guard *c.ExecutionAuthorityGuard, bound *reg.Bound, locked reg.LockedSnapshot, now time.Time) error {
	return p.recheckRows(ctx, tx, guard, bound, locked, now, nil)
}

func (p *PreparedProviderPermitIssue) recheckRows(ctx context.Context, tx *sql.Tx, guard *c.ExecutionAuthorityGuard, bound *reg.Bound, locked reg.LockedSnapshot, now time.Time, rows *heldProviderPermitRows) (resultErr error) {
	cost := startProviderPermitTimer(ctx, "Recheck")
	defer func() { cost.finish(resultErr != nil) }()
	segment := startProviderPermitTimer(ctx, "Recheck.GuardAndRevocation")
	defer func() { segment.finish(resultErr != nil) }()
	next := func(label string) {
		segment.finish(false)
		segment = startProviderPermitTimer(ctx, label)
	}
	if !now.Before(p.until) || guard.RecheckAfter(ctx, tx, now) != nil || bound.RequireUnrevoked(p.issuer.cfg.Binding.ConfigRef, reg.GenerateRevocation) != nil {
		return kms.ErrPermission
	}
	next("Recheck.Capability")
	var raw, sig []byte
	if rows == nil {
		if p.capability.Recheck(ctx, tx, locked, now) != nil {
			return kms.ErrPermission
		}
	} else {
		next("Recheck.CurrentRows")
		evidence, currentRaw, currentSig, err := rows.read(ctx, tx, p, guard)
		if err != nil || p.capability.recheckEvidence(ctx, locked.Facts(), now, evidence) != nil {
			return kms.ErrPermission
		}
		raw, sig = currentRaw, currentSig
	}
	next("Recheck.IssuerGrant")
	if p.grantProof.recheck(ctx, p.issuer.cfg, now) != nil {
		return kms.ErrPermission
	}
	next("Recheck.Mapping")
	if rows == nil {
		var err error
		raw, sig, err = (SQLOriginalReader{}).RecheckOriginal(ctx, tx, p.scope.Input.Authority.InstallationID, p.issuer.cfg.Binding.ConfigRef)
		if err != nil {
			return kms.ErrPermission
		}
	}
	if p.recheckMapping(raw, sig, now) != nil {
		return kms.ErrPermission
	}
	next("Recheck.SecurityBinding")
	for _, fact := range locked.Facts().Bindings {
		if fact.Binding.ConfigRef == p.issuer.cfg.Binding.ConfigRef && reg.SameSecurityBinding(fact.Binding, p.issuer.cfg.Binding) {
			return nil
		}
	}
	return kms.ErrPermission
}

// Every call is preceded by the original current FOR SHARE row read. Equal
// authenticated data needs no second decode/signature check. A changed current
// revision is fully authenticated as before, including legitimate renewals;
// it never extends this prepared request's original minimum lifetime.
func (p *PreparedProviderPermitIssue) recheckMapping(raw, sig []byte, now time.Time) error {
	m := p.mapping
	if len(p.mappingRaw) == 0 || !bytes.Equal(raw, p.mappingRaw) || !bytes.Equal(sig, p.mappingSignature) || !bytes.Equal(p.issuer.cfg.InstallationIssuer, p.mappingIssuer) {
		var err error
		m, err = decodeOwnerRecord(raw, sig, p.issuer.cfg.InstallationIssuer)
		if err != nil {
			return kms.ErrPermission
		}
	}
	if !reflect.DeepEqual(m.Binding, p.mapping.Binding) || m.GenerateRevoked || now.Before(m.NotBefore) || !now.Before(m.Until) || m.Until.Before(p.until) {
		return kms.ErrPermission
	}
	return nil
}

func (p *PreparedProviderPermitIssue) authenticateDelivery(raw []byte, checksum string, size uint64, expires time.Time, lease worker.KeyUseLease, now time.Time) (kms.DeliveredProviderPermit, error) {
	var delivery kms.DeliveredProviderPermit
	h := sha256.Sum256(raw)
	if len(raw) == 0 || len(raw) > 8192 || uint64(len(raw)) != size || hex.EncodeToString(h[:]) != checksum || strictPermitIssuerJSON(raw, &delivery) != nil || !ed25519.Verify(p.grant.SigningPublicKey, append([]byte(kms.PermitDeliveryDomain), delivery.Payload...), delivery.Signature) {
		return kms.DeliveredProviderPermit{}, kms.ErrPermission
	}
	var body kms.DeliveredPermitPayload
	if strictPermitIssuerJSON(delivery.Payload, &body) != nil {
		return kms.DeliveredProviderPermit{}, kms.ErrPermission
	}
	context64, _ := kms.TransitContext(lease.Access.Request)
	identityFile, err := workerJWTIdentityPath(p.grant.WorkerJWTIdentityFile, lease.Identity.PodUID)
	if err != nil {
		return kms.DeliveredProviderPermit{}, err
	}
	jwt := kms.JWTIdentityGrant{Mount: p.grant.GeneratePermission.AuthMount, Role: p.grant.GeneratePermission.Role, Policy: p.grant.GeneratePermission.Policy, IdentityFile: identityFile}
	q := body.Permit
	if body.Version != kms.PermitDeliveryVersion || body.IssuerGrantSHA256 != p.issuer.cfg.GrantMount.SHA256 || body.Nonce != lease.Nonce || body.Request != lease.Access.Request || q.Version != "system-backup-provider-permit.v1" || q.Identity != lease.Identity || q.Operation != kms.Generate || q.Endpoint != lease.Access.Endpoint || q.KeyName != lease.Access.KeyName || q.ContextBase64 != context64 || q.JWT != jwt || q.CredentialRef != "" || q.CredentialSHA256 != "" || now.Before(q.NotBefore) || !now.Before(q.ExpiresAt) || !q.ExpiresAt.Equal(lease.Until) || !expires.Equal(q.ExpiresAt) || q.ExpiresAt.After(p.until) {
		return kms.DeliveredProviderPermit{}, kms.ErrPermission
	}
	return delivery, nil
}

// ReadCommitted returns only an existing journaled permit under current original
// authority, independent issuer delegation and Generate source. A rollback,
// changed nonce or unknown commit has no substitute signer/reissue fallback.
func (p *PreparedProviderPermitIssue) ReadCommitted(ctx context.Context) (kms.DeliveredProviderPermit, error) {
	bad := func() (kms.DeliveredProviderPermit, error) { return kms.DeliveredProviderPermit{}, kms.ErrPermission }
	if p == nil || p.id == "" || p.lease == nil || ctx == nil || ctx.Err() != nil {
		return bad()
	}
	if checkControllerWorkload(ctx, p.issuer.cfg.Kubernetes, p.issuer.cfg.Workload) != nil {
		return bad()
	}
	tx, err := p.issuer.cfg.Authority.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return bad()
	}
	defer tx.Rollback()
	guard, err := p.issuer.cfg.Authority.Bind(ctx, tx, p.scope.Input.Authority)
	if err != nil {
		return bad()
	}
	var raw []byte
	var checksum string
	var size uint64
	var expires time.Time
	if tx.QueryRowContext(ctx, issuedPermitQuery+" FOR SHARE", p.id, p.scope.Input.Authority.TaskPublicID).Scan(&raw, &checksum, &size, &expires) != nil {
		return bad()
	}
	var keyUse []byte
	j, a := p.scope.Job, p.scope.Input.Authority
	if tx.QueryRowContext(ctx, `SELECT key_use_json FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND attempt_no=? AND phase='capture' AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND observed_uid=? AND revoked=FALSE AND stopped_at IS NULL AND lifecycle='ready' FOR SHARE`, a.TaskPublicID, a.AttemptNo, j.Namespace, j.Name, j.UID).Scan(&keyUse) != nil {
		return bad()
	}
	var current worker.KeyUseLease
	if strictPermitIssuerJSON(keyUse, &current) != nil {
		return bad()
	}
	want, got := *p.lease, current
	want.State, got.State = "", ""
	if !reflect.DeepEqual(want, got) || (current.State != "reserved" && current.State != "using" && current.State != "finished") {
		return bad()
	}
	bound, locked, err := (reg.SQLStore{}).Bind(ctx, tx, a.InstallationID)
	var now time.Time
	if err != nil || tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || p.recheck(ctx, tx, guard, bound, locked, now) != nil {
		return bad()
	}
	delivery, err := p.authenticateDelivery(raw, checksum, size, expires, current, now)
	if err != nil {
		return bad()
	}
	return delivery, nil
}
