package systembackupkekadapter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"time"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
	w "clawreef/internal/systembackupwire"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ControllerVerifierWorkload identifies the real verifier actor in both the
// original business grant and the independent provider permission observation.
// The actor uses its own Pod/SA/owner chain and never borrows the capture Job.
type ControllerVerifierWorkload struct {
	Namespace, PodName, PodUID                 string
	ServiceAccountName, ServiceAccountUID      string
	OwnerKind, OwnerUID                        string
	ControllerOwner, GrantSHA256, ConfigSHA256 string
	ConfigVersion                              uint64
}

type ControllerVerifierConfig struct {
	Capabilities *SQLProviderCapabilityPreparation
	Binding      reg.Binding
	CAPEM        []byte
	JWTFile      string
	Workload     ControllerVerifierWorkload
	Kubernetes   kubernetes.Interface
	Authority    c.SQLExecutionAuthority
	Records      c.SQLExecutionRecords
	// Keep the actual deploymentAuthorization wrapper above. RecordKeys still
	// come from the original forward/capture identity; the verifier grant below
	// is a separate original-owner authorization and must have a distinct hash.
	GrantMount         ControllerVerifierGrantMount
	CaptureGrantSHA256 string
	// Independent original installation-owner issuer; never inferred from a
	// registry row, config reference, verifier grant or provider observation.
	InstallationIssuer ed25519.PublicKey
	KubernetesReads    *VerifierKubernetesReads
}

type ControllerVerifierCandidate struct {
	Input              d.Input
	Job                d.JobBinding
	Invocation         worker.Invocation
	CandidateSHA256    string // original encrypted candidate journal's plaintext hash
	CaptureGrantSHA256 string
}

type ControllerVerifierFactory struct{ cfg ControllerVerifierConfig }

// NewControllerVerifierFactory is the concrete controller-process entry. It
// needs the existing original SQL authority/record custody and actual K8s
// client; there are no caller-supplied authentication callbacks or Job stand-ins.
func NewControllerVerifierFactory(cfg ControllerVerifierConfig) (*ControllerVerifierFactory, error) {
	if cfg.KubernetesReads != nil {
		if cfg.KubernetesReads.Validate(cfg.Workload) != nil {
			return nil, kms.ErrPermission
		}
		reads := *cfg.KubernetesReads
		cfg.KubernetesReads = &reads
	}
	recordKeys, recordKeysOK := cfg.Records.Keys.(*c.PinnedExecutionIdentity)
	_, bareForward := cfg.Authority.Authorization.(*c.PinnedExecutionIdentity)
	if cfg.Capabilities == nil || cfg.Authority.DB == nil || cfg.Records.Authority.DB != cfg.Authority.DB || cfg.Capabilities.db != cfg.Authority.DB ||
		cfg.Authority.InstallationID != cfg.Binding.InstallationID || cfg.Capabilities.installation != cfg.Binding.InstallationID || !cfg.Authority.DeploymentEnabled || cfg.Authority.ApplicationScope == "" ||
		bareForward || nilSource(cfg.Authority.Authorization) || !reflect.DeepEqual(cfg.Records.Authority.Authorization, cfg.Authority.Authorization) || !recordKeysOK || recordKeys == nil || recordKeys.GrantSHA256() != cfg.CaptureGrantSHA256 || cfg.CaptureGrantSHA256 == cfg.Workload.GrantSHA256 || cfg.Records.Authority.ApplicationScope != cfg.Authority.ApplicationScope || nilSource(cfg.Kubernetes) || !filepath.IsAbs(cfg.JWTFile) || len(cfg.CAPEM) == 0 || len(cfg.CAPEM) > 65536 || len(cfg.InstallationIssuer) != ed25519.PublicKeySize {
		return nil, kms.ErrPermission
	}
	for _, v := range []string{cfg.Workload.Namespace, cfg.Workload.PodName, cfg.Workload.PodUID, cfg.Workload.ServiceAccountName, cfg.Workload.ServiceAccountUID, cfg.Workload.OwnerKind, cfg.Workload.OwnerUID, cfg.Workload.ControllerOwner} {
		if v == "" || len(v) > 256 {
			return nil, kms.ErrPermission
		}
	}
	if cfg.Workload.OwnerKind != "Deployment" && cfg.Workload.OwnerKind != "StatefulSet" && cfg.Workload.OwnerKind != "Job" {
		return nil, kms.ErrPermission
	}
	if cfg.Workload.ConfigVersion == 0 || !authorityHash.MatchString(cfg.Workload.ConfigSHA256) || !authorityHash.MatchString(cfg.Workload.GrantSHA256) {
		return nil, kms.ErrPermission
	}
	h := sha256.Sum256(cfg.CAPEM)
	if hex.EncodeToString(h[:]) != cfg.Binding.Provider.CAPEMSHA256 {
		return nil, kms.ErrPermission
	}
	cfg.CAPEM = bytes.Clone(cfg.CAPEM)
	cfg.Binding.GenerateRef.RawJSON = bytes.Clone(cfg.Binding.GenerateRef.RawJSON)
	cfg.Binding.UnwrapRef.RawJSON = bytes.Clone(cfg.Binding.UnwrapRef.RawJSON)
	cfg.GrantMount.Issuer = bytes.Clone(cfg.GrantMount.Issuer)
	cfg.InstallationIssuer = bytes.Clone(cfg.InstallationIssuer)
	if _, err := readControllerVerifierGrant(context.Background(), cfg.GrantMount, cfg.Workload, cfg.Binding.InstallationID, cfg.CaptureGrantSHA256, cfg.Capabilities.database); err != nil {
		return nil, err
	}
	return &ControllerVerifierFactory{cfg: cfg}, nil
}

// ForCandidate consumes only an original frozen invocation. It rereads the
// encrypted original plan and exact SQL candidate before allowing any login.
func (f *ControllerVerifierFactory) ForCandidate(ctx context.Context, scope ControllerVerifierCandidate) (*ControllerVerifier, error) {
	if f == nil || ctx == nil || ctx.Err() != nil || scope.Invocation.ProviderKey == nil || scope.Invocation.FormalCapture == nil || !worker.ValidateRecordedInvocation(scope.Invocation) || !authorityHash.MatchString(scope.CandidateSHA256) {
		return nil, kms.ErrPermission
	}
	// Retain immutable copies of ordinary lookup DTOs; their presence is not
	// authority and later caller mutation must not change a constructed scope.
	rawScope, err := json.Marshal(scope)
	if err != nil || len(rawScope) > 4<<20 {
		return nil, kms.ErrPermission
	}
	var frozen ControllerVerifierCandidate
	err = json.Unmarshal(rawScope, &frozen)
	clear(rawScope)
	if err != nil {
		return nil, kms.ErrPermission
	}
	scope = frozen
	a := scope.Input.Authority
	grant := f.cfg.Workload
	r := scope.Invocation.ProviderKey.Request
	if a.TaskType != "backup" || a.Phase != "capture" || a.InstallationID != f.cfg.Binding.InstallationID || a.ClaimOwner != grant.ControllerOwner || a.ConfigVersion != grant.ConfigVersion || a.ConfigSHA256 != grant.ConfigSHA256 ||
		r.Key != f.cfg.Binding.Key || r.Context.InstallationID != a.InstallationID || r.Context.BackupPublicID != a.TaskPublicID || r.Context.AttemptNo != strconv.FormatUint(a.AttemptNo, 10) || scope.Job.UID == "" || scope.CaptureGrantSHA256 != f.cfg.CaptureGrantSHA256 {
		return nil, kms.ErrPermission
	}
	if _, err := kms.TransitContext(r); err != nil {
		return nil, kms.ErrPermission
	}
	capability, err := f.cfg.Capabilities.prepareOperation(ctx, f.cfg.Binding, kms.Unwrap)
	if err != nil {
		return nil, kms.ErrPermission
	}
	permission := capability.record.Facts.Permission
	if permission.ControllerVerifier == nil || *permission.ControllerVerifier != f.cfg.Workload {
		return nil, kms.ErrPermission
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(f.cfg.CAPEM) {
		return nil, kms.ErrPermission
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 16384, DisableCompression: true}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	v := &ControllerVerifier{factory: f, scope: scope, request: r, capability: capability, client: client, until: capability.ValidUntil()}
	originalGrant, err := v.originalGrant(ctx)
	if err != nil {
		v.Close()
		return nil, err
	}
	if originalGrant.Until.Before(v.until) {
		v.until = originalGrant.Until
	}
	originalMapping, err := v.currentOriginalMapping(ctx, f.cfg.Authority.DB, time.Now(), false)
	if err != nil {
		v.Close()
		return nil, err
	}
	if originalMapping.Until.Before(v.until) {
		v.until = originalMapping.Until
	}
	if a.DeadlineAt.Before(v.until) {
		v.until = a.DeadlineAt
	}
	session, err := v.begin(ctx)
	if err != nil {
		v.Close()
		return nil, kms.ErrPermission
	}
	if session.guard.ValidUntil().Before(v.until) {
		v.until = session.guard.ValidUntil()
	}
	session.tx.Rollback()
	cfg := kms.Config{Endpoint: f.cfg.Binding.Provider.Endpoint, InstallationID: a.InstallationID, KeyName: f.cfg.Binding.Provider.KeyName, Key: f.cfg.Binding.Key, CAPEM: f.cfg.CAPEM, CASHA256: f.cfg.Binding.Provider.CAPEMSHA256, NotBefore: capability.NotBefore(), NotAfter: v.until}
	v.unwrap, err = kms.NewRecoveryUnwrapper(cfg, v)
	if err != nil {
		v.Close()
		return nil, kms.ErrPermission
	}
	return v, nil
}

type ControllerVerifier struct {
	factory    *ControllerVerifierFactory
	scope      ControllerVerifierCandidate
	request    w.KeyRequest
	capability *sqlPreparedCapability
	client     *http.Client
	unwrap     *kms.RecoveryUnwrapper // transport only; no RecoveryJob/restore grant
	until      time.Time
	callMu     sync.Mutex
}

// ValidUntil bounds the ENTIRE candidate verification, including source reads
// and private custody writes performed by the wire callback. The observer must
// derive its stream context from this deadline: wire.WithDEK has no context
// parameter and cannot cancel I/O that captures an unrelated outer context.
func (v *ControllerVerifier) ValidUntil() time.Time {
	if v == nil {
		return time.Time{}
	}
	return v.until
}

func (v *ControllerVerifier) Close() {
	if v != nil {
		if v.client != nil {
			v.client.CloseIdleConnections()
		}
		if v.unwrap != nil {
			v.unwrap.Close()
		}
	}
}

func (v *ControllerVerifier) checkWorkload(ctx context.Context) error {
	if v == nil || ctx == nil || ctx.Err() != nil {
		return kms.ErrPermission
	}
	if _, err := v.originalGrant(ctx); err != nil {
		return err
	}
	if reads := v.factory.cfg.KubernetesReads; reads != nil {
		return reads.Check(ctx, v.factory.cfg.Kubernetes, v.factory.cfg.Workload)
	}
	return checkControllerWorkload(ctx, v.factory.cfg.Kubernetes, v.factory.cfg.Workload)
}

func checkControllerWorkload(ctx context.Context, k kubernetes.Interface, wk ControllerVerifierWorkload) error {
	if ctx == nil || ctx.Err() != nil || nilSource(k) {
		return kms.ErrPermission
	}
	pod, err := k.CoreV1().Pods(wk.Namespace).Get(ctx, wk.PodName, metav1.GetOptions{})
	if err != nil || string(pod.UID) != wk.PodUID || pod.DeletionTimestamp != nil || string(pod.Status.Phase) != "Running" || pod.Spec.ServiceAccountName != wk.ServiceAccountName {
		return kms.ErrPermission
	}
	sa, err := k.CoreV1().ServiceAccounts(wk.Namespace).Get(ctx, wk.ServiceAccountName, metav1.GetOptions{})
	if err != nil || string(sa.UID) != wk.ServiceAccountUID || sa.DeletionTimestamp != nil {
		return kms.ErrPermission
	}
	owners := pod.OwnerReferences
	if len(owners) != 1 || owners[0].Controller == nil || !*owners[0].Controller {
		return kms.ErrPermission
	}
	if wk.OwnerKind == "StatefulSet" {
		o := owners[0]
		if o.Kind != "StatefulSet" || o.APIVersion != "apps/v1" || string(o.UID) != wk.OwnerUID {
			return kms.ErrPermission
		}
		owner, e := k.AppsV1().StatefulSets(wk.Namespace).Get(ctx, o.Name, metav1.GetOptions{})
		if e != nil || string(owner.UID) != wk.OwnerUID || owner.DeletionTimestamp != nil {
			return kms.ErrPermission
		}
		return nil
	}
	if wk.OwnerKind == "Job" {
		o := owners[0]
		if o.Kind != "Job" || o.APIVersion != "batch/v1" || string(o.UID) != wk.OwnerUID {
			return kms.ErrPermission
		}
		owner, e := k.BatchV1().Jobs(wk.Namespace).Get(ctx, o.Name, metav1.GetOptions{})
		if e != nil || string(owner.UID) != wk.OwnerUID || owner.DeletionTimestamp != nil {
			return kms.ErrPermission
		}
		return nil
	}
	if wk.OwnerKind != "Deployment" || owners[0].Kind != "ReplicaSet" || owners[0].APIVersion != "apps/v1" {
		return kms.ErrPermission
	}
	rs, err := k.AppsV1().ReplicaSets(wk.Namespace).Get(ctx, owners[0].Name, metav1.GetOptions{})
	if err != nil || rs.UID != owners[0].UID || rs.DeletionTimestamp != nil || len(rs.OwnerReferences) != 1 {
		return kms.ErrPermission
	}
	o := rs.OwnerReferences[0]
	if o.Controller == nil || !*o.Controller || o.Kind != "Deployment" || o.APIVersion != "apps/v1" || string(o.UID) != wk.OwnerUID {
		return kms.ErrPermission
	}
	deployment, err := k.AppsV1().Deployments(wk.Namespace).Get(ctx, o.Name, metav1.GetOptions{})
	if err != nil || string(deployment.UID) != wk.OwnerUID || deployment.DeletionTimestamp != nil {
		return kms.ErrPermission
	}
	return nil
}

func (v *ControllerVerifier) loadPlan(ctx context.Context) (string, string, error) {
	return loadOriginalCandidatePlan(ctx, v.factory.cfg.Records, v.scope)
}

func loadOriginalCandidatePlan(ctx context.Context, records c.SQLExecutionRecords, scope ControllerVerifierCandidate) (string, string, error) {
	if scope.Invocation.ProviderKey == nil {
		return "", "", kms.ErrPermission
	}
	plan, err := records.LoadPlan(ctx, scope.Input)
	if err != nil {
		return "", "", kms.ErrPermission
	}
	defer clear(plan.CanonicalJSON)
	inner, err := d.UnwrapTaskPlan(scope.Input, plan, b.PlanVersion)
	if err != nil {
		return "", "", kms.ErrPermission
	}
	defer clear(inner.CanonicalJSON)
	desc, err := b.DescribePlan(scope.Input, inner)
	if err != nil {
		return "", "", kms.ErrPermission
	}
	hash, err := scope.Invocation.Hash()
	if err != nil {
		return "", "", kms.ErrPermission
	}
	for _, part := range desc.Parts {
		if part.Intent.JobUnitKey != scope.Job.JobUnitKey {
			continue
		}
		if part.Intent.Namespace != scope.Job.Namespace || part.Intent.Name != scope.Job.Name || part.Intent.Generation != scope.Job.Generation || part.InvocationSHA256 != hash {
			return "", "", kms.ErrPermission
		}
		var invocation worker.Invocation
		if json.Unmarshal(part.InvocationJSON, &invocation) != nil || invocation.ProviderKey == nil || invocation.ProviderKey.Request != scope.Invocation.ProviderKey.Request {
			return "", "", kms.ErrPermission
		}
		// The plan authenticates the ORIGINAL typed Job bytes. The runtime
		// journal instead pins kube.Intent's normalized unstructured request
		// (apiVersion/kind, no status, pre request-hash annotation). Preserve BOTH
		// checks; a plan SpecSHA is not the runtime RequestSHA.
		specSum := sha256.Sum256(part.Intent.SpecJSON)
		if hex.EncodeToString(specSum[:]) != part.Intent.SpecSHA256 {
			return "", "", kms.ErrPermission
		}
		var job batchv1.Job
		if json.Unmarshal(part.Intent.SpecJSON, &job) != nil {
			return "", "", kms.ErrPermission
		}
		intent, err := kube.Intent("Job", &job)
		if err != nil || intent.Identity.Namespace != scope.Job.Namespace || intent.Identity.Name != scope.Job.Name || intent.Identity.Owner != scope.Input.Authority.TaskPublicID {
			return "", "", kms.ErrPermission
		}
		return plan.SHA256, intent.RequestSHA256, nil
	}
	return "", "", kms.ErrPermission
}

type controllerVerifierSession struct {
	ctx      context.Context
	tx       *sql.Tx
	guard    *c.ExecutionAuthorityGuard
	kek      *reg.Bound
	locked   reg.LockedSnapshot
	verifier *ControllerVerifier
}

func (v *ControllerVerifier) begin(ctx context.Context) (*controllerVerifierSession, error) {
	if ctx == nil || ctx.Err() != nil || !time.Now().Before(v.until) || v.checkWorkload(ctx) != nil {
		return nil, kms.ErrPermission
	}
	planHash, specHash, err := v.loadPlan(ctx)
	if err != nil {
		return nil, err
	}
	tx, err := v.factory.cfg.Authority.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, kms.ErrPermission
	}
	fail := func() (*controllerVerifierSession, error) { tx.Rollback(); return nil, kms.ErrPermission }
	guard, err := v.factory.cfg.Authority.Bind(ctx, tx, v.scope.Input.Authority)
	if err != nil {
		return fail()
	}
	grant, err := v.originalGrant(ctx)
	if err != nil {
		return fail()
	}
	var account, server, database string
	if tx.QueryRowContext(ctx, "SELECT CURRENT_USER(),@@server_uuid,DATABASE()").Scan(&account, &server, &database) != nil || account != grant.DatabaseAccount || server != grant.Database.ServerUUID || database != grant.Database.Database {
		return fail()
	}
	a, j := v.scope.Input.Authority, v.scope.Job
	var originalPlan, candidate, spec string
	if tx.QueryRowContext(ctx, `SELECT payload_sha256 FROM system_backup_v2_execution_records WHERE origin_installation_id=? AND task_public_id=? AND attempt_no=? AND phase='capture' AND record_kind='plan' FOR SHARE`, a.InstallationID, a.TaskPublicID, a.AttemptNo).Scan(&originalPlan) != nil || originalPlan != planHash {
		return fail()
	}
	if tx.QueryRowContext(ctx, `SELECT candidate_sha256,request_sha256 FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND attempt_no=? AND phase='capture' AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND observed_uid=? AND revoked=FALSE AND lifecycle='ready' AND stopped_at IS NULL FOR SHARE`, a.TaskPublicID, a.AttemptNo, j.Namespace, j.Name, j.UID).Scan(&candidate, &spec) != nil || candidate != v.scope.CandidateSHA256 || spec != specHash {
		return fail()
	}
	kek, locked, err := (reg.SQLStore{}).Bind(ctx, tx, a.InstallationID)
	if err != nil || locked.Facts().Database != v.factory.cfg.Capabilities.database || kek.RequireUnrevoked(v.factory.cfg.Binding.ConfigRef, reg.UnwrapRevocation) != nil {
		return fail()
	}
	found := false
	for _, fact := range locked.Facts().Bindings {
		if fact.Binding.ConfigRef == v.factory.cfg.Binding.ConfigRef && reg.SameSecurityBinding(fact.Binding, v.factory.cfg.Binding) {
			found = true
		}
	}
	if !found {
		return fail()
	}
	session := &controllerVerifierSession{ctx: ctx, tx: tx, guard: guard, kek: kek, locked: locked, verifier: v}
	if session.check(ctx) != nil {
		return fail()
	}
	return session, nil
}

func (s *controllerVerifierSession) check(ctx context.Context) error {
	if s == nil || ctx == nil || ctx.Err() != nil || s.ctx.Err() != nil || !time.Now().Before(s.verifier.until) {
		return kms.ErrPermission
	}
	if _, err := s.verifier.originalGrant(ctx); err != nil {
		return err
	}
	var now time.Time
	if s.tx.QueryRowContext(s.ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || s.guard.RecheckAfter(s.ctx, s.tx, now) != nil || s.verifier.capability.Recheck(s.ctx, s.tx, s.locked, now) != nil || s.kek.RequireUnrevoked(s.verifier.factory.cfg.Binding.ConfigRef, reg.UnwrapRevocation) != nil {
		return kms.ErrPermission
	}
	original, err := s.verifier.currentOriginalMapping(s.ctx, s.tx, now, true)
	if err != nil || original.Until.Before(s.verifier.until) {
		return kms.ErrPermission
	}
	return nil
}

func (v *ControllerVerifier) currentOriginalMapping(ctx context.Context, view reg.SQLReadView, now time.Time, locked bool) (OriginalRecord, error) {
	cfg := v.factory.cfg
	return currentVerifierOriginalMapping(ctx, view, cfg.Binding, cfg.InstallationIssuer, now, locked)
}

func currentVerifierOriginalMapping(ctx context.Context, view reg.SQLReadView, binding reg.Binding, issuer ed25519.PublicKey, now time.Time, locked bool) (OriginalRecord, error) {
	var raw, sig []byte
	var err error
	if locked {
		raw, sig, err = (SQLOriginalReader{}).RecheckOriginal(ctx, view, binding.InstallationID, binding.ConfigRef)
	} else {
		raw, sig, err = readOriginal(ctx, view, binding.InstallationID, binding.ConfigRef)
	}
	if err != nil {
		return OriginalRecord{}, kms.ErrPermission
	}
	// Admission needs BOTH purposes; this current execution check intentionally
	// checks Unwrap alone. Retained ciphertext must remain readable when only
	// new generation was revoked by the original installation owner.
	r, err := decodeOwnerRecord(raw, sig, issuer)
	if err != nil || !reflect.DeepEqual(r.Binding, binding) || now.Before(r.NotBefore) || !now.Before(r.Until) || r.UnwrapRevoked {
		return OriginalRecord{}, kms.ErrPermission
	}
	return r, nil
}

func (v *ControllerVerifier) originalGrant(ctx context.Context) (ControllerVerifierGrant, error) {
	return readControllerVerifierGrant(ctx, v.factory.cfg.GrantMount, v.factory.cfg.Workload, v.factory.cfg.Binding.InstallationID, v.factory.cfg.CaptureGrantSHA256, v.factory.cfg.Capabilities.database)
}

// Workload is the independent verifier actor. Its GrantSHA256 is deliberately
// distinct from the original capture/record-encryption grant.
func (v *ControllerVerifier) Workload() ControllerVerifierWorkload {
	if v == nil {
		return ControllerVerifierWorkload{}
	}
	return v.factory.cfg.Workload
}

func (v *ControllerVerifier) ExpectedAccess() kms.Access {
	if v == nil {
		return kms.Access{}
	}
	return kms.Access{Request: v.request, Operation: kms.Unwrap, Endpoint: v.factory.cfg.Binding.Provider.Endpoint, KeyName: v.factory.cfg.Binding.Provider.KeyName}
}

func (v *ControllerVerifier) Recheck(ctx context.Context) error {
	if v == nil {
		return kms.ErrPermission
	}
	session, err := v.begin(ctx)
	if err != nil {
		return err
	}
	return session.tx.Rollback()
}

// Stream readers check the same original authority around every bounded read.
// This cannot renew the fixed per-use deadline captured by ForCandidate.
func (v *ControllerVerifier) RecheckStream(ctx context.Context) error { return v.Recheck(ctx) }

func (v *ControllerVerifier) Unwrap(ctx context.Context, expected w.KeyRequest, wrapped w.WrappedKey, use w.WithDEK) error {
	if v == nil || v.unwrap == nil || ctx == nil || ctx.Err() != nil || use == nil || expected != v.request || wrapped.Request != v.request {
		return kms.ErrPermission
	}
	ctx, cancel := context.WithDeadline(ctx, v.until)
	defer cancel()
	v.callMu.Lock()
	defer v.callMu.Unlock()
	return v.unwrap.Unwrap(ctx, expected, wrapped, use)
}

func (v *ControllerVerifier) Resolve(ctx context.Context, access kms.Access) (kms.Grant, error) {
	if v == nil || access.Operation != kms.Unwrap || access.Request != v.request || access.Endpoint != v.factory.cfg.Binding.Provider.Endpoint || access.KeyName != v.factory.cfg.Binding.Provider.KeyName || v.Recheck(ctx) != nil {
		return kms.Grant{}, kms.ErrPermission
	}
	secret, start, expires, jwtHash, err := v.login(ctx)
	if err != nil {
		return kms.Grant{}, kms.ErrPermission
	}
	check := func(c context.Context, a kms.Access) error {
		if a != access || v.Recheck(c) != nil {
			return kms.ErrPermission
		}
		jwt, e := readVerifierJWT(v.factory.cfg.JWTFile)
		defer clear(jwt)
		if e != nil || sha256.Sum256(jwt) != jwtHash {
			return kms.ErrPermission
		}
		return nil
	}
	if check(ctx, access) != nil {
		clear(secret)
		return kms.Grant{}, kms.ErrPermission
	}
	return kms.Grant{Access: access, Secret: secret, NotBefore: start, ExpiresAt: v.until, CredentialExpiresAt: expires, Recheck: check, WithUse: func(c context.Context, a kms.Access, use func() error) error {
		if c == nil || c.Err() != nil || a != access || use == nil {
			return kms.ErrPermission
		}
		c, cancel := context.WithDeadline(c, v.until)
		defer cancel()
		// Every check opens and closes an exact original task/KEK snapshot.
		// Holding that snapshot across inert stream I/O blocks the same-epoch
		// heartbeat and prevents observing revocation. The C stream performs
		// current-authority checks at read boundaries, and this final check
		// rejects the entire use before any original result/seal is committed.
		if check(c, a) != nil {
			return kms.ErrPermission
		}
		e := use()
		if e != nil {
			return e
		}
		if check(c, a) != nil {
			return kms.ErrPermission
		}
		return v.checkWorkload(c)
	}}, nil
}

func readVerifierJWT(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, kms.ErrPermission
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 16384 || runtime.GOOS == "linux" && st.Mode().Perm()&0077 != 0 {
		return nil, kms.ErrPermission
	}
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(raw) < 16 || len(raw) > 16384 {
		clear(raw)
		return nil, kms.ErrPermission
	}
	for _, b := range raw {
		if b < 33 || b > 126 {
			clear(raw)
			return nil, kms.ErrPermission
		}
	}
	return raw, nil
}

func (v *ControllerVerifier) login(ctx context.Context) ([]byte, time.Time, time.Time, [32]byte, error) {
	return loginVerifier(ctx, v.client, v.factory.cfg.Binding.Provider.Endpoint, v.factory.cfg.JWTFile, v.capability.record.Facts.Permission, v.factory.cfg.Workload, v.until)
}

// Transport parsing is shared; callers retain their distinct concrete
// capture or publisher authorization before/after every provider boundary.
func loginVerifier(ctx context.Context, client *http.Client, endpoint, jwtFile string, p ProviderCapabilityPermission, wk ControllerVerifierWorkload, until time.Time) ([]byte, time.Time, time.Time, [32]byte, error) {
	deny := func() ([]byte, time.Time, time.Time, [32]byte, error) {
		return nil, time.Time{}, time.Time{}, [32]byte{}, kms.ErrPermission
	}
	jwt, err := readVerifierJWT(jwtFile)
	defer clear(jwt)
	if err != nil {
		return deny()
	}
	jwtHash := sha256.Sum256(jwt)
	body, _ := json.Marshal(map[string]string{"role": p.Role, "jwt": string(jwt)})
	defer clear(body)
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v1/auth/"+p.AuthMount+"/login", bytes.NewReader(body))
	if err != nil {
		return deny()
	}
	req.Header.Set("Content-Type", "application/json")
	started := time.Now()
	res, err := client.Do(req)
	if err != nil {
		return deny()
	}
	defer res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("Content-Encoding") != "" {
		return deny()
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	defer clear(raw)
	if err != nil || len(raw) > 65536 {
		return deny()
	}
	if _, err = jsoncanonicalizer.Transform(raw); err != nil {
		return deny()
	}
	var response struct {
		Errors   []json.RawMessage `json:"errors"`
		WrapInfo json.RawMessage   `json:"wrap_info"`
		Auth     struct {
			Token            string            `json:"client_token"`
			Type             string            `json:"token_type"`
			Renewable        *bool             `json:"renewable"`
			TTL              int64             `json:"lease_duration"`
			Policies         []string          `json:"policies"`
			TokenPolicies    []string          `json:"token_policies"`
			IdentityPolicies []string          `json:"identity_policies"`
			Metadata         map[string]string `json:"metadata"`
		} `json:"auth"`
	}
	if json.Unmarshal(raw, &response) != nil {
		return deny()
	}
	auth := response.Auth
	if len(response.Errors) != 0 || len(response.WrapInfo) != 0 && !bytes.Equal(bytes.TrimSpace(response.WrapInfo), []byte("null")) || auth.Type != "batch" || auth.Renewable == nil || *auth.Renewable || auth.TTL < 1 || auth.TTL > 20 || len(auth.Token) < 16 || len(auth.Token) > 4096 || len(auth.Policies) != 1 || auth.Policies[0] != p.Policy || auth.TokenPolicies != nil && (len(auth.TokenPolicies) != 1 || auth.TokenPolicies[0] != p.Policy) || len(auth.IdentityPolicies) != 0 || auth.Metadata["role"] != p.Role || auth.Metadata["namespace"] != wk.Namespace || auth.Metadata["pod_uid"] != wk.PodUID || auth.Metadata["service_account_uid"] != wk.ServiceAccountUID {
		return deny()
	}
	for _, b := range []byte(auth.Token) {
		if b < 33 || b > 126 {
			return deny()
		}
	}
	expires := started.Add(time.Duration(auth.TTL) * time.Second)
	if expires.After(until) || !time.Now().Before(expires) {
		return deny()
	}
	return []byte(auth.Token), started, expires, jwtHash, nil
}

var _ w.Unwrapper = (*ControllerVerifier)(nil)
var _ kms.Resolver = (*ControllerVerifier)(nil)
