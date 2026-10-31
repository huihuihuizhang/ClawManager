package systembackupkekadapter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
	security "clawreef/internal/systembackupsecurity"
	w "clawreef/internal/systembackupwire"
	"k8s.io/client-go/kubernetes"
)

// Independent publisher permission, never a capture execution authority. The
// caller supplies no KeyRequest, Invocation, candidate hash or decryption hook.
type PublisherVerifierConfig struct {
	Capabilities       *SQLProviderCapabilityPreparation
	Binding            reg.Binding
	CAPEM              []byte
	JWTFile            string
	InstallationIssuer ed25519.PublicKey
	Workload           ControllerVerifierWorkload
	KubernetesReads    VerifierKubernetesReads
	Kubernetes         kubernetes.Interface
	Authority          security.PublisherCaptureAuthorityConfig
	Records            c.SQLExecutionRecords
}

type PublisherVerifierFactory struct{ cfg PublisherVerifierConfig }

func publisherVerifierFailure(stage string) error {
	return fmt.Errorf("publisher verifier %s: %w", stage, kms.ErrPermission)
}

func NewPublisherVerifierFactory(cfg PublisherVerifierConfig) (*PublisherVerifierFactory, error) {
	keys, ok := cfg.Records.Keys.(*c.PinnedExecutionIdentity)
	_, custody := cfg.Records.Authority.Authorization.(c.PublisherCaptureCustodyBinding)
	_, verifierDeployment := cfg.Records.Authority.Authorization.(c.PublisherVerifierDeploymentBinding)
	_, bare := cfg.Records.Authority.Authorization.(*c.PinnedExecutionIdentity)
	d, actor, wk := cfg.Authority.Deployment, cfg.Authority.Workload, cfg.Workload
	if cfg.Capabilities == nil || cfg.Authority.DB == nil || cfg.Capabilities.db != cfg.Authority.DB || cfg.Records.Authority.DB != cfg.Authority.DB || cfg.Records.Authority.InstallationID != d.InstallationID || !cfg.Records.Authority.DeploymentEnabled || !custody || !verifierDeployment || bare || !ok || keys == nil || keys.GrantSHA256() != d.CaptureGrantSHA256 || cfg.Capabilities.installation != d.InstallationID || cfg.Binding.InstallationID != d.InstallationID || cfg.Capabilities.database != (reg.DatabaseIdentity{ServerUUID: d.ServerUUID, Database: d.Database}) || nilSource(cfg.Kubernetes) || nilSource(cfg.Authority.Kubernetes) || cfg.KubernetesReads.Validate(wk) != nil || cfg.KubernetesReads.NamespaceUID != actor.NamespaceUID || wk.Namespace != actor.Namespace || wk.PodName != actor.PodName || wk.PodUID != actor.PodUID || wk.ServiceAccountName != actor.ServiceAccountName || wk.ServiceAccountUID != actor.ServiceAccountUID || wk.ControllerOwner != actor.PublisherOwner || wk.GrantSHA256 != actor.GrantSHA256 || wk.ConfigVersion != d.ConfigVersion || wk.ConfigSHA256 != d.ConfigSHA256 || !filepath.IsAbs(cfg.JWTFile) || len(cfg.InstallationIssuer) != ed25519.PublicKeySize || len(cfg.CAPEM) == 0 || len(cfg.CAPEM) > 65536 {
		return nil, kms.ErrPermission
	}
	sum := sha256.Sum256(cfg.CAPEM)
	if hex.EncodeToString(sum[:]) != cfg.Binding.Provider.CAPEMSHA256 {
		return nil, kms.ErrPermission
	}
	// Validate the SAME transport contract at startup as actual Unwrap uses,
	// including exact key version, HTTPS endpoint and a parseable pinned CA.
	// Construct/close performs no RPC and needs no task or KeyRequest.
	probe, err := kms.NewRecoveryUnwrapper(kms.Config{Endpoint: cfg.Binding.Provider.Endpoint, InstallationID: cfg.Binding.InstallationID, KeyName: cfg.Binding.Provider.KeyName, Key: cfg.Binding.Key, CAPEM: cfg.CAPEM, CASHA256: cfg.Binding.Provider.CAPEMSHA256, NotBefore: d.NotBefore, NotAfter: d.Until}, publisherVerifierResolver{})
	if err != nil {
		return nil, kms.ErrPermission
	}
	probe.Close()
	cfg.CAPEM = bytes.Clone(cfg.CAPEM)
	cfg.InstallationIssuer = bytes.Clone(cfg.InstallationIssuer)
	cfg.Authority.GrantMount.Issuer = bytes.Clone(cfg.Authority.GrantMount.Issuer)
	cfg.Binding.GenerateRef.RawJSON = bytes.Clone(cfg.Binding.GenerateRef.RawJSON)
	cfg.Binding.UnwrapRef.RawJSON = bytes.Clone(cfg.Binding.UnwrapRef.RawJSON)
	return &PublisherVerifierFactory{cfg: cfg}, nil
}

// CheckDeployment does not authenticate any task or perform provider I/O.
// Startup checks all independent original sources, exact real owner mapping,
// private projected JWT and original SQL peer before exposing the factory.
func (f *PublisherVerifierFactory) CheckDeployment(ctx context.Context) error {
	if f == nil || nilSource(ctx) || ctx.Err() != nil {
		return kms.ErrPermission
	}
	cfg := f.cfg
	if cfg.Records.Authority.Authorization.(c.PublisherVerifierDeploymentBinding).CheckPublisherVerifierDeployment(ctx, cfg.Authority.Deployment) != nil || cfg.KubernetesReads.Check(ctx, cfg.Kubernetes, cfg.Workload) != nil || security.CheckPublisherCaptureDeploymentWorkload(ctx, cfg.Authority) != nil {
		return kms.ErrPermission
	}
	jwt, err := readVerifierJWT(cfg.JWTFile)
	clear(jwt)
	if err != nil {
		return kms.ErrPermission
	}
	if cfg.Records.Keys.(*c.PinnedExecutionIdentity).CheckDeployment(ctx, cfg.Authority.DB) != nil {
		return kms.ErrPermission
	}
	capability, err := cfg.Capabilities.prepareOperation(ctx, cfg.Binding, kms.Unwrap)
	if err != nil || capability.record.Facts.Permission.ControllerVerifier == nil || *capability.record.Facts.Permission.ControllerVerifier != cfg.Workload {
		return kms.ErrPermission
	}
	tx, err := cfg.Authority.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return kms.ErrPermission
	}
	defer tx.Rollback()
	var account, server, database string
	var now time.Time
	d := cfg.Authority.Deployment
	if tx.QueryRowContext(ctx, "SELECT CURRENT_USER(),@@server_uuid,DATABASE(),UTC_TIMESTAMP(6)").Scan(&account, &server, &database, &now) != nil || account != d.DatabaseAccount || server != d.ServerUUID || database != d.Database || now.Before(d.NotBefore) || !now.Before(d.Until) {
		return kms.ErrPermission
	}
	kek, locked, err := (reg.SQLStore{}).Bind(ctx, tx, cfg.Binding.InstallationID)
	if err != nil || locked.Facts().Database != cfg.Capabilities.database || kek.RequireUnrevoked(cfg.Binding.ConfigRef, reg.UnwrapRevocation) != nil {
		return kms.ErrPermission
	}
	found := false
	for _, fact := range locked.Facts().Bindings {
		if fact.Binding.ConfigRef == cfg.Binding.ConfigRef && reg.SameSecurityBinding(fact.Binding, cfg.Binding) {
			found = true
		}
	}
	if !found {
		return kms.ErrPermission
	}
	original, err := currentVerifierOriginalMapping(ctx, tx, cfg.Binding, cfg.InstallationIssuer, now, true)
	if err != nil || !now.Before(original.Until) || capability.Recheck(ctx, tx, locked, now) != nil {
		return kms.ErrPermission
	}
	grant, err := security.CheckPublisherCaptureDeploymentGrant(ctx, cfg.Authority)
	if err != nil || now.Before(grant.NotBefore) || !now.Before(grant.Until) {
		return kms.ErrPermission
	}
	return tx.Rollback()
}

// ForPart accepts only the real current publisher scope. The concrete Records
// reader authenticates original sealed plan/result/candidate/finished-use/Job.
func (f *PublisherVerifierFactory) ForPart(ctx context.Context, scope security.PublisherCaptureScope) (*PublisherVerifier, error) {
	if f == nil || nilSource(ctx) || ctx.Err() != nil {
		return nil, kms.ErrPermission
	}
	access, err := security.NewSQLPublisherCaptureAuthority(ctx, f.cfg.Authority, scope)
	if err != nil {
		return nil, publisherVerifierFailure("current authority")
	}
	record, err := f.cfg.Records.LoadPublisherCapture(ctx, access)
	if err != nil || record.Invocation.ProviderKey == nil || record.Invocation.FormalCapture == nil {
		return nil, publisherVerifierFailure("original history")
	}
	request := record.Invocation.ProviderKey.Request
	if request.Key != f.cfg.Binding.Key || record.Invocation.ProviderKey.Endpoint != f.cfg.Binding.Provider.Endpoint || record.Invocation.ProviderKey.KeyName != f.cfg.Binding.Provider.KeyName || record.Invocation.ProviderKey.Operation != kms.Generate || request.Context.InstallationID != f.cfg.Binding.InstallationID || request.Context.BackupPublicID != scope.BackupPublicID || request.Context.AttemptNo != strconv.FormatUint(scope.CaptureAttemptNo, 10) || request.Context.Phase != "capture" {
		return nil, publisherVerifierFailure("original request")
	}
	if _, err = kms.TransitContext(request); err != nil {
		return nil, publisherVerifierFailure("transit context")
	}
	capability, err := f.cfg.Capabilities.prepareOperation(ctx, f.cfg.Binding, kms.Unwrap)
	if err != nil || capability.record.Facts.Permission.ControllerVerifier == nil || *capability.record.Facts.Permission.ControllerVerifier != f.cfg.Workload {
		return nil, publisherVerifierFailure("unwrap capability")
	}
	original, err := currentVerifierOriginalMapping(ctx, f.cfg.Authority.DB, f.cfg.Binding, f.cfg.InstallationIssuer, time.Now(), false)
	if err != nil {
		return nil, publisherVerifierFailure("original mapping")
	}
	until := access.ValidUntil()
	for _, bound := range []time.Time{record.ValidUntil, capability.ValidUntil(), original.Until} {
		if bound.Before(until) {
			until = bound
		}
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(f.cfg.CAPEM) {
		return nil, kms.ErrPermission
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 16384, DisableCompression: true}, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	v := &PublisherVerifier{factory: f, access: access, history: record, request: request, capability: capability, until: until, client: client, historyHash: publisherVerifierHistoryHash(record)}
	if v.historyHash == "" {
		v.Close()
		return nil, publisherVerifierFailure("history digest")
	}
	if err = v.Recheck(ctx); err != nil {
		v.Close()
		return nil, fmt.Errorf("publisher verifier original transaction: %w", err)
	}
	v.unwrap, err = kms.NewRecoveryUnwrapper(kms.Config{Endpoint: f.cfg.Binding.Provider.Endpoint, InstallationID: f.cfg.Binding.InstallationID, KeyName: f.cfg.Binding.Provider.KeyName, Key: f.cfg.Binding.Key, CAPEM: f.cfg.CAPEM, CASHA256: f.cfg.Binding.Provider.CAPEMSHA256, NotBefore: capability.NotBefore(), NotAfter: until}, publisherVerifierResolver{v})
	if err != nil {
		v.Close()
		return nil, kms.ErrPermission
	}
	return v, nil
}

type PublisherVerifier struct {
	factory         *PublisherVerifierFactory
	access          *security.SQLPublisherCaptureAuthority
	history         c.PublisherCaptureRecord
	historyHash     string
	request         w.KeyRequest
	capability      *sqlPreparedCapability
	until           time.Time
	client          *http.Client
	unwrap          *kms.RecoveryUnwrapper
	callMu, checkMu sync.Mutex
}

func (v *PublisherVerifier) ValidUntil() time.Time {
	if v == nil {
		return time.Time{}
	}
	return v.until
}
func (v *PublisherVerifier) Close() {
	if v != nil {
		if v.client != nil {
			v.client.CloseIdleConnections()
		}
		if v.unwrap != nil {
			v.unwrap.Close()
		}
	}
}
func (v *PublisherVerifier) ExpectedRequest() w.KeyRequest {
	if v == nil {
		return w.KeyRequest{}
	}
	return v.request
}

func publisherVerifierHistoryHash(record c.PublisherCaptureRecord) string {
	raw, err := json.Marshal(record)
	if err != nil {
		return ""
	}
	defer clear(raw)
	digest := sha256.New()
	for _, part := range [][]byte{[]byte("system-backup-publisher-verifier-history.v1\x00"), raw, record.Input.ConfigSnapshot, record.Input.SourceSnapshot, record.Plan.CanonicalJSON, record.CandidateJSON, record.PartResult.Checkpoint} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		digest.Write(size[:])
		digest.Write(part)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func (v *PublisherVerifier) checkExternal(ctx context.Context) error {
	if v == nil || nilSource(ctx) || ctx.Err() != nil || !time.Now().Before(v.until) {
		return kms.ErrPermission
	}
	cfg := v.factory.cfg
	if cfg.Records.Authority.Authorization.(c.PublisherVerifierDeploymentBinding).CheckPublisherVerifierDeployment(ctx, v.access.Deployment()) != nil {
		return publisherVerifierFailure("deployment binding")
	}
	if cfg.KubernetesReads.Check(ctx, cfg.Kubernetes, cfg.Workload) != nil {
		return kms.ErrPermission
	}
	current, err := cfg.Records.LoadPublisherCapture(ctx, v.access)
	if err != nil || publisherVerifierHistoryHash(current) != v.historyHash {
		return kms.ErrPermission
	}
	// Final external/material reads must precede the concrete authority's final
	// same-claim SQL check (including the last-workload-I/O race protection).
	if v.access.Check(ctx) != nil {
		return kms.ErrPermission
	}
	return nil
}

type publisherVerifierSession struct {
	ctx      context.Context
	tx       *sql.Tx
	guard    *security.SQLPublisherCaptureGuard
	kek      *reg.Bound
	locked   reg.LockedSnapshot
	verifier *PublisherVerifier
}

func (v *PublisherVerifier) begin(ctx context.Context) (*publisherVerifierSession, error) {
	if err := v.checkExternal(ctx); err != nil {
		return nil, err
	}
	tx, err := v.factory.cfg.Authority.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, kms.ErrPermission
	}
	fail := func(stage string) (*publisherVerifierSession, error) {
		tx.Rollback()
		return nil, publisherVerifierFailure(stage)
	}
	guard, err := v.access.Bind(ctx, tx)
	if err != nil {
		return fail("transaction claim")
	}
	if v.history.RecheckTx(ctx, tx, v.access) != nil {
		return fail("transaction receipt")
	}
	cfg := v.factory.cfg
	kek, locked, err := (reg.SQLStore{}).Bind(ctx, tx, cfg.Binding.InstallationID)
	if err != nil || locked.Facts().Database != cfg.Capabilities.database || kek.RequireUnrevoked(cfg.Binding.ConfigRef, reg.UnwrapRevocation) != nil {
		return fail("transaction KEK fence")
	}
	found := false
	for _, fact := range locked.Facts().Bindings {
		if fact.Binding.ConfigRef == cfg.Binding.ConfigRef && reg.SameSecurityBinding(fact.Binding, cfg.Binding) {
			found = true
		}
	}
	if !found {
		return fail("transaction KEK binding")
	}
	session := &publisherVerifierSession{ctx: ctx, tx: tx, guard: guard, kek: kek, locked: locked, verifier: v}
	if session.check(ctx) != nil {
		return fail("transaction source recheck")
	}
	return session, nil
}

func (s *publisherVerifierSession) check(ctx context.Context) error {
	if s == nil || nilSource(ctx) || ctx.Err() != nil || s.ctx.Err() != nil || !time.Now().Before(s.verifier.until) {
		return kms.ErrPermission
	}
	v := s.verifier
	cfg := v.factory.cfg
	if cfg.Records.Authority.Authorization.(c.PublisherVerifierDeploymentBinding).CheckPublisherVerifierDeployment(ctx, v.access.Deployment()) != nil {
		return publisherVerifierFailure("deployment binding")
	}
	var now time.Time
	if s.tx.QueryRowContext(s.ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !now.Before(v.until) || s.guard.RecheckTx(s.ctx, s.tx) != nil || v.history.RecheckTx(s.ctx, s.tx, v.access) != nil || v.capability.Recheck(s.ctx, s.tx, s.locked, now) != nil || s.kek.RequireUnrevoked(cfg.Binding.ConfigRef, reg.UnwrapRevocation) != nil {
		return kms.ErrPermission
	}
	original, err := currentVerifierOriginalMapping(s.ctx, s.tx, cfg.Binding, cfg.InstallationIssuer, now, true)
	if err != nil || original.Until.Before(v.until) {
		return kms.ErrPermission
	}
	return nil
}

func (v *PublisherVerifier) Recheck(ctx context.Context) error {
	if v == nil {
		return kms.ErrPermission
	}
	// Cipher and plaintext pipe readers run concurrently. Serialize each full
	// external-read/short-SQL check so neither starts workload I/O while the
	// other's original metadata snapshot is locked.
	v.checkMu.Lock()
	defer v.checkMu.Unlock()
	session, err := v.begin(ctx)
	if err != nil {
		return err
	}
	return session.tx.Rollback()
}

// ForEnvelope authenticates the bytes against the ORIGINAL sealed candidate
// receipt before exposing an Unwrapper. An arbitrary wrapped ciphertext with
// even the same KeyRequest cannot be substituted at the provider boundary.
func (v *PublisherVerifier) ForEnvelope(ctx context.Context, raw []byte) (*PublisherEnvelopeVerifier, error) {
	if v == nil || v.Recheck(ctx) != nil || len(raw) == 0 || len(raw) > 32<<20 {
		return nil, kms.ErrPermission
	}
	var candidate struct {
		Candidate worker.FormalCaptureResult `json:"candidate"`
	}
	sum := sha256.Sum256(raw)
	if json.Unmarshal(v.history.CandidateJSON, &candidate) != nil || !worker.ValidateFormalCaptureResult(v.history.Invocation, &candidate.Candidate) || candidate.Candidate.Envelope.Size != int64(len(raw)) || candidate.Candidate.Envelope.SHA256 != hex.EncodeToString(sum[:]) {
		return nil, kms.ErrPermission
	}
	i := v.history.Invocation
	if _, err := w.ParseStreamEnvelope(w.StreamSpec{Request: v.request, Path: i.Request.ArtifactName, MaxPlaintextBytes: i.Request.MaxCompressedBytes, MaxFrames: i.FormalCapture.MaxFrames}, raw); err != nil {
		return nil, kms.ErrPermission
	}
	var envelope struct {
		Entries []struct {
			Algorithm string `json:"wrap_algorithm"`
			Cipher    string `json:"wrapped_dek"`
		} `json:"entries"`
	}
	if json.Unmarshal(raw, &envelope) != nil || len(envelope.Entries) != 1 {
		return nil, kms.ErrPermission
	}
	cipher, err := base64.RawURLEncoding.Strict().DecodeString(envelope.Entries[0].Cipher)
	if err != nil {
		return nil, kms.ErrPermission
	}
	return &PublisherEnvelopeVerifier{parent: v, wrapped: w.WrappedKey{Request: v.request, Algorithm: envelope.Entries[0].Algorithm, Ciphertext: cipher}}, nil
}

func (v *PublisherVerifier) WithDEK(ctx context.Context, envelope []byte, use w.WithDEK) error {
	bound, err := v.ForEnvelope(ctx, envelope)
	if err != nil {
		return err
	}
	return bound.Unwrap(ctx, v.request, bound.wrapped, use)
}

type PublisherEnvelopeVerifier struct {
	parent  *PublisherVerifier
	wrapped w.WrappedKey
}

func (v *PublisherEnvelopeVerifier) ValidUntil() time.Time {
	if v == nil {
		return time.Time{}
	}
	return v.parent.ValidUntil()
}
func (v *PublisherEnvelopeVerifier) Recheck(ctx context.Context) error {
	if v == nil {
		return kms.ErrPermission
	}
	return v.parent.Recheck(ctx)
}

// The complete C and plaintext readers check original current authority around
// each bounded read. No DEK, claim, provider credential or deadline is renewed.
func (v *PublisherEnvelopeVerifier) RecheckStream(ctx context.Context) error { return v.Recheck(ctx) }
func (v *PublisherEnvelopeVerifier) Unwrap(ctx context.Context, expected w.KeyRequest, wrapped w.WrappedKey, use w.WithDEK) error {
	if v == nil || v.parent == nil || v.parent.unwrap == nil || nilSource(ctx) || ctx.Err() != nil || use == nil || expected != v.wrapped.Request || wrapped.Request != v.wrapped.Request || wrapped.Algorithm != v.wrapped.Algorithm || !bytes.Equal(wrapped.Ciphertext, v.wrapped.Ciphertext) {
		return kms.ErrPermission
	}
	parent := v.parent
	ctx, cancel := context.WithDeadline(ctx, parent.until)
	defer cancel()
	parent.callMu.Lock()
	defer parent.callMu.Unlock()
	return parent.unwrap.Unwrap(ctx, expected, wrapped, use)
}

type publisherVerifierResolver struct{ v *PublisherVerifier }

func (r publisherVerifierResolver) Resolve(ctx context.Context, access kms.Access) (kms.Grant, error) {
	v := r.v
	cfg := v.factory.cfg
	if access != (kms.Access{Request: v.request, Operation: kms.Unwrap, Endpoint: cfg.Binding.Provider.Endpoint, KeyName: cfg.Binding.Provider.KeyName}) || v.Recheck(ctx) != nil {
		return kms.Grant{}, kms.ErrPermission
	}
	secret, start, expires, jwtHash, err := loginVerifier(ctx, v.client, cfg.Binding.Provider.Endpoint, cfg.JWTFile, v.capability.record.Facts.Permission, cfg.Workload, v.until)
	if err != nil {
		return kms.Grant{}, kms.ErrPermission
	}
	check := func(c context.Context, a kms.Access) error {
		if a != access || v.Recheck(c) != nil {
			return kms.ErrPermission
		}
		jwt, err := readVerifierJWT(cfg.JWTFile)
		defer clear(jwt)
		if err != nil || sha256.Sum256(jwt) != jwtHash {
			return kms.ErrPermission
		}
		return nil
	}
	if check(ctx, access) != nil {
		clear(secret)
		return kms.Grant{}, kms.ErrPermission
	}
	return kms.Grant{Access: access, Secret: secret, NotBefore: start, ExpiresAt: v.until, CredentialExpiresAt: expires, Recheck: check, WithUse: func(c context.Context, a kms.Access, use func() error) error {
		if nilSource(c) || c.Err() != nil || a != access || use == nil {
			return kms.ErrPermission
		}
		c, cancel := context.WithDeadline(c, v.until)
		defer cancel()
		// Each check opens and closes the SAME original authority/KEK snapshot.
		// Holding it during remote C body reads blocks actual claim withdrawal
		// and makes revocation invisible. Read boundaries plus this final full
		// check reject the entire callback before any observation is committed.
		if check(c, a) != nil {
			return kms.ErrPermission
		}
		if err := use(); err != nil {
			return err
		}
		if check(c, a) != nil {
			return kms.ErrPermission
		}
		return v.access.Check(c)
	}}, nil
}

var _ w.Unwrapper = (*PublisherEnvelopeVerifier)(nil)
var _ w.StreamReadAuthority = (*PublisherEnvelopeVerifier)(nil)
var _ kms.Resolver = publisherVerifierResolver{}
