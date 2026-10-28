package systembackupexecution

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"clawreef/internal/systembackup/control"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	c "clawreef/internal/systembackupcontroller"
	api "clawreef/internal/systembackupdeployment"
	d "clawreef/internal/systembackupdispatch"
	"github.com/go-sql-driver/mysql"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

type DeploymentService struct {
	PublisherOwner           string
	publicationGeneration    uint64
	executionUnavailable     atomic.Bool
	ForwardEnabled           bool
	Config                   DeploymentConfig
	Runtime                  *PublicCapture
	Source                   *sql.DB
	ConfigPath, ConfigDigest string
	Forward, Recovery        *c.PinnedExecutionIdentity
	profile                  api.ExecutionProfile
	profileHash              string
	tlsConfig                *tls.Config
	staging                  *os.Root
}

func readPrivate(path string, max int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, c.ErrExecutionAuthority
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > max || (runtime.GOOS == "linux" && st.Mode().Perm()&0077 != 0) {
		return nil, c.ErrExecutionAuthority
	}
	raw, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(raw)) > max {
		return nil, c.ErrExecutionAuthority
	}
	return raw, nil
}
func deploymentIdentity(ref GrantReference, digest, keys string) (*c.PinnedExecutionIdentity, error) {
	public, e := base64.StdEncoding.DecodeString(ref.PublicKey)
	if e != nil || len(public) != ed25519.PublicKeySize {
		return nil, c.ErrExecutionAuthority
	}
	return c.NewPinnedExecutionIdentity(ref.Path, digest, keys, ed25519.PublicKey(public))
}
func NewDeploymentService(ctx context.Context, db *sql.DB, client kubernetes.Interface, dyn dynamic.Interface, path, digest, forwardDigest, recoveryDigest string, forwardEnabled bool) (out *DeploymentService, resultErr error) {
	if runtime.GOOS != "linux" || db == nil || client == nil || dyn == nil {
		return nil, d.ErrNotReady
	}
	cfg, e := LoadDeploymentConfig(path, digest)
	if e != nil {
		return nil, e
	}
	stage := "grant-binding"
	s := &DeploymentService{Config: cfg, ConfigPath: path, ConfigDigest: digest, ForwardEnabled: forwardEnabled}
	defer func() {
		if resultErr != nil {
			resultErr = deploymentFailure{stage, resultErr}
			s.Close()
		}
	}()
	s.Recovery, e = deploymentIdentity(cfg.RecoveryGrant, recoveryDigest, cfg.KeyDirectory)
	if e != nil {
		return nil, e
	}
	if e = s.Recovery.CheckDeployment(ctx, db); e != nil {
		return nil, e
	}
	recoveryActions := s.Recovery.DeploymentBinding().Actions
	if len(recoveryActions) != 1 || recoveryActions[0] != "recover" {
		return nil, c.ErrExecutionAuthority
	}
	s.Forward, e = deploymentIdentity(cfg.ForwardGrant, forwardDigest, cfg.KeyDirectory)
	if e != nil {
		// Only the independent, currently signed recovery grant may reconstruct
		// metadata/key references. It never gains prepare/capture/issuer rights.
		s.Forward = s.Recovery
		s.ForwardEnabled = false
	} else {
		if e = s.Forward.CheckDeployment(ctx, db); e != nil || !forwardCaptureActions(s.Forward.DeploymentBinding()) {
			s.ForwardEnabled = false
		}
	}
	stage = "profile"
	s.profile, e = api.LoadExecutionProfile(cfg.ProfileFile)
	if e != nil {
		return nil, e
	}
	_, s.profileHash, e = s.profile.CanonicalIdentity()
	if e != nil {
		return nil, e
	}
	for _, identity := range []*c.PinnedExecutionIdentity{s.Forward, s.Recovery} {
		grant := identity.DeploymentBinding()
		if grant.DeploymentConfigSHA256 != digest || grant.InstallationID != cfg.InstallationID || grant.ControllerOwner != cfg.ControllerOwner || grant.ProfileSHA256 != s.profileHash || s.profile.InstallationID != cfg.InstallationID {
			return nil, c.ErrExecutionAuthority
		}
	}
	stage = "control-grants"
	if e = s.checkControlGrants(ctx, db); e != nil {
		return nil, e
	}
	stage = "issuer"
	rootRaw, e := os.ReadFile(cfg.IssuerCertificate)
	if e != nil || len(rootRaw) > 65536 {
		return nil, c.ErrExecutionAuthority
	}
	block, _ := pem.Decode(rootRaw)
	if block == nil {
		return nil, c.ErrExecutionAuthority
	}
	root, e := x509.ParseCertificate(block.Bytes)
	issuerPin := cfg.IssuerSHA256
	if issuerPin == "" && s.Forward != s.Recovery {
		issuerPin = s.Forward.DeploymentBinding().WorkerIssuerSHA256
	}
	if e != nil || !root.IsCA || hash(root.Raw) != issuerPin {
		return nil, c.ErrExecutionAuthority
	}
	if s.ForwardEnabled && hash(root.Raw) != s.Forward.DeploymentBinding().WorkerIssuerSHA256 {
		return nil, c.ErrExecutionAuthority
	}
	var signer crypto.Signer
	if s.ForwardEnabled {
		privateRaw, e := readPrivate(cfg.IssuerKey, 16384)
		if e != nil {
			return nil, e
		}
		defer clear(privateRaw)
		block, _ = pem.Decode(privateRaw)
		if block == nil {
			return nil, c.ErrExecutionAuthority
		}
		key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return nil, c.ErrExecutionAuthority
		}
		var ok bool
		signer, ok = key.(crypto.Signer)
		if !ok {
			return nil, c.ErrExecutionAuthority
		}
		publicDER, _ := x509.MarshalPKIXPublicKey(signer.Public())
		wantDER, _ := x509.MarshalPKIXPublicKey(root.PublicKey)
		if !bytes.Equal(publicDER, wantDER) {
			return nil, c.ErrExecutionAuthority
		}
		stage = "control-tls"
		privateServerKey, e := readPrivate(cfg.ServerKey, 16384)
		if e != nil {
			return nil, e
		}
		clear(privateServerKey)
		cert, e := tls.LoadX509KeyPair(cfg.ServerCertificate, cfg.ServerKey)
		if e != nil {
			return nil, c.ErrExecutionAuthority
		}
		server, e := x509.ParseCertificate(cert.Certificate[0])
		if e != nil {
			return nil, c.ErrExecutionAuthority
		}
		endpoint, e := url.Parse(cfg.ControlURL)
		if e != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
			return nil, c.ErrExecutionAuthority
		}
		roots := x509.NewCertPool()
		roots.AddCert(root)
		if _, e = server.Verify(x509.VerifyOptions{Roots: roots, DNSName: endpoint.Hostname(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e != nil {
			return nil, c.ErrExecutionAuthority
		}
		s.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}
		stage = "source-connection"
		dsnRaw, e := readPrivate(cfg.SourceDSNFile, 16384)
		if e != nil {
			return nil, e
		}
		defer clear(dsnRaw)
		sqlCfg, e := mysql.ParseDSN(strings.TrimSpace(string(dsnRaw)))
		if e != nil || sqlCfg.User != cfg.SourceUser || sqlCfg.DBName != cfg.SourceDatabase || sqlCfg.MultiStatements {
			return nil, c.ErrExecutionAuthority
		}
		sqlCfg.ParseTime = true
		sqlCfg.Loc = time.UTC
		sqlCfg.Timeout = 5 * time.Second
		sqlCfg.ReadTimeout = 10 * time.Second
		sqlCfg.WriteTimeout = 10 * time.Second
		if sqlCfg.Params == nil {
			sqlCfg.Params = map[string]string{}
		}
		sqlCfg.Params["time_zone"] = "'+00:00'"
		s.Source, e = sql.Open("mysql", sqlCfg.FormatDSN())
		if e != nil {
			return nil, c.ErrExecutionAuthority
		}
		s.Source.SetMaxOpenConns(4)
		s.Source.SetMaxIdleConns(2)
		if e = s.checkSource(ctx); e != nil {
			return nil, e
		}
	}
	stage = "staging"
	s.staging, e = os.OpenRoot(cfg.StagingDirectory)
	if e != nil {
		return nil, c.ErrExecutionAuthority
	}
	authority := c.SQLExecutionAuthority{DB: db, InstallationID: cfg.InstallationID, ApplicationScope: cfg.ApplicationScope, Authorization: deploymentAuthorization{Service: s}, DeploymentEnabled: true}
	recovery := c.SQLRecoveryAuthority{DB: db, InstallationID: cfg.InstallationID, ApplicationScope: cfg.ApplicationScope, Identity: s.Recovery}
	records := c.SQLExecutionRecords{Authority: authority, Keys: s.Forward, CapacityReportFile: cfg.CapacityFile}
	gate := c.SQLCaptureGate{Authority: authority, Recovery: recovery, Records: records, AcquisitionTimeout: time.Duration(cfg.AcquireSeconds) * time.Second, HoldTimeout: time.Duration(cfg.HoldSeconds) * time.Second}
	owner := &PublicJobOwner{Gate: gate, Client: client, Dynamic: dyn, Namespace: cfg.Namespace, NamespaceUID: cfg.NamespaceUID, TrustDomain: cfg.TrustDomain, Security: cfg.Security, Identity: s.Forward, Issuer: control.IdentityIssuer{Certificate: root, Signer: signer, TrustDomain: cfg.TrustDomain, ServerRoots: rootRaw}, Staging: s.staging, AllowKubeletStopWitness: true}
	source, e := s.platformProfile(owner)
	if e != nil {
		return nil, e
	}
	queue := c.SQLExecutionQueue{DB: db, InstallationID: cfg.InstallationID, Owner: cfg.ControllerOwner, Policy: c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second}, Authorization: deploymentAuthorization{Service: s}, ApplicationScope: cfg.ApplicationScope, Recovery: &recovery}
	stage = "composition"
	s.Runtime, e = NewPublicCapture(PublicCaptureConfig{Owner: owner, Queue: queue, Source: source, Profile: b.ProfileKey{ID: s.profile.Profile, Revision: s.profile.Revision}, Guard: deploymentBaseProbe{Service: s}, Admission: s.admit, RecoveryAdmission: s.recoveryAdmit, Inventory: s.inventory, RecoveryTimeout: 2 * time.Minute})
	if e != nil {
		return nil, e
	}
	s.Runtime.Loop.Store = deploymentStoreTrace{ExecutionWorkStore: s.Runtime.Loop.Store}
	return s, nil
}
func (s *DeploymentService) Close() {
	if s.Source != nil {
		s.Source.Close()
	}
	if s.staging != nil {
		s.staging.Close()
	}
}
func (s *DeploymentService) admit(ctx context.Context, in d.Input) error {
	if e := s.recoveryAdmit(ctx, in); e != nil {
		return e
	}
	return CheckCaptureKubernetesAccess(ctx, s.Runtime.Owner.Client, s.Config)
}
func (s *DeploymentService) recoveryAdmit(_ context.Context, in d.Input) error {
	if supportedPublicCapture(in) != nil || in.ProfileID != s.profile.Profile || in.ProfileRevision != s.profile.Revision || in.Authority.InstallationID != s.Config.InstallationID {
		return d.ErrNotReady
	}
	return nil // Original journal reads/effects still require SQLRecoveryAuthority.
}
func (s *DeploymentService) inventory(_ context.Context, _ d.Input, x b.Discovery) error {
	if len(x.Writers) != len(s.Config.Writers) || len(x.Parts) != 1 || x.Parts[0].Part != "workspace" {
		return d.ErrNotReady
	}
	expected := map[string]bool{}
	for _, w := range s.Config.Writers {
		expected["deployment/"+w.Namespace+"/"+w.Name] = true
	}
	for _, w := range x.Writers {
		if !expected[w.ID] {
			return d.ErrNotReady
		}
		delete(expected, w.ID)
	}
	if len(expected) != 0 {
		return d.ErrNotReady
	}
	return nil
}

var sourceSelect = regexp.MustCompile("^GRANT SELECT ON `([A-Za-z0-9_]+)`\\.`(users|instances)` TO (?:'[^']+'|`[^`]+`)@(?:'[^']+'|`[^`]+`)$")

func (s *DeploymentService) checkSource(ctx context.Context) error {
	var account, role, database, server string
	if s.Source.QueryRowContext(ctx, "SELECT CURRENT_USER(),CURRENT_ROLE(),DATABASE(),@@server_uuid").Scan(&account, &role, &database, &server) != nil || !strings.HasPrefix(account, s.Config.SourceUser+"@") || role != "NONE" || database != s.Config.SourceDatabase || server != s.Config.SourceServerUUID {
		return c.ErrExecutionAuthority
	}
	rows, e := s.Source.QueryContext(ctx, "SHOW GRANTS")
	if e != nil {
		return c.ErrExecutionAuthority
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var grant string
		if rows.Scan(&grant) != nil {
			return c.ErrExecutionAuthority
		}
		if strings.HasPrefix(grant, "GRANT USAGE ON *.* TO ") {
			continue
		}
		m := sourceSelect.FindStringSubmatch(grant)
		if len(m) != 3 || m[1] != database {
			return c.ErrExecutionAuthority
		}
		seen[m[2]] = true
	}
	if rows.Err() != nil || !seen["users"] || !seen["instances"] {
		return c.ErrExecutionAuthority
	}
	return nil
}

type deploymentBaseProbe struct{ Service *DeploymentService }

func (p deploymentBaseProbe) Check(ctx context.Context) error {
	// Recovery stays live when a forward grant/config is revoked. Task-level
	// recovery checks still require its independent current signature and epoch.
	return p.Service.RuntimeBaseReady(ctx)
}
func (s *DeploymentService) RuntimeBaseReady(ctx context.Context) error {
	if e := s.Runtime.Owner.Gate.Ready(ctx); e != nil {
		return e
	}
	return s.Runtime.Owner.namespace(ctx)
}
func (s *DeploymentService) checkControlGrants(ctx context.Context, db *sql.DB) error {
	g := s.Forward.DeploymentBinding()
	if e := (c.SQLPublicCaptureGrantProbe{DB: db, Schema: g.Database, User: strings.Split(g.DatabaseAccount, "@")[0]}).Check(ctx); e != nil {
		return c.ErrExecutionAuthority
	}
	return nil
}
func (s *DeploymentService) PublishReadiness(ctx context.Context) (resultErr error) {
	stage := "forward-enabled"
	defer func() {
		if resultErr != nil {
			resultErr = deploymentFailure{stage, resultErr}
		}
	}()
	if s.executionUnavailable.Load() {
		stage = "execution-recovery"
		var active int
		if s.Runtime.Owner.Gate.Authority.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_backups WHERE origin_installation_id=? AND status IN ('preparing','ready_for_capture','acquiring_gate','capturing','canceling')`, s.Config.InstallationID).Scan(&active) != nil || active != 0 {
			return d.ErrNotReady
		}
		var phase string
		if s.Runtime.Owner.Gate.Authority.DB.QueryRowContext(ctx, "SELECT phase FROM system_backup_gate WHERE scope=?", s.Config.ApplicationScope).Scan(&phase) != nil || phase != "idle" {
			return d.ErrNotReady
		}
		s.executionUnavailable.Store(false)
	}
	if !s.ForwardEnabled {
		return d.ErrNotReady
	}
	stage = "pinned-config"
	if _, e := pinnedDeploymentFile(s.ConfigPath, s.ConfigDigest, 256<<10); e != nil {
		return e
	}
	stage = "forward-grant"
	if e := s.Forward.CheckDeployment(ctx, s.Runtime.Owner.Gate.Authority.DB); e != nil {
		return e
	}
	stage = "control-grants"
	if e := s.checkControlGrants(ctx, s.Runtime.Owner.Gate.Authority.DB); e != nil {
		return e
	}
	stage = "kubernetes-access"
	if e := CheckCaptureKubernetesAccess(ctx, s.Runtime.Owner.Client, s.Config); e != nil {
		return e
	}
	stage = "recovery-grant"
	if e := s.Recovery.CheckDeployment(ctx, s.Runtime.Owner.Gate.Authority.DB); e != nil {
		return e
	}
	stage = "runtime-schema"
	if e := s.RuntimeBaseReady(ctx); e != nil {
		return e
	}
	stage = "source-identity"
	if e := s.checkSource(ctx); e != nil {
		return e
	}
	stage = "source-scope"
	var instances int
	if s.Source.QueryRowContext(ctx, "SELECT COUNT(*) FROM instances").Scan(&instances) != nil || instances != 0 {
		return d.ErrNotReady
	}
	stage = "writer-registry"
	for _, w := range s.Config.Writers {
		if e := s.checkAutoscalers(ctx, w); e != nil {
			return e
		}
	}
	stage = "installation-state"
	grant := s.Forward.DeploymentBinding()
	var version uint64
	var enabled bool
	db := s.Runtime.Owner.Gate.Authority.DB
	if db.QueryRowContext(ctx, "SELECT active_config_version,last_effective_enabled FROM system_backup_v2_installation_state WHERE origin_installation_id=?", s.Config.InstallationID).Scan(&version, &enabled) != nil || !enabled || version != grant.ConfigVersion {
		return d.ErrNotReady
	}
	stage = "publisher-lease"
	lease, e := s.Runtime.Owner.Client.CoordinationV1().Leases(s.Config.Namespace).Get(ctx, "clawmanager-public-backup-controller", metav1.GetOptions{})
	if e != nil || lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity != s.PublisherOwner {
		return c.ErrClaimLost
	}
	stage = "readiness-transaction"
	tx, e := db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var oldOwner string
	var oldGeneration uint64
	e = tx.QueryRowContext(ctx, "SELECT owner,generation FROM system_backup_v2_execution_readiness WHERE origin_installation_id=? AND task_type='backup' FOR UPDATE", s.Config.InstallationID).Scan(&oldOwner, &oldGeneration)
	if e != nil && e != sql.ErrNoRows {
		return e
	}
	generation := s.publicationGeneration
	if generation == 0 {
		if oldGeneration == ^uint64(0) {
			return c.ErrClaimLost
		}
		generation = oldGeneration + 1
	} else if oldOwner != s.PublisherOwner || oldGeneration != generation {
		return c.ErrClaimLost
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO system_backup_v2_execution_readiness(origin_installation_id,task_type,config_version,profile_sha256,owner,generation,ready,checked_at,expires_at,execution_protocol,supported_parts,acceptance_ready) VALUES(?,'backup',?,?,?,?,TRUE,UTC_TIMESTAMP(6),TIMESTAMPADD(SECOND,5,UTC_TIMESTAMP(6)),'public-v1','workspace',FALSE) ON DUPLICATE KEY UPDATE config_version=VALUES(config_version),profile_sha256=VALUES(profile_sha256),owner=VALUES(owner),generation=VALUES(generation),ready=TRUE,checked_at=UTC_TIMESTAMP(6),expires_at=TIMESTAMPADD(SECOND,5,UTC_TIMESTAMP(6)),execution_protocol='public-v1',supported_parts='workspace',acceptance_ready=FALSE`, s.Config.InstallationID, version, s.profileHash, s.PublisherOwner, generation)
	if e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return c.ErrExecutionCommitUnknown
	}
	s.publicationGeneration = generation
	return nil
}
func (s *DeploymentService) Run(ctx context.Context) (resultErr error) {
	if s.PublisherOwner == "" {
		return d.ErrNotReady
	}
	s.publicationGeneration = 0
	active, cancel := context.WithCancel(ctx)
	failures := make(chan error, 2)
	loopDone := make(chan struct{})
	var server *http.Server
	if s.ForwardEnabled {
		listener, e := net.Listen("tcp", s.Config.Listen)
		if e != nil {
			cancel()
			return d.ErrNotReady
		}
		server = &http.Server{Handler: s.Runtime.Control, TLSConfig: s.tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
		go func() {
			e := server.Serve(tls.NewListener(listener, s.tlsConfig))
			if e != http.ErrServerClosed {
				failures <- d.ErrNotReady
			}
		}()
	} else {
		log.Printf("[system-backup-public] mode=recovery-only")
	}
	go func() {
		defer close(loopDone)
		failures <- runDeploymentPasses(active, s.Runtime.Loop.RunOnce, s.Runtime.Loop.Interval, func(e error) {
			if e != nil {
				s.executionUnavailable.Store(true)
			}
		})
	}()
	defer func() {
		cancel()
		if server != nil {
			server.Close()
		}
		select {
		case <-loopDone:
		case <-time.After(125 * time.Second):
			resultErr = c.ErrExecutionRecoveryRequired
		}
	}()
	lastReadiness := ""
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case e := <-failures:
			return e
		case <-ticker.C:
			probe, done := context.WithTimeout(active, 3*time.Second)
			e := s.PublishReadiness(probe)
			done()
			code := "ready"
			if e != nil {
				var failure deploymentFailure
				if errors.As(e, &failure) {
					code = failure.stage
				} else {
					code = "unavailable"
				}
			}
			if code != lastReadiness {
				log.Printf("[system-backup-public] readiness=%s", code)
				lastReadiness = code
			}
		}
	}
}

// Pinned invocation binding construction is shared by all platform workspace jobs.
func (s *DeploymentService) workspaceInvocation(in d.Input, until time.Time) worker.Invocation {
	return worker.Invocation{Request: worker.Request{Version: worker.Version, Operation: "capture-workspace", Binding: staging.Binding{BackupID: in.Authority.TaskPublicID, Attempt: "1", Path: "workspace", PartIndex: 1, CaptureContextHash: in.Authority.ConfigSHA256, EnvelopeID: "functional-workspace"}, Deadline: until, ArtifactName: "workspace.enc", MaxFiles: int64(s.Config.Workspace.MaxFiles), MaxFileBytes: s.Config.Workspace.MaxFileBytes, MaxArchiveBytes: s.Config.Workspace.MaxArchiveBytes, MaxCompressedBytes: s.Config.Workspace.MaxCompressedBytes}, WorkspacePath: "/workspace", StagingPath: "/staging"}
}

type deploymentFailure struct {
	stage string
	cause error
}

func (e deploymentFailure) Error() string { return "public deployment: " + e.stage }
func (e deploymentFailure) Unwrap() error { return e.cause }
