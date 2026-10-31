package systembackupexecution

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"time"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	e "clawreef/internal/systembackupevidence"
	p "clawreef/internal/systembackupproducer"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The same TLS listener serves both protocols. Relay is enabled only by the
// pinned runtime deployment and its explicitly extended database role.
func (s *DeploymentService) controlHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", s.Runtime.Control)
	if s.captureMaterials != nil && s.captureMaterials.ControlEvidence != nil {
		mux.Handle(ControlEvidencePullPath, s.controlEvidenceSourceHandler())
	}
	if s.Config.RuntimeSources != nil {
		o := s.Runtime.Owner
		mux.Handle("/relay", WorkloadIdentity{Client: o.Client, Namespace: o.Namespace, ServiceAccount: o.Security.ServiceAccountName, ServiceAccountUID: o.Security.ServiceAccountUID, Next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session := &deploymentRelayRequest{service: s}
			defer func() {
				if session.peer != nil {
					session.peer.Close()
				}
			}()
			handler, err := b.NewAuthenticatedRelayHandler(b.RelayAuthentication{ResolvePeer: session.resolve, TransactionBudget: 10 * time.Second}, session)
			if err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			handler.ServeHTTP(w, r)
		})})
	}
	return mux
}

// Per-request lifetime: the original owner, not B, closes the authenticator.
// Message fields are lookup hints only. SQL authority, Job binding, original
// identity Secret and certificate pin are all read independently below.
type deploymentRelayRequest struct {
	service  *DeploymentService
	peer     *e.RelayPeerAuthenticator
	acceptor *c.SQLAuthenticatedRelayAcceptor
}

func (r *deploymentRelayRequest) AcceptAuthenticatedRelay(ctx context.Context, relay *b.AuthenticatedRelay) (b.RelayDecision, error) {
	if r.acceptor == nil || r.peer == nil {
		return "", c.ErrExecutionAuthority
	}
	return r.acceptor.AcceptAuthenticatedRelay(ctx, relay)
}
func (r *deploymentRelayRequest) resolve(ctx context.Context, m b.RelayMessage) (*e.RelayPeerAuthenticator, error) {
	if r.peer != nil || r.service == nil || r.service.Runtime == nil {
		return nil, c.ErrExecutionAuthority
	}
	s := r.service
	o := s.Runtime.Owner
	pod, ok := boundPod(ctx)
	if !ok || pod.Namespace != o.Namespace || pod.ServiceAccountUID != o.Security.ServiceAccountUID || m.InstallationID != s.Config.InstallationID || m.TaskType != "backup" || m.Phase != "capture" {
		return nil, c.ErrExecutionAuthority
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	a := d.Authority{InstallationID: s.Config.InstallationID, TaskPublicID: m.TaskPublicID, TaskType: "backup", Phase: "capture", MaintenanceOwner: m.TaskPublicID}
	db := o.Gate.Authority.DB
	if db.QueryRowContext(ctx, `SELECT controller_owner,row_version,request_id,config_version,config_snapshot_sha256,deadline_at,maintenance_fencing_token,(SELECT MAX(attempt_no) FROM system_backup_v2_attempts WHERE target_type='backup' AND target_public_id=b.public_id AND phase='capture') FROM system_backup_v2_backups b WHERE public_id=? AND origin_installation_id=?`, a.TaskPublicID, a.InstallationID).Scan(&a.ClaimOwner, &a.ClaimRowVersion, &a.RequestID, &a.ConfigVersion, &a.ConfigSHA256, &a.DeadlineAt, &a.MaintenanceFencingToken, &a.AttemptNo) != nil {
		return nil, c.ErrExecutionAuthority
	}
	_, _, desc, err := o.input(ctx, a, false)
	if err != nil {
		return nil, err
	}
	part, err := partFor(desc, m.JobUnitKey)
	if err != nil {
		return nil, err
	}
	var raw, processRaw []byte
	var revoked bool
	if db.QueryRowContext(ctx, `SELECT binding_json,process_json,revoked FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND attempt_no=? AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND lifecycle='ready' AND create_dispatched=TRUE`, a.TaskPublicID, a.AttemptNo, part.Intent.Namespace, part.Intent.Name).Scan(&raw, &processRaw, &revoked) != nil || revoked {
		return nil, c.ErrExecutionAuthority
	}
	var binding d.JobBinding
	var originalProcess kube.WorkerProcess
	if json.Unmarshal(raw, &binding) != nil || json.Unmarshal(processRaw, &originalProcess) != nil || originalProcess.UID == "" {
		return nil, c.ErrExecutionRecord
	}
	_, record, err := o.Read(ctx, a, binding, false)
	if err != nil {
		return nil, err
	}
	security, err := o.workerSecurity(ctx, a, part)
	if err != nil {
		return nil, err
	}
	process, err := (kube.WorkerObserver{Client: o.Client}).Observe(ctx, record, security)
	if err != nil || !kube.SameWorkerProcess(process, originalProcess) || process.Name != pod.Name || process.UID != pod.UID {
		return nil, c.ErrExecutionAuthority
	}
	var job batchv1.Job
	if json.Unmarshal(part.Intent.SpecJSON, &job) != nil {
		return nil, c.ErrExecutionRecord
	}
	secretName := ""
	for _, volume := range job.Spec.Template.Spec.Volumes {
		if volume.Name == "worker-identity" && volume.Secret != nil {
			secretName = volume.Secret.SecretName
		}
	}
	if secretName == "" {
		return nil, c.ErrExecutionRecord
	}
	secret, err := o.Client.CoreV1().Secrets(o.Namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil || secret.Immutable == nil || !*secret.Immutable || secret.DeletionTimestamp != nil {
		return nil, c.ErrExecutionAuthority
	}
	var uid, digest string
	var original []byte
	if db.QueryRowContext(ctx, `SELECT observed_uid,request_sha256,request_json FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND resource_kind='IdentitySecret' AND namespace_name=? AND resource_name=? AND create_dispatched=TRUE AND lifecycle='ready'`, a.TaskPublicID, o.Namespace, secretName).Scan(&uid, &digest, &original) != nil || !originalIdentitySecretMatches(secret, uid, digest, original, part.InvocationSHA256) {
		return nil, c.ErrExecutionRecord
	}
	block, _ := pem.Decode(secret.Data["tls.crt"])
	if block == nil {
		return nil, c.ErrExecutionRecord
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	subject := "spiffe://" + o.TrustDomain + "/backup/" + a.TaskPublicID + "/" + part.InvocationSHA256
	if err != nil || len(cert.URIs) != 1 || cert.URIs[0].String() != subject || binding.RelayIdentityRef != uid || binding.RelayIdentityVersion != hash(cert.Raw) || binding.RelayExpiresAt.After(cert.NotAfter) {
		return nil, c.ErrExecutionAuthority
	}
	grant := s.Forward.DeploymentBinding()
	scope := p.Scope{ServerUUID: p.ServerUUID(grant.ServerUUID), Database: p.Database(grant.Database), Installation: p.Installation(a.InstallationID)}
	peer, err := e.NewRelayPeerAuthenticator(e.RelayPeerConfig{Peer: e.SystemPeerConfig{Scope: scope, IssuerIdentityHash: hash(o.Issuer.Certificate.Raw), Subject: subject, ClientCAPEM: o.Issuer.ServerRoots, ClientCASHA256: hash(o.Issuer.ServerRoots), CertificateSHA256: hash(cert.Raw), ExpiresAt: binding.RelayExpiresAt}, Binding: e.RelayJobBinding{Scope: scope, ConfigVersion: int64(a.ConfigVersion), ConfigSHA256: a.ConfigSHA256, TargetType: a.TaskType, TargetPublicID: a.TaskPublicID, AttemptNo: int64(a.AttemptNo), Phase: a.Phase, JobUnitKey: binding.JobUnitKey, JobUID: binding.UID, JobGeneration: int64(binding.Generation), RelayIdentityRef: binding.RelayIdentityRef, RelayIdentityVersion: binding.RelayIdentityVersion, RelayIdentityBoundAt: binding.RelayBoundAt, RelayIdentityExpiresAt: binding.RelayExpiresAt}})
	if err != nil {
		return nil, err
	}
	r.peer = peer
	r.acceptor = &c.SQLAuthenticatedRelayAcceptor{Authority: o.Gate.Authority, Current: a, Scope: scope}
	return peer, nil
}
