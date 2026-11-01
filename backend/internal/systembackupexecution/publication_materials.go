package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
	"github.com/google/uuid"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Immutable original evidence contains hashes/coordinates only. Native Secret
// data is the durable private boundary; grants and TLS private keys never enter
// SQL, evidence bodies, job specifications, annotations or logs.
type publicationMaterialIntent struct {
	Version                                                      string `json:"schema_version"`
	Installation, Backup                                         string
	Attempt                                                      uint64
	Namespace, Name, BodySHA256, RequestSHA256, CredentialSHA256 string
	CandidateResource, CandidateOwnerMAC                         string
	Claim                                                        c.ClaimToken
	Deadline                                                     time.Time
}
type publicationMaterialObservation struct {
	Version, IntentSHA256, SecretUID string
}
type publicationJobMaterials struct {
	request PublicationUploadRequest
	secret  *corev1.Secret
	intent  publicationMaterialIntent
}

func (publicationJobMaterials) String() string               { return "publication Job materials [redacted]" }
func (publicationJobMaterials) GoString() string             { return "publication Job materials [redacted]" }
func (publicationJobMaterials) MarshalJSON() ([]byte, error) { return nil, c.ErrExecutionRecord }
func (m *publicationJobMaterials) Close() {
	if m == nil {
		return
	}
	if m.secret != nil {
		for _, data := range m.secret.Data {
			clear(data)
		}
		m.secret.Data = nil
		m.secret = nil
	}
	clear(m.request.ManifestInput)
	clear(m.request.IndexBytes)
	clear(m.request.CaptureCertificate)
	clear(m.request.CaptureBootstrap)
	m.request = PublicationUploadRequest{}
}
func publicationMaterialID(installation, backup string, attempt uint64) string {
	raw, _ := ce.Canonical([]any{"original-publication-private-materials.v1", installation, backup, attempt})
	return "sev_pub_material_" + hash(raw)
}

func publicationPreparationOpenTx(ctx context.Context, tx *sql.Tx, installation, backup string) error {
	var open bool
	if tx.QueryRowContext(ctx, `SELECT status IN ('validating','publishing') AND can_cancel=TRUE AND commit_started_at IS NULL FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=?`, installation, backup).Scan(&open) != nil || !open {
		return c.ErrExecutionAuthority
	}
	return nil
}
func publicationMaterialBody(secret *corev1.Secret) ([]byte, error) {
	if secret == nil || secret.Immutable == nil || !*secret.Immutable || secret.Type != corev1.SecretTypeOpaque || len(secret.StringData) != 0 || len(secret.Data) != 6 {
		return nil, c.ErrExecutionRecord
	}
	for _, key := range []string{"request.json", "credential.json", "artifact-ca.crt", "ca.crt", "tls.crt", "tls.key"} {
		if len(secret.Data[key]) == 0 {
			return nil, c.ErrExecutionRecord
		}
	}
	// UID/resourceVersion/managedFields and later Job owner references are native
	// metadata. Every private/public byte, name and original ownership marker is
	// frozen here; owner references are separately checked against original 121.
	raw, err := json.Marshal(struct {
		Namespace, Name     string
		Labels, Annotations map[string]string
		Data                map[string][]byte
	}{secret.Namespace, secret.Name, secret.Labels, secret.Annotations, secret.Data})
	if err != nil || len(raw) > 900<<10 {
		clear(raw)
		return nil, c.ErrExecutionRecord
	}
	return raw, nil
}

func (s *DeploymentService) loadPublicationMaterialIntent(ctx context.Context, claim c.ClaimToken, attempt uint64) (publicationMaterialIntent, error) {
	var zero publicationMaterialIntent
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	guard, err := access.Bind(ctx, tx)
	if err != nil {
		return zero, err
	}
	raw, err := loadPublicationMetadata(ctx, tx, claim.Target.PublicID, publicationMaterialID(s.Config.InstallationID, claim.Target.PublicID, attempt))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if err := publicationPreparationOpenTx(ctx, tx, s.Config.InstallationID, claim.Target.PublicID); err != nil {
				return zero, err
			}
			var sends int
			if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_job_send_intents WHERE origin_installation_id=? AND task_public_id=? AND phase='publish'`, s.Config.InstallationID, claim.Target.PublicID).Scan(&sends) != nil || sends != 0 {
				return zero, c.ErrExecutionRecord
			}
		}
		return zero, err
	}
	var intent publicationMaterialIntent
	if decodeProviderDeploymentJSON(raw, &intent) != nil || intent.Version != "system-backup-original-publication-materials.v1" || intent.Installation != s.Config.InstallationID || intent.Backup != claim.Target.PublicID || intent.Attempt != attempt || intent.Namespace != s.Config.Namespace || !formalCandidateDigest(intent.BodySHA256) || !formalCandidateDigest(intent.RequestSHA256) || !formalCandidateDigest(intent.CredentialSHA256) || !formalCandidateDigest(intent.CandidateOwnerMAC) || intent.Claim.Target != claim.Target || intent.Claim.Owner == "" || intent.Claim.RowVersion == 0 || !time.Now().Before(intent.Deadline) || intent.Deadline.After(guard.Facts().TaskDeadline) || guard.RecheckTx(ctx, tx) != nil {
		return zero, c.ErrExecutionRecord
	}
	if intent.Name != "sbp-"+intent.RequestSHA256[:32]+"-upload" {
		return zero, c.ErrExecutionRecord
	}
	var mac, lifecycle string
	if tx.QueryRowContext(ctx, `SELECT owner_marker_hmac,lifecycle FROM system_backup_v2_staging_resources WHERE origin_installation_id=? AND backup_public_id=? AND attempt_no=? AND phase='publish' AND resource_type='remote_manifest_candidate' AND public_id=? FOR SHARE`, intent.Installation, intent.Backup, attempt, intent.CandidateResource).Scan(&mac, &lifecycle) != nil || mac != intent.CandidateOwnerMAC || lifecycle != "creating" {
		return zero, c.ErrExecutionRecord
	}
	if guard.RecheckTx(ctx, tx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	return intent, nil
}

// No new material is generated when any original intent exists. A native
// absent-after-intent outcome remains unknown and cannot start a new Job.
func (s *DeploymentService) preparePublicationJobMaterials(ctx context.Context, claim c.ClaimToken, attempt uint64, target PublicationTargetMaterials, proposed PublicationUploadRequest) (out *publicationJobMaterials, resultErr error) {
	if s == nil || s.Runtime == nil || s.Runtime.Owner == nil || s.Runtime.Owner.Client == nil || attempt != 1 || s.checkPublicationJobResources(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	previous, err := s.loadPublicationMaterialIntent(ctx, claim, attempt)
	if err == nil {
		return s.readPublicationJobMaterials(ctx, claim, attempt, target, previous)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if proposed.Version != publicationPresignedUploadVersion || proposed.CredentialHash != "" || proposed.CandidateOwnerHMAC != "" {
		return nil, c.ErrExecutionRecord
	}
	candidate, err := s.beginPublicationCandidate(ctx, claim, attempt, target, proposed)
	if err != nil {
		return nil, err
	}
	proposed.CandidateOwnerHMAC = candidate.MAC
	grants, err := s.issuePublicationPutGrants(ctx, claim, attempt, target, proposed)
	if err != nil {
		return nil, err
	}
	defer clear(grants)
	proposed.CredentialHash = hash(grants)
	_, grantUntil, err := parsePublicationPutGrantSet(proposed, grants)
	if err != nil {
		return nil, err
	}
	request, err := json.Marshal(proposed)
	if err != nil {
		return nil, err
	}
	defer clear(request)
	requestSHA := hash(request)
	identity, err := s.issuePublicationWorkerIdentity(ctx, claim, attempt, requestSHA)
	if err != nil {
		return nil, err
	}
	defer identity.Clear()
	artifactCA, err := pinnedDeploymentFile(target.CAFile, target.CASHA256, 1<<20)
	if err != nil {
		return nil, err
	}
	defer clear(artifactCA)
	marker := make([]byte, 32)
	if _, err = rand.Read(marker); err != nil {
		return nil, err
	}
	defer clear(marker)
	yes := true
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: s.Config.Namespace, Name: "sbp-" + requestSHA[:32] + "-upload", Labels: map[string]string{"backup.clawmanager.io/v2-task": claim.Target.PublicID}, Annotations: map[string]string{"backup.clawmanager.io/publication-material-owner": hex.EncodeToString(marker)}}, Immutable: &yes, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"request.json": request, "credential.json": grants, "artifact-ca.crt": artifactCA, "ca.crt": identity.Data["ca.crt"], "tls.crt": identity.Data["tls.crt"], "tls.key": identity.Data["tls.key"]}}
	body, err := publicationMaterialBody(secret)
	if err != nil {
		return nil, err
	}
	defer clear(body)
	until := identity.ExpiresAt
	if grantUntil.Before(until) {
		until = grantUntil
	}
	if proposed.Deadline.Before(until) {
		until = proposed.Deadline
	}
	intent := publicationMaterialIntent{Version: "system-backup-original-publication-materials.v1", Installation: s.Config.InstallationID, Backup: claim.Target.PublicID, Attempt: attempt, Namespace: secret.Namespace, Name: secret.Name, BodySHA256: hash(body), RequestSHA256: requestSHA, CredentialSHA256: proposed.CredentialHash, CandidateResource: candidate.owner.Resource, CandidateOwnerMAC: candidate.MAC, Claim: claim, Deadline: until}
	if err = s.beginPublicationMaterialIntent(ctx, claim, attempt, target, intent); err != nil {
		return nil, err
	}
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil || s.checkPublicationJobResources(ctx) != nil || !time.Now().Before(intent.Deadline) {
		return nil, c.ErrExecutionAuthority
	}
	nativeDeadline := intent.Deadline
	if access.ValidUntil().Before(nativeDeadline) {
		nativeDeadline = access.ValidUntil()
	}
	bounded, cancel := context.WithDeadline(ctx, nativeDeadline)
	defer cancel()
	if _, err = s.Runtime.Owner.Client.CoreV1().Secrets(secret.Namespace).Create(bounded, secret, metav1.CreateOptions{}); err != nil {
		return nil, ErrJobUncertain
	}
	// Native GET, exact bytes and actual UID must be acknowledged BEFORE 121.
	return s.readPublicationJobMaterials(ctx, claim, attempt, target, intent)
}

func (s *DeploymentService) beginPublicationMaterialIntent(ctx context.Context, claim c.ClaimToken, attempt uint64, target PublicationTargetMaterials, intent publicationMaterialIntent) error {
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil {
		return c.ErrExecutionAuthority
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	guard, err := access.Bind(ctx, tx)
	if err != nil {
		return err
	}
	if err = s.checkPublicationTargetTx(ctx, tx, guard.Facts(), target); err != nil {
		return err
	}
	if err = publicationPreparationOpenTx(ctx, tx, intent.Installation, intent.Backup); err != nil {
		return err
	}
	var sends int
	if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_job_send_intents WHERE origin_installation_id=? AND task_public_id=? AND phase='publish'`, intent.Installation, intent.Backup).Scan(&sends) != nil || sends != 0 {
		return c.ErrExecutionRecord
	}
	var resource, mac, lifecycle string
	if tx.QueryRowContext(ctx, `SELECT public_id,owner_marker_hmac,lifecycle FROM system_backup_v2_staging_resources WHERE origin_installation_id=? AND backup_public_id=? AND attempt_no=? AND phase='publish' AND resource_type='remote_manifest_candidate' AND public_id=? FOR SHARE`, intent.Installation, intent.Backup, attempt, intent.CandidateResource).Scan(&resource, &mac, &lifecycle) != nil || resource != intent.CandidateResource || mac != intent.CandidateOwnerMAC || lifecycle != "creating" {
		return c.ErrExecutionRecord
	}
	if !time.Now().Before(intent.Deadline) || intent.Deadline.After(access.ValidUntil()) || intent.Deadline.After(guard.Facts().TaskDeadline) {
		return c.ErrExecutionAuthority
	}
	id := publicationMaterialID(intent.Installation, intent.Backup, attempt)
	if _, err = loadPublicationMetadata(ctx, tx, intent.Backup, id); !errors.Is(err, sql.ErrNoRows) {
		if err == nil {
			return errPublicationConflict
		}
		return err
	}
	var capacity, retention int64
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT control_metadata_capacity_bytes,evidence_retention_seconds,UTC_TIMESTAMP(6) FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=? FOR SHARE`, intent.Installation, guard.Facts().ConfigVersion, guard.Facts().ConfigSHA256).Scan(&capacity, &retention, &now) != nil || retention < 60 || retention > 10*365*86400 {
		return c.ErrExecutionRecord
	}
	if !now.Add(time.Duration(retention) * time.Second).After(guard.Facts().TaskDeadline) {
		return c.ErrExecutionRecord
	}
	raw, err := ce.Canonical(intent)
	if err != nil {
		return err
	}
	if err = (security.RegistrationCapacity{ReportFile: s.Config.CapacityFile}).Reserve(ctx, tx, capacity, len(raw)); err != nil {
		return err
	}
	if err = registerPublicationMetadata(ctx, tx, intent.Installation, intent.Backup, id, raw, now.Add(time.Duration(retention)*time.Second)); err != nil {
		return err
	}
	if err = guard.RecheckTx(ctx, tx); err != nil {
		return err
	}
	if tx.Commit() != nil || ctx.Err() != nil {
		return c.ErrExecutionCommitUnknown
	}
	return nil
}

func (s *DeploymentService) readPublicationJobMaterials(ctx context.Context, claim c.ClaimToken, attempt uint64, target PublicationTargetMaterials, intent publicationMaterialIntent) (out *publicationJobMaterials, resultErr error) {
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil || s.checkPublicationJobResources(ctx) != nil || !time.Now().Before(intent.Deadline) {
		return nil, c.ErrExecutionAuthority
	}
	nativeDeadline := intent.Deadline
	if access.ValidUntil().Before(nativeDeadline) {
		nativeDeadline = access.ValidUntil()
	}
	bounded, cancel := context.WithDeadline(ctx, nativeDeadline)
	defer cancel()
	secret, err := s.Runtime.Owner.Client.CoreV1().Secrets(intent.Namespace).Get(bounded, intent.Name, metav1.GetOptions{})
	if err != nil {
		return nil, ErrJobUncertain
	}
	m := &publicationJobMaterials{secret: secret, intent: intent}
	defer func() {
		if resultErr != nil {
			m.Close()
		}
	}()
	body, err := publicationMaterialBody(secret)
	defer clear(body)
	if err != nil || hash(body) != intent.BodySHA256 || secret.UID == "" || secret.ResourceVersion == "" || secret.DeletionTimestamp != nil || secret.Namespace != intent.Namespace || secret.Name != intent.Name {
		return nil, c.ErrExecutionRecord
	}
	if parsed, err := uuid.Parse(string(secret.UID)); err != nil || parsed.String() != string(secret.UID) {
		return nil, c.ErrExecutionRecord
	}
	if hash(secret.Data["request.json"]) != intent.RequestSHA256 || hash(secret.Data["credential.json"]) != intent.CredentialSHA256 || hash(secret.Data["artifact-ca.crt"]) != target.CASHA256 || decodeProviderDeploymentJSON(secret.Data["request.json"], &m.request) != nil || m.request.CredentialHash != intent.CredentialSHA256 || m.request.CandidateOwnerHMAC != intent.CandidateOwnerMAC || m.request.Installation != intent.Installation || m.request.Backup != intent.Backup || m.request.Attempt != attempt {
		return nil, c.ErrExecutionRecord
	}
	normalized, err := json.Marshal(m.request)
	if err != nil || !bytes.Equal(normalized, secret.Data["request.json"]) {
		clear(normalized)
		return nil, c.ErrExecutionRecord
	}
	clear(normalized)
	if _, until, err := parsePublicationPutGrantSet(m.request, secret.Data["credential.json"]); err != nil || intent.Deadline.After(until) {
		return nil, c.ErrExecutionRecord
	}
	if err = checkPublicationMaterialCertificate(s, m); err != nil {
		return nil, err
	}
	candidate, err := s.beginPublicationCandidate(ctx, claim, attempt, target, m.request)
	if err != nil || candidate.owner.Resource != intent.CandidateResource || candidate.MAC != intent.CandidateOwnerMAC {
		return nil, c.ErrExecutionRecord
	}
	if err = s.checkPublicationMaterialOwner(ctx, claim, attempt, m); err != nil {
		return nil, err
	}
	if access.Check(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	if err = s.recordPublicationMaterialObservation(ctx, claim, attempt, intent, string(secret.UID)); err != nil {
		return nil, err
	}
	return m, nil
}

// Durable production ordering: original private bytes/UID observation precede
// original 121. The material's OLD deadline further bounds every native send.
// Fresh creation remains suspended. Existing original activation/107 evidence
// may authenticate a started Job without rewriting its owner or request bytes.
func (s *DeploymentService) ensureDurableSuspendedPublicationJob(ctx context.Context, claim c.ClaimToken, attempt uint64, target PublicationTargetMaterials, proposed PublicationUploadRequest) (*batchv1.Job, *publicationJobMaterials, error) {
	m, err := s.preparePublicationJobMaterials(ctx, claim, attempt, target, proposed)
	if err != nil {
		return nil, nil, err
	}
	bounded, cancel := context.WithDeadline(ctx, m.intent.Deadline)
	defer cancel()
	job, err := s.ensureSuspendedPublicationJob(bounded, claim, attempt, target, m.request)
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	return job, m, nil
}

func checkPublicationMaterialCertificate(s *DeploymentService, m *publicationJobMaterials) error {
	pair, err := tls.X509KeyPair(m.secret.Data["tls.crt"], m.secret.Data["tls.key"])
	if err != nil || len(pair.Certificate) != 1 {
		return c.ErrExecutionRecord
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return c.ErrExecutionRecord
	}
	roots := x509.NewCertPool()
	issuer := s.Runtime.Owner.Issuer
	if issuer.Certificate == nil || hash(issuer.Certificate.Raw) != s.Forward.DeploymentBinding().WorkerIssuerSHA256 || !bytes.Equal(m.secret.Data["ca.crt"], issuer.ServerRoots) {
		return c.ErrExecutionAuthority
	}
	roots.AddCert(issuer.Certificate)
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return c.ErrExecutionAuthority
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://"+s.Config.TrustDomain+"/backup/"+m.intent.Backup+"/"+m.intent.RequestSHA256 || leaf.NotAfter.Before(m.intent.Deadline) || !time.Now().Before(leaf.NotAfter) {
		return c.ErrExecutionRecord
	}
	return nil
}

func (s *DeploymentService) recordPublicationMaterialObservation(ctx context.Context, claim c.ClaimToken, attempt uint64, intent publicationMaterialIntent, uid string) error {
	access, err := s.publicationAccess(ctx, claim, attempt)
	if err != nil || access.Check(ctx) != nil {
		return c.ErrExecutionAuthority
	}
	tx, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	guard, err := access.Bind(ctx, tx)
	if err != nil {
		return err
	}
	id := publicationMaterialID(intent.Installation, intent.Backup, attempt)
	original, err := loadPublicationMetadata(ctx, tx, intent.Backup, id)
	if err != nil {
		return err
	}
	expected, err := ce.Canonical(intent)
	if err != nil || !bytes.Equal(expected, original) {
		return c.ErrExecutionRecord
	}
	observation, err := ce.Canonical(publicationMaterialObservation{Version: "system-backup-original-publication-material-observation.v1", IntentSHA256: hash(original), SecretUID: uid})
	if err != nil {
		return err
	}
	var capacity, retention int64
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT control_metadata_capacity_bytes,evidence_retention_seconds,UTC_TIMESTAMP(6) FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=? FOR SHARE`, intent.Installation, guard.Facts().ConfigVersion, guard.Facts().ConfigSHA256).Scan(&capacity, &retention, &now) != nil || retention < 60 || retention > 10*365*86400 {
		return c.ErrExecutionRecord
	}
	if !now.Add(time.Duration(retention) * time.Second).After(guard.Facts().TaskDeadline) {
		return c.ErrExecutionRecord
	}
	if _, err = loadPublicationMetadata(ctx, tx, intent.Backup, id+"_observed"); errors.Is(err, sql.ErrNoRows) {
		if err = (security.RegistrationCapacity{ReportFile: s.Config.CapacityFile}).Reserve(ctx, tx, capacity, len(observation)); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err = registerPublicationMetadata(ctx, tx, intent.Installation, intent.Backup, id+"_observed", observation, now.Add(time.Duration(retention)*time.Second)); err != nil {
		return err
	}
	if err = guard.RecheckTx(ctx, tx); err != nil {
		return err
	}
	if tx.Commit() != nil {
		return c.ErrExecutionCommitUnknown
	}
	return nil
}
