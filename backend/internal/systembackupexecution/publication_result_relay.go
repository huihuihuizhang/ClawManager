package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A private worker/controller transport, not a new artifact v12 wire format.
// Every message supplies one immutable-version lookup hint. It never proves
// provider contents, full-domain validity, acceptance or task success.
const PublicationResultPath = "/publication-result"
const publicationResultVersion = "system-backup-original-publication-result.v1"

type publicationResultMessage struct {
	Version, Installation, Backup, RequestSHA256 string
	Attempt, Sequence                            uint64
	Object                                       PublicationUploadObservation
}

func (m publicationResultMessage) validate(p PublicationUploadRequest, requestSHA string) error {
	if m.Version != publicationResultVersion || m.Installation != p.Installation || m.Backup != p.Backup || m.Attempt != p.Attempt || m.RequestSHA256 != requestSHA || !formalCandidateDigest(requestSHA) || m.Sequence < 1 || m.Sequence > uint64(len(p.Objects)+1) || m.Object.Version == "" || m.Object.Version == "null" || m.Object.Version == "latest" || len(m.Object.Version) > 256 || strings.ContainsAny(m.Object.Version, "\x00\r\n") {
		return c.ErrExecutionRecord
	}
	var key, digest string
	var size int64
	if m.Sequence <= uint64(len(p.Objects)) {
		o := p.Objects[m.Sequence-1]
		key, digest, size = p.ArtifactRoot+p.Backup+"/"+strconv.FormatUint(p.Attempt, 10)+"/"+o.Path, o.SHA256, o.Bytes
	} else {
		manifest, candidate, err := p.validate()
		if err != nil {
			return err
		}
		key, digest, size = candidate, hash(manifest), int64(len(manifest))
	}
	if m.Object.Key != key || m.Object.SHA256 != digest || m.Object.Bytes != size {
		return c.ErrExecutionRecord
	}
	return nil
}

func publicationResultID(intent publicationMaterialIntent, sequence uint64) string {
	return publicationMaterialID(intent.Installation, intent.Backup, intent.Attempt) + "_result_" + strconv.FormatUint(sequence, 10)
}

// Sending the result never repeats an upload. Failure leaves the exact original
// Job and objects for query-only reconciliation; the worker has no restart loop.
func SendPublicationUploadResult(ctx context.Context, endpoint, identityDir, tokenFile string, original []byte, result PublicationUploadResult) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != PublicationResultPath || u.RawQuery != "" || u.Fragment != "" || !filepath.IsAbs(identityDir) || !filepath.IsAbs(tokenFile) || len(original) < 2 || len(original) > 8<<20 {
		return c.ErrExecutionRecord
	}
	var p PublicationUploadRequest
	if decodeProviderDeploymentJSON(original, &p) != nil {
		return c.ErrExecutionRecord
	}
	if _, _, err = p.validate(); err != nil || p.Version != publicationPresignedUploadVersion || !time.Now().Before(p.Deadline) || result.Version != publicationUploadVersion || result.Installation != p.Installation || result.Backup != p.Backup || result.Attempt != p.Attempt || result.RequestSHA256 != hash(original) || len(result.Objects) != len(p.Objects) {
		return c.ErrExecutionRecord
	}
	ctx, cancel := context.WithDeadline(ctx, p.Deadline)
	defer cancel()
	ca, err := readPrivate(filepath.Join(identityDir, "ca.crt"), 1<<20)
	if err != nil {
		return c.ErrExecutionAuthority
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return c.ErrExecutionAuthority
	}
	cert, err := readPrivate(filepath.Join(identityDir, "tls.crt"), 65536)
	if err != nil {
		return c.ErrExecutionAuthority
	}
	key, err := readPrivate(filepath.Join(identityDir, "tls.key"), 65536)
	if err != nil {
		return c.ErrExecutionAuthority
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return c.ErrExecutionAuthority
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{pair}}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxConnsPerHost: 1}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	objects := append(append([]PublicationUploadObservation(nil), result.Objects...), result.Candidate)
	// Validate the whole result before any network request. No partial report is
	// emitted if a worker/proxy supplied an unexpected final key or digest.
	messages := make([][]byte, len(objects))
	for i, object := range objects {
		m := publicationResultMessage{Version: publicationResultVersion, Installation: p.Installation, Backup: p.Backup, Attempt: p.Attempt, RequestSHA256: result.RequestSHA256, Sequence: uint64(i + 1), Object: object}
		if m.validate(p, result.RequestSHA256) != nil {
			return c.ErrExecutionRecord
		}
		messages[i], err = ce.Canonical(m)
		if err != nil || len(messages[i]) > 8192 {
			return c.ErrExecutionRecord
		}
	}
	for _, raw := range messages {
		token, err := readPrivate(tokenFile, 16384)
		if err != nil || len(token) < 16 || strings.ContainsAny(string(token), "\x00\r\n") {
			clear(token)
			return c.ErrExecutionAuthority
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
		if err != nil {
			clear(token)
			return c.ErrExecutionRecord
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+string(token))
		clear(token)
		response, err := client.Do(request)
		if err != nil {
			return ErrJobUncertain
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1025))
		response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusNoContent {
			return ErrJobUncertain
		}
	}
	return nil
}

func (s *DeploymentService) publicationResultHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost || r.URL.Path != PublicationResultPath || r.URL.RawQuery != "" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 8193))
		var message publicationResultMessage
		if err != nil || len(raw) == 0 || len(raw) > 8192 || decodeProviderDeploymentJSON(raw, &message) != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		canonical, err := ce.Canonical(message)
		if err != nil || !bytes.Equal(canonical, raw) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if err = s.acceptPublicationResult(r, message, canonical); err != nil {
			if errors.Is(err, c.ErrExecutionCommitUnknown) || errors.Is(err, ErrJobUncertain) {
				w.WriteHeader(http.StatusServiceUnavailable)
			} else {
				w.WriteHeader(http.StatusForbidden)
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func (s *DeploymentService) acceptPublicationResult(r *http.Request, message publicationResultMessage, body []byte) error {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	pod, ok := boundPod(ctx)
	if !ok || s == nil || !s.ForwardEnabled || s.Runtime == nil || s.Runtime.Owner == nil || s.Config.PublicationWorker == nil || s.publisherVerifierDB == nil || message.Installation != s.Config.InstallationID || message.Attempt != 1 || !strings.HasPrefix(message.Backup, "sbk_") || len(message.Backup) != 40 || !formalCandidateDigest(message.RequestSHA256) || pod.Namespace != s.Config.Namespace || pod.ServiceAccountUID != s.Config.PublicationWorker.ServiceAccountUID {
		return c.ErrExecutionAuthority
	}
	// Untrusted fields only locate the immutable original receipt. They never
	// synthesize a publisher claim from current SQL owner/row-version fields.
	lookup, err := s.publisherVerifierDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	raw, err := loadPublicationMetadata(ctx, lookup, message.Backup, publicationMaterialID(message.Installation, message.Backup, message.Attempt))
	rollback := lookup.Rollback()
	var intent publicationMaterialIntent
	if err != nil || rollback != nil || decodeProviderDeploymentJSON(raw, &intent) != nil || intent.Installation != message.Installation || intent.Backup != message.Backup || intent.Attempt != message.Attempt || intent.RequestSHA256 != message.RequestSHA256 {
		return c.ErrExecutionRecord
	}
	store, err := s.publicationStore(ctx)
	if err != nil {
		return err
	}
	defer store.Close()
	m, err := s.preparePublicationJobMaterials(ctx, intent.Claim, intent.Attempt, store.config, PublicationUploadRequest{})
	if err != nil {
		return err
	}
	defer m.Close()
	if message.validate(m.request, m.intent.RequestSHA256) != nil {
		return c.ErrExecutionRecord
	}
	block, _ := pem.Decode(m.secret.Data["tls.crt"])
	if block == nil || !bytes.Equal(r.TLS.PeerCertificates[0].Raw, block.Bytes) {
		return c.ErrExecutionAuthority
	}
	job, _, err := s.readBoundPublicationJob(ctx, intent.Claim, intent.Attempt, m)
	if err != nil || job.Spec.Suspend == nil || *job.Spec.Suspend {
		return c.ErrExecutionAuthority
	}
	nativePod, err := s.Runtime.Owner.Client.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
	if err != nil || string(nativePod.UID) != pod.UID || nativePod.DeletionTimestamp != nil || nativePod.Spec.ServiceAccountName != s.Config.PublicationWorker.ServiceAccountName || len(nativePod.OwnerReferences) != 1 {
		return c.ErrExecutionAuthority
	}
	owner := nativePod.OwnerReferences[0]
	if owner.APIVersion != "batch/v1" || owner.Kind != "Job" || owner.Name != job.Name || owner.UID != job.UID || owner.Controller == nil || !*owner.Controller || nativePod.Labels["backup.clawmanager.io/v2-task"] != intent.Backup {
		return c.ErrExecutionAuthority
	}
	// Native scheduling may set nodeName. Every executable, volume, credential
	// projection and security property still matches the original Job template.
	podJob := job.DeepCopy()
	podJob.Spec.Template.Spec = *nativePod.Spec.DeepCopy()
	podJob.Spec.Template.Spec.NodeName = job.Spec.Template.Spec.NodeName
	if !sameJob(job, podJob) {
		return c.ErrExecutionRecord
	}
	process, err := s.originalPublicationProcessFromPod(ctx, job, nativePod, m.intent, message.Sequence)
	if err != nil {
		return err
	}
	return s.recordPublicationResult(ctx, intent.Claim, m, job, message, body, process)
}

func (s *DeploymentService) recordPublicationResult(ctx context.Context, claim c.ClaimToken, m *publicationJobMaterials, job *batchv1.Job, message publicationResultMessage, body []byte, process publicationUploadProcess) error {
	ctx, cancel := context.WithDeadline(ctx, m.intent.Deadline)
	defer cancel()
	access, err := s.publicationAccess(ctx, claim, m.intent.Attempt)
	if err != nil || access.Check(ctx) != nil || message.validate(m.request, m.intent.RequestSHA256) != nil {
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
	var sequence, rowVersion uint64
	var previous sql.NullString
	if tx.QueryRowContext(ctx, `SELECT last_accepted_sequence,last_accepted_body_sha256,row_version FROM system_backup_v2_job_observations WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND attempt_no=? AND phase='publish' AND job_unit_key='artifact-upload' FOR UPDATE`, m.intent.Installation, m.intent.Backup, m.intent.Attempt).Scan(&sequence, &previous, &rowVersion) != nil || rowVersion < 1 || sequence > uint64(len(m.request.Objects)+1) {
		return c.ErrExecutionRecord
	}
	a, err := s.loadPublicationActivationTx(ctx, tx, m.intent)
	if err != nil || a == nil || a.SecretUID != string(m.secret.UID) || a.JobUID != string(job.UID) || a.AfterGeneration != job.Generation {
		return c.ErrExecutionRecord
	}
	if sequence > 0 {
		original, _, err := loadPublicationProcessTx(ctx, tx, m.intent, *a)
		if err != nil || !samePublicationUploadProcess(original, process) {
			return c.ErrExecutionRecord
		}
	}
	if sequence > 0 {
		old, err := loadPublicationMetadata(ctx, tx, m.intent.Backup, publicationResultID(m.intent, sequence))
		if err != nil || !previous.Valid || hash(old) != previous.String {
			return c.ErrExecutionRecord
		}
	}
	if sequence >= message.Sequence {
		old, err := loadPublicationMetadata(ctx, tx, m.intent.Backup, publicationResultID(m.intent, message.Sequence))
		if err != nil || !bytes.Equal(old, body) || guard.RecheckTx(ctx, tx) != nil {
			return c.ErrExecutionRecord
		}
		return nil // exact original duplicate; no cursor/progress rewrite
	}
	if message.Sequence != sequence+1 || (sequence == 0 && previous.Valid) {
		return c.ErrExecutionRecord
	}
	var capacity, retention int64
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT control_metadata_capacity_bytes,evidence_retention_seconds,UTC_TIMESTAMP(6) FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=? FOR SHARE`, m.intent.Installation, guard.Facts().ConfigVersion, guard.Facts().ConfigSHA256).Scan(&capacity, &retention, &now) != nil || retention < 60 || retention > 10*365*86400 || now.Before(a.BoundAt) || !now.Before(a.ExpiresAt) || !now.Add(time.Duration(retention)*time.Second).After(guard.Facts().TaskDeadline) {
		return c.ErrExecutionRecord
	}
	id := publicationResultID(m.intent, message.Sequence)
	if _, err = loadPublicationMetadata(ctx, tx, m.intent.Backup, id); !errors.Is(err, sql.ErrNoRows) {
		return c.ErrExecutionRecord // cursor and immutable receipt must advance together
	}
	if err = (security.RegistrationCapacity{ReportFile: s.Config.CapacityFile}).Reserve(ctx, tx, capacity, len(body)); err != nil {
		return err
	}
	if sequence == 0 {
		if _, err = loadPublicationMetadata(ctx, tx, m.intent.Backup, publicationProcessID(m.intent)); !errors.Is(err, sql.ErrNoRows) {
			return c.ErrExecutionRecord
		}
		process.ObservedAt = now
		if !process.valid(m.intent, *a) {
			return c.ErrExecutionRecord
		}
		processRaw, err := ce.Canonical(process)
		if err != nil {
			return c.ErrExecutionRecord
		}
		if err = (security.RegistrationCapacity{ReportFile: s.Config.CapacityFile}).Reserve(ctx, tx, capacity, len(processRaw)); err != nil {
			return err
		}
		if err = registerPublicationMetadata(ctx, tx, m.intent.Installation, m.intent.Backup, publicationProcessID(m.intent), processRaw, now.Add(time.Duration(retention)*time.Second)); err != nil {
			return err
		}
	}
	if err = registerPublicationMetadata(ctx, tx, m.intent.Installation, m.intent.Backup, id, body, now.Add(time.Duration(retention)*time.Second)); err != nil {
		return err
	}
	status := "upload_objects"
	if message.Sequence == uint64(len(m.request.Objects)+1) {
		status = "upload_candidate"
	}
	result, err := tx.ExecContext(ctx, `UPDATE system_backup_v2_job_observations SET last_accepted_sequence=?,last_accepted_body_sha256=?,last_observed_status=?,last_observed_at=?,progress_sequence=?,progress_digest_sha256=?,last_business_progress_at=?,row_version=row_version+1 WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND attempt_no=? AND phase='publish' AND job_unit_key='artifact-upload' AND job_uid=? AND job_generation=? AND last_accepted_sequence=? AND row_version=?`, message.Sequence, hash(body), status, now, message.Sequence, hash(body), now, m.intent.Installation, m.intent.Backup, m.intent.Attempt, a.JobUID, a.AfterGeneration, sequence, rowVersion)
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 || guard.RecheckTx(ctx, tx) != nil {
		return c.ErrExecutionAuthority
	}
	if tx.Commit() != nil || ctx.Err() != nil {
		return c.ErrExecutionCommitUnknown
	}
	return nil
}
