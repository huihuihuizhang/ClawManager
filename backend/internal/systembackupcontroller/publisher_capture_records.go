package systembackupcontroller

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/staging"
	d "clawreef/internal/systembackupdispatch"
	security "clawreef/internal/systembackupsecurity"
)

// This is implemented by the ORIGINAL production deployment authorization
// wrapper. It checks its static file/deployment binding only, outside SQL;
// permission to read history still comes exclusively from the concrete guard.
type PublisherCaptureCustodyBinding interface {
	CheckPublisherCaptureCustody(context.Context, security.PublisherCaptureDeployment) error
}

type publisherRecordCipher struct {
	Digest, Ref string
	Cipher      []byte
}
type publisherResourceHistory struct {
	RequestSHA               string
	Request, Binding, KeyUse []byte
	UID                      string
	Candidate, Result        publisherRecordCipher
	StoppedAt                time.Time
}
type publisherHistorySnapshot struct {
	Coordinates  publisherCaptureCoordinates
	Facts        security.PublisherCaptureFacts
	Plan, Result publisherRecordCipher
	Resource     *publisherResourceHistory
}

// LoadPublisherCapture is a controlled, readonly original-history entry. There
// is no arbitrary kind/key/ciphertext, caller decryption callback or capture
// authority argument. It does not revive source actions, old leases or permits.
// SQL transactions only copy bounded metadata/ciphertext; Kube, key-file and
// AEAD work stay outside them. The SAME current publisher guard is checked
// around each read and the original rows are independently reloaded at end.
func (s SQLExecutionRecords) LoadPublisherCapture(ctx context.Context, access *security.SQLPublisherCaptureAuthority) (PublisherCaptureRecord, error) {
	var zero PublisherCaptureRecord
	if !s.ready() || ctx == nil || ctx.Err() != nil || access == nil || access.ValidUntil().IsZero() || !time.Now().Before(access.ValidUntil()) {
		return zero, ErrExecutionAuthority
	}
	identity, ok := s.Keys.(*PinnedExecutionIdentity)
	if !ok || identity == nil {
		return zero, ErrExecutionAuthority
	}
	binding, ok := s.Authority.Authorization.(PublisherCaptureCustodyBinding)
	if !ok {
		return zero, ErrExecutionAuthority
	}
	deployment := access.Deployment()
	if s.Authority.InstallationID != deployment.InstallationID || publisherIdentityMatches(identity, deployment) != nil {
		return zero, ErrExecutionAuthority
	}
	until := access.ValidUntil()
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	check := func() error {
		if ctx.Err() != nil || !access.ValidUntil().Equal(until) || binding.CheckPublisherCaptureCustody(ctx, deployment) != nil || identity.CheckDeployment(ctx, s.Authority.DB) != nil || access.CheckWorkload(ctx) != nil {
			return ErrExecutionAuthority
		}
		return nil
	}
	if check() != nil {
		return zero, ErrExecutionAuthority
	}
	first, err := s.publisherReadSnapshot(ctx, access, nil)
	if err != nil {
		return zero, err
	}
	if check() != nil {
		return zero, ErrExecutionAuthority
	}
	planKey, err := publisherReadRecordKey(identity, first.Plan.Ref)
	if err != nil {
		return zero, err
	}
	defer clear(planKey)
	planRaw, err := publisherOpenRecord(ctx, first.Plan.Cipher, planKey, publisherRecordBinding(first.Coordinates, "plan", first.Plan.Digest), 8<<20)
	if err != nil {
		return zero, err
	}
	defer clear(planRaw)
	part, err := publisherBootstrapPart(planRaw, access.Scope().Part)
	if err != nil {
		return zero, err
	}
	if check() != nil {
		return zero, ErrExecutionAuthority
	}
	second, err := s.publisherReadSnapshot(ctx, access, &part)
	if err != nil {
		return zero, err
	}
	if !publisherSameBase(first, second) || second.Resource == nil || check() != nil {
		return zero, ErrExecutionRecord
	}
	resource := second.Resource
	var job d.JobBinding
	if publisherDecodeClosed(resource.Binding, &job) != nil || job.UID != resource.UID || job.JobUnitKey != part.Intent.JobUnitKey || job.Namespace != part.Intent.Namespace || job.Name != part.Intent.Name || job.Generation != part.Intent.Generation {
		return zero, ErrExecutionRecord
	}
	candidateKey, err := publisherReadRecordKey(identity, resource.Candidate.Ref)
	if err != nil {
		return zero, err
	}
	defer clear(candidateKey)
	candidateRaw, err := publisherOpenRecord(ctx, resource.Candidate.Cipher, candidateKey, publisherCandidateBinding(second.Coordinates, job, resource.Candidate.Digest), 16384)
	if err != nil {
		return zero, err
	}
	defer clear(candidateRaw)
	resultKey, err := publisherReadRecordKey(identity, second.Result.Ref)
	if err != nil {
		return zero, err
	}
	defer clear(resultKey)
	resultRaw, err := publisherOpenRecord(ctx, second.Result.Cipher, resultKey, publisherRecordBinding(second.Coordinates, "capture_result", second.Result.Digest), 8<<20)
	if err != nil {
		return zero, err
	}
	defer clear(resultRaw)
	output, err := publisherValidateHistory(second.Coordinates, access.Scope().Part, planRaw, resultRaw, candidateRaw, resource.KeyUse, resource.Request, resource.Candidate.Digest, resource.RequestSHA, job)
	if err != nil {
		return zero, err
	}
	// The original per-Job sealed result must also be the exact ModuleResult
	// contained in the authenticated, successful original capture_result.
	moduleRaw, err := json.Marshal(output.PartResult)
	if err != nil || recordHash(moduleRaw) != resource.Result.Digest {
		return zero, ErrExecutionRecord
	}
	moduleKey, err := publisherReadRecordKey(identity, resource.Result.Ref)
	if err != nil {
		return zero, err
	}
	defer clear(moduleKey)
	moduleBinding := staging.Binding{BackupID: second.Coordinates.task, Attempt: strconv.FormatUint(second.Coordinates.attempt, 10), Path: "worker-result/" + job.JobUnitKey, CaptureContextHash: second.Coordinates.configSHA, EnvelopeID: resource.Result.Digest}
	modulePlain, err := publisherOpenRecord(ctx, resource.Result.Cipher, moduleKey, moduleBinding, 1<<20)
	if err != nil {
		return zero, err
	}
	defer clear(modulePlain)
	if !bytes.Equal(modulePlain, moduleRaw) || check() != nil {
		return zero, ErrExecutionRecord
	}
	// Recheck original file custody after the last Kubernetes I/O, then finish
	// with a short concrete SQL guard. A renewal/revocation during that final
	// workload GET must not leave a usable historical result.
	if check() != nil || binding.CheckPublisherCaptureCustody(ctx, deployment) != nil || identity.CheckDeployment(ctx, s.Authority.DB) != nil {
		return zero, ErrExecutionAuthority
	}
	final, err := s.publisherReadSnapshot(ctx, access, &part)
	if err != nil || !publisherSameSnapshot(second, final) || ctx.Err() != nil || !time.Now().Before(until) {
		return zero, ErrExecutionRecord
	}
	output.ValidUntil = until
	return output, nil
}

func publisherIdentityMatches(p *PinnedExecutionIdentity, d security.PublisherCaptureDeployment) error {
	if p == nil {
		return ErrExecutionAuthority
	}
	g := p.DeploymentBinding()
	if p.GrantSHA256() != d.CaptureGrantSHA256 || g.InstallationID != d.InstallationID || g.ControllerOwner != d.ControllerOwner || g.DatabaseAccount != d.DatabaseAccount || g.ServerUUID != d.ServerUUID || g.Database != d.Database || g.ConfigVersion != d.ConfigVersion || g.ConfigSHA256 != d.ConfigSHA256 || g.ProfileSHA256 != d.ProfileSHA256 || g.DeploymentConfigSHA256 != d.DeploymentConfigSHA256 || !g.NotBefore.Equal(d.NotBefore) || !g.ExpiresAt.Equal(d.Until) {
		return ErrExecutionAuthority
	}
	return nil
}

// Ref is selected ONLY from the scoped original SQL records above. This
// private helper cannot turn a caller's chosen key/file into a public API.
// CheckDeployment reauthenticates the same original signed key-custody grant
// before and after local decryption; no d.Authority/old claim is synthesized.
func publisherReadRecordKey(p *PinnedExecutionIdentity, ref string) ([]byte, error) {
	if p == nil || ref == "" || len(ref) > 256 {
		return nil, ErrExecutionAuthority
	}
	for _, key := range p.grant.RecordKeys {
		if key.Ref == ref {
			raw, err := readExecutionFile(filepath.Join(p.keyDirectory, key.Ref), 32)
			if err != nil || len(raw) != 32 || recordHash(raw) != key.SHA256 {
				clear(raw)
				return nil, ErrExecutionAuthority
			}
			return raw, nil
		}
	}
	return nil, ErrExecutionAuthority
}

func (s SQLExecutionRecords) publisherReadSnapshot(ctx context.Context, access *security.SQLPublisherCaptureAuthority, part *b.JobPart) (publisherHistorySnapshot, error) {
	var zero publisherHistorySnapshot
	tx, err := s.Authority.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, ErrExecutionRecord
	}
	defer tx.Rollback()
	guard, err := access.Bind(ctx, tx)
	if err != nil {
		return zero, ErrExecutionAuthority
	}
	facts := guard.Facts()
	deployment := access.Deployment()
	scope := access.Scope()
	snapshot := publisherHistorySnapshot{Facts: facts, Coordinates: publisherCaptureCoordinates{installation: deployment.InstallationID, task: scope.BackupPublicID, request: facts.RequestID, configSHA: facts.ConfigSHA256, profileSHA: deployment.ProfileSHA256, captureGrantSHA: deployment.CaptureGrantSHA256, captureOwner: deployment.ControllerOwner, configVersion: facts.ConfigVersion, attempt: scope.CaptureAttemptNo, epoch: facts.CaptureEpoch, deadline: facts.TaskDeadline}}
	c := &snapshot.Coordinates
	if tx.QueryRowContext(ctx, `SELECT config_snapshot_json,source_orchestrator,source_profile,matrix_key,datasource_topology,runner,task_purpose,requested_parts FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? AND config_snapshot_size_bytes BETWEEN 2 AND 262144 AND OCTET_LENGTH(config_snapshot_json)=config_snapshot_size_bytes FOR SHARE`, c.installation, c.task).Scan(&c.config, &c.spec.SourceOrchestrator, &c.spec.SourceProfile, &c.spec.MatrixKey, &c.spec.DatasourceTopology, &c.spec.Runner, &c.spec.TaskPurpose, &scopeParts{target: &c.spec.RequestedParts}) != nil {
		return zero, ErrExecutionRecord
	}
	if c.spec.TaskPurpose != facts.TaskPurpose || strings.Join(c.spec.RequestedParts, ",") != facts.RequestedParts || recordHash(c.config) != c.configSHA || d.ValidateBackupSpec(&c.spec) != nil {
		return zero, ErrExecutionRecord
	}
	var profileSHA string
	if tx.QueryRowContext(ctx, `SELECT profile_json,profile_sha256 FROM system_backup_v2_execution_inputs WHERE origin_installation_id=? AND task_public_id=? AND task_type='backup' AND OCTET_LENGTH(profile_json) BETWEEN 2 AND 65536 FOR SHARE`, c.installation, c.task).Scan(&c.profile, &profileSHA) != nil || profileSHA != c.profileSHA || recordHash(c.profile) != c.profileSHA {
		return zero, ErrExecutionRecord
	}
	read := func(kind string) (publisherRecordCipher, error) {
		var r publisherRecordCipher
		err := tx.QueryRowContext(ctx, `SELECT payload_sha256,key_ref,sealed_payload FROM system_backup_v2_execution_records WHERE origin_installation_id=? AND task_public_id=? AND attempt_no=? AND phase='capture' AND record_kind=? AND OCTET_LENGTH(sealed_payload) BETWEEN 2 AND 8392704 FOR SHARE`, c.installation, c.task, c.attempt, kind).Scan(&r.Digest, &r.Ref, &r.Cipher)
		if err != nil || !executionHash.MatchString(r.Digest) || r.Ref == "" || len(r.Ref) > 256 {
			return publisherRecordCipher{}, ErrExecutionRecord
		}
		return r, nil
	}
	snapshot.Plan, err = read("plan")
	if err != nil {
		return zero, err
	}
	snapshot.Result, err = read("capture_result")
	if err != nil || snapshot.Result.Digest != facts.CaptureResultSHA256 {
		return zero, ErrExecutionRecord
	}
	if part != nil {
		r := &publisherResourceHistory{}
		if tx.QueryRowContext(ctx, `SELECT request_sha256,request_json,observed_uid,binding_json,key_use_json,candidate_key_ref,candidate_sha256,candidate_cipher,result_key_ref,result_sha256,result_cipher,stopped_at FROM system_backup_v2_runtime_resources WHERE task_public_id=? AND attempt_no=? AND phase='capture' AND resource_kind='Job' AND namespace_name=? AND resource_name=? AND resource_owner=? AND create_dispatched=TRUE AND revoked=TRUE AND stopped_at IS NOT NULL AND OCTET_LENGTH(request_json) BETWEEN 2 AND 1048576 AND OCTET_LENGTH(binding_json) BETWEEN 2 AND 16384 AND OCTET_LENGTH(key_use_json) BETWEEN 2 AND 16384 AND OCTET_LENGTH(candidate_cipher) BETWEEN 2 AND 32768 AND OCTET_LENGTH(result_cipher) BETWEEN 2 AND 1052672 FOR SHARE`, c.task, c.attempt, part.Intent.Namespace, part.Intent.Name, c.task).Scan(&r.RequestSHA, &r.Request, &r.UID, &r.Binding, &r.KeyUse, &r.Candidate.Ref, &r.Candidate.Digest, &r.Candidate.Cipher, &r.Result.Ref, &r.Result.Digest, &r.Result.Cipher, &r.StoppedAt) != nil || r.UID == "" || r.StoppedAt.After(facts.CollectorsStoppedAt) || !executionHash.MatchString(r.RequestSHA) || !executionHash.MatchString(r.Candidate.Digest) || !executionHash.MatchString(r.Result.Digest) || r.Candidate.Ref == "" || r.Result.Ref == "" || len(r.Candidate.Ref) > 256 || len(r.Result.Ref) > 256 {
			return zero, ErrExecutionRecord
		}
		snapshot.Resource = r
	}
	if guard.RecheckTx(ctx, tx) != nil {
		return zero, ErrExecutionAuthority
	}
	if tx.Rollback() != nil || ctx.Err() != nil {
		return zero, ErrExecutionRecord
	}
	return snapshot, nil
}

type scopeParts struct{ target *[]string }

func (p *scopeParts) Scan(value any) error {
	var raw string
	switch v := value.(type) {
	case string:
		raw = v
	case []byte:
		raw = string(v)
	default:
		return ErrExecutionRecord
	}
	*p.target = strings.Split(raw, ",")
	return nil
}

func publisherSameBase(a, b publisherHistorySnapshot) bool {
	rawA, _ := json.Marshal(a.Coordinates.spec)
	rawB, _ := json.Marshal(b.Coordinates.spec)
	return bytes.Equal(rawA, rawB) && a.Facts == b.Facts && a.Coordinates.installation == b.Coordinates.installation && a.Coordinates.task == b.Coordinates.task && bytes.Equal(a.Coordinates.config, b.Coordinates.config) && bytes.Equal(a.Coordinates.profile, b.Coordinates.profile) && publisherSameCipher(a.Plan, b.Plan) && publisherSameCipher(a.Result, b.Result)
}
func publisherSameCipher(a, b publisherRecordCipher) bool {
	return a.Digest == b.Digest && a.Ref == b.Ref && bytes.Equal(a.Cipher, b.Cipher)
}
func publisherSameSnapshot(a, b publisherHistorySnapshot) bool {
	if !publisherSameBase(a, b) || a.Resource == nil || b.Resource == nil {
		return false
	}
	x, y := a.Resource, b.Resource
	return x.RequestSHA == y.RequestSHA && x.UID == y.UID && x.StoppedAt.Equal(y.StoppedAt) && bytes.Equal(x.Request, y.Request) && bytes.Equal(x.Binding, y.Binding) && bytes.Equal(x.KeyUse, y.KeyUse) && publisherSameCipher(x.Candidate, y.Candidate) && publisherSameCipher(x.Result, y.Result)
}
