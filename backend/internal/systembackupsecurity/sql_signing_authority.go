package systembackupsecurity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// SQLSigningOwnerGrant is an explicit original-owner capability in the
// independently signed installation record. It authorizes only this SQL
// workload to freeze/sign original public v2 task inputs. A config snapshot,
// capture execution grant, DB login or provider ACL cannot create this grant.
type SQLSigningOwnerGrant struct {
	ServerUUID, Database, DatabaseAccount string
	ControllerOwner                       string
	ConfigVersion                         uint64
	ConfigSHA256                          string
	Workload                              SigningWorkloadIdentity
}

// SQLSigningClaim is the exact currently held ORIGINAL public task claim.
// The original request_id is ArtifactSigningTask.OperationID. A heartbeat or
// takeover must not silently substitute a new row version during signing.
type SQLSigningClaim struct {
	ControllerOwner string
	RowVersion      uint64
}

type SQLInstallationArtifactSigners struct {
	*InstallationArtifactSigners
	owners map[string]*SQLArtifactSigningAuthority
}

// NewSQLInstallationArtifactSigners is the automatic production owner entry.
// One owner-signed installation capability serves new original public tasks;
// no per-task offline grant, private signing key or new task table is required.
func NewSQLInstallationArtifactSigners(ctx context.Context, db *sql.DB, reader OriginalSigningRecordReader, pin InstallationSigningPin, mounts []SigningJWTMount, task ArtifactSigningTask, claim SQLSigningClaim) (*SQLInstallationArtifactSigners, error) {
	if db == nil || candidateAuthorityNil(reader) || ctx == nil || ctx.Err() != nil || !providerBoundedString(claim.ControllerOwner) || claim.RowVersion == 0 {
		return nil, ErrRegistrationUnavailable
	}
	raw, sig, err := reader.ReadSigningRecord(ctx)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	record, _, err := authenticateInstallationSigning(raw, sig, pin, time.Now())
	if err != nil {
		return nil, err
	}
	owners := make(map[string]*SQLArtifactSigningAuthority, 3)
	for _, p := range record.Permissions {
		g := p.SQLOwner
		if g == nil || !providerBoundedString(g.ServerUUID) || !providerBoundedString(g.Database) || !providerBoundedString(g.DatabaseAccount) ||
			g.ControllerOwner != claim.ControllerOwner || g.Workload != task.Workload || g.ConfigVersion == 0 || !signingDigest.MatchString(g.ConfigSHA256) || owners[p.Binding.Purpose] != nil {
			return nil, ErrRegistrationUnavailable
		}
		copyGrant := *g
		owners[p.Binding.Purpose] = &SQLArtifactSigningAuthority{db: db, task: task, claim: claim, binding: p.Binding, grant: copyGrant, notBefore: record.NotBefore, until: record.Until}
	}
	if owners["capture_certificate"] == nil || owners["acceptance_record"] == nil || owners["catalog_record"] == nil {
		return nil, ErrRegistrationUnavailable
	}
	s, err := NewInstallationArtifactSigners(ctx, reader, pin, mounts, task, ArtifactSigningAuthorities{Capture: owners["capture_certificate"], Acceptance: owners["acceptance_record"], Catalog: owners["catalog_record"]})
	if err != nil {
		return nil, err
	}
	for _, owner := range owners {
		owner.materialCheck = s.check
	}
	return &SQLInstallationArtifactSigners{InstallationArtifactSigners: s, owners: owners}, nil
}

type frozenSQLSigningInput struct {
	Version             string
	Authorization       ArtifactSigningAuthorizationRequest
	Input               []byte
	CaptureResultSHA256 string
	CaptureEpoch        uint64
}

// Match the bounded Transit signing interface. The existing evidence table
// keeps its 8192-byte inline limit; larger frozen JSON uses atomic bounded
// chunks in that same registry, never a digest in place of signing input.
const maxArtifactSigningInputBytes = 16384
const maxFrozenSigningEvidenceBytes = 32768
const maxSigningEvidenceInlineBytes = 8192
const signingEvidenceChunkBytes = 4096

type SQLArtifactSigningAuthority struct {
	db               *sql.DB
	task             ArtifactSigningTask
	claim            SQLSigningClaim
	binding          TransitSigningBinding
	grant            SQLSigningOwnerGrant
	notBefore, until time.Time
	materialCheck    func(context.Context) error
	// Set only by the concrete production factory, never deployment/request
	// callbacks. Kube I/O runs outside current() and every SQL transaction.
	useCheck func(context.Context) error
}

type signingSQLView interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type signingSQLFacts struct {
	Status, CaptureHash string
	Lease, Deadline     time.Time
	Epoch               uint64
}

func signingInputEvidenceID(task ArtifactSigningTask, installation, purpose string) string {
	raw, _ := json.Marshal([]any{installation, task, purpose})
	h := sha256.Sum256(raw)
	return "sev_asign_" + hex.EncodeToString(h[:])
}

// current reads the original task, latest attempt, authenticated source result
// and actual collector/source recovery journal. It never derives permission
// from status alone; the independent original-owner grant is also mandatory.
func (a *SQLArtifactSigningAuthority) current(ctx context.Context, view signingSQLView, lock bool) (signingSQLFacts, time.Time, error) {
	bad := func() (signingSQLFacts, time.Time, error) {
		return signingSQLFacts{}, time.Time{}, ErrRegistrationUnavailable
	}
	if a == nil || ctx == nil || ctx.Err() != nil || view == nil || a.materialCheck == nil || a.materialCheck(ctx) != nil {
		return bad()
	}
	var account, server, database string
	var now time.Time
	if view.QueryRowContext(ctx, "SELECT CURRENT_USER(),@@server_uuid,DATABASE(),UTC_TIMESTAMP(6)").Scan(&account, &server, &database, &now) != nil || account != a.grant.DatabaseAccount || server != a.grant.ServerUUID || database != a.grant.Database || now.Before(a.notBefore) || !now.Before(a.until) {
		return bad()
	}
	suffix := ""
	if lock {
		suffix = " FOR SHARE"
	}
	var origin, request, status, owner, configHash, purpose, parts string
	var version, configVersion uint64
	var facts signingSQLFacts
	if view.QueryRowContext(ctx, `SELECT origin_installation_id,request_id,status,controller_owner,row_version,controller_lease_expires_at,deadline_at,config_version,config_snapshot_sha256,task_purpose,requested_parts FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=?`+suffix, a.binding.InstallationID, a.task.BackupPublicID).Scan(&origin, &request, &status, &owner, &version, &facts.Lease, &facts.Deadline, &configVersion, &configHash, &purpose, &parts) != nil ||
		origin != a.binding.InstallationID || request != a.task.OperationID || owner != a.claim.ControllerOwner || version != a.claim.RowVersion || configVersion != a.grant.ConfigVersion || configHash != a.grant.ConfigSHA256 || purpose != "acceptance" || parts != "mysql,redis,object_storage,workspace,deployment_resources,secret_bundle" || !now.Before(facts.Lease) || !now.Before(facts.Deadline) {
		return bad()
	}
	if a.binding.Purpose == "capture_certificate" {
		if status != "capturing" && status != "validating" && status != "publishing" {
			return bad()
		}
	} else if status != "validating" && status != "publishing" {
		return bad()
	}
	facts.Status = status
	var latest uint64
	var attemptStatus string
	if view.QueryRowContext(ctx, `SELECT attempt_no,status FROM system_backup_v2_attempts WHERE target_type='backup' AND target_public_id=? AND phase='capture' ORDER BY attempt_no DESC LIMIT 1`+suffix, a.task.BackupPublicID).Scan(&latest, &attemptStatus) != nil || latest != uint64(a.task.AttemptNo) || (status == "capturing" && attemptStatus != "running") || (status != "capturing" && attemptStatus != "sealed") {
		return bad()
	}
	var canceled int
	if view.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_operations WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND operation_type='cancel' AND status IN ('pending','running')`+suffix, a.binding.InstallationID, a.task.BackupPublicID).Scan(&canceled) != nil || canceled != 0 {
		return bad()
	}
	var stopped, resumed sql.NullTime
	if view.QueryRowContext(ctx, `SELECT gate_generation,collectors_stopped_at,source_resumed_at FROM system_backup_v2_runtime_captures WHERE task_public_id=?`+suffix, a.task.BackupPublicID).Scan(&facts.Epoch, &stopped, &resumed) != nil || facts.Epoch == 0 || !stopped.Valid || !resumed.Valid || resumed.Time.Before(stopped.Time) || resumed.Time.After(now) {
		return bad()
	}
	if view.QueryRowContext(ctx, `SELECT payload_sha256 FROM system_backup_v2_execution_records WHERE origin_installation_id=? AND task_public_id=? AND attempt_no=? AND phase='capture' AND record_kind='capture_result'`+suffix, a.binding.InstallationID, a.task.BackupPublicID, a.task.AttemptNo).Scan(&facts.CaptureHash) != nil || !signingDigest.MatchString(facts.CaptureHash) {
		return bad()
	}
	until := a.until
	for _, bound := range []time.Time{facts.Lease, facts.Deadline} {
		if bound.Before(until) {
			until = bound
		}
	}
	return facts, until, nil
}

// validateFrozenSigningInput checks the existing public-c-crypto JWS framing
// and exact task/key purpose identities. The original C owner remains
// responsible for computing and validating its complete business payload.
func validateFrozenSigningInput(input []byte, task ArtifactSigningTask, binding TransitSigningBinding) error {
	if len(input) == 0 || len(input) > maxArtifactSigningInputBytes {
		return ErrRegistrationUnavailable
	}
	parts := strings.Split(string(input), ".")
	if len(parts) != 2 {
		return ErrRegistrationUnavailable
	}
	h, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return ErrRegistrationUnavailable
	}
	p, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return ErrRegistrationUnavailable
	}
	for _, raw := range [][]byte{h, p} {
		canonical, e := jsoncanonicalizer.Transform(raw)
		if e != nil || !bytes.Equal(canonical, raw) {
			return ErrRegistrationUnavailable
		}
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Version   string `json:"key_version"`
		Purpose   string `json:"purpose"`
		Type      string `json:"typ"`
	}
	d := json.NewDecoder(bytes.NewReader(h))
	d.DisallowUnknownFields()
	if d.Decode(&header) != nil || header.Algorithm != "EdDSA" || header.KeyID != binding.KeyID || header.Version != binding.KeyVersion || header.Purpose != binding.Purpose {
		return ErrRegistrationUnavailable
	}
	typ := map[string]string{"capture_certificate": "clawmanager.system-backup.capture_certificate.v1", "acceptance_record": "clawmanager.system-backup.acceptance.v1", "catalog_record": "clawmanager.system-backup.catalog_record.v1"}[binding.Purpose]
	var payload struct {
		Installation string `json:"origin_installation_id"`
		Backup       string `json:"backup_public_id"`
		Attempt      int64  `json:"attempt_no"`
		SigningKey   struct {
			Purpose string `json:"purpose"`
			ID      string `json:"key_id"`
			Version string `json:"key_version"`
		} `json:"signing_key"`
	}
	if json.Unmarshal(p, &payload) != nil || header.Type != typ || payload.Backup != task.BackupPublicID || payload.Attempt != task.AttemptNo || payload.SigningKey.Purpose != binding.Purpose || payload.SigningKey.ID != binding.KeyID || payload.SigningKey.Version != binding.KeyVersion ||
		(binding.Purpose != "acceptance_record" && payload.Installation != binding.InstallationID) || (payload.Installation != "" && payload.Installation != binding.InstallationID) {
		return ErrRegistrationUnavailable
	}
	return nil
}

// StageSigningInput runs INSIDE the original C owner transaction after its
// capture/acceptance/catalog checks, before the external signing call. It
// freezes exact public signing bytes into the existing evidence registry,
// reusing the original task/attempt/claim. The caller commits or rolls back;
// this method neither commits nor creates an authorization/task endpoint.
func (s *SQLInstallationArtifactSigners) StageSigningInput(ctx context.Context, tx *sql.Tx, purpose string, input []byte) error {
	if s == nil || tx == nil || s.owners[purpose] == nil {
		return ErrRegistrationUnavailable
	}
	a := s.owners[purpose]
	input = bytes.Clone(input)
	if validateFrozenSigningInput(input, a.task, a.binding) != nil {
		return ErrRegistrationUnavailable
	}
	facts, until, err := a.current(ctx, tx, true)
	if err != nil {
		return err
	}
	h := sha256.Sum256(input)
	frozen := frozenSQLSigningInput{Version: "system-backup-original-sql-signing-input.v1", Authorization: ArtifactSigningAuthorizationRequest{Task: a.task, Signing: TransitSigningRequest{Binding: a.binding, InputSHA256: hex.EncodeToString(h[:])}}, Input: input, CaptureResultSHA256: facts.CaptureHash, CaptureEpoch: facts.Epoch}
	raw, err := json.Marshal(frozen)
	if err != nil || len(raw) > maxFrozenSigningEvidenceBytes {
		return ErrRegistrationUnavailable
	}
	old, oldUntil, err := a.readFrozen(ctx, tx, true)
	if err == nil {
		if !bytes.Equal(old, raw) || !time.Now().Before(oldUntil) {
			return ErrRegistrationUnavailable
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ErrRegistrationUnavailable
	}
	if err = a.insertFrozen(ctx, tx, raw, until); err != nil {
		return err
	}
	if again, end, e := a.current(ctx, tx, true); e != nil || again != facts || !end.Equal(until) {
		return ErrRegistrationUnavailable
	}
	return nil
}

func (a *SQLArtifactSigningAuthority) readFrozenEvidence(ctx context.Context, view signingSQLView, lock bool, id string) ([]byte, time.Time, error) {
	suffix := ""
	if lock {
		suffix = " FOR SHARE"
	}
	var raw []byte
	var hash, owner, ownerType, kind, state, health, encryption string
	var size uint64
	var until time.Time
	err := view.QueryRowContext(ctx, `SELECT inline_payload,content_checksum,content_size_bytes,owner_target_type,owner_target_public_id,evidence_type,storage_state,observed_health,encryption,expires_at FROM system_backup_v2_evidence WHERE public_id=?`+suffix, id).Scan(&raw, &hash, &size, &ownerType, &owner, &kind, &state, &health, &encryption, &until)
	if err != nil {
		return nil, time.Time{}, err
	}
	h := sha256.Sum256(raw)
	if len(raw) == 0 || len(raw) > maxSigningEvidenceInlineBytes || size != uint64(len(raw)) || hash != hex.EncodeToString(h[:]) || ownerType != "backup" || owner != a.task.BackupPublicID || kind != "diagnostic" || state != "inline" || health != "healthy" || encryption != "none" {
		return nil, time.Time{}, ErrRegistrationUnavailable
	}
	return raw, until, nil
}

type frozenSigningChunkIndex struct {
	Version     string
	Size, Count int
	SHA256      string
}
type frozenSigningChunk struct {
	Version, Parent string
	Index, Count    int
	Data            []byte
}

func signingChunkID(parent string, index int) string { return parent + "_p" + strconv.Itoa(index) }

func (a *SQLArtifactSigningAuthority) insertFrozenEvidence(ctx context.Context, tx *sql.Tx, id string, raw []byte, until time.Time) error {
	if len(raw) == 0 || len(raw) > maxSigningEvidenceInlineBytes {
		return ErrRegistrationUnavailable
	}
	digest := sha256.Sum256(raw)
	result, err := tx.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence(public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at) VALUES (?,'backup',?,'diagnostic','inline',?,?,?,'application/json','none','internal','healthy',?)`, id, a.task.BackupPublicID, raw, hex.EncodeToString(digest[:]), len(raw), until)
	if err != nil {
		return ErrRegistrationUnavailable
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return ErrRegistrationUnavailable
	}
	return nil
}

func (a *SQLArtifactSigningAuthority) insertFrozen(ctx context.Context, tx *sql.Tx, raw []byte, until time.Time) error {
	id := signingInputEvidenceID(a.task, a.binding.InstallationID, a.binding.Purpose)
	if len(raw) <= maxSigningEvidenceInlineBytes {
		return a.insertFrozenEvidence(ctx, tx, id, raw, until)
	}
	if len(raw) > maxFrozenSigningEvidenceBytes {
		return ErrRegistrationUnavailable
	}
	count := (len(raw) + signingEvidenceChunkBytes - 1) / signingEvidenceChunkBytes
	for i := 0; i < count; i++ {
		end := (i + 1) * signingEvidenceChunkBytes
		if end > len(raw) {
			end = len(raw)
		}
		body, err := json.Marshal(frozenSigningChunk{Version: "system-backup-original-sql-signing-chunk.v1", Parent: id, Index: i, Count: count, Data: raw[i*signingEvidenceChunkBytes : end]})
		if err != nil {
			return ErrRegistrationUnavailable
		}
		if err = a.insertFrozenEvidence(ctx, tx, signingChunkID(id, i), body, until); err != nil {
			return err
		}
	}
	h := sha256.Sum256(raw)
	index, err := json.Marshal(frozenSigningChunkIndex{Version: "system-backup-original-sql-signing-chunks.v1", Size: len(raw), Count: count, SHA256: hex.EncodeToString(h[:])})
	if err != nil {
		return ErrRegistrationUnavailable
	}
	return a.insertFrozenEvidence(ctx, tx, id, index, until)
}

func decodeFrozenSigningJSON(raw []byte, dest any) bool {
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dest) != nil || d.Decode(new(any)) != io.EOF {
		return false
	}
	// encoding/json accepts case-insensitive field aliases and absent zero
	// fields. The exact internal chunk schema accepts neither ambiguity.
	roundtrip, err := json.Marshal(dest)
	if err != nil {
		return false
	}
	roundtrip, err = jsoncanonicalizer.Transform(roundtrip)
	return err == nil && bytes.Equal(canonical, roundtrip)
}

func (a *SQLArtifactSigningAuthority) readFrozen(ctx context.Context, view signingSQLView, lock bool) ([]byte, time.Time, error) {
	id := signingInputEvidenceID(a.task, a.binding.InstallationID, a.binding.Purpose)
	raw, until, err := a.readFrozenEvidence(ctx, view, lock, id)
	if err != nil {
		return nil, time.Time{}, err
	}
	var version struct{ Version string }
	if json.Unmarshal(raw, &version) != nil {
		return nil, time.Time{}, ErrRegistrationUnavailable
	}
	if version.Version == "system-backup-original-sql-signing-input.v1" {
		return raw, until, nil
	}
	var index frozenSigningChunkIndex
	if !decodeFrozenSigningJSON(raw, &index) || index.Version != "system-backup-original-sql-signing-chunks.v1" || index.Size <= maxSigningEvidenceInlineBytes || index.Size > maxFrozenSigningEvidenceBytes || index.Count != (index.Size+signingEvidenceChunkBytes-1)/signingEvidenceChunkBytes || !signingDigest.MatchString(index.SHA256) {
		return nil, time.Time{}, ErrRegistrationUnavailable
	}
	joined := make([]byte, 0, index.Size)
	for i := 0; i < index.Count; i++ {
		body, end, e := a.readFrozenEvidence(ctx, view, lock, signingChunkID(id, i))
		if e != nil || !end.Equal(until) {
			return nil, time.Time{}, ErrRegistrationUnavailable
		}
		var chunk frozenSigningChunk
		size := signingEvidenceChunkBytes
		if i == index.Count-1 {
			size = index.Size - i*signingEvidenceChunkBytes
		}
		if !decodeFrozenSigningJSON(body, &chunk) || chunk.Version != "system-backup-original-sql-signing-chunk.v1" || chunk.Parent != id || chunk.Index != i || chunk.Count != index.Count || len(chunk.Data) != size {
			return nil, time.Time{}, ErrRegistrationUnavailable
		}
		joined = append(joined, chunk.Data...)
	}
	h := sha256.Sum256(joined)
	if hex.EncodeToString(h[:]) != index.SHA256 {
		return nil, time.Time{}, ErrRegistrationUnavailable
	}
	return joined, until, nil
}

func (a *SQLArtifactSigningAuthority) authorize(ctx context.Context, r ArtifactSigningAuthorizationRequest) (OriginalSigningUse, signingSQLFacts, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || r.Task != a.task || r.Signing.Binding != a.binding || !signingDigest.MatchString(r.Signing.InputSHA256) {
		return OriginalSigningUse{}, signingSQLFacts{}, ErrRegistrationUnavailable
	}
	if a.useCheck != nil && a.useCheck(ctx) != nil {
		return OriginalSigningUse{}, signingSQLFacts{}, ErrRegistrationUnavailable
	}
	tx, err := a.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return OriginalSigningUse{}, signingSQLFacts{}, ErrRegistrationUnavailable
	}
	defer tx.Rollback()
	facts, until, err := a.current(ctx, tx, false)
	if err != nil {
		return OriginalSigningUse{}, signingSQLFacts{}, err
	}
	raw, evidenceUntil, err := a.readFrozen(ctx, tx, false)
	if err != nil {
		return OriginalSigningUse{}, signingSQLFacts{}, ErrRegistrationUnavailable
	}
	var frozen frozenSQLSigningInput
	if _, e := jsoncanonicalizer.Transform(raw); e != nil {
		return OriginalSigningUse{}, signingSQLFacts{}, ErrRegistrationUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&frozen) != nil || d.Decode(new(any)) != io.EOF || frozen.Version != "system-backup-original-sql-signing-input.v1" || frozen.Authorization != r || frozen.CaptureResultSHA256 != facts.CaptureHash || frozen.CaptureEpoch != facts.Epoch || validateFrozenSigningInput(frozen.Input, a.task, a.binding) != nil {
		return OriginalSigningUse{}, signingSQLFacts{}, ErrRegistrationUnavailable
	}
	h := sha256.Sum256(frozen.Input)
	if hex.EncodeToString(h[:]) != r.Signing.InputSHA256 {
		return OriginalSigningUse{}, signingSQLFacts{}, ErrRegistrationUnavailable
	}
	if evidenceUntil.Before(until) {
		until = evidenceUntil
	}
	if !time.Now().Before(until) {
		return OriginalSigningUse{}, signingSQLFacts{}, ErrRegistrationUnavailable
	}
	// End the SQL snapshot before external workload rechecks. The resolver calls
	// this again after JWT login and immediately before provider use.
	if tx.Rollback() != nil {
		return OriginalSigningUse{}, signingSQLFacts{}, ErrRegistrationUnavailable
	}
	if a.useCheck != nil && a.useCheck(ctx) != nil {
		return OriginalSigningUse{}, signingSQLFacts{}, ErrRegistrationUnavailable
	}
	return OriginalSigningUse{Request: r.Signing, Workload: a.task.Workload, NotBefore: a.notBefore, ExpiresAt: until}, facts, nil
}

func (a *SQLArtifactSigningAuthority) AuthorizeArtifactSigning(ctx context.Context, r ArtifactSigningAuthorizationRequest) (AuthorizedArtifactSigningUse, error) {
	use, facts, err := a.authorize(ctx, r)
	if err != nil {
		return AuthorizedArtifactSigningUse{}, err
	}
	use.Recheck = func(c context.Context, request TransitSigningRequest) error {
		if request != r.Signing {
			return ErrRegistrationUnavailable
		}
		current, again, e := a.authorize(c, r)
		if e != nil || again != facts || !current.ExpiresAt.Equal(use.ExpiresAt) {
			return ErrRegistrationUnavailable
		}
		return nil
	}
	return AuthorizedArtifactSigningUse{Task: a.task, Use: use}, nil
}
