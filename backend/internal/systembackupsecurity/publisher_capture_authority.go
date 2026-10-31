package systembackupsecurity

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const PublisherCaptureGrantDomain = "system-backup-original-publisher-verifier-grant.v1\x00"
const PublisherCaptureGrantVersion = "system-backup-publisher-verifier-grant.v1"

func publisherCaptureContext(ctx context.Context) bool {
	return !candidateAuthorityNil(ctx) && reflect.TypeOf(ctx).Comparable() && ctx.Err() == nil
}

// These are the original deployment/record-custody pins, never an old live
// capture claim. A controlled Records reader must retain and check its actual
// original deployment authorization/record-key identity against this binding.
type PublisherCaptureDeployment struct {
	InstallationID, ServerUUID, Database, DatabaseAccount                   string
	ControllerOwner                                                         string // original capture deployment owner, not PublisherOwner
	ConfigVersion                                                           uint64
	ConfigSHA256, ProfileSHA256, DeploymentConfigSHA256, CaptureGrantSHA256 string
	NotBefore, Until                                                        time.Time
}

type PublisherCaptureWorkload struct {
	Namespace, NamespaceUID, PodName, PodUID, ServiceAccountName, ServiceAccountUID string
	PublisherOwner, GrantSHA256                                                     string
}

// Issued only by the independent original publisher-verification business
// owner. No signing/Generate/capture/restore permission is inferred from it.
type PublisherCaptureGrant struct {
	Version          string
	Deployment       PublisherCaptureDeployment
	Workload         PublisherCaptureWorkload // GrantSHA256 empty in signed payload
	NotBefore, Until time.Time
	Revoked          bool
}
type SignedPublisherCaptureGrant struct{ Record, Signature []byte }
type PublisherCaptureGrantMount struct {
	File, SHA256 string
	Issuer       ed25519.PublicKey
}
type PublisherCaptureAuthorityConfig struct {
	DB         *sql.DB
	Kubernetes kubernetes.Interface
	Deployment PublisherCaptureDeployment
	Workload   PublisherCaptureWorkload
	GrantMount PublisherCaptureGrantMount
}

// Part is a lookup locator, not proof that a part exists. Only the original
// authenticated plan's unique match may select ciphertext/KeyRequest later.
type PublisherCaptureScope struct {
	BackupPublicID   string
	Claim            SQLSigningClaim
	CaptureAttemptNo uint64
	Part             string
}

type PublisherCaptureFacts struct {
	InstallationID, BackupPublicID, RequestID, Status string
	ConfigVersion                                     uint64
	ConfigSHA256, TaskPurpose, RequestedParts         string
	CaptureAttemptNo, CaptureEpoch                    uint64
	CaptureResultSHA256                               string
	ClaimLeaseUntil, TaskDeadline                     time.Time
	CollectorsStoppedAt, SourceResumedAt              time.Time
}

type SQLPublisherCaptureAuthority struct {
	cfg   PublisherCaptureAuthorityConfig
	scope PublisherCaptureScope
	until time.Time
	facts PublisherCaptureFacts
	bound bool
}
type SQLPublisherCaptureGuard struct {
	authority    *SQLPublisherCaptureAuthority
	ctx          context.Context
	tx           *sql.Tx
	facts        PublisherCaptureFacts
	until, floor time.Time
}

func (a *SQLPublisherCaptureAuthority) Scope() PublisherCaptureScope {
	if a == nil {
		return PublisherCaptureScope{}
	}
	return a.scope
}
func (a *SQLPublisherCaptureAuthority) Deployment() PublisherCaptureDeployment {
	if a == nil {
		return PublisherCaptureDeployment{}
	}
	return a.cfg.Deployment
}
func (a *SQLPublisherCaptureAuthority) ValidUntil() time.Time {
	if a == nil {
		return time.Time{}
	}
	return a.until
}
func (g *SQLPublisherCaptureGuard) Facts() PublisherCaptureFacts {
	if g == nil {
		return PublisherCaptureFacts{}
	}
	return g.facts
}
func (g *SQLPublisherCaptureGuard) ValidUntil() time.Time {
	if g == nil {
		return time.Time{}
	}
	return g.until
}

func (a *SQLPublisherCaptureAuthority) grant(ctx context.Context) (PublisherCaptureGrant, error) {
	bad := func() (PublisherCaptureGrant, error) { return PublisherCaptureGrant{}, ErrRegistrationUnavailable }
	if a == nil || !publisherCaptureContext(ctx) {
		return bad()
	}
	m := a.cfg.GrantMount
	if !filepath.IsAbs(m.File) || filepath.Clean(m.File) != m.File || !signingDigest.MatchString(m.SHA256) || len(m.Issuer) != ed25519.PublicKeySize || a.cfg.Workload.GrantSHA256 != m.SHA256 || m.SHA256 == a.cfg.Deployment.CaptureGrantSHA256 {
		return bad()
	}
	f, err := os.Open(m.File)
	if err != nil {
		return bad()
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 65536 {
		return bad()
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	sum := sha256.Sum256(raw)
	if err != nil || len(raw) > 65536 || hex.EncodeToString(sum[:]) != m.SHA256 {
		return bad()
	}
	var signed SignedPublisherCaptureGrant
	if !decodeFrozenSigningJSON(raw, &signed) || len(signed.Record) > 32768 || !ed25519.Verify(m.Issuer, append([]byte(PublisherCaptureGrantDomain), signed.Record...), signed.Signature) {
		return bad()
	}
	var grant PublisherCaptureGrant
	if !decodeFrozenSigningJSON(signed.Record, &grant) {
		return bad()
	}
	expected := a.cfg.Workload
	expected.GrantSHA256 = ""
	now := time.Now()
	if grant.Version != PublisherCaptureGrantVersion || grant.Deployment != a.cfg.Deployment || grant.Workload != expected || grant.Revoked || grant.NotBefore.IsZero() || !grant.Until.After(grant.NotBefore) || grant.Until.Sub(grant.NotBefore) > 24*time.Hour || now.Before(grant.NotBefore) || !now.Before(grant.Until) {
		return bad()
	}
	return grant, nil
}

// CheckWorkload performs no SQL and must only be called outside original
// transactions. The exact real Pod/SA/namespace UID comes from the signed grant.
func (a *SQLPublisherCaptureAuthority) CheckWorkload(ctx context.Context) error {
	if a == nil || !publisherCaptureContext(ctx) || candidateAuthorityNil(a.cfg.Kubernetes) {
		return ErrRegistrationUnavailable
	}
	if _, err := a.grant(ctx); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	w := a.cfg.Workload
	k := a.cfg.Kubernetes
	ns, err := k.CoreV1().Namespaces().Get(ctx, w.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != w.NamespaceUID || ns.DeletionTimestamp != nil {
		return ErrRegistrationUnavailable
	}
	pod, err := k.CoreV1().Pods(w.Namespace).Get(ctx, w.PodName, metav1.GetOptions{})
	if err != nil || string(pod.UID) != w.PodUID || pod.DeletionTimestamp != nil || string(pod.Status.Phase) != "Running" || pod.Spec.ServiceAccountName != w.ServiceAccountName {
		return ErrRegistrationUnavailable
	}
	sa, err := k.CoreV1().ServiceAccounts(w.Namespace).Get(ctx, w.ServiceAccountName, metav1.GetOptions{})
	if err != nil || string(sa.UID) != w.ServiceAccountUID || sa.DeletionTimestamp != nil {
		return ErrRegistrationUnavailable
	}
	// Material replacement and expiry may occur during the final slow API GET.
	// Re-read the same independently pinned grant after ALL workload I/O.
	grant, err := a.grant(ctx)
	now := time.Now()
	if err != nil || now.Before(a.cfg.Deployment.NotBefore) || !now.Before(a.cfg.Deployment.Until) || now.Before(grant.NotBefore) || !now.Before(grant.Until) || !a.until.IsZero() && !now.Before(a.until) {
		return ErrRegistrationUnavailable
	}
	return nil
}

// Startup observation only. It verifies the separately signed, pinned current
// deployment/workload without selecting a task, record, KeyRequest or DEK.
// Every later read/use still requires NewSQLPublisherCaptureAuthority.
func CheckPublisherCaptureDeploymentWorkload(ctx context.Context, cfg PublisherCaptureAuthorityConfig) error {
	if cfg.DB == nil || candidateAuthorityNil(cfg.Kubernetes) || !publisherCaptureContext(ctx) || cfg.Workload.PublisherOwner != "public:"+cfg.Workload.PodUID || cfg.Workload.PublisherOwner == cfg.Deployment.ControllerOwner {
		return ErrRegistrationUnavailable
	}
	cfg.GrantMount.Issuer = append(ed25519.PublicKey(nil), cfg.GrantMount.Issuer...)
	a := &SQLPublisherCaptureAuthority{cfg: cfg}
	return a.CheckWorkload(ctx)
}

// Local pinned signature/window observation only, safe inside a short SQL
// deployment probe. It grants no task, record or DEK use and performs no Kube.
func CheckPublisherCaptureDeploymentGrant(ctx context.Context, cfg PublisherCaptureAuthorityConfig) (PublisherCaptureGrant, error) {
	if cfg.DB == nil || !publisherCaptureContext(ctx) || cfg.Workload.PublisherOwner != "public:"+cfg.Workload.PodUID || cfg.Workload.PublisherOwner == cfg.Deployment.ControllerOwner {
		return PublisherCaptureGrant{}, ErrRegistrationUnavailable
	}
	a := &SQLPublisherCaptureAuthority{cfg: cfg}
	return a.grant(ctx)
}

func NewSQLPublisherCaptureAuthority(ctx context.Context, cfg PublisherCaptureAuthorityConfig, scope PublisherCaptureScope) (*SQLPublisherCaptureAuthority, error) {
	if !publisherCaptureContext(ctx) || cfg.DB == nil || candidateAuthorityNil(cfg.Kubernetes) || !acceptanceBackupID.MatchString(scope.BackupPublicID) || scope.Claim.RowVersion == 0 || scope.CaptureAttemptNo == 0 || scope.CaptureAttemptNo > uint64(^uint32(0)) || !providerBoundedString(scope.Part) || len(scope.Part) > 128 || scope.Claim.ControllerOwner != cfg.Workload.PublisherOwner {
		return nil, ErrRegistrationUnavailable
	}
	d, w := cfg.Deployment, cfg.Workload
	for _, v := range []string{d.InstallationID, d.ServerUUID, d.Database, d.DatabaseAccount, d.ControllerOwner, w.Namespace, w.NamespaceUID, w.PodName, w.PodUID, w.ServiceAccountName, w.ServiceAccountUID, w.PublisherOwner} {
		if !providerBoundedString(v) {
			return nil, ErrRegistrationUnavailable
		}
	}
	for _, v := range []string{d.ConfigSHA256, d.ProfileSHA256, d.DeploymentConfigSHA256, d.CaptureGrantSHA256} {
		if !signingDigest.MatchString(v) {
			return nil, ErrRegistrationUnavailable
		}
	}
	if d.ConfigVersion == 0 || d.NotBefore.IsZero() || !d.Until.After(d.NotBefore) || w.PublisherOwner != "public:"+w.PodUID || w.PublisherOwner == d.ControllerOwner {
		return nil, ErrRegistrationUnavailable
	}
	cfg.GrantMount.Issuer = append(ed25519.PublicKey(nil), cfg.GrantMount.Issuer...)
	a := &SQLPublisherCaptureAuthority{cfg: cfg, scope: scope}
	if err := a.CheckWorkload(ctx); err != nil {
		return nil, err
	}
	tx, err := cfg.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	defer tx.Rollback()
	g, err := a.Bind(ctx, tx)
	if err != nil {
		return nil, err
	}
	a.until = g.ValidUntil()
	a.facts = g.Facts()
	a.bound = true
	if tx.Rollback() != nil || a.CheckWorkload(ctx) != nil {
		return nil, ErrRegistrationUnavailable
	}
	// The final workload/material I/O can race a real claim renewal. Do not
	// return the earlier SQL proof or silently adopt the fresh token/facts.
	if a.checkSQL(ctx) != nil {
		return nil, ErrRegistrationUnavailable
	}
	return a, nil
}

func (a *SQLPublisherCaptureAuthority) current(ctx context.Context, tx *sql.Tx) (PublisherCaptureFacts, time.Time, time.Time, error) {
	bad := func() (PublisherCaptureFacts, time.Time, time.Time, error) {
		return PublisherCaptureFacts{}, time.Time{}, time.Time{}, ErrRegistrationUnavailable
	}
	if a == nil || !publisherCaptureContext(ctx) || tx == nil {
		return bad()
	}
	grant, err := a.grant(ctx)
	if err != nil {
		return bad()
	}
	d, scope := a.cfg.Deployment, a.scope
	var account, server, database string
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT CURRENT_USER(),@@server_uuid,DATABASE(),UTC_TIMESTAMP(6)").Scan(&account, &server, &database, &now) != nil || account != d.DatabaseAccount || server != d.ServerUUID || database != d.Database || now.Before(d.NotBefore) || !now.Before(d.Until) || now.Before(grant.NotBefore) || !now.Before(grant.Until) {
		return bad()
	}
	var facts PublisherCaptureFacts
	var schema, kind, owner string
	var version uint64
	if tx.QueryRowContext(ctx, `SELECT schema_version,task_type,origin_installation_id,request_id,status,controller_owner,row_version,controller_lease_expires_at,deadline_at,config_version,config_snapshot_sha256,task_purpose,requested_parts FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? FOR SHARE`, d.InstallationID, scope.BackupPublicID).Scan(&schema, &kind, &facts.InstallationID, &facts.RequestID, &facts.Status, &owner, &version, &facts.ClaimLeaseUntil, &facts.TaskDeadline, &facts.ConfigVersion, &facts.ConfigSHA256, &facts.TaskPurpose, &facts.RequestedParts) != nil || schema != "system-backup-task.v1" || kind != "backup" || facts.InstallationID != d.InstallationID || owner != scope.Claim.ControllerOwner || version != scope.Claim.RowVersion || facts.ConfigVersion != d.ConfigVersion || facts.ConfigSHA256 != d.ConfigSHA256 || !providerBoundedString(facts.RequestID) || !now.Before(facts.ClaimLeaseUntil) || !now.Before(facts.TaskDeadline) {
		return bad()
	}
	if facts.Status != "validating" && facts.Status != "publishing" && facts.Status != "finalization_unknown" {
		return bad()
	}
	var status string
	if tx.QueryRowContext(ctx, `SELECT attempt_no,status FROM system_backup_v2_attempts WHERE target_type='backup' AND target_public_id=? AND phase='capture' ORDER BY attempt_no DESC LIMIT 1 FOR SHARE`, scope.BackupPublicID).Scan(&facts.CaptureAttemptNo, &status) != nil || facts.CaptureAttemptNo != scope.CaptureAttemptNo || status != "sealed" {
		return bad()
	}
	var canceled uint64
	if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_operations WHERE origin_installation_id=? AND target_type='backup' AND target_public_id=? AND operation_type='cancel' AND status IN ('pending','running') FOR SHARE`, d.InstallationID, scope.BackupPublicID).Scan(&canceled) != nil || canceled != 0 {
		return bad()
	}
	if tx.QueryRowContext(ctx, `SELECT gate_generation,collectors_stopped_at,source_resumed_at FROM system_backup_v2_runtime_captures WHERE task_public_id=? FOR SHARE`, scope.BackupPublicID).Scan(&facts.CaptureEpoch, &facts.CollectorsStoppedAt, &facts.SourceResumedAt) != nil || facts.CaptureEpoch == 0 || facts.CollectorsStoppedAt.IsZero() || facts.SourceResumedAt.IsZero() || facts.SourceResumedAt.Before(facts.CollectorsStoppedAt) || facts.SourceResumedAt.After(now) {
		return bad()
	}
	if tx.QueryRowContext(ctx, `SELECT payload_sha256 FROM system_backup_v2_execution_records WHERE origin_installation_id=? AND task_public_id=? AND attempt_no=? AND phase='capture' AND record_kind='capture_result' FOR SHARE`, d.InstallationID, scope.BackupPublicID, scope.CaptureAttemptNo).Scan(&facts.CaptureResultSHA256) != nil || !signingDigest.MatchString(facts.CaptureResultSHA256) {
		return bad()
	}
	facts.BackupPublicID = scope.BackupPublicID
	if a.bound && facts != a.facts {
		return bad()
	}
	until := grant.Until
	for _, bound := range []time.Time{d.Until, facts.ClaimLeaseUntil, facts.TaskDeadline, a.until} {
		if !bound.IsZero() && bound.Before(until) {
			until = bound
		}
	}
	if !now.Before(until) {
		return bad()
	}
	return facts, until, now, nil
}

// Bind/RecheckTx contain ONLY SQL plus bounded local signature checks. They do
// not contact Kube/provider, commit, return keys, or authorize arbitrary records.
func (a *SQLPublisherCaptureAuthority) Bind(ctx context.Context, tx *sql.Tx) (*SQLPublisherCaptureGuard, error) {
	if !publisherCaptureContext(ctx) {
		return nil, ErrRegistrationUnavailable
	}
	facts, until, now, err := a.current(ctx, tx)
	if err != nil {
		return nil, err
	}
	return &SQLPublisherCaptureGuard{authority: a, ctx: ctx, tx: tx, facts: facts, until: until, floor: now}, nil
}
func (g *SQLPublisherCaptureGuard) RecheckTx(ctx context.Context, tx *sql.Tx) error {
	if g == nil || !publisherCaptureContext(ctx) || !publisherCaptureContext(g.ctx) || ctx != g.ctx || tx == nil || tx != g.tx {
		return ErrRegistrationUnavailable
	}
	facts, until, now, err := g.authority.current(ctx, tx)
	if err != nil || facts != g.facts || !until.Equal(g.until) || now.Before(g.floor) {
		return ErrRegistrationUnavailable
	}
	g.floor = now
	return nil
}
func (a *SQLPublisherCaptureAuthority) Check(ctx context.Context) error {
	if a == nil || a.CheckWorkload(ctx) != nil {
		return ErrRegistrationUnavailable
	}
	if err := a.checkSQL(ctx); err != nil {
		return err
	}
	if a.CheckWorkload(ctx) != nil {
		return ErrRegistrationUnavailable
	}
	// Last external I/O precedes this short same-claim/facts/window check.
	return a.checkSQL(ctx)
}

func (a *SQLPublisherCaptureAuthority) checkSQL(ctx context.Context) error {
	if a == nil || !publisherCaptureContext(ctx) {
		return ErrRegistrationUnavailable
	}
	tx, err := a.cfg.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return ErrRegistrationUnavailable
	}
	defer tx.Rollback()
	guard, err := a.Bind(ctx, tx)
	if err != nil {
		return err
	}
	if err = guard.RecheckTx(ctx, tx); err != nil {
		return err
	}
	if tx.Rollback() != nil {
		return ErrRegistrationUnavailable
	}
	return nil
}
