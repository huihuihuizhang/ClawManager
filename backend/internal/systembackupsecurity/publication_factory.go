package systembackupsecurity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const PublicationSignerMaterialsVersion = "system-backup-publication-signers.v1"

// PublicationSignerInput is an independent deployment/startup pin. Its SHA
// must not be embedded back into the parent config/Forward grant being signed.
type PublicationSignerInput struct{ File, SHA256 string }

// PublicationSignerRuntime is supplied by the actual controller startup, not
// an HTTP task. PublisherOwner is the exact owner used by original AcquireClaim.
type PublicationSignerRuntime struct {
	InstallationID, ServerUUID, Database, PublisherOwner                            string
	Namespace, NamespaceUID, PodName, PodUID, ServiceAccountName, ServiceAccountUID string
}

type PublicationSigningMount struct {
	Binding   TransitSigningBinding `json:"binding"`
	AuthMount string                `json:"auth_mount"`
	Role      string                `json:"role"`
	Policy    string                `json:"policy"`
	JWTFile   string                `json:"jwt_file"`
	CAFile    string                `json:"ca_file"`
	CASHA256  string                `json:"ca_sha256"`
}

// No task, claim, private key, token, capture grant or parent config digest is
// derived here. SQLOwner permissions reside in the original signed record.
type PublicationSignerMaterials struct {
	Version string                    `json:"schema_version"`
	Record  FileSigningRecordReader   `json:"record"`
	Pin     InstallationSigningPin    `json:"pin"`
	Mounts  []PublicationSigningMount `json:"mounts"`
}

func loadPublicationSignerMaterials(input PublicationSignerInput) (PublicationSignerMaterials, error) {
	raw, err := publicationPinnedFile(input.File, input.SHA256, 1<<20)
	var materials PublicationSignerMaterials
	if err != nil || !decodeFrozenSigningJSON(raw, &materials) || materials.Version != PublicationSignerMaterialsVersion || len(materials.Mounts) != 3 {
		return PublicationSignerMaterials{}, ErrRegistrationUnavailable
	}
	return materials, nil
}

// Public history survives claim release, workload/JWT disappearance and expiry
// of signing permission. It remains bound to the independently deployed file
// pin and original signed key registry, including its current revocations.
func LoadPublicationSignerHistory(ctx context.Context, input PublicationSignerInput) (*ArtifactSigningKeyHistory, error) {
	materials, err := loadPublicationSignerMaterials(input)
	if err != nil {
		return nil, err
	}
	return LoadInstallationSigningHistory(ctx, materials.Record, materials.Pin)
}

type SQLPublicationSignerFactory struct {
	db         *sql.DB
	kubernetes kubernetes.Interface
	runtime    PublicationSignerRuntime
	input      PublicationSignerInput
	materials  PublicationSignerMaterials
	mounts     []SigningJWTMount
}

func publicationPinnedFile(path, expected string, max int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !signingDigest.MatchString(expected) {
		return nil, ErrRegistrationUnavailable
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > max {
		return nil, ErrRegistrationUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	sum := sha256.Sum256(raw)
	if err != nil || int64(len(raw)) > max || hex.EncodeToString(sum[:]) != expected {
		return nil, ErrRegistrationUnavailable
	}
	return raw, nil
}

func (f *SQLPublicationSignerFactory) local() error {
	if f == nil {
		return ErrRegistrationUnavailable
	}
	if _, err := publicationPinnedFile(f.input.File, f.input.SHA256, 1<<20); err != nil {
		return err
	}
	for _, mount := range f.materials.Mounts {
		if _, err := publicationPinnedFile(mount.CAFile, mount.CASHA256, 65536); err != nil {
			return err
		}
	}
	return nil
}

type publicationRecordReader struct{ factory *SQLPublicationSignerFactory }

func (r publicationRecordReader) ReadSigningRecord(ctx context.Context) ([]byte, []byte, error) {
	if r.factory == nil || r.factory.local() != nil {
		return nil, nil, ErrRegistrationUnavailable
	}
	return r.factory.materials.Record.ReadSigningRecord(ctx)
}

func (f *SQLPublicationSignerFactory) workload(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || f == nil || f.kubernetes == nil || f.local() != nil {
		return ErrRegistrationUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r := f.runtime
	ns, err := f.kubernetes.CoreV1().Namespaces().Get(bounded, r.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != r.NamespaceUID || ns.DeletionTimestamp != nil {
		return ErrRegistrationUnavailable
	}
	pod, err := f.kubernetes.CoreV1().Pods(r.Namespace).Get(bounded, r.PodName, metav1.GetOptions{})
	if err != nil || string(pod.UID) != r.PodUID || pod.DeletionTimestamp != nil || string(pod.Status.Phase) != "Running" || pod.Spec.ServiceAccountName != r.ServiceAccountName {
		return ErrRegistrationUnavailable
	}
	sa, err := f.kubernetes.CoreV1().ServiceAccounts(r.Namespace).Get(bounded, r.ServiceAccountName, metav1.GetOptions{})
	if err != nil || string(sa.UID) != r.ServiceAccountUID || sa.DeletionTimestamp != nil {
		return ErrRegistrationUnavailable
	}
	return nil
}

// NewSQLPublicationSignerFactory consumes only independently pinned mounted
// original-owner materials and real controller identity. It acquires no claim,
// creates no task and caches no task/claim/signer. No provider login occurs.
func NewSQLPublicationSignerFactory(ctx context.Context, db *sql.DB, k kubernetes.Interface, runtime PublicationSignerRuntime, input PublicationSignerInput) (*SQLPublicationSignerFactory, error) {
	if ctx == nil || ctx.Err() != nil || db == nil || k == nil {
		return nil, ErrRegistrationUnavailable
	}
	for _, value := range []string{runtime.InstallationID, runtime.ServerUUID, runtime.Database, runtime.PublisherOwner, runtime.Namespace, runtime.NamespaceUID, runtime.PodName, runtime.PodUID, runtime.ServiceAccountName, runtime.ServiceAccountUID} {
		if !providerBoundedString(value) {
			return nil, ErrRegistrationUnavailable
		}
	}
	materials, err := loadPublicationSignerMaterials(input)
	if err != nil || materials.Pin.InstallationID != runtime.InstallationID {
		return nil, ErrRegistrationUnavailable
	}
	f := &SQLPublicationSignerFactory{db: db, kubernetes: k, runtime: runtime, input: input, materials: materials}
	if !filepath.IsAbs(materials.Record.RecordFile) || !filepath.IsAbs(materials.Record.SignatureFile) || filepath.Clean(materials.Record.RecordFile) != materials.Record.RecordFile || filepath.Clean(materials.Record.SignatureFile) != materials.Record.SignatureFile || materials.Record.RecordFile == materials.Record.SignatureFile {
		return nil, ErrRegistrationUnavailable
	}
	for _, m := range materials.Mounts {
		if m.Binding.InstallationID != runtime.InstallationID || !filepath.IsAbs(m.JWTFile) || filepath.Clean(m.JWTFile) != m.JWTFile || m.JWTFile == materials.Record.RecordFile || m.JWTFile == materials.Record.SignatureFile || m.JWTFile == input.File {
			return nil, ErrRegistrationUnavailable
		}
		ca, e := publicationPinnedFile(m.CAFile, m.CASHA256, 65536)
		if e != nil {
			return nil, e
		}
		f.mounts = append(f.mounts, SigningJWTMount{Binding: m.Binding, AuthMount: m.AuthMount, Role: m.Role, Policy: m.Policy, JWTFile: m.JWTFile, CAPEM: ca, CASHA256: m.CASHA256})
	}
	// Validate all transport pins now, without a token request.
	tokens, err := NewJWTSigningTokenSource(f.mounts)
	if err != nil {
		return nil, err
	}
	tokens.Close()
	if f.workload(ctx) != nil {
		return nil, ErrRegistrationUnavailable
	}
	reader := publicationRecordReader{f}
	recordRaw, signature, err := reader.ReadSigningRecord(ctx)
	if err != nil {
		return nil, err
	}
	record, _, err := authenticateInstallationSigning(recordRaw, signature, materials.Pin, time.Now())
	if err != nil {
		return nil, err
	}
	var account, server, database string
	if db.QueryRowContext(ctx, "SELECT CURRENT_USER(),@@server_uuid,DATABASE()").Scan(&account, &server, &database) != nil || server != runtime.ServerUUID || database != runtime.Database {
		return nil, ErrRegistrationUnavailable
	}
	permissions := map[string]InstallationSigningPermission{}
	for _, permission := range record.Permissions {
		permissions[permission.Binding.Purpose] = permission
	}
	var originalConfigVersion uint64
	var originalConfigSHA string
	for _, mount := range f.mounts {
		p := permissions[mount.Binding.Purpose]
		g := p.SQLOwner
		if p.Binding != mount.Binding || p.AuthMount != mount.AuthMount || p.Role != mount.Role || p.Policy != mount.Policy || p.CASHA256 != mount.CASHA256 || g == nil || g.ServerUUID != server || g.Database != database || g.DatabaseAccount != account || g.ControllerOwner != runtime.PublisherOwner || g.Workload != (SigningWorkloadIdentity{runtime.Namespace, runtime.PodUID, runtime.ServiceAccountUID}) || g.ConfigVersion == 0 || !signingDigest.MatchString(g.ConfigSHA256) {
			return nil, ErrRegistrationUnavailable
		}
		if originalConfigVersion != 0 && (originalConfigVersion != g.ConfigVersion || originalConfigSHA != g.ConfigSHA256) {
			return nil, ErrRegistrationUnavailable
		}
		originalConfigVersion = g.ConfigVersion
		originalConfigSHA = g.ConfigSHA256
	}
	return f, nil
}

type SQLPublicationTaskSigners struct {
	factory *SQLPublicationSignerFactory
	signers *SQLInstallationArtifactSigners
}
type SQLPreparedPublicationRecord struct {
	task   *SQLPublicationTaskSigners
	record *PreparedPublicationRecord
}

// ForTask uses the exact claim obtained by the original controller. Request ID
// and latest sealed capture attempt come from original SQL, never arguments.
// It neither adopts a newer row version nor repairs a released/expired claim.
func (f *SQLPublicationSignerFactory) ForTask(ctx context.Context, backupPublicID string, claim SQLSigningClaim) (*SQLPublicationTaskSigners, error) {
	if f == nil || !acceptanceBackupID.MatchString(backupPublicID) || claim.ControllerOwner != f.runtime.PublisherOwner || claim.RowVersion == 0 || f.workload(ctx) != nil {
		return nil, ErrRegistrationUnavailable
	}
	var task ArtifactSigningTask
	task.BackupPublicID = backupPublicID
	task.Workload = SigningWorkloadIdentity{f.runtime.Namespace, f.runtime.PodUID, f.runtime.ServiceAccountUID}
	var status string
	if f.db.QueryRowContext(ctx, `SELECT request_id FROM system_backup_v2_backups WHERE origin_installation_id=? AND public_id=? AND controller_owner=? AND row_version=? AND status IN ('validating','publishing') AND controller_lease_expires_at>UTC_TIMESTAMP(6) AND deadline_at>UTC_TIMESTAMP(6)`, f.runtime.InstallationID, backupPublicID, claim.ControllerOwner, claim.RowVersion).Scan(&task.OperationID) != nil {
		return nil, ErrRegistrationUnavailable
	}
	if f.db.QueryRowContext(ctx, `SELECT attempt_no,status FROM system_backup_v2_attempts WHERE target_type='backup' AND target_public_id=? AND phase='capture' ORDER BY attempt_no DESC LIMIT 1`, backupPublicID).Scan(&task.AttemptNo, &status) != nil || status != "sealed" {
		return nil, ErrRegistrationUnavailable
	}
	s, err := NewSQLInstallationArtifactSigners(ctx, f.db, publicationRecordReader{f}, f.materials.Pin, f.mounts, task, claim)
	if err != nil {
		return nil, err
	}
	q := &SQLPublicationTaskSigners{factory: f, signers: s}
	for _, owner := range s.owners {
		owner.useCheck = f.workload
	}
	if q.check(ctx) != nil {
		s.Close()
		return nil, ErrRegistrationUnavailable
	}
	return q, nil
}

func (q *SQLPublicationTaskSigners) check(ctx context.Context) error {
	if q == nil || q.factory == nil || q.signers == nil || q.factory.workload(ctx) != nil {
		return ErrRegistrationUnavailable
	}
	// Read transactions finish before Kube/provider operations. Stage below
	// performs only local material checks plus its caller's original SQL tx.
	tx, err := q.factory.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return ErrRegistrationUnavailable
	}
	defer tx.Rollback()
	for _, purpose := range []string{"capture_certificate", "acceptance_record", "catalog_record"} {
		facts, _, e := q.signers.owners[purpose].current(ctx, tx, false)
		if e != nil || facts.Status != "validating" && facts.Status != "publishing" {
			return ErrRegistrationUnavailable
		}
	}
	if tx.Commit() != nil {
		return ErrRegistrationUnavailable
	}
	return nil
}

func (q *SQLPublicationTaskSigners) Close() {
	if q != nil && q.signers != nil {
		q.signers.Close()
	}
}
func (q *SQLPublicationTaskSigners) PublicationSigningKey(ctx context.Context, purpose string) (PublicationSigningKey, error) {
	if q.check(ctx) != nil {
		return PublicationSigningKey{}, ErrRegistrationUnavailable
	}
	return q.signers.PublicationSigningKey(ctx, purpose)
}
func (q *SQLPublicationTaskSigners) History(ctx context.Context) (*ArtifactSigningKeyHistory, error) {
	if q == nil || q.factory == nil {
		return nil, ErrRegistrationUnavailable
	}
	return q.factory.History(ctx)
}

func (f *SQLPublicationSignerFactory) History(ctx context.Context) (*ArtifactSigningKeyHistory, error) {
	if f == nil {
		return nil, ErrRegistrationUnavailable
	}
	return LoadPublicationSignerHistory(ctx, f.input)
}
func (q *SQLPublicationTaskSigners) PreparePublicationRecord(ctx context.Context, purpose string, payload []byte) (*SQLPreparedPublicationRecord, error) {
	if q.check(ctx) != nil {
		return nil, ErrRegistrationUnavailable
	}
	p, err := q.signers.PreparePublicationRecord(ctx, purpose, payload)
	if err != nil {
		return nil, err
	}
	return &SQLPreparedPublicationRecord{task: q, record: p}, nil
}
func (p *SQLPreparedPublicationRecord) Stage(ctx context.Context, tx *sql.Tx) error {
	if p == nil || p.task == nil || p.record == nil || p.task.factory.local() != nil {
		return ErrRegistrationUnavailable
	}
	return p.record.Stage(ctx, tx)
}
func (p *SQLPreparedPublicationRecord) SignCommitted(ctx context.Context) ([]byte, string, error) {
	if p == nil || p.task == nil || p.record == nil || p.task.check(ctx) != nil {
		return nil, "", ErrRegistrationUnavailable
	}
	raw, sum, err := p.record.SignCommitted(ctx)
	if err != nil || p.task.check(ctx) != nil {
		return nil, "", ErrRegistrationUnavailable
	}
	return raw, sum, nil
}
