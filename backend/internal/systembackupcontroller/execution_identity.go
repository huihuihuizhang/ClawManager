package systembackupcontroller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	d "clawreef/internal/systembackupdispatch"
)

// ExecutionGrant is issued by the deployment's independent signing authority.
// ConfigSHA256 binds the exact purposes/resources/versions admitted by A. This
// does not grant provider access, Job creation, publication, or recovery.
type ExecutionGrant struct {
	Version                string               `json:"schema_version"`
	InstallationID         string               `json:"installation_id"`
	ControllerOwner        string               `json:"controller_owner"`
	DatabaseAccount        string               `json:"database_account"`
	ServerUUID             string               `json:"server_uuid"`
	Database               string               `json:"database"`
	ConfigVersion          uint64               `json:"config_version"`
	ConfigSHA256           string               `json:"config_sha256"`
	ProfileSHA256          string               `json:"profile_sha256"`
	NotBefore              time.Time            `json:"not_before"`
	ExpiresAt              time.Time            `json:"expires_at"`
	Actions                []string             `json:"actions"`
	RecordKeys             []ExecutionRecordKey `json:"record_keys"`
	CaptureKeys            []ExecutionRecordKey `json:"capture_keys,omitempty"`
	DeploymentConfigSHA256 string               `json:"deployment_config_sha256,omitempty"`
	WorkerIssuerSHA256     string               `json:"worker_issuer_sha256,omitempty"`
}
type ExecutionRecordKey struct {
	Ref    string `json:"ref"`
	SHA256 string `json:"sha256"`
}
type executionGrantEnvelope struct {
	Payload   string `json:"payload_base64"`
	Signature string `json:"signature_base64"`
}

// PinnedExecutionIdentity authenticates the dedicated SQL workload against a
// signed, independently hash-pinned deployment grant. No request may supply its
// paths, trust key or digest. Recheck reads the SAME bytes, so removing/replacing
// a grant revokes it; neither a different grant nor a refreshed expiry is used.
type PinnedExecutionIdentity struct {
	path, digest, keyDirectory string
	public                     ed25519.PublicKey
	grant                      ExecutionGrant
}

func readExecutionFile(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrExecutionAuthority
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > max {
		return nil, ErrExecutionAuthority
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(raw)) > max {
		return nil, ErrExecutionAuthority
	}
	return raw, nil
}
func decodeExecutionJSON(raw []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(out) != nil || dec.Decode(new(any)) != io.EOF {
		return ErrExecutionAuthority
	}
	return nil
}

func NewPinnedExecutionIdentity(path, digest, keyDirectory string, public ed25519.PublicKey) (*PinnedExecutionIdentity, error) {
	if !filepath.IsAbs(path) || !filepath.IsAbs(keyDirectory) || !executionHash.MatchString(digest) || len(public) != ed25519.PublicKeySize {
		return nil, ErrExecutionAuthority
	}
	p := &PinnedExecutionIdentity{path: path, digest: digest, keyDirectory: keyDirectory, public: bytes.Clone(public)}
	raw, err := readExecutionFile(path, 65536)
	if err != nil {
		return nil, err
	}
	g, err := p.decode(raw)
	if err != nil {
		return nil, err
	}
	p.grant = g
	return p, nil
}

// LoadPinnedExecutionIdentity is the mounted deployment composition entry.
// Its trust anchor is independently pinned; the grant cannot supply its own key.
func LoadPinnedExecutionIdentity(path, digest, keyDirectory, publicPath, publicSHA256 string) (*PinnedExecutionIdentity, error) {
	if !filepath.IsAbs(publicPath) || !executionHash.MatchString(publicSHA256) {
		return nil, ErrExecutionAuthority
	}
	public, err := readExecutionFile(publicPath, ed25519.PublicKeySize)
	if err != nil || len(public) != ed25519.PublicKeySize || recordHash(public) != publicSHA256 {
		return nil, ErrExecutionAuthority
	}
	return NewPinnedExecutionIdentity(path, digest, keyDirectory, public)
}
func (p *PinnedExecutionIdentity) decode(raw []byte) (ExecutionGrant, error) {
	var g ExecutionGrant
	var e executionGrantEnvelope
	if recordHash(raw) != p.digest || decodeExecutionJSON(raw, &e) != nil {
		return g, ErrExecutionAuthority
	}
	body, err := base64.StdEncoding.Strict().DecodeString(e.Payload)
	if err != nil || len(body) > 32768 {
		return g, ErrExecutionAuthority
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(e.Signature)
	if err != nil || !ed25519.Verify(p.public, body, sig) || decodeExecutionJSON(body, &g) != nil {
		return g, ErrExecutionAuthority
	}
	account := strings.Split(g.DatabaseAccount, "@")
	if len(account) != 2 || ValidateControllerDatabaseUser(account[0]) != nil || account[1] == "" || g.Version != "system-backup-execution-grant.v1" || !installationIDPattern.MatchString(g.InstallationID) || !controllerOwnerPattern.MatchString(g.ControllerOwner) || g.Database == "" || g.ServerUUID == "" || g.ConfigVersion < 1 || !executionHash.MatchString(g.ConfigSHA256) || !executionHash.MatchString(g.ProfileSHA256) || g.NotBefore.IsZero() || !g.ExpiresAt.After(g.NotBefore) || g.ExpiresAt.Sub(g.NotBefore) > 24*time.Hour || len(g.Actions) == 0 || len(g.RecordKeys) == 0 || len(g.RecordKeys) > 8 {
		return ExecutionGrant{}, ErrExecutionAuthority
	}
	actions := map[string]bool{}
	for _, a := range g.Actions {
		if (a != "prepare" && a != "capture" && a != "preflight" && a != "recover" && a != "issue_worker") || actions[a] {
			return ExecutionGrant{}, ErrExecutionAuthority
		}
		actions[a] = true
	}
	if actions["issue_worker"] != executionHash.MatchString(g.WorkerIssuerSHA256) {
		return ExecutionGrant{}, ErrExecutionAuthority
	}
	keys := map[string]bool{}
	for _, k := range g.RecordKeys {
		if !controllerOwnerPattern.MatchString(k.Ref) || strings.Contains(k.Ref, "..") || strings.ContainsAny(k.Ref, "/\\") || !executionHash.MatchString(k.SHA256) || keys[k.Ref] {
			return ExecutionGrant{}, ErrExecutionAuthority
		}
		keys[k.Ref] = true
	}
	if g.DeploymentConfigSHA256 != "" && !executionHash.MatchString(g.DeploymentConfigSHA256) {
		return ExecutionGrant{}, ErrExecutionAuthority
	}
	if len(g.CaptureKeys) > 8 {
		return ExecutionGrant{}, ErrExecutionAuthority
	}
	for _, k := range g.CaptureKeys {
		if !controllerOwnerPattern.MatchString(k.Ref) || strings.Contains(k.Ref, "..") || strings.ContainsAny(k.Ref, "/\\") || !executionHash.MatchString(k.SHA256) || keys[k.Ref] {
			return ExecutionGrant{}, ErrExecutionAuthority
		}
		keys[k.Ref] = true
	}
	return g, nil
}
func (p *PinnedExecutionIdentity) current(a d.Authority, now time.Time) error {
	if p == nil || a.InstallationID != p.grant.InstallationID || a.ClaimOwner != p.grant.ControllerOwner || a.ConfigVersion != p.grant.ConfigVersion || a.ConfigSHA256 != p.grant.ConfigSHA256 || now.Before(p.grant.NotBefore) || !now.Before(p.grant.ExpiresAt) {
		return ErrExecutionAuthority
	}
	raw, err := readExecutionFile(p.path, 65536)
	if err != nil {
		return err
	}
	_, err = p.decode(raw)
	return err
}

type pinnedExecutionGuard struct {
	identity  *PinnedExecutionIdentity
	authority d.Authority
	until     time.Time
}

func (g *pinnedExecutionGuard) ValidUntil() time.Time { return g.until }
func (g *pinnedExecutionGuard) RecheckExecution(ctx context.Context, tx *sql.Tx, a d.Authority, now time.Time) error {
	if g == nil || a != g.authority || !now.Before(g.until) {
		return ErrExecutionAuthority
	}
	return g.identity.checkSQL(ctx, tx, a, now)
}
func (p *PinnedExecutionIdentity) checkSQL(ctx context.Context, tx *sql.Tx, a d.Authority, now time.Time) error {
	return p.checkSQLAction(ctx, tx, a, now, "")
}
func (p *PinnedExecutionIdentity) checkSQLAction(ctx context.Context, tx *sql.Tx, a d.Authority, now time.Time, requestedAction string) error {
	if tx == nil || p.current(a, now) != nil {
		return ErrExecutionAuthority
	}
	var account, server, database, status string
	if tx.QueryRowContext(ctx, "SELECT CURRENT_USER(),@@server_uuid,DATABASE()").Scan(&account, &server, &database) != nil || account != p.grant.DatabaseAccount || server != p.grant.ServerUUID || database != p.grant.Database {
		return ErrExecutionAuthority
	}
	table := "system_backup_v2_backups"
	action := "capture"
	if a.TaskType == "preflight" {
		table = "system_backup_v2_preflights"
		action = "preflight"
	} else if a.TaskType != "backup" {
		return ErrExecutionAuthority
	}
	if tx.QueryRowContext(ctx, "SELECT status FROM "+table+" WHERE origin_installation_id=? AND public_id=? FOR SHARE", a.InstallationID, a.TaskPublicID).Scan(&status) != nil {
		return ErrExecutionAuthority
	}
	var profile []byte
	var profileHash string
	if tx.QueryRowContext(ctx, "SELECT profile_json,profile_sha256 FROM system_backup_v2_execution_inputs WHERE origin_installation_id=? AND task_public_id=? AND task_type=? FOR SHARE", a.InstallationID, a.TaskPublicID, a.TaskType).Scan(&profile, &profileHash) != nil || profileHash != p.grant.ProfileSHA256 || recordHash(profile) != profileHash {
		return ErrExecutionAuthority
	}
	if a.TaskType == "backup" && a.MaintenanceOwner == "" && (status == "preparing" || status == "ready_for_capture" || status == "acquiring_gate") {
		action = "prepare"
	}
	if requestedAction != "" {
		if requestedAction != "recover" && requestedAction != "issue_worker" {
			return ErrExecutionAuthority
		}
		action = requestedAction
	}
	for _, v := range p.grant.Actions {
		if v == action {
			return nil
		}
	}
	return ErrExecutionAuthority
}

func (p *PinnedExecutionIdentity) AuthorizeWorkerIssuer(ctx context.Context, tx *sql.Tx, a d.Authority, digest string) error {
	var now time.Time
	if p == nil || digest != p.grant.WorkerIssuerSHA256 || !executionHash.MatchString(digest) || tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil {
		return ErrExecutionAuthority
	}
	return p.checkSQLAction(ctx, tx, a, now, "issue_worker")
}

// DeriveCaptureKey is a task/part-specific INTERNAL staging key for functional
// capture. It never supplies record keys, restore unwrap, or a final envelope.
// Acceptance capture must use the separately authorized provider/finalizer.
func (p *PinnedExecutionIdentity) DeriveCaptureKey(ctx context.Context, a d.Authority, binding []byte) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || p.current(a, time.Now().UTC()) != nil || len(binding) < 2 || len(binding) > 8192 || len(p.grant.CaptureKeys) != 1 {
		return nil, ErrExecutionAuthority
	}
	allowed := false
	for _, v := range p.grant.Actions {
		allowed = allowed || v == "capture"
	}
	if !allowed {
		return nil, ErrExecutionAuthority
	}
	k := p.grant.CaptureKeys[0]
	root, err := readExecutionFile(filepath.Join(p.keyDirectory, k.Ref), 32)
	defer clear(root)
	if err != nil || len(root) != 32 || recordHash(root) != k.SHA256 {
		return nil, ErrExecutionAuthority
	}
	mac := hmac.New(sha256.New, root)
	mac.Write([]byte("clawmanager-functional-staging-key.v1\x00"))
	mac.Write([]byte(a.InstallationID + "\x00" + a.TaskPublicID + "\x00" + a.ConfigSHA256 + "\x00"))
	mac.Write(binding)
	return mac.Sum(nil), nil
}
func (p *PinnedExecutionIdentity) AuthorizeExecution(ctx context.Context, tx *sql.Tx, a d.Authority, now time.Time) (ExecutionAuthorizationGuard, error) {
	if p.checkSQL(ctx, tx, a, now) != nil {
		return nil, ErrExecutionAuthority
	}
	return &pinnedExecutionGuard{p, a, p.grant.ExpiresAt}, nil
}

// Resolve reads only the exact record-encryption key versions in the signed
// workload grant. It is not a provider credential or a capture/unwrap grant.
func (p *PinnedExecutionIdentity) Resolve(ctx context.Context, a d.Authority, ref string) (string, []byte, error) {
	if ctx == nil || ctx.Err() != nil || p.current(a, time.Now().UTC()) != nil {
		return "", nil, ErrExecutionAuthority
	}
	if ref == "" {
		ref = p.grant.RecordKeys[0].Ref
	}
	for _, k := range p.grant.RecordKeys {
		if k.Ref != ref {
			continue
		}
		key, err := readExecutionFile(filepath.Join(p.keyDirectory, ref), 32)
		if err != nil || len(key) != 32 {
			clear(key)
			return "", nil, ErrExecutionAuthority
		}
		sum := sha256.Sum256(key)
		if hex.EncodeToString(sum[:]) != k.SHA256 {
			clear(key)
			return "", nil, ErrExecutionAuthority
		}
		return ref, key, nil
	}
	return "", nil, ErrExecutionAuthority
}

var _ ExecutionAuthorization = (*PinnedExecutionIdentity)(nil)
var _ ExecutionRecordKeys = (*PinnedExecutionIdentity)(nil)

// DeploymentBinding is public metadata, never a grant to execute a task.
func (p *PinnedExecutionIdentity) DeploymentBinding() ExecutionGrant {
	if p == nil {
		return ExecutionGrant{}
	}
	g := p.grant
	g.Actions = append([]string(nil), g.Actions...)
	g.RecordKeys = append([]ExecutionRecordKey(nil), g.RecordKeys...)
	g.CaptureKeys = append([]ExecutionRecordKey(nil), g.CaptureKeys...)
	return g
}
func (p *PinnedExecutionIdentity) CheckDeployment(ctx context.Context, db *sql.DB) error {
	if p == nil || db == nil {
		return ErrExecutionAuthority
	}
	var now time.Time
	var account, server, database string
	if db.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6),CURRENT_USER(),@@server_uuid,DATABASE()").Scan(&now, &account, &server, &database) != nil {
		return ErrExecutionAuthority
	}
	a := d.Authority{InstallationID: p.grant.InstallationID, ClaimOwner: p.grant.ControllerOwner, ConfigVersion: p.grant.ConfigVersion, ConfigSHA256: p.grant.ConfigSHA256}
	if p.current(a, now) != nil || account != p.grant.DatabaseAccount || server != p.grant.ServerUUID || database != p.grant.Database {
		return ErrExecutionAuthority
	}
	for _, k := range append(append([]ExecutionRecordKey(nil), p.grant.RecordKeys...), p.grant.CaptureKeys...) {
		raw, e := readExecutionFile(filepath.Join(p.keyDirectory, k.Ref), 32)
		valid := e == nil && len(raw) == 32 && recordHash(raw) == k.SHA256
		clear(raw)
		if !valid {
			return ErrExecutionAuthority
		}
	}
	return nil
}
