package systembackupexecution

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"clawreef/internal/systembackup/kube"
	c "clawreef/internal/systembackupcontroller"
)

// DeploymentConfig is an administrator-pinned input; public create requests
// cannot supply paths, trusted roots, source identities or resource UIDs.
type DeploymentConfig struct {
	Version             string               `json:"schema_version"`
	CaptureScope        string               `json:"capture_scope"`
	InstallationID      string               `json:"installation_id"`
	ControllerOwner     string               `json:"controller_owner"`
	ApplicationScope    string               `json:"application_scope"`
	Namespace           string               `json:"namespace"`
	NamespaceUID        string               `json:"namespace_uid"`
	TrustDomain         string               `json:"trust_domain"`
	ForwardGrant        GrantReference       `json:"forward_grant"`
	RecoveryGrant       GrantReference       `json:"recovery_grant"`
	KeyDirectory        string               `json:"key_directory"`
	ProfileFile         string               `json:"profile_file"`
	CapacityFile        string               `json:"capacity_file"`
	SourceDSNFile       string               `json:"source_dsn_file"`
	SourceUser          string               `json:"source_user"`
	SourceDatabase      string               `json:"source_database"`
	SourceServerUUID    string               `json:"source_server_uuid"`
	StagingDirectory    string               `json:"staging_directory"`
	SealCustodyMaxBytes int64                `json:"seal_custody_max_bytes"`
	StagingClaim        string               `json:"staging_claim"`
	WorkerImage         string               `json:"worker_image"`
	Security            kube.WorkerSecurity  `json:"worker_security"`
	ControlURL          string               `json:"control_url"`
	Listen              string               `json:"listen"`
	ServerCertificate   string               `json:"server_certificate"`
	ServerKey           string               `json:"server_key"`
	IssuerCertificate   string               `json:"issuer_certificate"`
	IssuerSHA256        string               `json:"issuer_certificate_sha256,omitempty"`
	IssuerKey           string               `json:"issuer_key"`
	Writers             []PlatformDeployment `json:"platform_writers"`
	Workspace           WorkspaceCapture     `json:"workspace"`
	AcquireSeconds      int                  `json:"acquire_seconds"`
	HoldSeconds         int                  `json:"hold_seconds"`
	RuntimeSources      *RuntimeSourceConfig `json:"runtime_sources,omitempty"`
}
type GrantReference struct {
	Path      string `json:"path"`
	PublicKey string `json:"public_key_base64"`
}
type PlatformDeployment struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}
type WorkspaceCapture struct {
	Claim              string        `json:"claim"`
	NFS                *NFSWorkspace `json:"nfs,omitempty"`
	SubPath            string        `json:"sub_path"`
	Node               string        `json:"node"`
	MaxFiles           int           `json:"max_files"`
	MaxFileBytes       int64         `json:"max_file_bytes"`
	MaxArchiveBytes    int64         `json:"max_archive_bytes"`
	MaxCompressedBytes int64         `json:"max_compressed_bytes"`
}
type NFSWorkspace struct {
	Server string `json:"server"`
	Export string `json:"export"`
}

// The NFS capture mount is restricted to one installation tree. A shared
// export root is never a source scope, even when the app lives in one namespace.
func (w WorkspaceCapture) validSource(installation string) bool {
	if w.NFS == nil {
		return w.Claim != ""
	}
	if w.Claim != "" || net.ParseIP(w.NFS.Server) == nil || !path.IsAbs(w.NFS.Export) || path.Clean(w.NFS.Export) != w.NFS.Export || strings.ContainsAny(w.NFS.Export, "\\\x00\r\n:") {
		return false
	}
	h := sha256.Sum256([]byte(installation))
	return w.SubPath == "installations/"+hex.EncodeToString(h[:])
}

func pinnedDeploymentFile(path, digest string, max int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(digest) != 64 {
		return nil, c.ErrExecutionAuthority
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, c.ErrExecutionAuthority
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > max {
		return nil, c.ErrExecutionAuthority
	}
	raw, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(raw)) > max || hash(raw) != digest {
		return nil, c.ErrExecutionAuthority
	}
	return raw, nil
}
func LoadDeploymentConfig(path, digest string) (DeploymentConfig, error) {
	var cfg DeploymentConfig
	raw, e := pinnedDeploymentFile(path, digest, 256<<10)
	if e != nil {
		return cfg, e
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cfg) != nil || decoder.Decode(new(any)) != io.EOF || cfg.Validate() != nil {
		return cfg, c.ErrExecutionAuthority
	}
	return cfg, nil
}
func (cnf DeploymentConfig) Validate() error {
	if cnf.SealCustodyMaxBytes < 1<<20 || cnf.SealCustodyMaxBytes > 1<<40 {
		return c.ErrExecutionAuthority
	}
	if cnf.IssuerSHA256 != "" {
		if len(cnf.IssuerSHA256) != 64 || cnf.IssuerSHA256 != strings.ToLower(cnf.IssuerSHA256) {
			return c.ErrExecutionAuthority
		}
		if _, e := hex.DecodeString(cnf.IssuerSHA256); e != nil {
			return c.ErrExecutionAuthority
		}
	}
	if cnf.CaptureScope != "platform-workspace" && cnf.CaptureScope != "runtime-workspace" {
		return c.ErrExecutionAuthority
	}
	if cnf.Workspace.NFS != nil && cnf.CaptureScope != "runtime-workspace" {
		return c.ErrExecutionAuthority
	}
	if (cnf.CaptureScope == "runtime-workspace") != (cnf.RuntimeSources != nil) || (cnf.RuntimeSources != nil && cnf.RuntimeSources.validate() != nil) {
		return c.ErrExecutionAuthority
	}
	if cnf.RuntimeSources != nil && cnf.RuntimeSources.Namespaces[0] != cnf.Namespace {
		return c.ErrExecutionAuthority
	}
	if cnf.Version != "system-backup-public-deployment.v1" || cnf.InstallationID == "" || cnf.ControllerOwner == "" || cnf.ApplicationScope == "" || cnf.Namespace == "" || cnf.NamespaceUID == "" || cnf.TrustDomain == "" || strings.ContainsAny(cnf.TrustDomain, "/: ") || !strings.Contains(cnf.WorkerImage, "@sha256:") || cnf.StagingClaim == "" || !cnf.Workspace.validSource(cnf.InstallationID) || cnf.Security.ServiceAccountName == "" || cnf.Security.ServiceAccountUID == "" || len(cnf.Security.NodeUIDs) == 0 || len(cnf.Writers) == 0 || len(cnf.Writers) > 1000 || cnf.AcquireSeconds < 10 || cnf.AcquireSeconds > 600 || cnf.HoldSeconds < 30 || time.Duration(cnf.HoldSeconds)*time.Second > time.Hour || cnf.Listen == "" || !strings.HasPrefix(cnf.ControlURL, "https://") || cnf.SourceUser == "" || strings.EqualFold(cnf.SourceUser, "root") || cnf.SourceDatabase == "" || cnf.SourceServerUUID == "" {
		return c.ErrExecutionAuthority
	}
	for _, path := range []string{cnf.KeyDirectory, cnf.ProfileFile, cnf.CapacityFile, cnf.SourceDSNFile, cnf.StagingDirectory, cnf.ServerCertificate, cnf.ServerKey, cnf.IssuerCertificate, cnf.IssuerKey, cnf.ForwardGrant.Path, cnf.RecoveryGrant.Path} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return c.ErrExecutionAuthority
		}
	}
	for _, g := range []GrantReference{cnf.ForwardGrant, cnf.RecoveryGrant} {
		key, e := base64.StdEncoding.DecodeString(g.PublicKey)
		if e != nil || len(key) != ed25519.PublicKeySize {
			return c.ErrExecutionAuthority
		}
	}
	seen := map[string]bool{}
	for _, w := range cnf.Writers {
		id := w.Namespace + "/" + w.Name
		if w.Namespace != cnf.Namespace || w.Name == "" || w.UID == "" || seen[id] {
			return c.ErrExecutionAuthority
		}
		seen[id] = true
	}
	if cnf.Workspace.MaxFiles <= 0 || cnf.Workspace.MaxFiles > 1_000_000 || cnf.Workspace.MaxFileBytes <= 0 || cnf.Workspace.MaxArchiveBytes < cnf.Workspace.MaxFileBytes || cnf.Workspace.MaxArchiveBytes > 1<<50 || cnf.Workspace.MaxCompressedBytes <= 0 || cnf.Workspace.MaxCompressedBytes > 1<<50 || cnf.Workspace.Node == "" || cnf.Security.NodeUIDs[cnf.Workspace.Node] == "" {
		return c.ErrExecutionAuthority
	}
	return nil
}
