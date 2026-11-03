package install

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"clawreef/internal/systembackup/worker"
	api "clawreef/internal/systembackupdeployment"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-sql-driver/mysql"
)

// The ORIGINAL struct-order wire is retained with RawMessage for opaque
// operation/policy bodies. Roundtrip equality and the independently signed
// metadata scope prevent unknown/duplicate/aliased fields or guessed scope.
// This DATA projection creates no service, Forward identity, task or callback.
type bootstrapSourceMaterialsWire struct {
	Version, Revision                                                           string
	InstallationID, ControllerOwner, DeploymentConfigSHA256, CaptureGrantSHA256 string
	Operations                                                                  map[string]json.RawMessage
	Redis, Objects                                                              worker.FormalSourceMount
	SkillBucket, SkillPrefix                                                    string
	UserMetadataAllowlist                                                       []string
	MaxObjects                                                                  int
	MaxObjectBytes, MaxObjectTotalBytes                                         int64
	ResourceTypes                                                               []json.RawMessage
	ControlEvidence                                                             json.RawMessage               `json:"ControlEvidence,omitempty"`
	ControlEvidenceSource                                                       json.RawMessage               `json:"ControlEvidenceSource,omitempty"`
	Discovery                                                                   *bootstrapSourceDiscoveryWire `json:",omitempty"`
}
type bootstrapSourceDiscoveryWire struct {
	PublicationPolicy                                     json.RawMessage `json:",omitempty"`
	GrantFile, GrantSHA256                                string
	Issuer                                                ed25519.PublicKey
	ControllerDeployment, ControllerDeploymentUID         string
	ControllerServiceAccount, ControllerServiceAccountUID string
	SourceAPI                                             worker.ResourceSourceMount
	SourceAPITokenSHA256                                  string
	SourceAPIServiceAccount, SourceAPIServiceAccountUID   string
	Redis                                                 json.RawMessage
	RuntimePolicies                                       []json.RawMessage
	ResourceActors                                        map[string]struct{ Name, UID string }
	TeamPlatformUnits                                     map[string][]string
	RuntimeImageReferences                                map[string]string
	SecretPolicy                                          json.RawMessage `json:",omitempty"`
}

func bootstrapSourceStrictJSON(raw []byte, out any, limit int) error {
	if len(raw) == 0 || len(raw) > limit || json.Unmarshal(raw, out) != nil {
		return ErrInstall
	}
	encoded, err := json.Marshal(out)
	actual, ae := jsoncanonicalizer.Transform(raw)
	want, we := jsoncanonicalizer.Transform(encoded)
	if err != nil || ae != nil || we != nil || !bytes.Equal(actual, want) {
		return ErrInstall
	}
	return nil
}

func BootstrapSourceMetadataScopeFromMaterials(raw []byte) (string, error) {
	var m bootstrapSourceMaterialsWire
	if bootstrapSourceStrictJSON(raw, &m, 8<<20) != nil || m.Discovery == nil {
		return "", ErrInstall
	}
	// Preserve original Go struct-order JSON, not JCS; the metadata issuer used
	// this exact original typed scope wire when it signed the controller grant.
	original, err := json.Marshal(m)
	if err != nil || !bytes.Equal(original, raw) {
		return "", ErrInstall
	}
	m.Discovery.GrantFile, m.Discovery.GrantSHA256 = "", ""
	scope, err := json.Marshal(m)
	if err != nil {
		return "", ErrInstall
	}
	return hash(scope), nil
}

type bootstrapSourceCoreWire struct {
	Version          string                          `json:"schema_version"`
	CaptureScope     string                          `json:"capture_scope"`
	InstallationID   string                          `json:"installation_id"`
	ControllerOwner  string                          `json:"controller_owner"`
	ApplicationScope string                          `json:"application_scope"`
	Namespace        string                          `json:"namespace"`
	NamespaceUID     string                          `json:"namespace_uid"`
	SourceDSNFile    string                          `json:"source_dsn_file"`
	SourceUser       string                          `json:"source_user"`
	SourceDatabase   string                          `json:"source_database"`
	SourceServerUUID string                          `json:"source_server_uuid"`
	ProfileFile      string                          `json:"profile_file"`
	CaptureModules   struct{ Protocol, Path string } `json:"capture_modules"`
	ForwardGrant     struct {
		Path      string
		PublicKey string `json:"public_key_base64"`
	} `json:"forward_grant"`
	RuntimeSources struct {
		AgentTokenFile string `json:"agent_token_file"`
		AgentCAFile    string `json:"agent_ca_file"`
		AgentCASHA256  string `json:"agent_ca_sha256"`
	} `json:"runtime_sources"`
}

// Return a strict projection of a CLOSED core object. Unrelated known original
// core fields stay opaque, never interpreted as execution/provider authority.
func decodeBootstrapSourceCore(raw []byte) (bootstrapSourceCoreWire, error) {
	var out bootstrapSourceCoreWire
	var fields map[string]json.RawMessage
	if len(raw) > 262144 || json.Unmarshal(raw, &fields) != nil {
		return out, ErrInstall
	}
	if _, err := jsoncanonicalizer.Transform(raw); err != nil {
		return out, ErrInstall
	}
	allowed := strings.Fields("source_tls redis_read_keepers schema_version capture_scope installation_id controller_owner application_scope namespace namespace_uid trust_domain forward_grant recovery_grant key_directory profile_file capacity_file source_dsn_file source_user source_database source_server_uuid staging_directory seal_custody_max_bytes staging_claim staging_location worker_image worker_security control_url listen server_certificate server_key issuer_certificate issuer_certificate_sha256 issuer_key platform_writers workspace acquire_seconds hold_seconds runtime_sources formal_verifier publication_signers publisher_verifier capture_modules publication_target publication_worker")
	known := map[string]bool{}
	for _, name := range allowed {
		known[name] = true
	}
	for name := range fields {
		if !known[name] {
			return out, ErrInstall
		}
	}
	if json.Unmarshal(raw, &out) != nil {
		return out, ErrInstall
	}
	return out, nil
}

// ValidateBootstrapSourceV2Inputs is DATA consistency only. Callers first read
// these exact bytes through original signed pins. Success creates no terminal
// or physical evidence; native privilege/TLS/EOF/census checks remain required.
func ValidateBootstrapSourceV2Inputs(r BootstrapSourceRegistryV2Record, coreRaw, materialsRaw, profileRaw, forwardRaw []byte) error {
	if validateBootstrapSourceV2(r) != nil || hash(coreRaw) != r.Source.Deployment.SHA256 || hash(materialsRaw) != r.Source.Materials.SHA256 || hash(profileRaw) != r.Source.ExecutionProfile.SHA256 || hash(forwardRaw) != r.Source.ForwardGrant.SHA256 {
		return ErrInstall
	}
	cfg, err := decodeBootstrapSourceCore(coreRaw)
	var m bootstrapSourceMaterialsWire
	var profile api.ExecutionProfile
	if err != nil || bootstrapSourceStrictJSON(materialsRaw, &m, 8<<20) != nil || bootstrapSourceStrictJSON(profileRaw, &profile, 262144) != nil || m.Discovery == nil {
		return ErrInstall
	}
	_, profileSHA, err := profile.CanonicalIdentity()
	scope, se := BootstrapSourceMetadataScopeFromMaterials(materialsRaw)
	g, d := r.Metadata, r.Source
	if err != nil || se != nil || scope != g.ScopeSHA256 || cfg.Version != "system-backup-public-deployment.v1" || cfg.CaptureScope != "six-part" || cfg.InstallationID != r.Target.InstallationID || cfg.ControllerOwner != g.ControllerOwner || cfg.ApplicationScope != d.ApplicationScope || cfg.Namespace != r.Target.Namespace || cfg.NamespaceUID != r.Target.NamespaceUID || cfg.CaptureModules.Protocol != "original-six-part-capture-materials.v1" || cfg.CaptureModules.Path != d.Materials.File || cfg.ProfileFile != d.ExecutionProfile.File || cfg.ForwardGrant.Path != d.ForwardGrant.File || m.Version != "original-six-part-capture-materials.v1" || m.InstallationID != cfg.InstallationID || m.ControllerOwner != cfg.ControllerOwner || m.DeploymentConfigSHA256 != d.Deployment.SHA256 || m.CaptureGrantSHA256 != g.CaptureGrantSHA256 || profile.InstallationID != cfg.InstallationID {
		return ErrInstall
	}
	p := m.Discovery
	if p.GrantFile != d.MetadataGrant.File || p.GrantSHA256 != d.MetadataGrant.SHA256 || hash(p.Issuer) != r.MetadataIssuerSHA256 || p.ControllerDeployment != d.Controller.Deployment || p.ControllerDeploymentUID != d.Controller.DeploymentUID || p.ControllerServiceAccount != d.Controller.ServiceAccount || p.ControllerServiceAccountUID != d.Controller.ServiceAccountUID || m.Redis.Redis == nil || m.Objects.Objects == nil {
		return ErrInstall
	}
	roles := map[string]BootstrapSourceConnection{}
	for _, c := range d.Connections {
		roles[c.Purpose] = c
	}
	sqlSource, redis, objects, kube := roles["source_sql"], roles["source_redis"], roles["source_objects"], roles["source_api"]
	if sqlSource.Credential.File != cfg.SourceDSNFile || sqlSource.Database != cfg.SourceDatabase || sqlSource.ServerUUID != cfg.SourceServerUUID || !strings.HasPrefix(sqlSource.Account, cfg.SourceUser+"@") || redis.Endpoint != "rediss://"+m.Redis.Redis.Address || redis.CA != (BootstrapSourceFilePin{m.Redis.Redis.CAFile, m.Redis.Redis.CASHA256}) || redis.Credential != (BootstrapSourceFilePin{m.Redis.CredentialFile, m.Redis.CredentialSHA256}) || objects.Endpoint != "https://"+m.Objects.Objects.Address || objects.CA != (BootstrapSourceFilePin{m.Objects.Objects.CAFile, m.Objects.Objects.CASHA256}) || objects.Credential != (BootstrapSourceFilePin{m.Objects.CredentialFile, m.Objects.CredentialSHA256}) || kube.Endpoint != p.SourceAPI.Server || kube.Account != p.SourceAPIServiceAccountUID || kube.CA != (BootstrapSourceFilePin{p.SourceAPI.CAFile, p.SourceAPI.CASHA256}) || kube.Credential != (BootstrapSourceFilePin{p.SourceAPI.TokenFile, p.SourceAPITokenSHA256}) {
		return ErrInstall
	}
	if a := d.RuntimeAgent; a != nil && (a.CA != (BootstrapSourceFilePin{cfg.RuntimeSources.AgentCAFile, cfg.RuntimeSources.AgentCASHA256}) || a.Credential.File != cfg.RuntimeSources.AgentTokenFile) {
		return ErrInstall
	}
	return validateBootstrapSourceForward(r, cfg.ForwardGrant.PublicKey, profileSHA, forwardRaw)
}

func validateBootstrapSourceForward(r BootstrapSourceRegistryV2Record, public64, profileSHA string, raw []byte) error {
	var envelope struct {
		Payload   string `json:"payload_base64"`
		Signature string `json:"signature_base64"`
	}
	if bootstrapSourceStrictJSON(raw, &envelope, 65536) != nil {
		return ErrInstall
	}
	public, pe := base64.StdEncoding.Strict().DecodeString(public64)
	body, be := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
	signature, se := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	if pe != nil || be != nil || se != nil || len(public) != ed25519.PublicKeySize || len(body) > 32768 || !ed25519.Verify(public, body, signature) {
		return ErrInstall
	}
	var grant struct {
		Version      string    `json:"schema_version"`
		Installation string    `json:"installation_id"`
		Controller   string    `json:"controller_owner"`
		Config       string    `json:"config_sha256"`
		Profile      string    `json:"profile_sha256"`
		Deployment   string    `json:"deployment_config_sha256"`
		NotBefore    time.Time `json:"not_before"`
		Until        time.Time `json:"expires_at"`
	}
	// The old execution envelope is read ONLY as independently signed original
	// DATA/window. Never construct a Forward object or require enabled config.
	if json.Unmarshal(body, &grant) != nil || grant.Version != "system-backup-execution-grant.v1" || grant.Installation != r.Target.InstallationID || grant.Controller != r.Metadata.ControllerOwner || grant.Config != string(r.Selection.ConfigHash) || grant.Profile != profileSHA || grant.Deployment != r.Source.Deployment.SHA256 || grant.NotBefore.IsZero() || !grant.NotBefore.Before(grant.Until) || grant.Until.Sub(grant.NotBefore) > 24*time.Hour || r.NotBefore.Before(grant.NotBefore) || r.Until.After(grant.Until) {
		return ErrInstall
	}
	return nil
}

func checkBootstrapSourceV2SelectedInputs(r BootstrapSourceRegistryV2Record) error {
	var raws [][]byte
	for _, pin := range []BootstrapSourceFilePin{r.Source.Deployment, r.Source.Materials, r.Source.ExecutionProfile, r.Source.ForwardGrant} {
		limit := int64(262144)
		if pin == r.Source.Materials {
			limit = 8 << 20
		}
		raw, err := readBootstrapSourcePin(pin, limit)
		if err != nil {
			return ErrInstall
		}
		raws = append(raws, raw)
	}
	if ValidateBootstrapSourceV2Inputs(r, raws[0], raws[1], raws[2], raws[3]) != nil {
		return ErrInstall
	}
	for _, c := range r.Source.Connections {
		raw, err := readBootstrapSourcePin(c.Credential, 65536)
		if err != nil {
			return ErrInstall
		}
		if c.Purpose == "source_sql" || c.Purpose == "control_sql" {
			dsn, err := mysql.ParseDSN(strings.TrimSpace(string(raw)))
			u, ue := url.Parse(c.Endpoint)
			clear(raw)
			if err != nil || ue != nil || dsn.Net != "tcp" || dsn.Addr != u.Host || dsn.DBName != c.Database || dsn.User == "" || strings.EqualFold(dsn.User, "root") || !strings.HasPrefix(c.Account, dsn.User+"@") || dsn.MultiStatements || dsn.AllowAllFiles || dsn.AllowCleartextPasswords || dsn.AllowFallbackToPlaintext {
				return ErrInstall
			}
		} else {
			clear(raw)
		}
	}
	return nil
}
