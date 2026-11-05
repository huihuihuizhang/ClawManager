package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"

	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	sec "clawreef/internal/systembackupsecurity"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

type ControlEvidenceSourceIssueResult struct {
	Version, State, OriginalDefinitionSHA256, ScopeSHA256 string
	Source                                                worker.ControlEvidenceSourceMount
	Grant                                                 BootstrapSourceFilePin
	Input                                                 ce.CaptureInput
	NotBefore, Until                                      time.Time
}

type controlEvidenceStaticDefinition struct {
	Version, CoreFile, CoreSHA256, ConfigFile, ConfigSHA256, ForwardGrantSHA256 string
	NotBefore, Until                                                            time.Time
	Materials                                                                   json.RawMessage
}
type controlEvidenceStaticMaterials struct {
	Version, InstallationID, ControllerOwner, DeploymentConfigSHA256, CaptureGrantSHA256 string
	ControlEvidence                                                                      *ce.CaptureInput
	ControlEvidenceSource                                                                *worker.ControlEvidenceSourceMount
	Operations                                                                           map[string]struct{ Request worker.Request }
	Discovery                                                                            *struct{ ControllerDeployment, ControllerDeploymentUID, ControllerServiceAccount, ControllerServiceAccountUID, SourceAPIServiceAccount, SourceAPIServiceAccountUID string }
}

// Static comparison data only. The original authenticated SourceMaterialIssuer
// selects the whole declaration, actors and window. No caller supplies a grant,
// ready flag, ScopeSHA, task, attempt or future Job to this signing method.
func (p *SourceMaterialIssuer) controlEvidenceSourceDefinition(ctx context.Context) (controlEvidenceStaticDefinition, worker.ControlEvidenceSourceMount, ce.CaptureInput, string, error) {
	var zero controlEvidenceStaticDefinition
	var mount worker.ControlEvidenceSourceMount
	var input ce.CaptureInput
	if p == nil || p.Recheck(ctx) != nil {
		return zero, mount, input, "", ErrInstall
	}
	i := p.intent
	raw, e := ReadSourceMaterialFile(i.DefinitionFile)
	if e != nil || hash(raw) != i.DefinitionSHA256 {
		return zero, mount, input, "", ErrInstall
	}
	// JCS rejects duplicate/ambiguous keys before subset DATA decoding. The
	// full immutable declaration hash stays fixed; no subset becomes authority.
	if _, e = jsoncanonicalizer.Transform(raw); e != nil {
		return zero, mount, input, "", ErrInstall
	}
	var d controlEvidenceStaticDefinition
	if json.Unmarshal(raw, &d) != nil || d.Version != "original-six-part-source-material-definition.v1" || d.CoreSHA256 != i.DeploymentConfigSHA256 || d.ConfigSHA256 != i.ConfigSHA256 || d.ForwardGrantSHA256 != i.CaptureGrantSHA256 || !d.NotBefore.Equal(i.NotBefore) || !d.Until.Equal(i.Until) {
		return zero, mount, input, "", ErrInstall
	}
	coreRaw, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: d.CoreFile, SHA256: d.CoreSHA256}, 262144)
	var core struct {
		CaptureScope string `json:"capture_scope"`
		KeyDirectory string `json:"key_directory"`
		Forward      struct {
			Path      string `json:"path"`
			PublicKey string `json:"public_key_base64"`
		} `json:"forward_grant"`
		Installation    string                                                 `json:"installation_id"`
		Namespace       string                                                 `json:"namespace"`
		NamespaceUID    string                                                 `json:"namespace_uid"`
		ControllerOwner string                                                 `json:"controller_owner"`
		ControlURL      string                                                 `json:"control_url"`
		ServerUUID      string                                                 `json:"source_server_uuid"`
		Database        string                                                 `json:"source_database"`
		Security        struct{ ServiceAccountName, ServiceAccountUID string } `json:"worker_security"`
	}
	if e != nil || json.Unmarshal(coreRaw, &core) != nil || core.Installation != i.InstallationID || core.Namespace != i.Namespace || core.NamespaceUID != i.NamespaceUID || core.ControllerOwner != i.ControllerOwner || core.ServerUUID != i.ServerUUID || core.Database != i.Database || core.Security.ServiceAccountName != i.WorkerServiceAccount || core.Security.ServiceAccountUID != i.WorkerServiceAccountUID {
		return zero, mount, input, "", ErrInstall
	}
	public, e := base64.StdEncoding.Strict().DecodeString(core.Forward.PublicKey)
	if e != nil || core.CaptureScope != "six-part" {
		return zero, mount, input, "", ErrInstall
	}
	forward, e := c.NewPinnedExecutionIdentity(core.Forward.Path, i.CaptureGrantSHA256, core.KeyDirectory, public)
	if e != nil {
		return zero, mount, input, "", ErrInstall
	}
	g := forward.DeploymentBinding()
	if g.InstallationID != i.InstallationID || g.ControllerOwner != i.ControllerOwner || g.ServerUUID != i.ServerUUID || g.Database != i.Database || g.ConfigVersion != 1 || g.ConfigSHA256 != i.ConfigSHA256 || g.DeploymentConfigSHA256 != i.DeploymentConfigSHA256 || i.NotBefore.Before(g.NotBefore) || i.Until.After(g.ExpiresAt) {
		return zero, mount, input, "", ErrInstall
	}
	configRaw, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: d.ConfigFile, SHA256: d.ConfigSHA256}, 262144)
	if e != nil {
		return zero, mount, input, "", ErrInstall
	}
	config, e := sec.DecodeConfigValues(configRaw)
	if e != nil || config.SHA256() != i.ConfigSHA256 {
		return zero, mount, input, "", ErrInstall
	}
	var materials controlEvidenceStaticMaterials
	if json.Unmarshal(d.Materials, &materials) != nil || materials.Version != "original-six-part-capture-materials.v1" || materials.InstallationID != i.InstallationID || materials.ControllerOwner != i.ControllerOwner || materials.DeploymentConfigSHA256 != i.DeploymentConfigSHA256 || materials.CaptureGrantSHA256 != i.CaptureGrantSHA256 || materials.ControlEvidence == nil || materials.ControlEvidenceSource == nil || materials.Discovery == nil {
		return zero, mount, input, "", ErrInstall
	}
	actor := materials.Discovery
	if actor.ControllerDeployment != i.ControllerDeployment || actor.ControllerDeploymentUID != i.ControllerDeploymentUID || actor.ControllerServiceAccount != i.ControllerServiceAccount || actor.ControllerServiceAccountUID != i.ControllerServiceAccountUID || actor.SourceAPIServiceAccount != i.SourceServiceAccount || actor.SourceAPIServiceAccountUID != i.SourceServiceAccountUID {
		return zero, mount, input, "", ErrInstall
	}
	op, ok := materials.Operations[ce.Operation]
	if !ok || op.Request.Operation != "" && op.Request.Operation != ce.Operation || op.Request.Database != nil || op.Request.SourceRedis != nil || op.Request.Teams != nil || op.Request.TeamWorkspace != nil || op.Request.Resources != nil || op.Request.CaptureDescription != nil || op.Request.SkillObjects != nil || op.Request.SkillWorkspace != nil {
		return zero, mount, input, "", ErrInstall
	}
	input = *materials.ControlEvidence
	mount = *materials.ControlEvidenceSource
	if input.Validate() != nil || mount.Endpoint != core.ControlURL || !bytes.Equal(mount.Issuer, p.operator.installer.public) || !filepath.IsAbs(mount.GrantFile) || filepath.Clean(mount.GrantFile) != mount.GrantFile || !filepath.IsAbs(mount.ControllerGrantFile) || filepath.Clean(mount.ControllerGrantFile) != mount.ControllerGrantFile {
		return zero, mount, input, "", ErrInstall
	}
	for _, path := range []string{i.DefinitionFile, d.CoreFile, d.ConfigFile, input.SchemaRegistryFile, input.RedactionRegistryFile} {
		if mount.ControllerGrantFile == path {
			return zero, mount, input, "", ErrInstall
		}
	}
	schema, e := ReadSourceMaterialFile(input.SchemaRegistryFile)
	if e != nil {
		return zero, mount, input, "", ErrInstall
	}
	redaction, e := readBootstrapSourcePin(BootstrapSourceFilePin{File: input.RedactionRegistryFile, SHA256: input.RedactionRegistrySHA256}, 65536)
	if e != nil {
		return zero, mount, input, "", ErrInstall
	}
	schemaPin, redactionPin, _, e := ce.ReadPolicies(schema, redaction, input)
	if e != nil {
		return zero, mount, input, "", ErrInstall
	}
	source, e := ce.SourceIdentity(i.ServerUUID, i.Database)
	if e != nil {
		return zero, mount, input, "", ErrInstall
	}
	expected := ce.Expected{Scope: ce.Scope{Installation: i.InstallationID}, ConfigSHA256: i.ConfigSHA256, SourceIdentitySHA256: source, SchemaRegistry: schemaPin, RedactionRegistry: redactionPin}
	scope, e := worker.ControlEvidenceSourceScopeSHA256(expected, mount.Endpoint)
	if e != nil || p.Recheck(ctx) != nil {
		return zero, mount, input, "", ErrInstall
	}
	return d, mount, input, scope, nil
}

// IssueControlEvidenceSource issues ONLY the original static source grant.
// Head0 is accepted through the unchanged authenticated source-issuer window.
// It never invokes runtime capture or impersonates a task/Job/KEK lease.
func (p *SourceMaterialIssuer) IssueControlEvidenceSource(ctx context.Context, issuerPrivate []byte) (ControlEvidenceSourceIssueResult, error) {
	var zero ControlEvidenceSourceIssueResult
	_, mount, _, scope, e := p.controlEvidenceSourceDefinition(ctx)
	if e != nil || mount.GrantSHA256 != "" {
		return zero, ErrInstall
	}
	if _, e = os.Lstat(mount.ControllerGrantFile); !os.IsNotExist(e) {
		return zero, ErrInstall
	}
	key, e := p.operator.privateKey(issuerPrivate)
	if e != nil {
		return zero, ErrInstall
	}
	defer clear(key)
	i := p.intent
	grant := worker.ControlEvidenceSourceGrant{Version: worker.ControlEvidenceSourceGrantVersion, InstallationID: i.InstallationID, ConfigSHA256: i.ConfigSHA256, WorkerNamespace: i.Namespace, WorkerServiceAccountUID: i.WorkerServiceAccountUID, Operation: ce.Operation, ScopeSHA256: scope, NotBefore: i.NotBefore, Until: i.Until}
	record, e := json.Marshal(grant)
	if e != nil {
		return zero, ErrInstall
	}
	signed, e := json.Marshal(worker.SignedControlEvidenceSourceGrant{Record: record, Signature: ed25519.Sign(key, append([]byte(worker.ControlEvidenceSourceGrantDomain), record...))})
	if e != nil {
		return zero, ErrInstall
	}
	// All registry/actor/authority reads precede immutable file creation. The
	// original issuer is the enrollment key, never the KEK permit delivery key.
	if p.Recheck(ctx) != nil {
		return zero, ErrInstall
	}
	if writeNewFiles(filepath.Dir(mount.ControllerGrantFile), map[string][]byte{filepath.Base(mount.ControllerGrantFile): signed}) != nil {
		return zero, ErrInstall
	}
	return p.QueryControlEvidenceSource(ctx)
}

// Query only authenticates retained ORIGINAL bytes and original live scope.
// ControllerGrantFile is the physical issuer output. D projects these same
// bytes to GrantFile for the worker through its immutable mapping factory.
func (p *SourceMaterialIssuer) QueryControlEvidenceSource(ctx context.Context) (ControlEvidenceSourceIssueResult, error) {
	var zero ControlEvidenceSourceIssueResult
	_, mount, input, scope, e := p.controlEvidenceSourceDefinition(ctx)
	if e != nil {
		return zero, ErrInstall
	}
	raw, e := ReadSourceMaterialFile(mount.ControllerGrantFile)
	if e != nil || len(raw) > 65536 {
		return zero, ErrInstall
	}
	var signed worker.SignedControlEvidenceSourceGrant
	decode := func(raw []byte, v any) error {
		if _, e := jsoncanonicalizer.Transform(raw); e != nil {
			return ErrInstall
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
			return ErrInstall
		}
		return nil
	}
	if decode(raw, &signed) != nil || !ed25519.Verify(p.operator.installer.public, append([]byte(worker.ControlEvidenceSourceGrantDomain), signed.Record...), signed.Signature) {
		return zero, ErrInstall
	}
	var grant worker.ControlEvidenceSourceGrant
	i := p.intent
	if decode(signed.Record, &grant) != nil || grant.Version != worker.ControlEvidenceSourceGrantVersion || grant.InstallationID != i.InstallationID || grant.ConfigSHA256 != i.ConfigSHA256 || grant.WorkerNamespace != i.Namespace || grant.WorkerServiceAccountUID != i.WorkerServiceAccountUID || grant.Operation != ce.Operation || grant.ScopeSHA256 != scope || grant.Revoked || !grant.NotBefore.Equal(i.NotBefore) || !grant.Until.Equal(i.Until) || time.Now().Before(grant.NotBefore) || !time.Now().Before(grant.Until) || p.Recheck(ctx) != nil {
		return zero, ErrInstall
	}
	if mount.GrantSHA256 != "" && mount.GrantSHA256 != hash(raw) {
		return zero, ErrInstall
	}
	mount.GrantSHA256 = hash(raw)
	if mount.Validate() != nil {
		return zero, ErrInstall
	}
	return ControlEvidenceSourceIssueResult{Version: "original-control-evidence-source-result.v1", State: "original_static_grant_issued_exact_readback_not_task_or_capture", OriginalDefinitionSHA256: i.DefinitionSHA256, ScopeSHA256: scope, Source: mount, Grant: BootstrapSourceFilePin{File: mount.ControllerGrantFile, SHA256: hash(raw)}, Input: input, NotBefore: grant.NotBefore, Until: grant.Until}, nil
}

// Intent decoding is inert transport only. The original constructor still
// authenticates real admin/enrollment/SQL/actors and enforces its original scope.
func DecodeControlEvidenceSourceIntent(raw []byte, expectedSHA string) (SourceMaterialIntent, error) {
	var i SourceMaterialIntent
	if hash(raw) != expectedSHA || decodeExact(raw, &i) != nil {
		return SourceMaterialIntent{}, ErrInstall
	}
	return i, nil
}
