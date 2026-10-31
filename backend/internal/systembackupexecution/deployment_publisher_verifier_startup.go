package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"os"
	"path/filepath"
	"reflect"

	c "clawreef/internal/systembackupcontroller"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	s "clawreef/internal/systembackupsecurity"
	"k8s.io/client-go/kubernetes"
)

const PublisherVerifierMaterialsVersion = "system-backup-publisher-verifier-materials.v1"

type PublisherVerifierReference struct {
	Protocol string `json:"protocol"`
	Path     string `json:"path"`
}
type PublisherVerifierInput struct{ File, SHA256 string }

func PublisherVerifierInputsFromEnvironment() []PublisherVerifierInput {
	file, pin := os.Getenv("SYSTEM_BACKUP_PUBLISHER_VERIFIER_MATERIALS_FILE"), os.Getenv("SYSTEM_BACKUP_PUBLISHER_VERIFIER_MATERIALS_SHA256")
	if file == "" && pin == "" {
		return nil
	}
	return []PublisherVerifierInput{{File: file, SHA256: pin}}
}

type PublisherVerifierMaterials struct {
	Version            string                       `json:"schema_version"`
	Database           reg.DatabaseIdentity         `json:"database"`
	Binding            reg.Binding                  `json:"binding"`
	GenerateCapability a.ProviderCapabilityPin      `json:"generate_capability"`
	UnwrapCapability   a.ProviderCapabilityPin      `json:"unwrap_capability"`
	InstallationIssuer ed25519.PublicKey            `json:"installation_issuer"`
	CAFile             string                       `json:"ca_file"`
	JWTFile            string                       `json:"jwt_file"`
	Workload           a.ControllerVerifierWorkload `json:"workload"`
	KubernetesReads    a.VerifierKubernetesReads    `json:"kubernetes_reads"`
	Grant              s.PublisherCaptureGrantMount `json:"grant"`
}

func (r PublisherVerifierReference) validate() error {
	if r.Protocol != PublisherVerifierMaterialsVersion || !filepath.IsAbs(r.Path) || filepath.Clean(r.Path) != r.Path {
		return c.ErrExecutionAuthority
	}
	return nil
}
func (p PublisherVerifierMaterials) validate(cfg DeploymentConfig) error {
	if p.Version != PublisherVerifierMaterialsVersion || p.Database.Database == "" || p.Database.ServerUUID == "" || p.Binding.InstallationID != cfg.InstallationID || p.Workload.ControllerOwner != "public:"+p.Workload.PodUID || p.Workload.Namespace != cfg.Namespace || p.KubernetesReads.NamespaceUID != cfg.NamespaceUID || p.Workload.ServiceAccountUID == cfg.Security.ServiceAccountUID || p.Workload.ServiceAccountName == cfg.Security.ServiceAccountName || p.KubernetesReads.Validate(p.Workload) != nil || len(p.InstallationIssuer) != ed25519.PublicKeySize || len(p.GenerateCapability.Issuer) != ed25519.PublicKeySize || len(p.UnwrapCapability.Issuer) != ed25519.PublicKeySize || len(p.Grant.Issuer) != ed25519.PublicKeySize || !formalCandidateDigest(p.Grant.SHA256) || p.Workload.GrantSHA256 != p.Grant.SHA256 {
		return c.ErrExecutionAuthority
	}
	for _, path := range []string{p.CAFile, p.JWTFile, p.Grant.File} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return c.ErrExecutionAuthority
		}
	}
	if _, err := reg.BindingFingerprint(p.Binding); err != nil {
		return c.ErrExecutionAuthority
	}
	return nil
}
func loadPublisherVerifierMaterials(cfg DeploymentConfig, inputs []PublisherVerifierInput) (*PublisherVerifierMaterials, error) {
	ref := cfg.PublisherVerifier
	if ref == nil {
		if len(inputs) != 0 {
			return nil, c.ErrExecutionAuthority
		}
		return nil, nil
	}
	if ref.validate() != nil || len(inputs) != 1 || inputs[0].File != ref.Path {
		return nil, c.ErrExecutionAuthority
	}
	raw, err := pinnedDeploymentFile(inputs[0].File, inputs[0].SHA256, 1<<20)
	if err != nil {
		return nil, err
	}
	var p PublisherVerifierMaterials
	if decodeProviderDeploymentJSON(raw, &p) != nil || p.validate(cfg) != nil {
		return nil, c.ErrExecutionAuthority
	}
	return &p, nil
}
func (d *DeploymentService) loadPublisherVerifierInput(inputs []PublisherVerifierInput) error {
	p, err := loadPublisherVerifierMaterials(d.Config, inputs)
	if err != nil {
		return err
	}
	if p == nil {
		return nil
	}
	if d.publicationBinding() != nil {
		return c.ErrExecutionAuthority
	}
	g := d.Forward.DeploymentBinding()
	if p.Database != (reg.DatabaseIdentity{ServerUUID: g.ServerUUID, Database: g.Database}) || p.Workload.ConfigVersion != g.ConfigVersion || p.Workload.ConfigSHA256 != g.ConfigSHA256 {
		return c.ErrExecutionAuthority
	}
	input := inputs[0]
	d.publisherVerifierInput = &input
	d.publisherVerifier = p
	return nil
}
func (d *DeploymentService) attachPublisherVerifier(ctx context.Context, db *sql.DB, client kubernetes.Interface, records c.SQLExecutionRecords) error {
	if d == nil {
		return c.ErrExecutionAuthority
	}
	if !d.ForwardEnabled {
		return nil
	}
	if d.Config.PublisherVerifier == nil {
		if d.publisherVerifier != nil {
			return c.ErrExecutionAuthority
		}
		return nil
	}
	p := d.publisherVerifier
	if p == nil || d.publisherVerifierInput == nil || d.publicationBinding() != nil || p.validate(d.Config) != nil || p.Workload.PodName != d.controllerActor.PodName || p.Workload.PodUID != d.controllerActor.PodUID || p.Workload.ServiceAccountName != d.controllerActor.ServiceAccountName || p.Workload.ControllerOwner != d.PublisherOwner {
		return c.ErrExecutionAuthority
	}
	if d.Forward.CheckDeployment(ctx, db) != nil {
		return c.ErrExecutionAuthority
	}
	ca, err := pinnedDeploymentFile(p.CAFile, p.Binding.Provider.CAPEMSHA256, 65536)
	if err != nil {
		return err
	}
	g := d.Forward.DeploymentBinding()
	deployment := s.PublisherCaptureDeployment{InstallationID: g.InstallationID, ServerUUID: g.ServerUUID, Database: g.Database, DatabaseAccount: g.DatabaseAccount, ControllerOwner: g.ControllerOwner, ConfigVersion: g.ConfigVersion, ConfigSHA256: g.ConfigSHA256, ProfileSHA256: g.ProfileSHA256, DeploymentConfigSHA256: g.DeploymentConfigSHA256, CaptureGrantSHA256: d.Forward.GrantSHA256(), NotBefore: g.NotBefore, Until: g.ExpiresAt}
	w := p.Workload
	actor := s.PublisherCaptureWorkload{Namespace: w.Namespace, NamespaceUID: p.KubernetesReads.NamespaceUID, PodName: w.PodName, PodUID: w.PodUID, ServiceAccountName: w.ServiceAccountName, ServiceAccountUID: w.ServiceAccountUID, PublisherOwner: w.ControllerOwner, GrantSHA256: w.GrantSHA256}
	capabilities, err := a.NewSQLProviderCapabilityPreparation(db, p.Database, d.Config.InstallationID, p.GenerateCapability, p.UnwrapCapability)
	if err != nil {
		return err
	}
	factory, err := a.NewPublisherVerifierFactory(a.PublisherVerifierConfig{Capabilities: capabilities, Binding: p.Binding, CAPEM: ca, JWTFile: p.JWTFile, InstallationIssuer: p.InstallationIssuer, Workload: w, KubernetesReads: p.KubernetesReads, Kubernetes: client, Authority: s.PublisherCaptureAuthorityConfig{DB: db, Kubernetes: client, Deployment: deployment, Workload: actor, GrantMount: p.Grant}, Records: records})
	if err != nil {
		return err
	}
	if factory.CheckDeployment(ctx) != nil {
		return c.ErrExecutionAuthority
	}
	d.publisherVerifierFactory, d.publisherVerifierDB = factory, db
	return nil
}
func (d *DeploymentService) PublisherVerifierForPart(ctx context.Context, claim c.ClaimToken, attempt uint64, part string) (*a.PublisherVerifier, error) {
	if d == nil || d.publisherVerifierFactory == nil || d.publisherVerifierDB == nil || claim.Target.Kind != c.TargetBackup || claim.Owner != d.PublisherOwner || d.checkPublisherVerifierBinding(ctx) != nil {
		return nil, c.ErrExecutionAuthority
	}
	return d.publisherVerifierFactory.ForPart(ctx, s.PublisherCaptureScope{BackupPublicID: claim.Target.PublicID, Claim: s.SQLSigningClaim{ControllerOwner: claim.Owner, RowVersion: claim.RowVersion}, CaptureAttemptNo: attempt, Part: part})
}

// Shared current no-task/no-provider probe for real readiness and admission.
// It is not task authorization; ForPart independently authenticates its claim.
func (d *DeploymentService) CheckPublisherVerifierReadiness(ctx context.Context) error {
	if d == nil || ctx == nil || ctx.Err() != nil || !d.ForwardEnabled {
		return c.ErrExecutionAuthority
	}
	if d.Config.PublisherVerifier == nil {
		return c.ErrExecutionAuthority
	}
	if d.publisherVerifierFactory == nil || d.publisherVerifierDB == nil || d.checkPublisherVerifierBinding(ctx) != nil {
		return c.ErrExecutionAuthority
	}
	if d.publisherVerifierFactory.CheckDeployment(ctx) != nil {
		return c.ErrExecutionAuthority
	}
	return d.checkPublisherVerifierBinding(ctx)
}

// Local-only, bounded checks remain safe inside the original task/KEK locks.
func (d *DeploymentService) checkPublisherVerifierBinding(ctx context.Context) error {
	if d == nil || ctx == nil || ctx.Err() != nil || !d.ForwardEnabled {
		return c.ErrExecutionAuthority
	}
	if d.Config.PublisherVerifier == nil {
		if d.publisherVerifierInput != nil || d.publisherVerifier != nil || d.publisherVerifierFactory != nil {
			return c.ErrExecutionAuthority
		}
		return nil
	}
	if d.publisherVerifierInput == nil || d.publisherVerifier == nil || d.publicationBinding() != nil {
		return c.ErrExecutionAuthority
	}
	p, err := loadPublisherVerifierMaterials(d.Config, []PublisherVerifierInput{*d.publisherVerifierInput})
	if err != nil || !reflect.DeepEqual(p, d.publisherVerifier) {
		return c.ErrExecutionAuthority
	}
	if _, err := pinnedDeploymentFile(p.CAFile, p.Binding.Provider.CAPEMSHA256, 65536); err != nil {
		return c.ErrExecutionAuthority
	}
	return nil
}
