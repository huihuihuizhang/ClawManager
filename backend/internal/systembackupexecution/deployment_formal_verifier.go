package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"path/filepath"

	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// Independent deployed pins; public task requests cannot provide these values.
// Capability/installation/verifier business issuers have separate provenance.
type FormalVerifierDeploymentConfig struct {
	Version            string                          `json:"schema_version"`
	Database           reg.DatabaseIdentity            `json:"database"`
	Binding            reg.Binding                     `json:"binding"`
	GenerateCapability a.ProviderCapabilityPin         `json:"generate_capability"`
	UnwrapCapability   a.ProviderCapabilityPin         `json:"unwrap_capability"`
	InstallationIssuer ed25519.PublicKey               `json:"installation_issuer"`
	CAFile             string                          `json:"ca_file"`
	JWTFile            string                          `json:"jwt_file"`
	Workload           a.ControllerVerifierWorkload    `json:"workload"`
	Grant              a.ControllerVerifierGrantMount  `json:"grant"`
	ProviderPermits    *ProviderPermitDeploymentConfig `json:"provider_permits,omitempty"`
	KubernetesReads    *a.VerifierKubernetesReads      `json:"kubernetes_reads,omitempty"`
}

const formalVerifierMaterialsVersion = "controller-verifier-materials.v1"

// Core configuration pins only this static path/protocol. The later bundle's
// hash is an independent startup argument, so config -> Forward -> verifier
// grant -> bundle hash is acyclic and the full core config digest stays exact.
type FormalVerifierReference struct {
	Protocol string `json:"protocol"`
	Path     string `json:"path"`
}
type FormalVerifierInput struct{ File, SHA256 string }

func (v FormalVerifierReference) validate(DeploymentConfig) error {
	if v.Protocol != formalVerifierMaterialsVersion || !filepath.IsAbs(v.Path) || filepath.Clean(v.Path) != v.Path {
		return c.ErrExecutionAuthority
	}
	return nil
}

func (s *DeploymentService) loadFormalVerifier(inputs []FormalVerifierInput) error {
	ref := s.Config.FormalVerifier
	if ref == nil {
		if len(inputs) != 0 {
			return c.ErrExecutionAuthority
		}
		return nil
	}
	if ref.validate(s.Config) != nil || len(inputs) != 1 || inputs[0].File != ref.Path {
		return c.ErrExecutionAuthority
	}
	raw, err := pinnedDeploymentFile(inputs[0].File, inputs[0].SHA256, 1<<20)
	if err != nil {
		return err
	}
	if _, err = jsoncanonicalizer.Transform(raw); err != nil {
		return c.ErrExecutionAuthority
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var materials FormalVerifierDeploymentConfig
	if decoder.Decode(&materials) != nil || decoder.Decode(new(any)) != io.EOF || materials.validate(s.Config) != nil {
		return c.ErrExecutionAuthority
	}
	s.formalVerifier = &materials
	return nil
}

func (v FormalVerifierDeploymentConfig) validate(cfg DeploymentConfig) error {
	if v.KubernetesReads != nil && v.KubernetesReads.Validate(v.Workload) != nil {
		return c.ErrExecutionAuthority
	}
	if v.ProviderPermits != nil && v.ProviderPermits.validate(cfg) != nil {
		return c.ErrExecutionAuthority
	}
	if v.Version != formalVerifierMaterialsVersion || v.Database.Database == "" || v.Database.ServerUUID == "" || v.Binding.InstallationID != cfg.InstallationID || v.Workload.ControllerOwner != cfg.ControllerOwner || v.Workload.ServiceAccountUID == cfg.Security.ServiceAccountUID || len(v.InstallationIssuer) != ed25519.PublicKeySize || len(v.Grant.Issuer) != ed25519.PublicKeySize || len(v.GenerateCapability.Issuer) != ed25519.PublicKeySize || len(v.UnwrapCapability.Issuer) != ed25519.PublicKeySize || !formalCandidateDigest(v.Grant.SHA256) || v.Workload.GrantSHA256 != v.Grant.SHA256 || !formalCandidateDigest(v.Binding.Provider.CAPEMSHA256) {
		return c.ErrExecutionAuthority
	}
	for _, p := range []string{v.CAFile, v.JWTFile, v.Grant.File} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return c.ErrExecutionAuthority
		}
	}
	if _, err := reg.BindingFingerprint(v.Binding); err != nil {
		return c.ErrExecutionAuthority
	}
	return nil
}

// attachFormalVerifier is called by NewDeploymentService after constructing its
// actual captureGate. No factory can replace deploymentAuthorization or Forward.
func (s *DeploymentService) attachFormalVerifier(o *PublicJobOwner) error {
	if !s.ForwardEnabled {
		return nil
	}
	v := s.formalVerifier
	if v == nil && s.Config.FormalVerifier == nil {
		return nil
	}
	if v == nil || o == nil || o.Identity != s.Forward || v.validate(s.Config) != nil {
		return c.ErrExecutionAuthority
	}
	if reads := v.KubernetesReads; reads != nil && (v.Workload.Namespace != s.Config.Namespace || reads.NamespaceUID != s.Config.NamespaceUID || v.Workload.PodName != s.controllerActor.PodName || v.Workload.PodUID != s.controllerActor.PodUID || v.Workload.ServiceAccountName != s.controllerActor.ServiceAccountName) {
		return c.ErrExecutionAuthority
	}
	deployment := s.Forward.DeploymentBinding()
	if v.Database.Database != deployment.Database || v.Database.ServerUUID != deployment.ServerUUID {
		return c.ErrExecutionAuthority
	}
	ca, err := pinnedDeploymentFile(v.CAFile, v.Binding.Provider.CAPEMSHA256, 65536)
	if err != nil {
		return err
	}
	capabilities, err := a.NewSQLProviderCapabilityPreparation(o.Gate.Authority.DB, v.Database, s.Config.InstallationID, v.GenerateCapability, v.UnwrapCapability)
	if err != nil {
		return err
	}
	if err = s.attachProviderPermits(o, capabilities); err != nil {
		return err
	}
	factory, err := a.NewControllerVerifierFactory(a.ControllerVerifierConfig{Capabilities: capabilities, Binding: v.Binding, CAPEM: ca, JWTFile: v.JWTFile, Workload: v.Workload, Kubernetes: o.Client, Authority: o.Gate.Authority, Records: o.Gate.Records, GrantMount: v.Grant, CaptureGrantSHA256: s.Forward.GrantSHA256(), InstallationIssuer: v.InstallationIssuer, KubernetesReads: v.KubernetesReads})
	if err != nil {
		return err
	}
	o.FormalKeys = func(ctx context.Context, scope FormalCandidateReadScope) (FormalCandidateKeyUse, error) {
		in, _, _, err := o.input(ctx, scope.Authority, false)
		if err != nil {
			return nil, err
		}
		record, err := o.ReadFormalCandidate(ctx, scope.Authority, scope.Job, false)
		if err != nil {
			return nil, err
		}
		actual, _ := json.Marshal(record.Candidate)
		expected, _ := json.Marshal(scope.Candidate)
		if !bytes.Equal(actual, expected) || record.Pod != scope.CapturePod || record.ExecutionGrantSHA256 != scope.CaptureGrantSHA256 {
			return nil, c.ErrExecutionRecord
		}
		raw, err := json.Marshal(record)
		if err != nil {
			return nil, err
		}
		use, err := factory.ForCandidate(ctx, a.ControllerVerifierCandidate{Input: in, Job: scope.Job, Invocation: scope.Invocation, CandidateSHA256: hash(raw), CaptureGrantSHA256: scope.CaptureGrantSHA256})
		if err != nil {
			return nil, err
		}
		frozen, err := json.Marshal(scope)
		if err != nil {
			use.Close()
			return nil, err
		}
		return &deploymentFormalVerifierUse{ControllerVerifier: use, scope: frozen}, nil
	}
	return nil
}

type deploymentFormalVerifierUse struct {
	*a.ControllerVerifier
	scope []byte
}

func (v *deploymentFormalVerifierUse) Identity() FormalVerifierIdentity {
	w := v.Workload()
	return FormalVerifierIdentity{Namespace: w.Namespace, PodName: w.PodName, PodUID: w.PodUID, ServiceAccountName: w.ServiceAccountName, ServiceAccountUID: w.ServiceAccountUID, OwnerKind: w.OwnerKind, OwnerUID: w.OwnerUID, GrantSHA256: w.GrantSHA256}
}
func (v *deploymentFormalVerifierUse) Recheck(ctx context.Context, scope FormalCandidateReadScope) error {
	raw, err := json.Marshal(scope)
	if err != nil || !bytes.Equal(raw, v.scope) {
		return d.ErrNotReady
	}
	return v.ControllerVerifier.Recheck(ctx)
}

var _ FormalCandidateKeyUse = (*deploymentFormalVerifierUse)(nil)
