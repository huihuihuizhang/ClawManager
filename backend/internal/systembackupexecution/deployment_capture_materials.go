package systembackupexecution

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	k "clawreef/internal/systembackupkms"
)

const productionCaptureMaterialsVersion = "original-six-part-capture-materials.v1"

// Only this path/protocol is in the parent core config. The later material
// digest arrives independently at startup, preserving core -> source grants ->
// worker mapping hashes without a future task/Job/hash cycle.
type ProductionCaptureReference struct {
	Protocol string `json:"protocol"`
	Path     string `json:"path"`
}

type ProductionCaptureInput struct{ File, SHA256 string }

func ProductionCaptureInputsFromEnvironment() []ProductionCaptureInput {
	file, digest := os.Getenv("SYSTEM_BACKUP_CAPTURE_MATERIALS_FILE"), os.Getenv("SYSTEM_BACKUP_CAPTURE_MATERIALS_SHA256")
	if file == "" && digest == "" {
		return nil
	}
	return []ProductionCaptureInput{{File: file, SHA256: digest}}
}

// Original deployment templates contain no task/attempt/Job identity. The
// factory binds those coordinates only after the original inventory freezes.
type productionCaptureOperation struct {
	Request         worker.Request
	Formal          worker.FormalCaptureSpec
	Provider        k.Access
	Workload        kube.JobRequest
	MountIdentities []kube.MountIdentity `json:",omitempty"`
}

type productionCaptureMaterials struct {
	Version, Revision                                                           string
	InstallationID, ControllerOwner, DeploymentConfigSHA256, CaptureGrantSHA256 string
	Operations                                                                  map[string]productionCaptureOperation
	Redis, Objects                                                              worker.FormalSourceMount
	SkillBucket, SkillPrefix                                                    string
	UserMetadataAllowlist                                                       []string
	MaxObjects                                                                  int
	MaxObjectBytes, MaxObjectTotalBytes                                         int64
	ResourceTypes                                                               []productionResourceType
	ControlEvidence                                                             *ce.CaptureInput                   `json:"ControlEvidence,omitempty"`
	ControlEvidenceSource                                                       *worker.ControlEvidenceSourceMount `json:"ControlEvidenceSource,omitempty"`
	Discovery                                                                   *productionSourceDiscovery         `json:",omitempty"`
}

type productionResourceType struct {
	Part, Group, Version, Resource, LabelSelector string
}

func (r ProductionCaptureReference) validate() error {
	if r.Protocol != productionCaptureMaterialsVersion || !filepath.IsAbs(r.Path) || filepath.Clean(r.Path) != r.Path {
		return c.ErrExecutionAuthority
	}
	return nil
}

func (s *DeploymentService) loadProductionCapture(inputs []ProductionCaptureInput) error {
	if s == nil {
		return c.ErrExecutionAuthority
	}
	s.captureMaterials, s.captureInput = nil, nil
	ref := s.Config.CaptureModules
	if ref == nil {
		if len(inputs) != 0 {
			return c.ErrExecutionAuthority
		}
		return nil
	}
	if !s.ForwardEnabled || s.publicationBinding() != nil || ref.validate() != nil || len(inputs) != 1 || inputs[0].File != ref.Path {
		return c.ErrExecutionAuthority
	}
	raw, err := pinnedDeploymentFile(inputs[0].File, inputs[0].SHA256, 8<<20)
	if err != nil {
		return err
	}
	var materials productionCaptureMaterials
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&materials) != nil || decoder.Decode(new(any)) != io.EOF {
		return c.ErrExecutionAuthority
	}
	canonical, err := json.Marshal(materials)
	if err != nil || !bytes.Equal(canonical, raw) || s.validateProductionCapture(materials) != nil {
		return c.ErrExecutionAuthority
	}
	s.captureMaterials = &materials
	copy := inputs[0]
	s.captureInput = &copy
	return nil
}

func (s *DeploymentService) validateProductionCapture(m productionCaptureMaterials) error {
	if m.Discovery != nil {
		if s == nil || m.Discovery.validate() != nil {
			return c.ErrExecutionAuthority
		}
		platform := map[string]bool{}
		for _, writer := range s.Config.Writers {
			platform["deployment/"+writer.Namespace+"/"+writer.Name] = true
		}
		for id := range m.Discovery.TeamPlatformUnits {
			if !platform[id] {
				return c.ErrExecutionAuthority
			}
		}
		for _, operation := range m.Operations {
			if operation.Formal.PermitDelivery != nil && bytes.Equal(m.Discovery.Issuer, operation.Formal.PermitDelivery.Issuer) {
				return c.ErrExecutionAuthority
			}
		}
	}
	if s == nil || (m.ControlEvidence != nil) != (m.ControlEvidenceSource != nil) || m.ControlEvidence != nil && (m.ControlEvidence.Validate() != nil || m.ControlEvidenceSource.Validate() != nil || m.ControlEvidenceSource.ControllerGrantFile == "" || m.ControlEvidenceSource.Endpoint != s.Config.ControlURL) {
		return c.ErrExecutionAuthority
	}
	if s == nil || !s.ForwardEnabled || s.Forward == nil || s.Config.CaptureScope != "six-part" || s.Config.RuntimeSources == nil || s.Config.FormalVerifier == nil || m.Version != productionCaptureMaterialsVersion || m.Revision == "" || len(m.Revision) > 128 || m.InstallationID != s.Config.InstallationID || m.ControllerOwner != s.Config.ControllerOwner || m.DeploymentConfigSHA256 != s.ConfigDigest || m.CaptureGrantSHA256 != s.Forward.GrantSHA256() || len(m.Operations) < 6 || len(m.Operations) > 8 || m.MaxObjects < 1 || m.MaxObjects > 10000 || m.MaxObjectBytes < 1 || m.MaxObjectTotalBytes < m.MaxObjectBytes || m.MaxObjectTotalBytes > 64<<20 || len(m.ResourceTypes) < 1 || len(m.ResourceTypes) > 32 {
		return c.ErrExecutionAuthority
	}
	for _, operation := range []string{"capture-database", "capture-workspace", "capture-source-redis", "capture-skill-objects", "capture-deployment-resources", "capture-secret-bundle"} {
		if _, exists := m.Operations[operation]; !exists {
			return c.ErrExecutionAuthority
		}
	}
	if _, exists := m.Operations[ce.Operation]; exists != (m.ControlEvidence != nil) {
		return c.ErrExecutionAuthority
	}
	for name, x := range m.Operations {
		switch name {
		case "capture-database", "capture-workspace", "capture-source-redis", "capture-team-objects", "capture-skill-objects", "capture-deployment-resources", "capture-secret-bundle", ce.Operation:
		default:
			return c.ErrExecutionAuthority
		}
		if x.Formal.PermitDelivery == nil || !k.ValidPermitDeliveryPin(*x.Formal.PermitDelivery) || x.Provider.Operation != k.Generate || x.Workload.FormalMaterials == nil || x.Workload.WorkerControl == nil || x.Workload.WorkerControl.URL != s.Config.ControlURL || x.Workload.Identity.Namespace != s.Config.Namespace || x.Workload.Image != s.Config.WorkerImage || x.Workload.StagingClaim != s.Config.StagingClaim || x.Workload.ServiceAccount != s.Config.Security.ServiceAccountName || x.Formal.Version != worker.FormalCaptureVersion || !formalCandidateDigest(x.Formal.ConfigSHA256) || len(x.Workload.Command) != 0 {
			return c.ErrExecutionAuthority
		}
		if name == ce.Operation && bytes.Equal(m.ControlEvidenceSource.Issuer, x.Formal.PermitDelivery.Issuer) {
			return c.ErrExecutionAuthority
		}
	}
	return nil
}

func (s *DeploymentService) checkProductionCaptureMaterials() error {
	if s == nil || s.publicationBinding() != nil || s.captureMaterials == nil || s.captureInput == nil || s.validateProductionCapture(*s.captureMaterials) != nil {
		return c.ErrExecutionAuthority
	}
	raw, err := pinnedDeploymentFile(s.captureInput.File, s.captureInput.SHA256, 8<<20)
	if err != nil {
		return err
	}
	var observed productionCaptureMaterials
	if json.Unmarshal(raw, &observed) != nil || !reflect.DeepEqual(observed, *s.captureMaterials) {
		return c.ErrExecutionAuthority
	}
	return nil
}
