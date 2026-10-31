package publicadapter

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	ce "clawreef/internal/systembackupcontrolevidence"
	d "clawreef/internal/systembackupdispatch"
)

// ModuleCatalogVersion is B's CANDIDATE in-process module intake contract, not
// a replacement public ABI, frozen owner approval or a new worker operation.
const ModuleCatalogVersion = "system-backup-b-module-intake.v1alpha1"

type CaptureModulePart struct {
	Part, Category string
	// RequestedPart is a public BackupSpec storage part, NOT a business domain.
	RequestedPart string
	Operation     string
}

type CaptureModuleDependency struct{ Part, Owner, RequestedPart, Operation string }
type CaptureModuleDescriptor struct {
	ID, Owner, Revision string
	Parts               []CaptureModulePart
	Requires            []CaptureModuleDependency `json:"Requires,omitempty"`
	Required            bool                      `json:"Required,omitempty"`
	DependencyOnly      bool                      `json:"DependencyOnly,omitempty"`
}

// ModuleCaptureContext is D's original admitted capture-point projection.
// Neither a matching hash nor this serializable value proves a physical SQL/
// Redis/filesystem checkpoint. A/D must bind/check the referenced original
// context and current authorization; B never creates that context or its hash.
type ModuleCaptureContext struct {
	InstallationID, TaskPublicID                    string
	ConfigVersion, AttemptNo                        uint64
	Phase, ConfigSHA256, ProfileID, ProfileRevision string
	InventorySHA256, CatalogSHA256                  string
	CaptureContextSHA256                            string
	HoldUntil                                       time.Time
}

type CaptureModuleSelection struct {
	CaptureModulePart
	PartIndex uint32
}

type CaptureModuleInput struct {
	Input   d.Input
	Source  SourceInventory
	Context ModuleCaptureContext
	Parts   []CaptureModuleSelection
}

type CaptureModuleRegistration struct {
	Descriptor CaptureModuleDescriptor
	// Build constructs manifests/payloads only, without SQL, source reads,
	// identity issuance, writes or dispatch. No arbitrary Job command is allowed.
	Build func(CaptureModuleInput) ([]CapturePartRequest, error)
}

// CaptureContextResolver reads an already admitted immutable projection from
// D's original mapping. The existing BuildParts ABI has no context.Context:
// this callback must be bounded and PURE, with no network or database IO.
type CaptureContextResolver func(d.Input, SourceInventory, time.Time, string) (ModuleCaptureContext, error)

type CaptureModules struct {
	modules []CaptureModuleRegistration
	resolve CaptureContextResolver
	hash    string
}

func knownRequestedPart(part string) bool {
	switch part {
	case "mysql", "redis", "object_storage", "workspace", "deployment_resources", "secret_bundle":
		return true
	}
	return false
}

// NewCaptureModules freezes the actual registered operations and dependencies.
// A dependency-only domain contributes its data to another owner's shared
// capture (for example empty Teams plus template/history SQL), never a fake Job.
func NewCaptureModules(registrations []CaptureModuleRegistration, resolve CaptureContextResolver) (*CaptureModules, error) {
	if len(registrations) == 0 || len(registrations) > 256 || resolve == nil {
		return nil, d.ErrNotReady
	}
	m := &CaptureModules{resolve: resolve}
	ids, parts := map[string]bool{}, map[string]bool{}
	for _, registration := range registrations {
		descriptor := registration.Descriptor
		if !unit.MatchString(descriptor.ID) || ids[descriptor.ID] || !strings.Contains("ABCD", descriptor.Owner) || len(descriptor.Owner) != 1 || descriptor.Revision == "" || len(descriptor.Revision) > 128 || !utf8.ValidString(descriptor.Revision) || strings.ContainsAny(descriptor.Revision, "\x00\r\n") || registration.Build == nil {
			return nil, d.ErrNotReady
		}
		if (len(descriptor.Parts) == 0) != descriptor.DependencyOnly || (descriptor.DependencyOnly && (!descriptor.Required || len(descriptor.Requires) == 0)) {
			return nil, d.ErrNotReady
		}
		ids[descriptor.ID] = true
		if !validControlEvidenceDescriptor(descriptor) {
			return nil, d.ErrNotReady
		}
		descriptor.Parts = append([]CaptureModulePart(nil), descriptor.Parts...)
		descriptor.Requires = append([]CaptureModuleDependency(nil), descriptor.Requires...)
		for _, part := range descriptor.Parts {
			if !unit.MatchString(part.Part) || !unit.MatchString(part.Category) || parts[part.Part] || !knownRequestedPart(part.RequestedPart) {
				return nil, d.ErrNotReady
			}
			switch part.Operation {
			case ce.Operation:
				if descriptor.ID != ce.Part || descriptor.Owner != "D" || part.RequestedPart != "mysql" || part.Category != ce.Part || part.Part != ce.Part && part.Part != ce.ProofPart {
					return nil, d.ErrNotReady
				}
			case "capture-source-redis":
				if descriptor.Owner != "D" || part.RequestedPart != "redis" {
					return nil, d.ErrNotReady
				}
			case "capture-skill-objects":
				if descriptor.Owner != "D" || part.RequestedPart != "object_storage" {
					return nil, d.ErrNotReady
				}
			case "capture-deployment-resources":
				if descriptor.Owner != "D" || part.RequestedPart != "deployment_resources" {
					return nil, d.ErrNotReady
				}
			case "capture-secret-bundle":
				if descriptor.Owner != "D" || part.RequestedPart != "secret_bundle" {
					return nil, d.ErrNotReady
				}
			case "capture-workspace":
				if part.RequestedPart != "workspace" {
					return nil, d.ErrNotReady
				}
			case "capture-database":
				if part.RequestedPart != "mysql" || descriptor.Owner != "B" {
					return nil, d.ErrNotReady
				}
			case "capture-team-redis":
				if descriptor.Owner != "C" || part.RequestedPart != "redis" {
					return nil, d.ErrNotReady
				}
			case "capture-team-objects":
				if descriptor.Owner != "C" || part.RequestedPart != "object_storage" {
					return nil, d.ErrNotReady
				}
			default:
				return nil, d.ErrNotReady
			}
			parts[part.Part] = true
		}
		if len(parts) > 10000 {
			return nil, d.ErrNotReady
		}
		sort.Slice(descriptor.Parts, func(i, j int) bool { return descriptor.Parts[i].Part < descriptor.Parts[j].Part })
		m.modules = append(m.modules, CaptureModuleRegistration{descriptor, registration.Build})
	}
	definitions := map[string]CaptureModuleDependency{}
	for _, registration := range m.modules {
		for _, part := range registration.Descriptor.Parts {
			definitions[part.Part] = CaptureModuleDependency{part.Part, registration.Descriptor.Owner, part.RequestedPart, part.Operation}
		}
	}
	for _, registration := range m.modules {
		seen := map[string]bool{}
		for _, required := range registration.Descriptor.Requires {
			if !parts[required.Part] || seen[required.Part] || !unit.MatchString(required.Part) || definitions[required.Part] != required {
				return nil, d.ErrNotReady
			}
			seen[required.Part] = true
		}
	}
	sort.Slice(m.modules, func(i, j int) bool { return m.modules[i].Descriptor.ID < m.modules[j].Descriptor.ID })
	catalog, _ := json.Marshal(struct {
		Version string
		Modules []CaptureModuleDescriptor
	}{ModuleCatalogVersion, m.Describe()})
	m.hash = digest(catalog)
	return m, nil
}

func (m *CaptureModules) Describe() []CaptureModuleDescriptor {
	if m == nil {
		return nil
	}
	out := make([]CaptureModuleDescriptor, len(m.modules))
	for i, registration := range m.modules {
		out[i] = registration.Descriptor
		out[i].Parts = append([]CaptureModulePart(nil), registration.Descriptor.Parts...)
		out[i].Requires = append([]CaptureModuleDependency(nil), registration.Descriptor.Requires...)
	}
	return out
}

func (m *CaptureModules) CatalogSHA256() string {
	if m == nil {
		return ""
	}
	return m.hash
}

func (c ModuleCaptureContext) matches(in d.Input, inventorySHA, catalogSHA string, hold time.Time) bool {
	a := in.Authority
	return c.InstallationID == a.InstallationID && c.TaskPublicID == a.TaskPublicID && c.ConfigVersion == a.ConfigVersion && c.AttemptNo == a.AttemptNo && c.Phase == a.Phase && c.ConfigSHA256 == a.ConfigSHA256 && c.ProfileID == in.ProfileID && c.ProfileRevision == in.ProfileRevision && c.InventorySHA256 == inventorySHA && c.CatalogSHA256 == catalogSHA && hexHash.MatchString(c.CaptureContextSHA256) && c.HoldUntil.Equal(hold)
}

// BuildParts calls selected real module builders and BuildCapturePart. Missing
// requested storage parts, empty/extra/duplicate module output, inconsistent
// capture points or invalid Jobs reject the ENTIRE assembly without dispatch.
// Storage-kind coverage here never replaces Dependencies.ValidateInventory's
// full domain/writer registry checks or A/C authentication and immutable seals.
func (m *CaptureModules) BuildParts(in d.Input, source SourceInventory, hold time.Time) ([]JobPart, error) {
	if m == nil || m.resolve == nil || validateInput(in, false) != nil || in.Authority.TaskType != "backup" || d.ValidateBackupSpec(in.Backup) != nil || !time.Now().Before(hold) || hold.After(in.Authority.DeadlineAt) {
		return nil, d.ErrNotReady
	}
	raw, err := json.Marshal(source)
	if err != nil {
		return nil, d.ErrNotReady
	}
	requested, covered := map[string]bool{}, map[string]bool{}
	for _, part := range in.Backup.RequestedParts {
		requested[part] = true
	}
	selections := make([][]CaptureModuleSelection, len(m.modules))
	var index uint32
	for i, registration := range m.modules {
		if registration.Descriptor.Required {
			for _, part := range registration.Descriptor.Parts {
				if !requested[part.RequestedPart] {
					return nil, d.ErrNotReady
				}
			}
		}
		for _, part := range registration.Descriptor.Parts {
			if requested[part.RequestedPart] {
				selections[i] = append(selections[i], CaptureModuleSelection{part, index})
				covered[part.RequestedPart] = true
				index++
			}
		}
	}
	selectedParts := map[string]bool{}
	for _, list := range selections {
		for _, part := range list {
			selectedParts[part.Part] = true
		}
	}
	for n, registration := range m.modules {
		if registration.Descriptor.Required || len(selections[n]) > 0 {
			for _, part := range registration.Descriptor.Requires {
				if !selectedParts[part.Part] {
					return nil, d.ErrNotReady
				}
			}
		}
	}
	if len(covered) != len(requested) {
		return nil, d.ErrNotReady
	}
	point, err := m.resolve(cloneInput(in), cloneSourceInventory(source), hold, m.hash)
	if err != nil {
		return nil, classify(err)
	}
	if !point.matches(in, digest(raw), m.hash, hold) {
		return nil, d.ErrNotReady
	}
	var out []JobPart
	outputs := map[string]bool{}
	for i, registration := range m.modules {
		if len(selections[i]) == 0 && !registration.Descriptor.DependencyOnly {
			continue
		}
		expected := map[string]CaptureModuleSelection{}
		for _, selection := range selections[i] {
			expected[selection.Part] = selection
		}
		requests, err := registration.Build(CaptureModuleInput{cloneInput(in), cloneSourceInventory(source), point, append([]CaptureModuleSelection(nil), selections[i]...)})
		if err != nil {
			return nil, classify(err)
		}
		if len(requests) != len(expected) {
			return nil, d.ErrNotReady
		}
		// Builders may return another order; the persisted plan stays canonical.
		requests = append([]CapturePartRequest(nil), requests...)
		sort.Slice(requests, func(i, j int) bool { return requests[i].Part < requests[j].Part })
		for _, request := range requests {
			selection, ok := expected[request.Part]
			if !ok || request.Category != selection.Category || request.Invocation.Request.Operation != selection.Operation || request.Invocation.Request.Binding.PartIndex != selection.PartIndex || request.Invocation.Request.Binding.CaptureContextHash != point.CaptureContextSHA256 {
				return nil, d.ErrNotReady
			}
			if request.Workload.WorkerControl == nil || !request.Workload.WorkerControl.BoundPodIdentity {
				return nil, d.ErrNotReady
			}
			// All Jobs mount the task subdirectory on their staging PVC. Distinct
			// bindings do not make the same output filename safe to write twice.
			names := []string{request.Invocation.Request.ArtifactName}
			if request.Invocation.FormalCapture != nil {
				names = append(names, request.Invocation.FormalCapture.EnvelopeName)
			}
			for _, name := range names {
				output := request.Workload.Identity.Namespace + "/" + request.Workload.StagingClaim + "/" + name
				if outputs[output] {
					return nil, d.ErrNotReady
				}
				outputs[output] = true
			}
			if selection.Operation == "capture-database" {
				database := request.Invocation.Request.Database
				if database == nil || source.Database == "" || source.ServerUUID == "" || database.Name != source.Database || database.ServerUUID != source.ServerUUID {
					return nil, d.ErrNotReady
				}
				if source.Teams != nil && (database.TeamsInventory == nil || database.TeamsInventory.SHA256() != source.Teams.SHA256()) {
					return nil, d.ErrNotReady
				}
				if source.Skills != nil && (database.SkillsInventory == nil || database.SkillsInventory.SHA256() != source.Skills.SHA256()) {
					return nil, d.ErrNotReady
				}
			}
			delete(expected, request.Part)
			part, err := BuildCapturePart(in, hold, request)
			if err != nil {
				return nil, err
			}
			out = append(out, part)
		}
	}
	if validateControlEvidenceParts(in, out) != nil || validateSkillWorkspaceParts(source, out) != nil || validateDiscovery(in, Discovery{Source: raw, SourceSHA256: digest(raw), Writers: []FrozenWriter{}, Parts: out, HoldUntil: hold}) != nil {
		return nil, d.ErrNotReady
	}
	return out, nil
}
