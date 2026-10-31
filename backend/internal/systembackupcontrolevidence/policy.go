package systembackupcontrolevidence

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"

	business "clawreef/internal/systembackupbusinessa"
)

// Static owner-supplied lookup material. No future task/Job/hash, credentials,
// success bit, owner-complete declaration or caller-supplied table SQL exists.
type CaptureInput struct {
	SchemaRegistryFile      string `json:"schema_registry_file"`
	SchemaRegistrySHA256    string `json:"schema_registry_sha256"`
	RedactionRegistryFile   string `json:"redaction_registry_file"`
	RedactionRegistrySHA256 string `json:"redaction_registry_sha256"`
	CoverageWindowSeconds   uint32 `json:"coverage_window_seconds"`
}

func (p CaptureInput) Validate() error {
	if !filepath.IsAbs(p.SchemaRegistryFile) || filepath.Clean(p.SchemaRegistryFile) != p.SchemaRegistryFile || !filepath.IsAbs(p.RedactionRegistryFile) || filepath.Clean(p.RedactionRegistryFile) != p.RedactionRegistryFile || !digestPattern.MatchString(p.SchemaRegistrySHA256) || !digestPattern.MatchString(p.RedactionRegistrySHA256) || p.CoverageWindowSeconds < 1 || p.CoverageWindowSeconds > 86400 {
		return ErrInvalid
	}
	return nil
}

type RedactionPolicy struct {
	Version         string              `json:"schema_version"`
	RegistryVersion string              `json:"registry_version"`
	Contract        string              `json:"contract_version"`
	Status          string              `json:"status"`
	Projections     map[string][]string `json:"projections"`
}

// Schema acceptance reuses A's original independently pinned FROZEN registry
// reader, including real observed schema evidence and reviewed object policy.
// A draft or pending_live_evidence document can never become a production pin.
func ReadPolicies(schemaRaw, redactionRaw []byte, input CaptureInput) (RegistryPin, RegistryPin, []string, error) {
	if input.Validate() != nil || SHA256(schemaRaw) != input.SchemaRegistrySHA256 || SHA256(redactionRaw) != input.RedactionRegistrySHA256 {
		return RegistryPin{}, RegistryPin{}, nil, ErrInvalid
	}
	if _, err := business.NewPinnedCaptureScope(schemaRaw, input.SchemaRegistrySHA256); err != nil {
		return RegistryPin{}, RegistryPin{}, nil, ErrInvalid
	}
	var registry struct {
		Version string `json:"registry_version"`
		Objects []struct {
			Type     string `json:"object_type"`
			Name     string `json:"name"`
			Category string `json:"category"`
			Backup   string `json:"backup_strategy"`
			Restore  string `json:"restore_strategy"`
		} `json:"objects"`
	}
	if json.Unmarshal(schemaRaw, &registry) != nil {
		return RegistryPin{}, RegistryPin{}, nil, ErrInvalid
	}
	names := []string{}
	for _, object := range registry.Objects {
		if object.Category == "system_backup" && object.Type == "table" {
			if object.Backup != "metadata_only" || object.Restore != "reference_only" {
				return RegistryPin{}, RegistryPin{}, nil, ErrInvalid
			}
			names = append(names, object.Name)
		}
	}
	sort.Strings(names)
	if _, err := namesHash(names); err != nil {
		return RegistryPin{}, RegistryPin{}, nil, ErrInvalid
	}
	var policy RedactionPolicy
	if closed(redactionRaw, &policy) != nil || policy.Version != "system-backup-control-redaction-registry.v1" || policy.Contract != "system-backup-plan.v12" || policy.Status != "frozen" || policy.RegistryVersion == "" || !reflect.DeepEqual(policy.Projections, ProjectionColumns()) {
		return RegistryPin{}, RegistryPin{}, nil, ErrInvalid
	}
	return RegistryPin{Version: registry.Version, SHA256: input.SchemaRegistrySHA256}, RegistryPin{Version: policy.RegistryVersion, SHA256: input.RedactionRegistrySHA256}, names, nil
}
