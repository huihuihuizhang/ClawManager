// Package systembackupresources owns the resources business-domain boundary.
// It does not grant access to credentials, other business domains, or the
// system-backup control tables.
package systembackupresources

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
)

const contractVersion = "system-backup-plan.v12"
const registryVersion = "system-backup-schema-registry.v1"

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var evidenceIDPattern = regexp.MustCompile(`^sev_[A-Za-z0-9_-]+$`)

func validOwner(owner string) bool {
	return owner == "A" || owner == "B" || owner == "C" || owner == "D"
}

func validateCrossReviews(owner string, required, approved []string, key string) error {
	if !validOwner(owner) {
		return fmt.Errorf("schema object has invalid owner at %s", key)
	}
	requiredReviewers := make(map[string]struct{}, len(required))
	for _, reviewer := range required {
		if !validOwner(reviewer) || reviewer == owner {
			return fmt.Errorf("schema object has invalid cross-reviewer at %s", key)
		}
		if _, duplicate := requiredReviewers[reviewer]; duplicate {
			return fmt.Errorf("schema object has duplicate cross-reviewer at %s", key)
		}
		requiredReviewers[reviewer] = struct{}{}
	}
	approvedReviewers := make(map[string]struct{}, len(approved))
	for _, reviewer := range approved {
		if _, required := requiredReviewers[reviewer]; !required {
			return fmt.Errorf("schema object has unexpected approval at %s", key)
		}
		if _, duplicate := approvedReviewers[reviewer]; duplicate {
			return fmt.Errorf("schema object has duplicate approval at %s", key)
		}
		approvedReviewers[reviewer] = struct{}{}
	}
	if len(approvedReviewers) != len(requiredReviewers) {
		return fmt.Errorf("schema object cross-review missing at %s", key)
	}
	return nil
}

// The plan's D-owned business tables are deliberately closed. Adding a table
// requires changing the plan, registry, and this capture boundary together.
var resourceTables = map[string]struct{}{
	"audit_logs":                {},
	"egress_private_exceptions": {},
	"northbound_admin_settings": {},
	"northbound_settings_audit": {},
	"security_scan_configs":     {},
	"security_scan_job_items":   {},
	"security_scan_jobs":        {},
	"security_scan_reports":     {},
	"system_image_settings":     {},
}

type registry struct {
	Kind            string `json:"kind"`
	RegistryVersion string `json:"registry_version"`
	ContractVersion string `json:"contract_version"`
	ContractStatus  string `json:"contract_status"`
	SchemaHash      struct {
		Algorithm string  `json:"algorithm"`
		Status    string  `json:"status"`
		Hash      *string `json:"hash"`
		Evidence  *struct {
			PublicID string `json:"public_id"`
			SHA256   string `json:"sha256"`
		} `json:"evidence"`
	} `json:"schema_hash"`
	Summary struct {
		ObjectCount        int `json:"object_count"`
		PolicyRecorded     int `json:"policy_recorded"`
		PolicyPending      int `json:"policy_pending"`
		CrossReviewPending int `json:"cross_review_pending"`
	} `json:"summary"`
	Objects []struct {
		ObjectType             string   `json:"object_type"`
		Name                   string   `json:"name"`
		Owner                  string   `json:"owner"`
		Category               string   `json:"category"`
		Classification         *string  `json:"data_classification"`
		BackupStrategy         string   `json:"backup_strategy"`
		RestoreStrategy        string   `json:"restore_strategy"`
		NormalizerID           string   `json:"normalizer_id"`
		VerifierID             string   `json:"verifier_id"`
		DecisionStatus         string   `json:"decision_status"`
		RequiredCrossReviewers []string `json:"required_cross_reviewers"`
		ApprovedCrossReviewers []string `json:"approved_cross_reviewers"`
	} `json:"objects"`
}

// CaptureTableAllowlist returns the complete, sorted D resources MySQL dump
// scope only after the shared registry and every D resource decision are
// frozen. Callers must not interpret a draft scope as a partial allowlist.
func CaptureTableAllowlist(registryJSON []byte) ([]string, error) {
	var document registry
	if err := json.Unmarshal(registryJSON, &document); err != nil {
		return nil, fmt.Errorf("decode schema registry: %w", err)
	}
	if document.Kind != "system_backup_schema_registry" || document.RegistryVersion != registryVersion ||
		document.ContractVersion != contractVersion || document.ContractStatus != "frozen" {
		return nil, errors.New("resources capture requires frozen v12 schema registry")
	}
	if document.SchemaHash.Algorithm != "sha256-information-schema-canonical-v1" ||
		document.SchemaHash.Status != "observed" || document.SchemaHash.Hash == nil ||
		!sha256Pattern.MatchString(*document.SchemaHash.Hash) || document.SchemaHash.Evidence == nil ||
		!evidenceIDPattern.MatchString(document.SchemaHash.Evidence.PublicID) ||
		!sha256Pattern.MatchString(document.SchemaHash.Evidence.SHA256) {
		return nil, errors.New("resources capture requires observed schema hash with registered evidence")
	}
	if document.Summary.ObjectCount != len(document.Objects) || document.Summary.PolicyRecorded != len(document.Objects) ||
		document.Summary.PolicyPending != 0 || document.Summary.CrossReviewPending != 0 {
		return nil, errors.New("resources capture requires complete frozen registry summary")
	}
	seenObjects := make(map[string]struct{}, len(document.Objects))
	seenResources := make(map[string]struct{}, len(resourceTables))
	for _, object := range document.Objects {
		key := object.ObjectType + ":" + object.Name
		if object.ObjectType == "" || object.Name == "" {
			return nil, errors.New("schema registry contains unnamed object")
		}
		if _, duplicate := seenObjects[key]; duplicate {
			return nil, fmt.Errorf("duplicate schema object %s", key)
		}
		seenObjects[key] = struct{}{}
		if object.DecisionStatus != "frozen" {
			return nil, fmt.Errorf("schema object is not frozen: %s", key)
		}
		if err := validateCrossReviews(object.Owner, object.RequiredCrossReviewers, object.ApprovedCrossReviewers, key); err != nil {
			return nil, err
		}
		_, required := resourceTables[object.Name]
		if object.Category != "resources" && !required {
			continue
		}
		if !required || object.ObjectType != "table" || object.Category != "resources" || object.Owner != "D" {
			return nil, fmt.Errorf("resources capture scope mismatch at %s", key)
		}
		if object.Classification == nil ||
			(*object.Classification != "public" && *object.Classification != "internal" && *object.Classification != "confidential") ||
			object.BackupStrategy != "mysql_dump" || object.RestoreStrategy != "normalize" ||
			object.NormalizerID != "resources."+object.Name+".normalize.v1" ||
			object.VerifierID != "resources."+object.Name+".verify.v1" ||
			len(object.RequiredCrossReviewers) == 0 {
			return nil, fmt.Errorf("resources capture policy is incomplete for %s", key)
		}
		seenResources[object.Name] = struct{}{}
	}
	if len(seenResources) != len(resourceTables) {
		return nil, fmt.Errorf("resources capture scope incomplete: got %d of %d tables", len(seenResources), len(resourceTables))
	}
	tables := make([]string, 0, len(seenResources))
	for table := range seenResources {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	return tables, nil
}
