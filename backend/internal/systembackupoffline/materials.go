// Package systembackupoffline checks inert public handoff data. It never opens
// a credential, connects to a service, signs, imports, or returns a grant.
package systembackupoffline

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"time"

	root "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/worker"
	adapter "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	sec "clawreef/internal/systembackupsecurity"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	authz "k8s.io/api/authorization/v1"
)

const Protocol = "system-backup-offline-security-materials.v1"
const ReviewOnly = "review_only_not_authorized"
const MaxBytes = 16 << 20

var ErrInput = errors.New("offline material input rejected")
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Bytes are base64 in JSON, preserving the exact externally signed/pinned file.
type SignedMaterial struct{ Record, Signature []byte }
type SecretMaterial struct {
	Policy     []byte
	Selections []root.KubernetesSelection
}
type KEKPin struct {
	Issuer                 ed25519.PublicKey
	RecordSHA256, Revision string
	Reference              reg.ReferencePin
}
type SecretPin struct{ RegistryVersion, SHA256 string }
type SourcePin struct {
	Issuer       ed25519.PublicKey
	RecordSHA256 string
	Expected     worker.FormalSourceGrant
}
type RulesMaterial struct {
	Selections []root.KubernetesSelection
	Rules      authz.SubjectRulesReviewStatus
}
type SQLMaterial struct {
	Database    reg.DatabaseIdentity
	CurrentRole string
	Grants      []string
}

// Expected contains an independently exported original inventory snapshot, NOT
// a count or a claimed Complete boolean. Trust pins its exact original bytes.
type CoverageMaterial struct {
	Expected []byte
	Observed reg.Snapshot
}
type Trust struct {
	Protocol, Status, InstallationID, Namespace, WorkerNamespace string
	Signing                                                      *sec.InstallationSigningPin
	KEK                                                          *KEKPin
	SecretPolicy                                                 *SecretPin
	Capabilities                                                 map[string]sec.CapabilityPolicy
	SourceGrants                                                 map[string]SourcePin
	CoverageInventorySHA256                                      string
	SourceDatabase                                               reg.DatabaseIdentity
}
type Bundle struct {
	Protocol, Status, MaterialKind string
	Signing                        *SignedMaterial
	KEK                            *SignedMaterial
	SecretPolicy                   *SecretMaterial
	Capabilities                   map[string]sec.CapabilityEvidence
	SourceGrants                   map[string]SignedMaterial
	SourceRules                    *RulesMaterial
	SourceSQL                      *SQLMaterial
	Coverage                       *CoverageMaterial
}
type Check struct {
	Slot   string `json:"slot"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}
type Report struct {
	Protocol        string   `json:"protocol"`
	Status          string   `json:"status"`
	MaterialKind    string   `json:"material_kind"`
	ProductionReady bool     `json:"production_ready"`
	Checks          []Check  `json:"checks"`
	Unverified      []string `json:"unverified"`
}

func Digest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

// Decode rejects duplicate keys, unknown members and trailing values before
// Go's case-insensitive field matching can accidentally alias a member.
func Decode(raw []byte, value any) error {
	if len(raw) == 0 || len(raw) > MaxBytes {
		return ErrInput
	}
	if _, err := jsoncanonicalizer.Transform(raw); err != nil {
		return ErrInput
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInput
	}
	// Reject case aliases at every typed object, including nested exported DTOs.
	var submitted any
	if json.Unmarshal(raw, &submitted) != nil {
		return ErrInput
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return ErrInput
	}
	var typed any
	if json.Unmarshal(encoded, &typed) != nil || !memberNames(submitted, typed) {
		return ErrInput
	}
	return nil
}
func memberNames(a, b any) bool {
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok {
			return false
		}
		for k, v := range x {
			w, ok := y[k]
			if !ok || !memberNames(v, w) {
				return false
			}
		}
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !memberNames(x[i], y[i]) {
				return false
			}
		}
	}
	return true
}

var requiredCapabilities = map[string][]string{
	"artifact": {"conditional_create", "checksum_bound_request", "scoped_upload_credential", "scoped_read_credential", "scoped_delete_credential", "multipart_resume", "object_checksum", "version_listing", "delete_marker_listing", "strong_read_after_write", "tls_verified"},
	"catalog":  {"conditional_create", "checksum_bound_request", "scoped_read_credential", "scoped_append_credential", "strong_read_after_write", "provider_snapshot_listing", "inventory_manifest_listing", "versioned_absence_proof", "tls_verified"},
	"evidence": {"conditional_create", "checksum_bound_request", "scoped_read_credential", "scoped_write_credential", "scoped_delete_credential", "object_checksum", "strong_read_after_write", "versioned_absence_proof", "tls_verified"},
	"kms":      {"generate_data_key", "unwrap_data_key", "identity_scope", "identity_revocation", "version_retention"},
	"secret":   {"exact_version_read", "resource_version_guard", "uid_guard", "aes256_kw", "identity_revocation"},
	"signing":  {"purpose_key_separation", "historic_verification", "key_rotation", "scoped_signer", "policy_separation"},
}
var sourceOperations = []string{"capture-database", "capture-source-redis", "capture-skill-objects", "capture-team-redis", "capture-team-objects"}

func Review(t Trust, b Bundle, now time.Time) (Report, error) {
	r := Report{Protocol: Protocol, Status: "offline_materials_checked", MaterialKind: b.MaterialKind, Checks: []Check{}, Unverified: []string{
		"independent_trust_pin_provenance", "current_installation_and_database_identity", "live_revocation_and_original_task_authority",
		"provider_acl_role_jwt_and_current_capabilities", "source_credentials_and_cross_namespace_effective_permissions",
		"authorized_mount_uid_node_and_readonly_observation", "coverage_eof_adoption_writer_fence_and_transaction_recheck",
		"independent_restore_unwrap_and_full_payload_verification",
	}}
	if t.Protocol != Protocol || b.Protocol != Protocol || t.Status != ReviewOnly || b.Status != ReviewOnly || now.IsZero() ||
		(b.MaterialKind != "template" && b.MaterialKind != "local_test_only" && b.MaterialKind != "operator_supplied") {
		return r, ErrInput
	}
	add := func(slot string, present, valid bool) {
		status, reason := "checked_offline", "local_material_only"
		if !present {
			status, reason = "unverified", "real_input_not_provided"
			r.Unverified = append(r.Unverified, slot)
		} else if !valid {
			status, reason = "rejected", "material_mismatch_or_invalid"
		}
		r.Checks = append(r.Checks, Check{slot, status, reason})
		if status == "rejected" {
			r.Status = "rejected"
		} else if status == "unverified" && r.Status != "rejected" {
			r.Status = "incomplete"
		}
	}
	identity := t.InstallationID != "" && t.Namespace != ""
	add("installation_binding", identity, identity)
	valid := false
	if t.Signing != nil && b.Signing != nil && t.Signing.InstallationID == t.InstallationID && identity {
		valid = sec.InspectInstallationSigningMaterial(b.Signing.Record, b.Signing.Signature, *t.Signing, now) == nil
	}
	add("three_purpose_signing", t.Signing != nil || b.Signing != nil, valid)
	valid = false
	if t.KEK != nil && b.KEK != nil && identity {
		p := t.KEK
		valid = adapter.InspectOriginalKEKMaterial(b.KEK.Record, b.KEK.Signature, p.Issuer, p.RecordSHA256, t.InstallationID, p.Revision, p.Reference, now) == nil
	}
	add("original_kek_mapping", t.KEK != nil || b.KEK != nil, valid)
	valid = false
	if t.SecretPolicy != nil && b.SecretPolicy != nil && identity {
		p, err := root.DecodeSecretCapturePolicy(b.SecretPolicy.Policy, t.SecretPolicy.RegistryVersion, t.SecretPolicy.SHA256)
		valid = err == nil && p.ValidateSelections(t.Namespace, b.SecretPolicy.Selections) == nil
	}
	add("secret_policy_selection", t.SecretPolicy != nil || b.SecretPolicy != nil, valid)
	for _, role := range []string{"artifact", "catalog", "evidence", "kms", "secret", "signing"} {
		p, pinned := t.Capabilities[role]
		e, present := b.Capabilities[role]
		p.Now = now
		valid = pinned && present && p.Role == role && identity && sec.ValidateCapabilityEvidence(e, p) == nil
		seen := map[string]bool{}
		for _, c := range e.Capabilities {
			seen[c.Code] = c.Status == "supported" && c.Reason == "none"
		}
		for _, code := range requiredCapabilities[role] {
			valid = valid && seen[code]
		}
		add("capability:"+role, pinned || present, valid)
	}
	for role := range t.Capabilities {
		if requiredCapabilities[role] == nil {
			return r, ErrInput
		}
	}
	for role := range b.Capabilities {
		if requiredCapabilities[role] == nil {
			return r, ErrInput
		}
	}
	known := map[string]bool{}
	for _, op := range sourceOperations {
		known[op] = true
		p, pinned := t.SourceGrants[op]
		m, present := b.SourceGrants[op]
		valid = pinned && present && identity && t.WorkerNamespace != "" && sourceGrant(p, m, t.InstallationID, t.WorkerNamespace, op, now)
		add("source_grant:"+op, pinned || present, valid)
	}
	for op := range t.SourceGrants {
		if !known[op] {
			return r, ErrInput
		}
	}
	for op := range b.SourceGrants {
		if !known[op] {
			return r, ErrInput
		}
	}
	valid = b.SourceRules != nil && b.SourceRules.Selections != nil && len(b.SourceRules.Selections) > 0 && identity
	if valid {
		valid = worker.ResourceSourceRules(worker.ResourceCaptureSpec{Selections: b.SourceRules.Selections}, b.SourceRules.Rules)
	}
	add("source_resource_readonly_rules", b.SourceRules != nil, valid)
	valid = b.SourceSQL != nil && identity && t.SourceDatabase.ServerUUID != "" && t.SourceDatabase.Database != ""
	if valid {
		valid = b.SourceSQL.Database == t.SourceDatabase && b.SourceSQL.CurrentRole == "NONE" && domain.ValidateBusinessSourceGrants(t.SourceDatabase.Database, b.SourceSQL.Grants) == nil
	}
	add("source_sql_readonly_grants", b.SourceSQL != nil, valid)
	coverageChecks := reviewCoverage(t, b.Coverage, now)
	for _, c := range coverageChecks {
		add(c.Slot, c.Status != "unverified", c.Status == "checked_offline")
	}
	return r, nil
}

func sourceGrant(p SourcePin, m SignedMaterial, installation, namespace, operation string, now time.Time) bool {
	if len(p.Issuer) != ed25519.PublicKeySize || !digestPattern.MatchString(p.RecordSHA256) || Digest(m.Record) != p.RecordSHA256 || len(m.Record) > 32768 ||
		!ed25519.Verify(p.Issuer, append([]byte(worker.FormalSourceGrantDomain), m.Record...), m.Signature) {
		return false
	}
	var g worker.FormalSourceGrant
	if Decode(m.Record, &g) != nil || !reflect.DeepEqual(g, p.Expected) || g.Version != worker.FormalSourceGrantVersion || g.InstallationID != installation ||
		g.WorkerNamespace != namespace || g.WorkerServiceAccountUID == "" || g.Operation != operation || g.Revoked || g.NotBefore.IsZero() || now.Before(g.NotBefore) || !now.Before(g.Until) || g.Until.Sub(g.NotBefore) > 24*time.Hour {
		return false
	}
	return digestPattern.MatchString(g.ConfigSHA256) && digestPattern.MatchString(g.ScopeSHA256) && digestPattern.MatchString(g.CredentialSHA256)
}

func Templates() (Trust, Bundle) {
	return Trust{Protocol: Protocol, Status: ReviewOnly, Capabilities: map[string]sec.CapabilityPolicy{}, SourceGrants: map[string]SourcePin{}},
		Bundle{Protocol: Protocol, Status: ReviewOnly, MaterialKind: "template", Capabilities: map[string]sec.CapabilityEvidence{}, SourceGrants: map[string]SignedMaterial{}}
}
