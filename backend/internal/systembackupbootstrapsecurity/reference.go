package systembackupbootstrapsecurity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"unicode/utf8"

	sec "clawreef/internal/systembackupsecurity"
)

// SecurityReference is an immutable projection of secret-ref.schema.json's
// draft wire contract. It contains no resolved material or provider locator.
// Decoding and pin matching confer no resource authority: a deployment adapter
// must still resolve, authorize, observe and recheck the actual resource.
type SecurityReference struct{ fields map[string]string }

func (r SecurityReference) Kind() string             { return r.fields["ref_kind"] }
func (r SecurityReference) Purpose() string          { return r.fields["purpose"] }
func (r SecurityReference) IdentityHash() string     { return r.fields["identity_hash"] }
func (r SecurityReference) Version() string          { return r.fields["identity_version"] }
func (r SecurityReference) ProviderIdentity() string { return r.fields["provider_identity_hash"] }
func (r SecurityReference) ScopeHash() string        { return r.fields["scope_hash"] }
func (r SecurityReference) Capability() string       { return r.fields["credential_capability"] }
func (SecurityReference) String() string             { return "BootstrapSecurityReference" }
func (SecurityReference) GoString() string           { return "BootstrapSecurityReference" }
func (SecurityReference) MarshalJSON() ([]byte, error) {
	return nil, sec.ErrRegistrationUnavailable
}

var refHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var refVersion = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var refDomain = regexp.MustCompile(`^clawmanager\.system-backup\.[a-z0-9_.-]+\.v[0-9]+$`)

// DecodeSecurityReference checks the exact complete input-byte SHA, not the
// identity hash or a projection digest. Every member must be a unique scalar
// string; variant-specific closed fields prevent credentials from hiding in an
// ignored member. The draft schema remains draft after this check.
func DecodeSecurityReference(raw []byte, fileSHA256 string) (SecurityReference, error) {
	fail := func() (SecurityReference, error) { return SecurityReference{}, sec.ErrRegistrationUnavailable }
	if len(raw) == 0 || len(raw) > 16384 || !utf8.Valid(raw) || !refHash.MatchString(fileSHA256) {
		return fail()
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != fileSHA256 {
		return fail()
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return fail()
	}
	fields := map[string]string{}
	for d.More() {
		keyToken, e := d.Token()
		key, ok := keyToken.(string)
		if e != nil || !ok {
			return fail()
		}
		if _, duplicate := fields[key]; duplicate {
			return fail()
		}
		valueToken, e := d.Token()
		value, ok := valueToken.(string)
		if e != nil || !ok {
			return fail()
		}
		fields[key] = value
	}
	last, err := d.Token()
	if err != nil || last != json.Delim('}') {
		return fail()
	}
	if _, err = d.Token(); err != io.EOF {
		return fail()
	}
	common := []string{"ref_kind", "purpose", "identity_hash", "identity_version", "provider_identity_hash", "scope_hash", "description_redacted"}
	for _, name := range []string{"identity_hash", "provider_identity_hash", "scope_hash"} {
		if !refHash.MatchString(fields[name]) {
			return fail()
		}
	}
	version := fields["identity_version"]
	if !refVersion.MatchString(version) || version == "latest" || version == "current" || version == "default" || utf8.RuneCountInString(fields["description_redacted"]) < 1 || utf8.RuneCountInString(fields["description_redacted"]) > 256 {
		return fail()
	}
	extra, valid := referenceVariant(fields)
	if !valid || len(fields) != len(common)+len(extra) {
		return fail()
	}
	for _, name := range append(common, extra...) {
		if _, exists := fields[name]; !exists {
			return fail()
		}
	}
	return SecurityReference{fields}, nil
}

func referenceVariant(f map[string]string) ([]string, bool) {
	purpose := f["purpose"]
	switch f["ref_kind"] {
	case "external_kms_key":
		return []string{"kms_capability"}, (purpose == "data_key_generation" && f["kms_capability"] == "generate_data_key") || (purpose == "kek_unwrap" && f["kms_capability"] == "unwrap_data_key")
	case "external_secret", "kubernetes_secret":
		valid := has([]string{"secret_bundle_part", "strong_auth_nonce_hmac", "kek_wrap", "kek_unwrap"}, purpose)
		if f["ref_kind"] == "external_secret" {
			return []string{"read_mode"}, valid && f["read_mode"] == "exact_version_only"
		}
		names := []string{"namespace_hash", "name_hash", "uid_hash", "key_name_hash"}
		for _, name := range names {
			valid = valid && refHash.MatchString(f[name])
		}
		return append(names, "read_mode"), valid && f["read_mode"] == "resource_name_get_only"
	case "signing_key":
		valid := has([]string{"capture_certificate", "acceptance_record", "catalog_record", "provider_proof_issuer", "strong_auth_issuer"}, purpose) && refDomain.MatchString(f["domain_separator"]) && utf8.RuneCountInString(f["algorithm"]) >= 1 && utf8.RuneCountInString(f["algorithm"]) <= 32
		if has([]string{"capture_certificate", "acceptance_record", "catalog_record"}, purpose) {
			valid = valid && f["algorithm"] == "EdDSA"
		}
		return []string{"algorithm", "domain_separator"}, valid
	case "artifact_credential", "catalog_credential", "evidence_credential":
		role := map[string]string{"artifact_credential": "artifact", "catalog_credential": "catalog", "evidence_credential": "evidence"}[f["ref_kind"]]
		purposes := map[string][]string{"artifact": {"artifact_write", "artifact_read", "artifact_delete"}, "catalog": {"catalog_append", "catalog_read", "catalog_discovery"}, "evidence": {"evidence_read_write", "evidence_read", "evidence_write", "evidence_delete"}}
		capabilities := map[string][]string{
			"artifact_write": {"exact_write", "conditional_create"}, "artifact_read": {"exact_read", "range_read"}, "artifact_delete": {"exact_delete"},
			"catalog_append": {"append_record"}, "catalog_read": {"exact_read"}, "catalog_discovery": {"snapshot_list", "inventory_read"},
			"evidence_read_write": {"exact_write", "exact_read", "conditional_create", "range_read"},
			"evidence_read":       {"exact_read", "range_read"}, "evidence_write": {"exact_write", "conditional_create"}, "evidence_delete": {"exact_delete"},
		}
		return []string{"provider_role", "credential_capability"}, f["provider_role"] == role && has(purposes[role], purpose) && has(capabilities[purpose], f["credential_capability"])
	case "ca_bundle":
		return nil, has([]string{"artifact_ca", "catalog_ca", "evidence_ca"}, purpose)
	}
	return nil, false
}

// MatchesBootstrapPin is a draft metadata correspondence, not a validator or
// approval. A KEK requires a set of operations/retained versions, evidence_store
// is a store identity, and upload issuers/relays need their own contracts: none
// can be satisfied by matching one superficially similar SecretRef.
func (r SecurityReference) MatchesBootstrapPin(pin sec.BootstrapSecretRef) bool {
	if r.IdentityHash() != pin.IdentityHash || r.Version() != pin.Version {
		return false
	}
	want := map[string]string{
		"nonce_hmac": "strong_auth_nonce_hmac", "capture_signing": "capture_certificate",
		"acceptance_signing": "acceptance_record", "catalog_signing": "catalog_record",
		"artifact_write": "artifact_write", "artifact_read": "artifact_read", "artifact_delete": "artifact_delete", "artifact_ca": "artifact_ca",
		"evidence_write": "evidence_write", "evidence_read": "evidence_read", "evidence_delete": "evidence_delete", "evidence_ca": "evidence_ca",
		"catalog_read": "catalog_read", "catalog_append": "catalog_append", "catalog_snapshot": "catalog_discovery",
	}[pin.Purpose]
	return want != "" && r.Purpose() == want
}
