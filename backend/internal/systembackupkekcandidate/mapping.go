package systembackupkekcandidate

import (
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var revision = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var positive = regexp.MustCompile(`^[1-9][0-9]*$`)
var keyName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var backupID = regexp.MustCompile(`^sbk_[A-Za-z0-9_-]+$`)

func text(s string, max int) bool {
	n := utf8.RuneCountInString(s)
	return utf8.ValidString(s) && n >= 1 && n <= max
}
func version(s string) bool {
	return revision.MatchString(s) && s != "latest" && s != "current" && s != "default"
}
func source(s SourceRecord) bool {
	return text(s.SourceID, 256) && text(s.RecordID, 256) && version(s.RecordVersion) && digest.MatchString(s.ContentSHA256)
}
func binding(k KeyBindingInput) bool {
	return k.Provider == "external-kms" && digest.MatchString(k.IdentityHash) && version(k.RegistryVersion) && text(k.ProviderKeyID, 256) && positive.MatchString(k.ProviderVersion) && len(k.ProviderVersion) <= 10
}
func exactEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Opaque == "" && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && !u.ForceQuery && !strings.ContainsAny(endpoint, "?#\r\n") && text(endpoint, 2048)
}
func kmsRef(r KMSReference, purpose, capability string, p ProviderInput) bool {
	return r.Kind == "external_kms_key" && r.Purpose == purpose && r.Capability == capability && digest.MatchString(r.IdentityHash) && version(r.Version) && text(r.Description, 256) && r.ProviderIdentityHash == p.ProviderIdentityHash && r.ScopeHash == p.ScopeHash
}

// DecodeMapping checks schema and candidate-internal relationships only. In
// particular, matching hashes do not authenticate the original two-ref relation.
func DecodeMapping(raw []byte) (UnadmittedMapping, error) {
	var m MappingInput
	b, err := decode(raw, MaxMappingBytes, &m)
	p := m.Provider
	if err != nil || m.SchemaVersion != MappingVersion || !text(m.InstallationID, 256) || !digest.MatchString(m.ConfigSHA256) || !version(m.SourceRevision) ||
		m.ConfigRef.Purpose != "kek" || !binding(m.KeyBinding) || m.ConfigRef.IdentityHash != m.KeyBinding.IdentityHash || m.ConfigRef.Version != m.KeyBinding.RegistryVersion ||
		!exactEndpoint(p.Endpoint) || !keyName.MatchString(p.KeyName) || !digest.MatchString(p.ProviderIdentityHash) || !digest.MatchString(p.ScopeHash) || !digest.MatchString(p.CAPEMSHA256) || !source(p.CASource) ||
		!kmsRef(m.GenerateRef, "data_key_generation", "generate_data_key", p) || !kmsRef(m.UnwrapRef, "kek_unwrap", "unwrap_data_key", p) {
		return UnadmittedMapping{}, ErrInvalid
	}
	return UnadmittedMapping{m, b}, nil
}

// MatchObservation compares caller-supplied expected pins; it does not prove
// that those pins came from the current authorized configuration or source.
func (m UnadmittedMapping) MatchObservation(installation, configSHA, sourceRevision string) error {
	if len(m.canonical) == 0 || m.input.InstallationID != installation || m.input.ConfigSHA256 != configSHA || m.input.SourceRevision != sourceRevision {
		return ErrMismatch
	}
	return nil
}

// CheckSameKeyMapping rejects rebinding of one existing logical key. Config
// hashes/source revisions and redacted descriptions are observations/metadata;
// they may change while the same immutable key remains referenced. Different
// logical keys require separate rotation/retention admission, not this helper.
func CheckSameKeyMapping(a, b UnadmittedMapping) error {
	if len(a.canonical) == 0 || len(b.canonical) == 0 || a.input.InstallationID != b.input.InstallationID || a.input.ConfigRef != b.input.ConfigRef {
		return ErrMismatch
	}
	x, y := a.input, b.input
	x.ConfigSHA256 = ""
	y.ConfigSHA256 = ""
	x.SourceRevision = ""
	y.SourceRevision = ""
	x.GenerateRef.Description = ""
	y.GenerateRef.Description = ""
	x.UnwrapRef.Description = ""
	y.UnwrapRef.Description = ""
	if x != y {
		return ErrRebinding
	}
	return nil
}
