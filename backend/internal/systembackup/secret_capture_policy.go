package systembackup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"unicode"
	"unicode/utf8"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"k8s.io/apimachinery/pkg/util/validation"
)

const SecretCapturePolicyVersion = "system-backup-secret-capture-policy.v1"
const MaxSecretCapturePolicyBytes = 8 << 20

var ErrSecretCapturePolicy = errors.New("original secret capture policy unavailable or incomplete")
var secretEntryID = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)

// An entry authorizes full-object ENCRYPTED capture of one independently named
// Secret in the signed installation namespace. It contains no UID, key, source
// observation or supplied captured count. Missing optional entries are allowed;
// every selected Secret must still match one entry exactly.
type SecretCapturePolicyEntry struct {
	ID           string `json:"entry_id"`
	SecretName   string `json:"secret_name"`
	Required     bool   `json:"required"`
	ExpectedType string `json:"expected_type"`
	Purpose      string `json:"purpose"`
}

type SecretCapturePolicy struct {
	SchemaVersion   string                     `json:"schema_version"`
	RegistryVersion string                     `json:"registry_version"`
	RegistryKind    string                     `json:"registry_kind"`
	NamespaceScope  string                     `json:"namespace_scope"`
	CaptureMode     string                     `json:"capture_mode"`
	Entries         []SecretCapturePolicyEntry `json:"entries"`
}

// This inert frozen document belongs to the original plan/stream scope.
// Its hash/version must be checked against ORIGINAL 097 config pins by the
// deployment loader; constructing this DTO creates no source authority.
type FrozenSecretCapturePolicy struct {
	SHA256 string              `json:"registry_sha256"`
	Policy SecretCapturePolicy `json:"policy"`
}

func (p SecretCapturePolicy) canonical() ([]byte, error) {
	if p.SchemaVersion != SecretCapturePolicyVersion || p.RegistryKind != "secret_allowlist" || p.RegistryVersion == "" || len(p.RegistryVersion) > 128 || !utf8.ValidString(p.RegistryVersion) || p.NamespaceScope != "installation_namespace" || p.CaptureMode != "encrypted_full_object" || p.Entries == nil || len(p.Entries) > 10000 {
		return nil, ErrSecretCapturePolicy
	}
	for _, r := range p.RegistryVersion {
		if unicode.IsControl(r) {
			return nil, ErrSecretCapturePolicy
		}
	}
	types := map[string]bool{"Opaque": true, "kubernetes.io/tls": true, "kubernetes.io/basic-auth": true, "kubernetes.io/ssh-auth": true, "kubernetes.io/dockerconfigjson": true}
	purposes := map[string]bool{"application_secret": true, "database_credentials": true, "team_credentials": true, "tls_credentials": true, "external_integration": true}
	names := map[string]bool{}
	previous := ""
	for _, entry := range p.Entries {
		if !secretEntryID.MatchString(entry.ID) || entry.ID <= previous || len(validation.IsDNS1123Subdomain(entry.SecretName)) != 0 || names[entry.SecretName] || !types[entry.ExpectedType] || !purposes[entry.Purpose] {
			return nil, ErrSecretCapturePolicy
		}
		names[entry.SecretName] = true
		previous = entry.ID
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, ErrSecretCapturePolicy
	}
	raw, err = jsoncanonicalizer.Transform(raw)
	if err != nil || len(raw) > MaxSecretCapturePolicyBytes {
		return nil, ErrSecretCapturePolicy
	}
	return raw, nil
}

// Decode uses the FULL exact JCS file checksum, supplied by original config,
// not a self-declared registry checksum or a policy regenerated from selectors.
func DecodeSecretCapturePolicy(raw []byte, version, expectedSHA string) (FrozenSecretCapturePolicy, error) {
	var zero FrozenSecretCapturePolicy
	if len(raw) == 0 || len(raw) > MaxSecretCapturePolicyBytes || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(expectedSHA) || !boundedSecretPolicy(raw) {
		return zero, ErrSecretCapturePolicy
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != expectedSHA {
		return zero, ErrSecretCapturePolicy
	}
	var policy SecretCapturePolicy
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&policy) != nil || policy.RegistryVersion != version {
		return zero, ErrSecretCapturePolicy
	}
	canonical, err := policy.canonical()
	if err != nil || !bytes.Equal(canonical, raw) {
		return zero, ErrSecretCapturePolicy
	}
	return FrozenSecretCapturePolicy{SHA256: expectedSHA, Policy: policy}, nil
}

func (p FrozenSecretCapturePolicy) ValidateSelections(namespace string, selections []KubernetesSelection) error {
	if len(validation.IsDNS1123Label(namespace)) != 0 || selections == nil {
		return ErrSecretCapturePolicy
	}
	raw, err := p.Policy.canonical()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != p.SHA256 {
		return ErrSecretCapturePolicy
	}
	entries := map[string]SecretCapturePolicyEntry{}
	for _, entry := range p.Policy.Entries {
		entries[entry.SecretName] = entry
	}
	seen := map[string]bool{}
	for _, ref := range selections {
		if ref.Group != "" || ref.Version != "v1" || ref.Resource != "secrets" || ref.UID == "" || seen[ref.Name] {
			return ErrSecretCapturePolicy
		}
		if _, ok := entries[ref.Name]; !ok {
			return ErrSecretCapturePolicy
		}
		seen[ref.Name] = true
	}
	for _, entry := range p.Policy.Entries {
		if entry.Required && !seen[entry.SecretName] {
			return ErrSecretCapturePolicy
		}
	}
	return nil
}

// CheckCaptured examines actual captured object metadata/type. Secret values
// are never decoded, retained or hashed for a report. The existing archive
// producer/reader separately checks namespace/name/UID against the frozen plan.
func (p FrozenSecretCapturePolicy) CheckCaptured(namespace string, ref KubernetesSelection, raw json.RawMessage) (string, error) {
	if ref.Group != "" || ref.Version != "v1" || ref.Resource != "secrets" || ref.UID == "" {
		return "", ErrSecretCapturePolicy
	}
	var object struct {
		Type       string `json:"type"`
		Kind       string `json:"kind"`
		APIVersion string `json:"apiVersion"`
		Metadata   struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			UID       string `json:"uid"`
		} `json:"metadata"`
	}
	if json.Unmarshal(raw, &object) != nil || object.Kind != "Secret" || object.APIVersion != "v1" || object.Metadata.Name != ref.Name || object.Metadata.Namespace != namespace || object.Metadata.UID != ref.UID {
		return "", ErrSecretCapturePolicy
	}
	if object.Type == "" {
		object.Type = "Opaque"
	} // Kubernetes' defined default; bytes are never rewritten.
	for _, entry := range p.Policy.Entries {
		if entry.SecretName == ref.Name {
			if object.Type != entry.ExpectedType {
				return "", ErrSecretCapturePolicy
			}
			return entry.ID, nil
		}
	}
	return "", ErrSecretCapturePolicy
}

func boundedSecretPolicy(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return false
	}
	allowed := map[string]bool{"schema_version": true, "registry_version": true, "registry_kind": true, "namespace_scope": true, "capture_mode": true, "entries": true}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] || seen[key] {
			return false
		}
		seen[key] = true
		if key != "entries" {
			var value json.RawMessage
			if decoder.Decode(&value) != nil {
				return false
			}
			continue
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
			return false
		}
		count := 0
		for decoder.More() {
			if count >= 10000 {
				return false
			}
			var entry json.RawMessage
			if decoder.Decode(&entry) != nil || len(entry) > 4096 {
				return false
			}
			count++
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
			return false
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || len(seen) != len(allowed) {
		return false
	}
	var tail any
	return decoder.Decode(&tail) == io.EOF
}

func (p FrozenSecretCapturePolicy) RequiredEntries() int64 {
	var count int64
	for _, entry := range p.Policy.Entries {
		if entry.Required {
			count++
		}
	}
	return count
}
