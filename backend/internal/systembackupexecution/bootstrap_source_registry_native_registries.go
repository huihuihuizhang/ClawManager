package systembackupexecution

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"time"

	root "clawreef/internal/systembackup"
	"clawreef/internal/systembackupinstallationowner/install"
	sec "clawreef/internal/systembackupsecurity"
)

// Original config registry SHAs and the original signed mapping bind these
// DATA file pins. V2 independently authorizes the already existing finite
// Redis/resource native reads, not a new operation or an implicit grant upgrade.
type BootstrapSourceNativeRegistryFiles struct {
	RedisSources, SecretAllowlist install.BootstrapSourceFilePin
}

const bootstrapRedisSourcesVersion = "system-backup-original-redis-sources.v1"

type bootstrapRedisSourceRegistry struct {
	SchemaVersion, Installation, Version, ApplicationScope string
	Source                                                 bootstrapRedisSourceDeclaration
	Metadata                                               []root.RedisSourceMetadataEntry
}
type bootstrapRedisSourceDeclaration struct {
	SourceID, SourceVersion, Endpoint, Account, ServerID string
	Database                                             int
	CA, Credential                                       install.BootstrapSourceFilePin
	Topology, CaptureMode, TTLPolicy, Purpose            string
	Prefixes, ExcludePrefixes                            []string
	MaxItems, MaxBytes, MaxClockSkew                     int64
}

func validBootstrapNativeFiles(files BootstrapSourceNativeRegistryFiles) bool {
	for _, p := range []install.BootstrapSourceFilePin{files.RedisSources, files.SecretAllowlist} {
		if !filepath.IsAbs(p.File) || filepath.Clean(p.File) != p.File || !formalCandidateDigest(p.SHA256) {
			return false
		}
	}
	return files.RedisSources.File != files.SecretAllowlist.File
}

func bootstrapNativeRegistryRefs(config sec.BootstrapConfig, files BootstrapSourceNativeRegistryFiles) (sec.BootstrapRegistryRef, sec.BootstrapRegistryRef, error) {
	var redis, secrets sec.BootstrapRegistryRef
	for _, ref := range config.Registries() {
		if ref.Kind == "redis_sources" {
			redis = ref
		}
		if ref.Kind == "secret_allowlist" {
			secrets = ref
		}
	}
	if !validBootstrapNativeFiles(files) || redis.Version == "" || secrets.Version == "" || redis.SHA256 != files.RedisSources.SHA256 || secrets.SHA256 != files.SecretAllowlist.SHA256 {
		return redis, secrets, install.ErrInstall
	}
	return redis, secrets, nil
}

func readBootstrapNativeRegistryPin(pin install.BootstrapSourceFilePin) ([]byte, error) {
	if !filepath.IsAbs(pin.File) || filepath.Clean(pin.File) != pin.File || !formalCandidateDigest(pin.SHA256) {
		return nil, install.ErrInstall
	}
	raw, err := install.ReadSourceMaterialFile(pin.File)
	if err != nil || hash(raw) != pin.SHA256 {
		clear(raw)
		return nil, install.ErrInstall
	}
	return raw, nil
}

func (x *bootstrapSourceRegistryReader) nativeRegistryFile(pin install.BootstrapSourceFilePin) ([]byte, error) {
	if x.access.Check(x.ctx) != nil {
		return nil, install.ErrInstall
	}
	raw, err := readBootstrapNativeRegistryPin(pin)
	if err != nil || x.access.Check(x.ctx) != nil {
		clear(raw)
		return nil, install.ErrInstall
	}
	return raw, nil
}

func (x *bootstrapSourceRegistryReader) redisSourceRegistry(version string, facts *bootstrapSourceRegistryFacts) (bootstrapRedisSourceRegistry, error) {
	var zero bootstrapRedisSourceRegistry
	if facts == nil || facts.redis == nil || x.materials.Discovery == nil || x.materials.Discovery.Redis.Validate() != nil {
		return zero, install.ErrInstall
	}
	connection, err := x.connection("source_redis")
	if err != nil {
		return zero, install.ErrInstall
	}
	p := x.materials.Discovery.Redis
	// Source's existing opaque reference digest is already selected by original
	// V2 metadata. Do not embed that digest (potentially a registry reference) or
	// any final metadata/config/grant/self hash in a pre-capture fact document.
	s := bootstrapRedisSourceDeclaration{SourceID: p.Policy.Source.ID, SourceVersion: p.Policy.Source.Version, Endpoint: connection.Endpoint, Account: connection.Account, ServerID: p.ServerID, Database: p.Policy.DB, CA: connection.CA, Credential: connection.Credential, Topology: p.Policy.Topology, CaptureMode: p.Policy.CaptureMode, TTLPolicy: p.Policy.TTLPolicy, Purpose: p.Policy.Purpose, Prefixes: append([]string{}, p.Policy.Prefixes...), ExcludePrefixes: append([]string{}, p.ExcludePrefixes...), MaxItems: p.Policy.MaxItems, MaxBytes: p.Policy.MaxBytes, MaxClockSkew: p.Policy.MaxClockSkew}
	return bootstrapRedisSourceRegistry{SchemaVersion: bootstrapRedisSourcesVersion, Installation: x.association.Target.InstallationID, Version: version, ApplicationScope: x.association.Source.ApplicationScope, Source: s, Metadata: facts.redis}, nil
}

// The Secret policy is original owner INTENT, never synthesized from observed
// names/UIDs. Validate required/allowed selections using metadata only. The
// existing encrypted capture CheckCaptured independently validates actual type.
func (x *bootstrapSourceRegistryReader) selectedSecretPolicy(pin install.BootstrapSourceFilePin, version string, facts *bootstrapSourceRegistryFacts) (root.FrozenSecretCapturePolicy, error) {
	var zero root.FrozenSecretCapturePolicy
	if facts == nil || x.materials.Discovery == nil || x.materials.Discovery.SecretPolicy == nil {
		return zero, install.ErrInstall
	}
	ref := *x.materials.Discovery.SecretPolicy
	if ref.validate() != nil || ref.Path != pin.File || ref.SHA256 != pin.SHA256 {
		return zero, install.ErrInstall
	}
	raw, err := x.nativeRegistryFile(pin)
	if err != nil {
		return zero, install.ErrInstall
	}
	if version == "" {
		if strictSecretRegistryVersion(raw, &version) != nil {
			return zero, install.ErrInstall
		}
	}
	policy, err := root.DecodeSecretCapturePolicy(raw, version, pin.SHA256)
	if err != nil || policy.ValidateSelections(x.config.Namespace, facts.secrets.Selections) != nil || x.access.Check(x.ctx) != nil {
		return zero, install.ErrInstall
	}
	return policy, nil
}

func strictSecretRegistryVersion(raw []byte, version *string) error {
	// DecodeSecretCapturePolicy performs the complete closed/duplicate/JCS check.
	var data struct {
		RegistryVersion string `json:"registry_version"`
	}
	if json.Unmarshal(raw, &data) != nil || data.RegistryVersion == "" {
		return install.ErrInstall
	}
	*version = data.RegistryVersion
	return nil
}

func (x *bootstrapSourceRegistryReader) observeRegistriesWithNative(config sec.BootstrapConfig, files BootstrapSourceNativeRegistryFiles) (time.Time, time.Time, error) {
	redisRef, secretRef, err := bootstrapNativeRegistryRefs(config, files)
	if err != nil {
		return time.Time{}, time.Time{}, install.ErrInstall
	}
	facts, err := x.collectBootstrapSourceFacts()
	if err != nil || x.matchSourceRegistries(facts) != nil {
		return time.Time{}, time.Time{}, install.ErrInstall
	}
	raw, err := x.nativeRegistryFile(files.RedisSources)
	if err != nil {
		return time.Time{}, time.Time{}, install.ErrInstall
	}
	var actual bootstrapRedisSourceRegistry
	want, err := x.redisSourceRegistry(redisRef.Version, facts)
	if err != nil || strictBootstrapSourceJSON(raw, &actual) != nil || !reflect.DeepEqual(actual, want) {
		return time.Time{}, time.Time{}, install.ErrInstall
	}
	if _, err = x.selectedSecretPolicy(files.SecretAllowlist, secretRef.Version, facts); err != nil {
		return time.Time{}, time.Time{}, install.ErrInstall
	}
	return x.access.Bounds(x.ctx)
}
