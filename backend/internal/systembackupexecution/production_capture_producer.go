package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	api "clawreef/internal/systembackupdeployment"
	"clawreef/internal/systembackupinstallationowner/install"
)

const productionMaterialDefinitionVersion = "original-six-part-source-material-definition.v1"

// An original unsigned declaration, selected and SHA-pinned by its source
// owner. It contains references/templates, never approval or ready booleans.
type ProductionMaterialDefinition struct {
	Version                                      string
	CoreFile, CoreSHA256                         string
	ConfigFile, ConfigSHA256, ForwardGrantSHA256 string
	NotBefore, Until                             time.Time
	PublisherVerifier                            []PublisherVerifierInput
	Materials                                    json.RawMessage
}

type ProductionMaterialReceipt struct {
	Version, Purpose, File, SHA256, ScopeSHA256 string
	NotBefore, Until                            time.Time
}

// ProduceOriginalCaptureMaterials issues one functional_test six-domain bundle
// through A's concrete authenticated installation-owner source. It grants no
// source permissions and performs no task/config/readiness/provider mutations.
func ProduceOriginalCaptureMaterials(ctx context.Context, owner *install.Installer, password []byte, enrollment install.EnrollmentPin, definitionFile, definitionSHA, issuerPrivateFile string) (ProductionMaterialReceipt, error) {
	var zero ProductionMaterialReceipt
	if ctx == nil || ctx.Err() != nil || owner == nil {
		return zero, c.ErrExecutionAuthority
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return zero, c.ErrExecutionAuthority
	}
	raw, err := install.ReadSourceMaterialFile(definitionFile)
	var definition ProductionMaterialDefinition
	if err != nil || hash(raw) != definitionSHA || decodeMetadataCanonical(raw, &definition) != nil || definition.Version != productionMaterialDefinitionVersion {
		return zero, c.ErrExecutionAuthority
	}
	core, err := LoadDeploymentConfig(definition.CoreFile, definition.CoreSHA256)
	if err != nil {
		return zero, err
	}
	public, err := base64.StdEncoding.DecodeString(core.ForwardGrant.PublicKey)
	if err != nil {
		return zero, c.ErrExecutionAuthority
	}
	forward, err := c.NewPinnedExecutionIdentity(core.ForwardGrant.Path, definition.ForwardGrantSHA256, core.KeyDirectory, public)
	if err != nil {
		return zero, err
	}
	grant := forward.DeploymentBinding()
	config, err := pinnedDeploymentFile(definition.ConfigFile, definition.ConfigSHA256, 262144)
	if err != nil || definition.ConfigSHA256 != grant.ConfigSHA256 || core.InstallationID != grant.InstallationID || core.ControllerOwner != grant.ControllerOwner || grant.DeploymentConfigSHA256 != definition.CoreSHA256 || !forwardCaptureActions(grant) || definition.NotBefore.Before(grant.NotBefore) || definition.Until.After(grant.ExpiresAt) || time.Now().Before(definition.NotBefore) || !time.Now().Before(definition.Until) {
		return zero, c.ErrExecutionAuthority
	}
	var configFields map[string]json.RawMessage
	if json.Unmarshal(config, &configFields) != nil || len(configFields) == 0 {
		return zero, c.ErrExecutionAuthority
	}
	profile, err := api.LoadExecutionProfile(core.ProfileFile)
	if err != nil {
		return zero, err
	}
	_, profileSHA, err := profile.CanonicalIdentity()
	if err != nil || profileSHA != grant.ProfileSHA256 || profile.InstallationID != core.InstallationID {
		return zero, c.ErrExecutionAuthority
	}
	var materials productionCaptureMaterials
	if decodeMetadataCanonical(definition.Materials, &materials) != nil || materials.Discovery == nil || core.CaptureScope != "six-part" || core.CaptureModules == nil || materials.Discovery.Redis.Validate() != nil || materials.Discovery.Redis.Policy.Purpose != "functional_test" || materials.Discovery.GrantSHA256 != "" || materials.Redis.GrantSHA256 != "" || materials.Objects.GrantSHA256 != "" || materials.InstallationID != core.InstallationID || materials.ControllerOwner != core.ControllerOwner || materials.DeploymentConfigSHA256 != definition.CoreSHA256 || materials.CaptureGrantSHA256 != definition.ForwardGrantSHA256 || materials.ControlEvidence == nil || materials.ControlEvidenceSource == nil {
		return zero, c.ErrExecutionAuthority
	}
	if _, exists := materials.Operations[ce.Operation]; !exists {
		return zero, c.ErrExecutionAuthority
	}
	key, err := install.ReadPrivateFile(issuerPrivateFile, ed25519.PrivateKeySize)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		clear(key)
		return zero, c.ErrExecutionAuthority
	}
	defer clear(key)
	issuer := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	if !bytes.Equal(materials.Discovery.Issuer, issuer) || !bytes.Equal(materials.Redis.Issuer, issuer) || !bytes.Equal(materials.Objects.Issuer, issuer) {
		return zero, c.ErrExecutionAuthority
	}
	redisScope, err := producerWorkerScope(materials, "capture-source-redis")
	if err != nil {
		return zero, err
	}
	objectsScope, err := producerWorkerScope(materials, "capture-skill-objects")
	if err != nil {
		return zero, err
	}
	p := materials.Discovery
	authority, err := owner.PrepareSourceMaterialIssue(ctx, password, enrollment, install.SourceMaterialIntent{DefinitionFile: definitionFile, DefinitionSHA256: definitionSHA, InstallationID: core.InstallationID, Namespace: core.Namespace, NamespaceUID: core.NamespaceUID, Purpose: "functional_test", ServerUUID: grant.ServerUUID, Database: grant.Database, DatabaseAccount: grant.DatabaseAccount, DeploymentConfigSHA256: definition.CoreSHA256, CaptureGrantSHA256: definition.ForwardGrantSHA256, ConfigSHA256: definition.ConfigSHA256, ControllerOwner: core.ControllerOwner, ControllerDeployment: p.ControllerDeployment, ControllerDeploymentUID: p.ControllerDeploymentUID, ControllerServiceAccount: p.ControllerServiceAccount, ControllerServiceAccountUID: p.ControllerServiceAccountUID, WorkerServiceAccount: core.Security.ServiceAccountName, WorkerServiceAccountUID: core.Security.ServiceAccountUID, SourceServiceAccount: p.SourceAPIServiceAccount, SourceServiceAccountUID: p.SourceAPIServiceAccountUID, RedisScopeSHA256: redisScope, RedisCredentialSHA256: materials.Redis.CredentialSHA256, ObjectScopeSHA256: objectsScope, ObjectCredentialSHA256: materials.Objects.CredentialSHA256, NotBefore: definition.NotBefore, Until: definition.Until})
	if err != nil {
		return zero, err
	}
	files := map[string][]byte{}
	for _, object := range []bool{false, true} {
		mount, operation, scope := &materials.Redis, "capture-source-redis", redisScope
		if object {
			mount, operation, scope = &materials.Objects, "capture-skill-objects", objectsScope
		}
		credential, err := readMetadataSourceCredential(*mount)
		if err != nil {
			return zero, err
		}
		clear(credential.Password)
		clear(credential.SecretKey)
		clear(credential.SessionToken)
		mapping := mount.Redis
		if object {
			mapping = mount.Objects
		}
		if mapping == nil {
			return zero, c.ErrExecutionAuthority
		}
		if _, err := sourceMetadataTLS(*mapping); err != nil {
			return zero, err
		}
		encoded, err := authority.SignWorkerSource(ctx, worker.FormalSourceGrant{Version: worker.FormalSourceGrantVersion, InstallationID: core.InstallationID, ConfigSHA256: definition.ConfigSHA256, WorkerNamespace: core.Namespace, WorkerServiceAccountUID: core.Security.ServiceAccountUID, Operation: operation, ScopeSHA256: scope, CredentialSHA256: mount.CredentialSHA256, NotBefore: definition.NotBefore, Until: definition.Until}, key)
		if err != nil {
			return zero, err
		}
		mount.GrantSHA256 = hash(encoded)
		files[mount.GrantFile] = encoded
	}
	scope, err := sourceMetadataScope(materials)
	if err != nil {
		return zero, err
	}
	metadata, err := authority.SignControllerMetadata(ctx, install.ControllerSourceMetadataGrant{Version: sourceMetadataGrantVersion, InstallationID: core.InstallationID, ControllerOwner: core.ControllerOwner, DeploymentConfigSHA256: definition.CoreSHA256, CaptureGrantSHA256: definition.ForwardGrantSHA256, ConfigSHA256: definition.ConfigSHA256, ScopeSHA256: scope, Namespace: core.Namespace, NamespaceUID: core.NamespaceUID, ControllerDeployment: p.ControllerDeployment, ControllerDeploymentUID: p.ControllerDeploymentUID, ControllerServiceAccount: p.ControllerServiceAccount, ControllerServiceAccountUID: p.ControllerServiceAccountUID, NotBefore: definition.NotBefore, Until: definition.Until}, key)
	if err != nil {
		return zero, err
	}
	p.GrantSHA256 = hash(metadata)
	files[p.GrantFile] = metadata
	service := &DeploymentService{ForwardEnabled: true, Config: core, ConfigPath: definition.CoreFile, ConfigDigest: definition.CoreSHA256, Forward: forward}
	if err := service.loadPublisherVerifierInput(definition.PublisherVerifier); err != nil {
		return zero, err
	}
	if service.validateProductionCapture(materials) != nil || p.validate() != nil {
		return zero, c.ErrExecutionAuthority
	}
	for _, operation := range materials.Operations {
		if !validProductionOperationMounts(operation) {
			return zero, c.ErrExecutionAuthority
		}
	}
	if _, err := newProductionCapturePlan(materials.Operations, materials.Revision); err != nil {
		return zero, err
	}
	material, err := json.Marshal(materials)
	if err != nil || len(material) > 8<<20 {
		return zero, c.ErrExecutionAuthority
	}
	files[core.CaptureModules.Path] = material
	directory := filepath.Dir(core.CaptureModules.Path)
	if err := producerOutputPaths(directory, files); err != nil {
		return zero, err
	}
	if authority.Recheck(ctx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	for path, content := range files {
		if err := writeOriginalMaterialFile(path, content); err != nil {
			return zero, err
		}
	}
	if authority.Recheck(ctx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	for path, expected := range files {
		actual, err := install.ReadSourceMaterialFile(path)
		if err != nil || !bytes.Equal(actual, expected) {
			return zero, c.ErrExecutionAuthority
		}
	}
	if _, err := pinnedDeploymentFile(definition.ConfigFile, definition.ConfigSHA256, 262144); err != nil {
		return zero, err
	}
	if _, err := pinnedDeploymentFile(core.ForwardGrant.Path, definition.ForwardGrantSHA256, 262144); err != nil {
		return zero, err
	}
	if err := service.loadPublisherVerifierInput(definition.PublisherVerifier); err != nil {
		return zero, err
	}
	if err := service.loadProductionCapture([]ProductionCaptureInput{{File: core.CaptureModules.Path, SHA256: hash(material)}}); err != nil {
		return zero, err
	}
	if authority.Recheck(ctx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	return ProductionMaterialReceipt{Version: "original-six-part-source-material-result.v1", Purpose: "functional_test", File: core.CaptureModules.Path, SHA256: hash(material), ScopeSHA256: scope, NotBefore: definition.NotBefore, Until: definition.Until}, nil
}

func producerWorkerScope(m productionCaptureMaterials, operation string) (string, error) {
	if m.Discovery == nil || operation != "capture-source-redis" && operation != "capture-skill-objects" {
		return "", c.ErrExecutionAuthority
	}
	_, exists := m.Operations[operation]
	if !exists {
		return "", c.ErrExecutionAuthority
	}
	if operation == "capture-source-redis" {
		redis, mount := m.Discovery.Redis, m.Redis
		boundary := mount.RedisScope
		if redis.Validate() != nil || redis.Policy.Purpose != "functional_test" || mount.Redis == nil || mount.Objects != nil || len(mount.ObjectPrefixes) != 0 || boundary == nil || boundary.ID != redis.Policy.Source.ID || boundary.ServerID != redis.ServerID || boundary.Database != redis.Policy.DB || boundary.KeyPrefix != "" || !reflect.DeepEqual(mount.RedisPrefixes, redis.Policy.Prefixes) || !reflect.DeepEqual(mount.RedisExcludedPrefixes, redis.ExcludePrefixes) {
			return "", c.ErrExecutionAuthority
		}
		raw, err := json.Marshal(struct {
			Operation                                        string
			Mapping                                          *worker.SourceTLSMapping
			Boundary                                         *worker.RedisSourceBoundary
			Prefixes, ExcludedPrefixes                       []string
			SourceID, SourceVersion, SourceSHA256, TTLPolicy string
		}{operation, mount.Redis, boundary, mount.RedisPrefixes, mount.RedisExcludedPrefixes, redis.Policy.Source.ID, redis.Policy.Source.Version, redis.Policy.Source.SHA256, redis.Policy.TTLPolicy})
		if err != nil {
			return "", c.ErrExecutionAuthority
		}
		return hash(raw), nil
	}
	// The worker's skill-source delegation binds the provider root, not a
	// future task's inventory. Encode that exact existing scope wire shape
	// directly: no fabricated inventory hash or observed-keyset assertion.
	mount := m.Objects
	if mount.Objects == nil || mount.Redis != nil || mount.RedisScope != nil || len(mount.RedisPrefixes) != 0 || len(mount.RedisExcludedPrefixes) != 0 || len(mount.ObjectPrefixes) != 1 || mount.ObjectPrefixes[0].Bucket != m.SkillBucket || mount.ObjectPrefixes[0].Prefix != m.SkillPrefix+"/" || m.SkillBucket == "" || strings.ContainsAny(m.SkillBucket, "/\\*?\r\n\x00") || m.SkillPrefix == "" || path.IsAbs(m.SkillPrefix) || path.Clean(m.SkillPrefix) != m.SkillPrefix || m.SkillPrefix == "." || m.SkillPrefix == ".." || strings.HasPrefix(m.SkillPrefix, "../") || strings.ContainsAny(m.SkillPrefix, "\\*?\r\n\x00") {
		return "", c.ErrExecutionAuthority
	}
	raw, err := json.Marshal(struct {
		Operation      string
		ObjectPrefixes []worker.ObjectSourcePrefix
		ObjectsMapping *worker.SourceTLSMapping
	}{operation, mount.ObjectPrefixes, mount.Objects})
	if err != nil {
		return "", c.ErrExecutionAuthority
	}
	return hash(raw), nil
}

func producerOutputPaths(directory string, files map[string][]byte) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return c.ErrExecutionAuthority
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return c.ErrExecutionAuthority
	}
	if len(files) != 4 {
		return c.ErrExecutionAuthority
	}
	for path := range files {
		if filepath.Dir(path) != directory || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return c.ErrExecutionAuthority
		}
	}
	return nil
}

// Deterministic same-window retries may reuse only the exact existing bytes.
// Unknown/partial files are never overwritten or deleted by the producer.
func writeOriginalMaterialFile(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		raw, e := install.ReadSourceMaterialFile(path)
		if e == nil && bytes.Equal(raw, content) {
			return nil
		}
		return c.ErrExecutionAuthority
	}
	if err != nil {
		return err
	}
	n, writeErr := file.Write(content)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n != len(content) {
		return c.ErrExecutionAuthority
	}
	return nil
}
