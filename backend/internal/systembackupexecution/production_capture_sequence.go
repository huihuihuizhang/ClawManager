package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"time"

	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	api "clawreef/internal/systembackupdeployment"
	"clawreef/internal/systembackupinstallationowner/install"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// OriginalCaptureSequence holds the concrete installation-owner authority and
// original declaration. It is not a task admission, source capability, or a
// serializable receipt. No password or private signing key is retained.
type OriginalCaptureSequence struct {
	mu               sync.Mutex
	ctx              context.Context
	failed, finished bool
	definition       ProductionMaterialDefinition
	core             DeploymentConfig
	forward          *c.PinnedExecutionIdentity
	authority        *install.SourceMaterialIssuer
	materials        productionCaptureMaterials
	privateFile      string
}

func (*OriginalCaptureSequence) MarshalJSON() ([]byte, error) { return nil, c.ErrExecutionAuthority }
func (*OriginalCaptureSequence) String() string               { return "OriginalCaptureSequence" }

// enter serializes this one sequence and latches even a foreign-context
// rejection. Returning to the original context can never resurrect a failure.
func (s *OriginalCaptureSequence) enter(ctx context.Context) (func(), error) {
	if s == nil {
		return nil, c.ErrExecutionAuthority
	}
	s.mu.Lock()
	if s.failed || s.finished || ctx == nil || s.ctx == nil || !reflect.TypeOf(ctx).Comparable() || ctx != s.ctx || ctx.Err() != nil || s.ctx.Err() != nil {
		s.failed = true
		s.mu.Unlock()
		return nil, c.ErrExecutionAuthority
	}
	return s.mu.Unlock, nil
}

// WorkerSourceMounts returns detached signed references for the materializer;
// it is not permission to read a source or to select a different scope.
func (s *OriginalCaptureSequence) WorkerSourceMounts(ctx context.Context) (_ worker.FormalSourceMount, _ worker.FormalSourceMount, resultErr error) {
	var zero worker.FormalSourceMount
	leave, err := s.enter(ctx)
	if err != nil {
		return zero, zero, err
	}
	defer func() {
		if resultErr != nil {
			s.failed = true
		}
		leave()
	}()
	if s.authority == nil || s.authority.Recheck(ctx) != nil {
		return zero, zero, c.ErrExecutionAuthority
	}
	raw, err := json.Marshal([]worker.FormalSourceMount{s.materials.Redis, s.materials.Objects})
	var mounts []worker.FormalSourceMount
	if err != nil || json.Unmarshal(raw, &mounts) != nil || len(mounts) != 2 {
		return zero, zero, c.ErrExecutionAuthority
	}
	return mounts[0], mounts[1], nil
}

// BeginOriginalCaptureSequence preserves the single producer's exact original
// declaration/core/profile/source checks, but publishes ONLY the two signed
// worker-source grants. Actual immutable formal mappings may now be created
// from those bytes before metadata scope is signed. No enabled-v1/task is used.
func BeginOriginalCaptureSequence(ctx context.Context, owner *install.Installer, password []byte, enrollment install.EnrollmentPin, definitionFile, definitionSHA, issuerPrivateFile string) (*OriginalCaptureSequence, error) {
	var zero *OriginalCaptureSequence
	if ctx == nil || !reflect.TypeOf(ctx).Comparable() || ctx.Err() != nil || owner == nil {
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
	// Validate all four eventual output paths before publishing either grant.
	paths := map[string][]byte{materials.Redis.GrantFile: nil, materials.Objects.GrantFile: nil, p.GrantFile: nil, core.CaptureModules.Path: nil}
	if err := producerOutputPaths(filepath.Dir(core.CaptureModules.Path), paths); err != nil {
		return zero, err
	}
	names := []string{materials.Redis.GrantFile, materials.Objects.GrantFile}
	sort.Strings(names)
	for _, name := range names {
		if authority.Recheck(ctx) != nil {
			return zero, c.ErrExecutionAuthority
		}
		if err := writeOriginalMaterialFile(name, files[name]); err != nil {
			return zero, err
		}
		actual, err := install.ReadSourceMaterialFile(name)
		if err != nil || !bytes.Equal(actual, files[name]) {
			return zero, c.ErrExecutionAuthority
		}
	}
	if authority.Recheck(ctx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	return &OriginalCaptureSequence{ctx: ctx, definition: definition, core: core, forward: forward, authority: authority, materials: materials, privateFile: issuerPrivateFile}, nil
}

// Finalize observes existing immutable Kubernetes objects; it never creates or
// trusts a caller's UID observation. Only mapping hashes and mount identities
// may be filled after Begin. Every other original source/template byte stays
// selected by the original owner declaration, including the absolute window.
func (s *OriginalCaptureSequence) Finalize(ctx context.Context, client kubernetes.Interface, materialFile, materialSHA string) (_ ProductionMaterialReceipt, resultErr error) {
	var zero ProductionMaterialReceipt
	leave, err := s.enter(ctx)
	if err != nil {
		return zero, err
	}
	defer func() {
		if resultErr != nil {
			s.failed = true
		}
		leave()
	}()
	if client == nil || s.authority == nil || s.authority.Recheck(ctx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	raw, err := install.ReadSourceMaterialFile(materialFile)
	var materials productionCaptureMaterials
	if err != nil || hash(raw) != materialSHA || decodeMetadataCanonical(raw, &materials) != nil || !s.sameDeclaration(materials) {
		return zero, c.ErrExecutionAuthority
	}
	if s.observeMappings(ctx, client, materials) != nil {
		return zero, c.ErrExecutionAuthority
	}
	for _, mount := range []worker.FormalSourceMount{materials.Redis, materials.Objects} {
		signed, err := install.ReadSourceMaterialFile(mount.GrantFile)
		if err != nil || hash(signed) != mount.GrantSHA256 {
			return zero, c.ErrExecutionAuthority
		}
	}
	service := &DeploymentService{ForwardEnabled: true, Config: s.core, ConfigPath: s.definition.CoreFile, ConfigDigest: s.definition.CoreSHA256, Forward: s.forward}
	if service.loadPublisherVerifierInput(s.definition.PublisherVerifier) != nil {
		return zero, c.ErrExecutionAuthority
	}
	scope, err := sourceMetadataScope(materials)
	if err != nil {
		return zero, err
	}
	key, err := install.ReadPrivateFile(s.privateFile, ed25519.PrivateKeySize)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		clear(key)
		return zero, c.ErrExecutionAuthority
	}
	defer clear(key)
	p := materials.Discovery
	if !bytes.Equal(ed25519.PrivateKey(key).Public().(ed25519.PublicKey), p.Issuer) {
		return zero, c.ErrExecutionAuthority
	}
	metadata, err := s.authority.SignControllerMetadata(ctx, install.ControllerSourceMetadataGrant{Version: sourceMetadataGrantVersion, InstallationID: s.core.InstallationID, ControllerOwner: s.core.ControllerOwner, DeploymentConfigSHA256: s.definition.CoreSHA256, CaptureGrantSHA256: s.definition.ForwardGrantSHA256, ConfigSHA256: s.definition.ConfigSHA256, ScopeSHA256: scope, Namespace: s.core.Namespace, NamespaceUID: s.core.NamespaceUID, ControllerDeployment: p.ControllerDeployment, ControllerDeploymentUID: p.ControllerDeploymentUID, ControllerServiceAccount: p.ControllerServiceAccount, ControllerServiceAccountUID: p.ControllerServiceAccountUID, NotBefore: s.definition.NotBefore, Until: s.definition.Until}, key)
	if err != nil {
		return zero, err
	}
	p.GrantSHA256 = hash(metadata)
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
	// Re-observe after signing/validation, before publishing complete metadata.
	if s.observeMappings(ctx, client, materials) != nil || s.authority.Recheck(ctx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	for _, file := range []struct {
		path string
		data []byte
	}{{p.GrantFile, metadata}, {s.core.CaptureModules.Path, material}} {
		if err := writeOriginalMaterialFile(file.path, file.data); err != nil {
			return zero, err
		}
		actual, err := install.ReadSourceMaterialFile(file.path)
		if err != nil || !bytes.Equal(actual, file.data) {
			return zero, c.ErrExecutionAuthority
		}
	}
	// Keep the original producer's independent post-output owner recheck and
	// its later final tail, including SQL clock changes during actor API reads.
	if s.authority.Recheck(ctx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	if _, err := pinnedDeploymentFile(s.definition.CoreFile, s.definition.CoreSHA256, 256<<10); err != nil {
		return zero, err
	}
	if _, err := pinnedDeploymentFile(s.definition.ConfigFile, s.definition.ConfigSHA256, 262144); err != nil {
		return zero, err
	}
	if _, err := pinnedDeploymentFile(s.core.ForwardGrant.Path, s.definition.ForwardGrantSHA256, 262144); err != nil {
		return zero, err
	}
	if service.loadProductionCapture([]ProductionCaptureInput{{File: s.core.CaptureModules.Path, SHA256: hash(material)}}) != nil || s.observeMappings(ctx, client, materials) != nil || s.authority.Recheck(ctx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	if ctx.Err() != nil || time.Now().Before(s.definition.NotBefore) || !time.Now().Before(s.definition.Until) {
		return zero, c.ErrExecutionAuthority
	}
	s.finished = true
	return ProductionMaterialReceipt{Version: "original-six-part-source-material-result.v1", Purpose: "functional_test", File: s.core.CaptureModules.Path, SHA256: hash(material), ScopeSHA256: scope, NotBefore: s.definition.NotBefore, Until: s.definition.Until}, nil
}

func (s *OriginalCaptureSequence) sameDeclaration(m productionCaptureMaterials) bool {
	raw, err := json.Marshal(m)
	var normalized productionCaptureMaterials
	if err != nil || decodeMetadataCanonical(raw, &normalized) != nil || len(m.Operations) != len(s.materials.Operations) {
		return false
	}
	for name, operation := range normalized.Operations {
		original, exists := s.materials.Operations[name]
		if !exists || !formalCandidateDigest(operation.Formal.ConfigSHA256) || !validProductionOperationMounts(operation) {
			return false
		}
		operation.Formal.ConfigSHA256 = original.Formal.ConfigSHA256
		operation.MountIdentities = original.MountIdentities
		normalized.Operations[name] = operation
	}
	return reflect.DeepEqual(normalized, s.materials)
}

func (s *OriginalCaptureSequence) observeMappings(ctx context.Context, client kubernetes.Interface, m productionCaptureMaterials) error {
	ns, err := client.CoreV1().Namespaces().Get(ctx, s.core.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != s.core.NamespaceUID || ns.DeletionTimestamp != nil {
		return c.ErrExecutionAuthority
	}
	for operation, part := range m.Operations {
		if !validProductionOperationMounts(part) {
			return c.ErrExecutionAuthority
		}
		inputs := map[string][]string{}
		for _, input := range part.Workload.FormalMaterials.Inputs {
			for _, item := range input.Items {
				inputs[input.Volume] = append(inputs[input.Volume], item.Key)
			}
		}
		for _, pin := range part.MountIdentities {
			var digest, uid string
			var mapping []byte
			switch pin.Kind {
			case "ConfigMap":
				cm, e := client.CoreV1().ConfigMaps(s.core.Namespace).Get(ctx, pin.Name, metav1.GetOptions{})
				if e != nil || cm.Immutable == nil || !*cm.Immutable || cm.DeletionTimestamp != nil {
					return c.ErrExecutionAuthority
				}
				uid, digest = string(cm.UID), kube.ContentHash([]any{cm.Data, cm.BinaryData})
				for _, key := range inputs[pin.Volume] {
					if _, ok := cm.Data[key]; !ok {
						if _, ok := cm.BinaryData[key]; !ok {
							return c.ErrExecutionAuthority
						}
					}
				}
				if pin.Volume == "formal-mapping" {
					mapping = []byte(cm.Data["materials.json"])
				}
			case "Secret":
				secret, e := client.CoreV1().Secrets(s.core.Namespace).Get(ctx, pin.Name, metav1.GetOptions{})
				if e != nil || secret.Immutable == nil || !*secret.Immutable || secret.DeletionTimestamp != nil {
					return c.ErrExecutionAuthority
				}
				uid, digest = string(secret.UID), kube.ContentHash(secret.Data)
				for _, key := range inputs[pin.Volume] {
					if _, ok := secret.Data[key]; !ok {
						return c.ErrExecutionAuthority
					}
				}
			default:
				return c.ErrExecutionAuthority
			}
			if uid == "" || uid != pin.UID || digest != pin.SHA256 {
				return c.ErrExecutionAuthority
			}
			if pin.Volume == "formal-mapping" {
				var formal worker.FormalCaptureMaterials
				if hash(mapping) != part.Formal.ConfigSHA256 || decodeMetadataCanonical(mapping, &formal) != nil || formal.Version != worker.FormalCaptureVersion || formal.KMS.Key != part.Provider.Request.Key || formal.KMS.Endpoint != part.Provider.Endpoint || formal.KMS.KeyName != part.Provider.KeyName || formal.KMS.InstallationID != s.core.InstallationID || formal.PermitDelivery == nil || !reflect.DeepEqual(formal.PermitDelivery, part.Formal.PermitDelivery) {
					return c.ErrExecutionAuthority
				}
				if operation == "capture-source-redis" && (formal.Sources == nil || !reflect.DeepEqual(*formal.Sources, m.Redis)) {
					return c.ErrExecutionAuthority
				}
				if operation == "capture-skill-objects" && (formal.Sources == nil || !reflect.DeepEqual(*formal.Sources, m.Objects)) {
					return c.ErrExecutionAuthority
				}
			}
		}
	}
	return nil
}
