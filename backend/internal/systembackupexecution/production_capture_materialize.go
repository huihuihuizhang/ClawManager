package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/worker"
	cd "clawreef/internal/systembackupcapturedescription"
	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	"clawreef/internal/systembackupinstallationowner/install"
	k "clawreef/internal/systembackupkms"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
)

const OriginalCaptureMappingDefinitionVersion = "original-capture-mapping-components.v1"

// OriginalCaptureMappingDefinition contains independently selected component
// inputs, not a caller-filled productionCaptureMaterials or observed UID list.
// This does not issue provider/source permission. Native owners must supply
// actual pinned KMS CA/config and a separately signed database source grant.
type OriginalCaptureMappingDefinition struct {
	Version, OriginalDefinitionSHA256 string
	KMS                               map[string]k.Config
	DatabaseSource                    worker.FormalSourceMount
	TeamsSource                       *worker.FormalSourceMount `json:",omitempty"`
	Files                             []OriginalCaptureMappingFile
}

// WorkerPath is the exact projected path declared in the original Job template.
// File is a controlled private staging input, SHA256 is its selected byte pin.
// No raw credential value is accepted in this declaration or returned receipt.
type OriginalCaptureMappingFile struct{ WorkerPath, File, SHA256 string }

// MaterializeMappings uses the same one-shot original context and issuer.
// It creates only original named immutable ConfigMaps/Secrets, independently
// GETs their actual UIDs/content and writes a private canonical intermediate.
// Call Finalize with its result and the SAME context. Failure permanently
// latches this sequence; no existing file/object is overwritten or deleted.
func (s *OriginalCaptureSequence) MaterializeMappings(ctx context.Context, client kubernetes.Interface, componentsFile, componentsSHA, outputFile string) (result ProductionCaptureInput, resultErr error) {
	var zero ProductionCaptureInput
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
	if client == nil || s.authority == nil || s.authority.Recheck(ctx) != nil || !filepath.IsAbs(outputFile) || filepath.Clean(outputFile) != outputFile || filepath.Dir(outputFile) != filepath.Dir(s.core.CaptureModules.Path) {
		return zero, c.ErrExecutionAuthority
	}
	// Reject stale original runtime/volume pins before creating any mapping
	// resources. This read grants neither SQL ownership nor physical stop.
	if s.materials.Discovery.PersistentMounts != nil {
		if err := checkOriginalPersistentMountPins(ctx, client, s.core, s.materials.Discovery.PersistentMounts); err != nil {
			return zero, err
		}
		if s.authority.Recheck(ctx) != nil {
			return zero, c.ErrExecutionAuthority
		}
	}
	for _, reserved := range []string{s.definition.CoreFile, s.definition.ConfigFile, s.core.ForwardGrant.Path, s.privateFile, s.materials.Redis.GrantFile, s.materials.Objects.GrantFile, s.materials.Discovery.GrantFile, s.core.CaptureModules.Path, componentsFile} {
		if outputFile == reserved {
			return zero, c.ErrExecutionAuthority
		}
	}
	diagnostic := &originalMaterializationDiagnostic{Version: "original-materialization-diagnostic.v1", OriginalDefinitionSHA256: hashMustMaterialDefinition(s.definition), Phase: "load-components", NotBefore: s.definition.NotBefore, Until: s.definition.Until, Assets: []OriginalMaterializationAsset{}}
	defer func() {
		if resultErr == nil {
			diagnostic.Status = "materialization_complete_not_finalized"
		} else {
			diagnostic.Status = "materialization_failed_resources_may_remain"
		}
		ref := diagnostic.persist(outputFile)
		if ref.File == "" && resultErr == nil {
			resultErr = c.ErrExecutionAuthority
		}
		if resultErr != nil {
			result = zero
			resultErr = &originalMaterializationFailure{cause: resultErr, diagnostic: ref}
		}
	}()
	raw, err := install.ReadSourceMaterialFile(componentsFile)
	var definition OriginalCaptureMappingDefinition
	if err != nil || hash(raw) != componentsSHA || decodeMetadataCanonical(raw, &definition) != nil || definition.Version != OriginalCaptureMappingDefinitionVersion || definition.OriginalDefinitionSHA256 != hashMustMaterialDefinition(s.definition) || len(definition.KMS) != len(s.materials.Operations) {
		return zero, c.ErrExecutionAuthority
	}
	// Work on detached bytes. Original declaration and signed source mounts in
	// the live sequence remain unchanged until B's independent Finalize checks.
	raw, err = json.Marshal(s.materials)
	var material productionCaptureMaterials
	if err != nil || decodeMetadataCanonical(raw, &material) != nil {
		return zero, c.ErrExecutionAuthority
	}
	files := map[string]OriginalCaptureMappingFile{}
	for _, file := range definition.Files {
		if file.WorkerPath == "" || path.Clean(file.WorkerPath) != file.WorkerPath || !path.IsAbs(file.WorkerPath) || files[file.WorkerPath].File != "" || !formalCandidateDigest(file.SHA256) || file.File == outputFile {
			return zero, c.ErrExecutionAuthority
		}
		files[file.WorkerPath] = file
	}
	if len(files) == 0 || len(files) > 512 {
		return zero, c.ErrExecutionAuthority
	}
	objects := map[string]*originalMappingObject{}
	diagnostic.Phase = "assemble-and-validate"
	defer func() {
		for _, object := range objects {
			for _, value := range object.data {
				clear(value)
			}
		}
	}()
	names := make([]string, 0, len(material.Operations))
	for name := range material.Operations {
		names = append(names, name)
	}
	sort.Strings(names)
	used := map[string]bool{}
	for _, name := range names {
		operation := material.Operations[name]
		formal, err := s.mappingComponents(name, operation, definition)
		if err != nil || kube.ValidateFormalJobMaterials(operation.Workload.FormalMaterials) != nil {
			return zero, c.ErrExecutionAuthority
		}
		mapping, err := json.Marshal(formal)
		if err != nil || len(mapping) > 1<<20 {
			return zero, c.ErrExecutionAuthority
		}
		operation.Formal.ConfigSHA256 = hash(mapping)
		operation.MountIdentities = nil
		if mergeOriginalMappingObject(objects, "ConfigMap", operation.Workload.FormalMaterials.ConfigMap, "materials.json", mapping, true) != nil {
			return zero, c.ErrExecutionAuthority
		}
		operationFiles := map[string]OriginalCaptureMappingFile{}
		volumes, directories := map[string]bool{"formal-mapping": true}, map[string]bool{}
		if len(operation.Workload.FormalMaterials.Inputs) == 0 || len(operation.Workload.FormalMaterials.Inputs) > 32 {
			return zero, c.ErrExecutionAuthority
		}
		for _, input := range operation.Workload.FormalMaterials.Inputs {
			if len(validation.IsDNS1123Label(input.Volume)) != 0 || len(input.Volume) < len("formal-") || input.Volume[:len("formal-")] != "formal-" || volumes[input.Volume] || directories[input.Directory] {
				return zero, c.ErrExecutionAuthority
			}
			volumes[input.Volume], directories[input.Directory] = true, true
			if path.Dir(input.Directory) != "/run/backup/materials" || len(validation.IsDNS1123Label(path.Base(input.Directory))) != 0 || len(input.Items) == 0 || len(input.Items) > 32 {
				return zero, c.ErrExecutionAuthority
			}
			for _, item := range input.Items {
				workerPath := path.Join(input.Directory, item.Path)
				file, exists := files[workerPath]
				if !exists || operationFiles[workerPath].File != "" || item.Path == "" || path.Base(item.Path) != item.Path || item.Path == "." || item.Path == ".." || strings.ContainsAny(item.Path, "\\\x00\r\n:") || item.Mode != nil {
					return zero, c.ErrExecutionAuthority
				}
				value, err := install.ReadSourceMaterialFile(file.File)
				if err != nil || hash(value) != file.SHA256 || len(value) > 1<<20 || mergeOriginalMappingObject(objects, input.Kind, input.Name, item.Key, value, false) != nil {
					clear(value)
					return zero, c.ErrExecutionAuthority
				}
				clear(value)
				used[workerPath] = true
				operationFiles[workerPath] = file
			}
		}
		if checkOriginalMappingDependencies(formal, operationFiles, s.materials.Discovery.SourceAPITokenSHA256) != nil {
			return zero, c.ErrExecutionAuthority
		}
		material.Operations[name] = operation
	}
	for _, object := range objects {
		size := 0
		for _, value := range object.data {
			size += len(value)
		}
		if size > 1<<20 {
			return zero, c.ErrExecutionAuthority
		}
	}
	if len(used) != len(files) || s.mappingNamespace(ctx, client) != nil {
		return zero, c.ErrExecutionAuthority
	}
	keys := make([]string, 0, len(objects))
	for key := range objects {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	pins := map[string]kube.MountIdentity{}
	diagnostic.Phase = "create-or-observe-immutable-objects"
	for _, key := range keys {
		if s.authority.Recheck(ctx) != nil {
			return zero, c.ErrExecutionAuthority
		}
		pin, err := s.createOriginalMappingObject(ctx, client, objects[key], diagnostic)
		if err != nil {
			return zero, err
		}
		pins[key] = pin
	}
	for _, name := range names {
		operation := material.Operations[name]
		pin := pins["ConfigMap/"+operation.Workload.FormalMaterials.ConfigMap]
		pin.Volume = "formal-mapping"
		operation.MountIdentities = append(operation.MountIdentities, pin)
		for _, input := range operation.Workload.FormalMaterials.Inputs {
			pin := pins[input.Kind+"/"+input.Name]
			pin.Volume = input.Volume
			operation.MountIdentities = append(operation.MountIdentities, pin)
		}
		if !validProductionOperationMounts(operation) {
			return zero, c.ErrExecutionAuthority
		}
		material.Operations[name] = operation
	}
	diagnostic.Phase = "independent-mapping-and-owner-tail"
	if !s.sameDeclaration(material) || s.observeMappings(ctx, client, material) != nil || s.authority.Recheck(ctx) != nil || s.mappingNamespace(ctx, client) != nil {
		return zero, c.ErrExecutionAuthority
	}
	// Re-read ALL selected files after the final API read; do not publish an
	// intermediate whose original local source changed during materialization.
	for _, file := range definition.Files {
		value, err := install.ReadSourceMaterialFile(file.File)
		ok := err == nil && hash(value) == file.SHA256
		clear(value)
		if !ok {
			return zero, c.ErrExecutionAuthority
		}
	}
	check, err := install.ReadSourceMaterialFile(componentsFile)
	if err != nil || hash(check) != componentsSHA || s.authority.Recheck(ctx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	raw, err = json.Marshal(material)
	diagnostic.Phase = "write-private-intermediate"
	if err != nil || writeOriginalMaterialFile(outputFile, raw) != nil {
		return zero, c.ErrExecutionAuthority
	}
	actual, err := install.ReadSourceMaterialFile(outputFile)
	if err != nil || !bytes.Equal(actual, raw) || s.authority.Recheck(ctx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	diagnostic.Phase = "materialization-complete-not-finalized"
	return ProductionCaptureInput{File: outputFile, SHA256: hash(raw)}, nil
}

func hashMustMaterialDefinition(definition ProductionMaterialDefinition) string {
	raw, err := json.Marshal(definition)
	if err != nil {
		return ""
	}
	return hash(raw)
}

func (s *OriginalCaptureSequence) mappingComponents(name string, operation productionCaptureOperation, d OriginalCaptureMappingDefinition) (worker.FormalCaptureMaterials, error) {
	var zero worker.FormalCaptureMaterials
	config, exists := d.KMS[name]
	if !exists || k.ValidateCaptureConfig(config) != nil || config.InstallationID != s.core.InstallationID || config.Endpoint != operation.Provider.Endpoint || config.KeyName != operation.Provider.KeyName || config.Key != operation.Provider.Request.Key || config.NotBefore.After(s.definition.NotBefore) || config.NotAfter.Before(s.definition.Until) || operation.Formal.PermitDelivery == nil || !k.ValidPermitDeliveryPin(*operation.Formal.PermitDelivery) {
		return zero, c.ErrExecutionAuthority
	}
	m := worker.FormalCaptureMaterials{Version: worker.FormalCaptureVersion, KMS: config, PermitDelivery: operation.Formal.PermitDelivery}
	switch name {
	case "capture-source-redis":
		m.Sources = &s.materials.Redis
	case "capture-skill-objects":
		m.Sources = &s.materials.Objects
	case "capture-database", "capture-team-objects":
		mount := d.DatabaseSource
		if name == "capture-team-objects" {
			if d.TeamsSource == nil || d.TeamsSource.GrantFile == s.materials.Objects.GrantFile || d.TeamsSource.GrantFile == s.materials.Redis.GrantFile || d.TeamsSource.GrantFile == d.DatabaseSource.GrantFile || d.TeamsSource.Objects == nil || d.TeamsSource.Redis != nil {
				return zero, c.ErrExecutionAuthority
			}
			mount = *d.TeamsSource
		}
		request := operation.Request
		if request.Operation != "" && request.Operation != name {
			return zero, c.ErrExecutionAuthority
		}
		request.Operation = name
		scope, err := worker.FormalSourceScopeSHA256(worker.Invocation{Request: request}, mount)
		if name == "capture-team-objects" {
			scope, err = worker.TeamObjectsSourceScopeSHA256(mount)
		}
		grantFile := ""
		for _, file := range d.Files {
			if file.WorkerPath == mount.GrantFile && file.SHA256 == mount.GrantSHA256 {
				grantFile = file.File
			}
		}
		raw, readErr := install.ReadSourceMaterialFile(grantFile)
		var signed worker.SignedFormalSourceGrant
		var grant worker.FormalSourceGrant
		now := time.Now()
		if err != nil || readErr != nil || len(raw) > 65536 || hash(raw) != mount.GrantSHA256 || decodeMetadataCanonical(raw, &signed) != nil || len(signed.Record) == 0 || len(signed.Record) > 32768 || decodeMetadataCanonical(signed.Record, &grant) != nil || len(mount.Issuer) != ed25519.PublicKeySize || bytes.Equal(mount.Issuer, m.PermitDelivery.Issuer) || !ed25519.Verify(mount.Issuer, append([]byte(worker.FormalSourceGrantDomain), signed.Record...), signed.Signature) || grant.Version != worker.FormalSourceGrantVersion || grant.InstallationID != s.core.InstallationID || grant.ConfigSHA256 != s.definition.ConfigSHA256 || !formalCandidateDigest(grant.ConfigSHA256) || grant.WorkerNamespace != s.core.Namespace || grant.WorkerServiceAccountUID != s.core.Security.ServiceAccountUID || grant.Operation != name || grant.ScopeSHA256 != scope || grant.CredentialSHA256 != mount.CredentialSHA256 || grant.Revoked || grant.NotBefore.IsZero() || grant.Until.Sub(grant.NotBefore) > 24*time.Hour || grant.NotBefore.After(s.definition.NotBefore) || grant.Until.Before(s.definition.Until) || now.Before(grant.NotBefore) || !now.Before(grant.Until) {
			return zero, c.ErrExecutionAuthority
		}
		m.Sources = &mount
	case "capture-deployment-resources", "capture-secret-bundle":
		source := s.materials.Discovery.SourceAPI
		m.Resources = &source
	case ce.Operation:
		if s.materials.ControlEvidenceSource == nil || s.materials.ControlEvidenceSource.Validate() != nil {
			return zero, c.ErrExecutionAuthority
		}
		m.ControlEvidence = s.materials.ControlEvidenceSource
	case "capture-workspace", cd.Operation:
	default:
		return zero, c.ErrExecutionAuthority
	}
	return m, nil
}

type originalMappingObject struct {
	kind, name string
	mapping    bool
	data       map[string][]byte
}

func mergeOriginalMappingObject(objects map[string]*originalMappingObject, kind, name, key string, value []byte, mapping bool) error {
	if kind != "ConfigMap" && kind != "Secret" || len(validation.IsDNS1123Subdomain(name)) != 0 || len(validation.IsConfigMapKey(key)) != 0 || len(value) == 0 {
		return c.ErrExecutionAuthority
	}
	id := kind + "/" + name
	object := objects[id]
	if object == nil {
		object = &originalMappingObject{kind: kind, name: name, mapping: mapping, data: map[string][]byte{}}
		objects[id] = object
	}
	if object.mapping != mapping {
		return c.ErrExecutionAuthority
	}
	if previous, exists := object.data[key]; exists {
		if !bytes.Equal(previous, value) {
			return c.ErrExecutionAuthority
		}
		return nil
	}
	object.data[key] = bytes.Clone(value)
	return nil
}

func checkOriginalMappingDependencies(m worker.FormalCaptureMaterials, files map[string]OriginalCaptureMappingFile, sourceTokenSHA string) error {
	required := map[string]string{}
	add := func(file, digest string) bool {
		if file == "" || !formalCandidateDigest(digest) || required[file] != "" && required[file] != digest {
			return false
		}
		required[file] = digest
		return true
	}
	if m.Sources != nil {
		s := m.Sources
		if !add(s.GrantFile, s.GrantSHA256) || !add(s.CredentialFile, s.CredentialSHA256) {
			return c.ErrExecutionAuthority
		}
		for _, tls := range []*worker.SourceTLSMapping{s.Redis, s.Objects} {
			if tls != nil && !add(tls.CAFile, tls.CASHA256) {
				return c.ErrExecutionAuthority
			}
		}
	}
	if m.Resources != nil && (!add(m.Resources.CAFile, m.Resources.CASHA256) || !add(m.Resources.TokenFile, sourceTokenSHA)) {
		return c.ErrExecutionAuthority
	}
	if m.ControlEvidence != nil && !add(m.ControlEvidence.GrantFile, m.ControlEvidence.GrantSHA256) {
		return c.ErrExecutionAuthority
	}
	for file, digest := range required {
		if selected, exists := files[file]; !exists || selected.SHA256 != digest {
			return c.ErrExecutionAuthority
		}
	}
	return nil
}

func (s *OriginalCaptureSequence) mappingNamespace(ctx context.Context, client kubernetes.Interface) error {
	ns, err := client.CoreV1().Namespaces().Get(ctx, s.core.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != s.core.NamespaceUID || ns.DeletionTimestamp != nil {
		return c.ErrExecutionAuthority
	}
	return nil
}

func (s *OriginalCaptureSequence) createOriginalMappingObject(ctx context.Context, client kubernetes.Interface, expected *originalMappingObject, diagnostics ...*originalMaterializationDiagnostic) (kube.MountIdentity, error) {
	var zero kube.MountIdentity
	labels := map[string]string{"system-backup.clawreef.io/managed-by": "original-owner-materializer"}
	annotations := map[string]string{"system-backup.clawreef.io/definition-sha256": hashMustMaterialDefinition(s.definition)}
	metadata := metav1.ObjectMeta{Name: expected.name, Namespace: s.core.Namespace, Labels: labels, Annotations: annotations}
	yes := true
	if s.mappingNamespace(ctx, client) != nil {
		return zero, c.ErrExecutionAuthority
	}
	var uid, digest string
	var diagnostic *originalMaterializationDiagnostic
	if len(diagnostics) == 1 {
		diagnostic = diagnostics[0]
	}
	record := func(meta metav1.ObjectMeta, sha, disposition, responseUID string, accepted bool) {
		diagnostic.record(OriginalMaterializationAsset{Kind: expected.kind, Namespace: s.core.Namespace, Name: expected.name, UID: string(meta.UID), ContentSHA256: sha, Disposition: disposition, CreateResponseUID: responseUID, Observed: meta.UID != "", Accepted: accepted})
	}
	validMeta := func(actual metav1.ObjectMeta) bool {
		return actual.Name == expected.name && actual.Namespace == s.core.Namespace && actual.UID != "" && actual.ResourceVersion != "" && actual.DeletionTimestamp == nil && len(actual.OwnerReferences) == 0 && len(actual.Finalizers) == 0 && reflect.DeepEqual(actual.Labels, labels) && reflect.DeepEqual(actual.Annotations, annotations)
	}
	switch expected.kind {
	case "ConfigMap":
		data, binary := map[string]string(nil), expected.data
		if expected.mapping {
			data, binary = map[string]string{"materials.json": string(expected.data["materials.json"])}, nil
		}
		object, err := client.CoreV1().ConfigMaps(s.core.Namespace).Get(ctx, expected.name, metav1.GetOptions{})
		disposition, responseUID := "reused", ""
		if apierrors.IsNotFound(err) {
			disposition = "create-unknown"
			created, createErr := client.CoreV1().ConfigMaps(s.core.Namespace).Create(ctx, &corev1.ConfigMap{ObjectMeta: metadata, Immutable: &yes, Data: data, BinaryData: binary}, metav1.CreateOptions{})
			err = createErr
			if created != nil {
				responseUID = string(created.UID)
			}
			if err == nil {
				disposition = "created"
			} else if apierrors.IsAlreadyExists(err) {
				disposition = "reused"
			}
			if err != nil && !apierrors.IsAlreadyExists(err) {
				probe, e := client.CoreV1().ConfigMaps(s.core.Namespace).Get(ctx, expected.name, metav1.GetOptions{})
				if e == nil && probe != nil {
					record(probe.ObjectMeta, kube.ContentHash([]any{probe.Data, probe.BinaryData}), "create-unknown", responseUID, false)
				} else {
					record(metadata, "", "create-unknown", responseUID, false)
				}
				return zero, c.ErrExecutionAuthority
			}
			object, err = client.CoreV1().ConfigMaps(s.core.Namespace).Get(ctx, expected.name, metav1.GetOptions{})
		}
		if err != nil || object == nil {
			if disposition != "reused" {
				record(metadata, "", "create-unknown", responseUID, false)
			}
			return zero, c.ErrExecutionAuthority
		}
		accepted := validMeta(object.ObjectMeta) && object.Immutable != nil && *object.Immutable && reflect.DeepEqual(object.Data, data) && reflect.DeepEqual(object.BinaryData, binary)
		if disposition == "created" && (responseUID == "" || responseUID != string(object.UID)) {
			disposition = "create-unknown"
		}
		if disposition == "reused" && !accepted {
			disposition = "preexisting-rejected"
		}
		record(object.ObjectMeta, kube.ContentHash([]any{object.Data, object.BinaryData}), disposition, responseUID, accepted)
		if !accepted {
			return zero, c.ErrExecutionAuthority
		}
		uid, digest = string(object.UID), kube.ContentHash([]any{object.Data, object.BinaryData})
	case "Secret":
		object, err := client.CoreV1().Secrets(s.core.Namespace).Get(ctx, expected.name, metav1.GetOptions{})
		disposition, responseUID := "reused", ""
		if apierrors.IsNotFound(err) {
			disposition = "create-unknown"
			created, createErr := client.CoreV1().Secrets(s.core.Namespace).Create(ctx, &corev1.Secret{ObjectMeta: metadata, Immutable: &yes, Type: corev1.SecretTypeOpaque, Data: expected.data}, metav1.CreateOptions{})
			err = createErr
			if created != nil {
				responseUID = string(created.UID)
			}
			if err == nil {
				disposition = "created"
			} else if apierrors.IsAlreadyExists(err) {
				disposition = "reused"
			}
			if err != nil && !apierrors.IsAlreadyExists(err) {
				probe, e := client.CoreV1().Secrets(s.core.Namespace).Get(ctx, expected.name, metav1.GetOptions{})
				if e == nil && probe != nil {
					record(probe.ObjectMeta, kube.ContentHash(probe.Data), "create-unknown", responseUID, false)
				} else {
					record(metadata, "", "create-unknown", responseUID, false)
				}
				return zero, c.ErrExecutionAuthority
			}
			object, err = client.CoreV1().Secrets(s.core.Namespace).Get(ctx, expected.name, metav1.GetOptions{})
		}
		if err != nil || object == nil {
			if disposition != "reused" {
				record(metadata, "", "create-unknown", responseUID, false)
			}
			return zero, c.ErrExecutionAuthority
		}
		accepted := validMeta(object.ObjectMeta) && object.Immutable != nil && *object.Immutable && object.Type == corev1.SecretTypeOpaque && reflect.DeepEqual(object.Data, expected.data) && len(object.StringData) == 0
		if disposition == "created" && (responseUID == "" || responseUID != string(object.UID)) {
			disposition = "create-unknown"
		}
		if disposition == "reused" && !accepted {
			disposition = "preexisting-rejected"
		}
		record(object.ObjectMeta, kube.ContentHash(object.Data), disposition, responseUID, accepted)
		if !accepted {
			return zero, c.ErrExecutionAuthority
		}
		uid, digest = string(object.UID), kube.ContentHash(object.Data)
	default:
		return zero, c.ErrExecutionAuthority
	}
	return kube.MountIdentity{Kind: expected.kind, Name: expected.name, UID: uid, SHA256: digest}, nil
}
