package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"time"

	cd "clawreef/internal/systembackupcapturedescription"
	c "clawreef/internal/systembackupcontroller"
	api "clawreef/internal/systembackupdeployment"
	"clawreef/internal/systembackupinstallationowner/install"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	kms "clawreef/internal/systembackupkms"
	s "clawreef/internal/systembackupsecurity"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// File coordinates only. Permission/binding/auth/role/policy/CA hashes are
// derived from the independently signed original InstallationSigningRecord.
type PublicationSigningMountFiles struct{ Purpose, JWTFile, CAFile string }

// Independently selected original sources, not either finished runtime bundle.
// Neither an original signing permission nor publisher business grant can be
// replaced with a capture grant or an installer login in this action.
type PublicationRuntimeSources struct {
	Version                              string
	SigningRecord                        s.FileSigningRecordReader
	SigningPin                           s.InstallationSigningPin
	SigningFiles                         []PublicationSigningMountFiles
	Binding                              reg.Binding
	GenerateCapability, UnwrapCapability a.ProviderCapabilityPin
	InstallationIssuer                   ed25519.PublicKey
	VerifierCAFile, VerifierJWTFile      string
	VerifierGrant                        s.PublisherCaptureGrantMount
	ControllerPodName                    string
}

type PublicationRuntimeMaterialInputs struct {
	OwnerInputs                                   install.BootstrapSourceFilePin
	SourceDefinition, ComponentsTemplate, Sources install.BootstrapSourceFilePin
	OutputDefinitionFile, OutputComponentsFile    string
}

type PublicationRuntimeMaterialReceipt struct {
	State                                string
	Version                              string
	Signers                              PublicationSignerInput
	Verifier                             PublisherVerifierInput
	SourceDefinition, ComponentsTemplate install.BootstrapSourceFilePin
}

// ProducePublicationRuntimeMaterials is an explicit original installation
// action. It authenticates the original local administrator/enrollment, derives
// current actor coordinates from Kubernetes, consumes independently signed
// permissions and uses original startup file/signer and native owner checks.
// Installed-binding verification remains mandatory in normal post-A2 startup.
// It creates no task/claim, renews no deadline and issues no provider/business
// permission. Failed outputs are retained; only a complete receipt is success.
func ProducePublicationRuntimeMaterials(ctx context.Context, owner *install.Installer, runtimeDB *sql.DB, kube kubernetes.Interface, password []byte, enrollment install.EnrollmentPin, in PublicationRuntimeMaterialInputs) (PublicationRuntimeMaterialReceipt, error) {
	return producePublicationRuntimeMaterials(ctx, owner, runtimeDB, kube, password, enrollment, in, nil)
}

// Explicit enabled branch requires the same opaque, live committed-enable
// proof. Callers still supply real independently issued provider capabilities.
func ProduceEnabledPublicationRuntimeMaterials(ctx context.Context, owner *install.Installer, runtimeDB *sql.DB, kube kubernetes.Interface, password []byte, enrollment install.EnrollmentPin, in PublicationRuntimeMaterialInputs, enabled *install.OriginalEnabledPublication) (PublicationRuntimeMaterialReceipt, error) {
	if enabled == nil || enabled.Recheck(ctx) != nil {
		return PublicationRuntimeMaterialReceipt{}, c.ErrExecutionAuthority
	}
	return producePublicationRuntimeMaterials(ctx, owner, runtimeDB, kube, password, enrollment, in, enabled)
}
func producePublicationRuntimeMaterials(ctx context.Context, owner *install.Installer, runtimeDB *sql.DB, kube kubernetes.Interface, password []byte, enrollment install.EnrollmentPin, in PublicationRuntimeMaterialInputs, enabled *install.OriginalEnabledPublication) (PublicationRuntimeMaterialReceipt, error) {
	var zero PublicationRuntimeMaterialReceipt
	if ctx == nil || ctx.Err() != nil || owner == nil || runtimeDB == nil || kube == nil {
		return zero, c.ErrExecutionAuthority
	}
	if _, ok := ctx.Deadline(); !ok {
		return zero, c.ErrExecutionAuthority
	}
	pins := []install.BootstrapSourceFilePin{in.SourceDefinition, in.ComponentsTemplate, in.Sources, in.OwnerInputs}
	raws := make([][]byte, len(pins))
	for n, p := range pins {
		var e error
		raws[n], e = install.ReadSourceMaterialFile(p.File)
		if e != nil || hash(raws[n]) != p.SHA256 {
			return zero, c.ErrExecutionAuthority
		}
	}
	var def ProductionMaterialDefinition
	var components OriginalCaptureMappingDefinition
	var sources PublicationRuntimeSources
	if decodeMetadataCanonical(raws[0], &def) != nil || def.Version != productionMaterialDefinitionVersion || decodeMetadataCanonical(raws[1], &components) != nil || components.Version != OriginalCaptureInstallationTemplateVersion || components.OriginalDefinitionSHA256 != in.SourceDefinition.SHA256 || decodeMetadataCanonical(raws[2], &sources) != nil || sources.Version != "original-publication-runtime-sources.v1" || len(def.PublisherVerifier) != 0 {
		return zero, c.ErrExecutionAuthority
	}
	readOwner := func() (install.OriginalPublicationRuntimeOwnerInputs, error) {
		if enabled != nil {
			return owner.ReadEnabledPublicationRuntimeOwnerInputs(ctx, password, enrollment, in.OwnerInputs, enabled, runtimeDB)
		}
		return owner.ReadOriginalPublicationRuntimeOwnerInputs(ctx, password, enrollment, in.OwnerInputs, runtimeDB)
	}
	issued, e := readOwner()
	if e != nil {
		return zero, e
	}
	filesFromOwner := make([]PublicationSigningMountFiles, 0, len(issued.SigningMounts))
	for _, m := range issued.SigningMounts {
		filesFromOwner = append(filesFromOwner, PublicationSigningMountFiles{Purpose: m.Binding.Purpose, JWTFile: m.JWTFile, CAFile: m.CAFile})
	}
	// Optional redundant source coordinates must match genuine producer output.
	// A self-signed owner/grant inside provider source JSON cannot choose trust.
	if sources.SigningRecord != (s.FileSigningRecordReader{}) && sources.SigningRecord != issued.SigningRecord || sources.SigningPin.InstallationID != "" && !reflect.DeepEqual(sources.SigningPin, issued.SigningPin) || len(sources.SigningFiles) > 0 && !reflect.DeepEqual(sources.SigningFiles, filesFromOwner) || sources.VerifierGrant.File != "" && !reflect.DeepEqual(sources.VerifierGrant, issued.PublisherGrant) {
		return zero, c.ErrExecutionAuthority
	}
	sources.SigningRecord = issued.SigningRecord
	sources.SigningPin = issued.SigningPin
	sources.SigningFiles = filesFromOwner
	sources.VerifierGrant = issued.PublisherGrant
	if len(sources.SigningFiles) != 3 {
		return zero, c.ErrExecutionAuthority
	}
	core, e := LoadDeploymentConfig(def.CoreFile, def.CoreSHA256)
	if e != nil || core.CaptureScope != "six-part" || core.CaptureModules == nil || core.PublicationSigners == nil || core.PublisherVerifier == nil {
		return zero, c.ErrExecutionAuthority
	}
	pub, e := base64.StdEncoding.DecodeString(core.ForwardGrant.PublicKey)
	if e != nil {
		return zero, c.ErrExecutionAuthority
	}
	forward, e := c.NewPinnedExecutionIdentity(core.ForwardGrant.Path, def.ForwardGrantSHA256, core.KeyDirectory, pub)
	if e != nil {
		return zero, e
	}
	g := forward.DeploymentBinding()
	if g.InstallationID != core.InstallationID || g.ControllerOwner != core.ControllerOwner || g.ConfigSHA256 != def.ConfigSHA256 || g.DeploymentConfigSHA256 != def.CoreSHA256 || !forwardCaptureActions(g) || def.NotBefore.Before(g.NotBefore) || def.Until.After(g.ExpiresAt) || time.Now().Before(def.NotBefore) || !time.Now().Before(def.Until) {
		return zero, c.ErrExecutionAuthority
	}
	if _, e = pinnedDeploymentFile(def.ConfigFile, def.ConfigSHA256, 262144); e != nil {
		return zero, e
	}
	profile, e := api.LoadExecutionProfile(core.ProfileFile)
	if e != nil {
		return zero, e
	}
	_, profileSHA, e := profile.CanonicalIdentity()
	if e != nil || profileSHA != g.ProfileSHA256 || profile.InstallationID != core.InstallationID || profile.TargetClass != "same-cluster-copy" {
		return zero, c.ErrExecutionAuthority
	}
	var m productionCaptureMaterials
	if decodeMetadataCanonical(def.Materials, &m) != nil || m.Discovery == nil || m.Discovery.GrantSHA256 != "" || m.Redis.GrantSHA256 != "" || m.Objects.GrantSHA256 != "" || m.InstallationID != core.InstallationID || m.ControllerOwner != core.ControllerOwner || m.DeploymentConfigSHA256 != def.CoreSHA256 || m.CaptureGrantSHA256 != def.ForwardGrantSHA256 {
		return zero, c.ErrExecutionAuthority
	}
	redisScope, e := producerWorkerScope(m, "capture-source-redis")
	if e != nil {
		return zero, e
	}
	objectScope, e := producerWorkerScope(m, "capture-skill-objects")
	if e != nil {
		return zero, e
	}
	d := m.Discovery
	authority, e := owner.PrepareSourceMaterialIssue(ctx, password, enrollment, install.SourceMaterialIntent{DefinitionFile: in.SourceDefinition.File, DefinitionSHA256: in.SourceDefinition.SHA256, InstallationID: core.InstallationID, Namespace: core.Namespace, NamespaceUID: core.NamespaceUID, Purpose: "functional_test", ServerUUID: g.ServerUUID, Database: g.Database, DatabaseAccount: g.DatabaseAccount, DeploymentConfigSHA256: def.CoreSHA256, CaptureGrantSHA256: def.ForwardGrantSHA256, ConfigSHA256: def.ConfigSHA256, ControllerOwner: core.ControllerOwner, ControllerDeployment: d.ControllerDeployment, ControllerDeploymentUID: d.ControllerDeploymentUID, ControllerServiceAccount: d.ControllerServiceAccount, ControllerServiceAccountUID: d.ControllerServiceAccountUID, WorkerServiceAccount: core.Security.ServiceAccountName, WorkerServiceAccountUID: core.Security.ServiceAccountUID, SourceServiceAccount: d.SourceAPIServiceAccount, SourceServiceAccountUID: d.SourceAPIServiceAccountUID, RedisScopeSHA256: redisScope, RedisCredentialSHA256: m.Redis.CredentialSHA256, ObjectScopeSHA256: objectScope, ObjectCredentialSHA256: m.Objects.CredentialSHA256, NotBefore: def.NotBefore, Until: def.Until}, runtimeDB)
	if e != nil {
		return zero, e
	}
	// Observe the actual Pod -> ReplicaSet -> declared original Deployment chain.
	pod, e := kube.CoreV1().Pods(core.Namespace).Get(ctx, sources.ControllerPodName, metav1.GetOptions{})
	if e != nil || pod.UID == "" || pod.DeletionTimestamp != nil || string(pod.Status.Phase) != "Running" || pod.Spec.ServiceAccountName != d.ControllerServiceAccount || len(pod.OwnerReferences) != 1 {
		return zero, c.ErrExecutionAuthority
	}
	parent := pod.OwnerReferences[0]
	if parent.Controller == nil || !*parent.Controller || parent.Kind != "ReplicaSet" || parent.APIVersion != "apps/v1" {
		return zero, c.ErrExecutionAuthority
	}
	rs, e := kube.AppsV1().ReplicaSets(core.Namespace).Get(ctx, parent.Name, metav1.GetOptions{})
	if e != nil || string(rs.UID) != string(parent.UID) || rs.DeletionTimestamp != nil || len(rs.OwnerReferences) != 1 {
		return zero, c.ErrExecutionAuthority
	}
	deployment := rs.OwnerReferences[0]
	if deployment.Controller == nil || !*deployment.Controller || deployment.Kind != "Deployment" || deployment.APIVersion != "apps/v1" || deployment.Name != d.ControllerDeployment || string(deployment.UID) != d.ControllerDeploymentUID {
		return zero, c.ErrExecutionAuthority
	}
	w := a.ControllerVerifierWorkload{Namespace: core.Namespace, PodName: pod.Name, PodUID: string(pod.UID), ServiceAccountName: d.ControllerServiceAccount, ServiceAccountUID: d.ControllerServiceAccountUID, OwnerKind: "Deployment", OwnerUID: d.ControllerDeploymentUID, ControllerOwner: "public:" + string(pod.UID), GrantSHA256: sources.VerifierGrant.SHA256, ConfigSHA256: g.ConfigSHA256, ConfigVersion: g.ConfigVersion}
	reads := a.VerifierKubernetesReads{Version: a.VerifierKubernetesReadsVersion, Namespace: core.Namespace, NamespaceUID: core.NamespaceUID, PodName: pod.Name, PodUID: string(pod.UID), ServiceAccountName: d.ControllerServiceAccount, ServiceAccountUID: d.ControllerServiceAccountUID, OwnerKind: "Deployment", OwnerName: d.ControllerDeployment, OwnerUID: d.ControllerDeploymentUID, ReplicaSetName: rs.Name, ReplicaSetUID: string(rs.UID)}
	if reads.Check(ctx, kube, w) != nil {
		return zero, c.ErrExecutionAuthority
	}
	verifier := PublisherVerifierMaterials{Version: PublisherVerifierMaterialsVersion, Database: reg.DatabaseIdentity{ServerUUID: g.ServerUUID, Database: g.Database}, Binding: sources.Binding, GenerateCapability: sources.GenerateCapability, UnwrapCapability: sources.UnwrapCapability, InstallationIssuer: sources.InstallationIssuer, CAFile: sources.VerifierCAFile, JWTFile: sources.VerifierJWTFile, Workload: w, KubernetesReads: reads, Grant: sources.VerifierGrant}
	if op, ok := m.Operations[cd.Operation]; ok {
		verifier.DescriptionMaxPlaintextBytes = op.Request.MaxArchiveBytes
	}
	// RecoveryTrust remains nil: this action cannot claim DR or restore approval.
	if verifier.validate(core) != nil {
		return zero, c.ErrExecutionAuthority
	}
	if _, e = s.LoadInstallationSigningHistory(ctx, sources.SigningRecord, sources.SigningPin); e != nil {
		return zero, e
	}
	recordRaw, _, e := sources.SigningRecord.ReadSigningRecord(ctx)
	var record s.InstallationSigningRecord
	if e != nil || hash(recordRaw) != sources.SigningPin.RecordSHA256 || decodeProviderDeploymentJSON(recordRaw, &record) != nil || len(record.Permissions) != 3 {
		return zero, c.ErrExecutionAuthority
	}
	signers := PublicationSignerMaterials{Version: PublicationSignerMaterialsVersion, Record: sources.SigningRecord, Pin: sources.SigningPin}
	files := map[string]PublicationSigningMountFiles{}
	for _, f := range sources.SigningFiles {
		if f.Purpose != "capture_certificate" && f.Purpose != "acceptance_record" && f.Purpose != "catalog_record" {
			return zero, c.ErrExecutionAuthority
		}
		if _, ok := files[f.Purpose]; ok {
			return zero, c.ErrExecutionAuthority
		}
		files[f.Purpose] = f
	}
	for _, p := range record.Permissions {
		f, ok := files[p.Binding.Purpose]
		if !ok {
			return zero, c.ErrExecutionAuthority
		}
		delete(files, p.Binding.Purpose)
		signers.Mounts = append(signers.Mounts, s.PublicationSigningMount{Binding: p.Binding, AuthMount: p.AuthMount, Role: p.Role, Policy: p.Policy, CASHA256: p.CASHA256, JWTFile: f.JWTFile, CAFile: f.CAFile})
	}
	if len(files) != 0 {
		return zero, c.ErrExecutionAuthority
	}
	// A real current capability read precedes file publication. It issues no DEK.
	caps, e := a.NewSQLProviderCapabilityPreparation(runtimeDB, verifier.Database, core.InstallationID, sources.GenerateCapability, sources.UnwrapCapability)
	if e != nil {
		return zero, e
	}
	if _, e = caps.PrepareCapabilities(ctx, sources.Binding); e != nil {
		return zero, e
	}
	protected := map[string]bool{}
	for _, p := range pins {
		protected[p.File] = true
	}
	for _, f := range []string{def.CoreFile, def.ConfigFile, core.ForwardGrant.Path, core.ProfileFile, core.CaptureModules.Path, d.GrantFile, m.Redis.GrantFile, m.Objects.GrantFile, sources.SigningRecord.RecordFile, sources.SigningRecord.SignatureFile, sources.VerifierGrant.File, sources.VerifierCAFile, sources.VerifierJWTFile} {
		protected[f] = true
	}
	for _, f := range sources.SigningFiles {
		protected[f.JWTFile] = true
		protected[f.CAFile] = true
	}
	outputs := []string{core.PublicationSigners.Path, core.PublisherVerifier.Path, in.OutputDefinitionFile, in.OutputComponentsFile}
	for _, f := range outputs {
		if !filepath.IsAbs(f) || filepath.Clean(f) != f || protected[f] {
			return zero, c.ErrExecutionAuthority
		}
		protected[f] = true
		if _, e := os.Lstat(f); !os.IsNotExist(e) {
			return zero, c.ErrExecutionAuthority
		}
	}
	for _, f := range []string{core.CaptureModules.Path, d.GrantFile, m.Redis.GrantFile, m.Objects.GrantFile} {
		if _, e := os.Lstat(f); !os.IsNotExist(e) {
			return zero, c.ErrExecutionAuthority
		}
	}
	signerRaw, e := json.Marshal(signers)
	if e != nil {
		return zero, c.ErrExecutionAuthority
	}
	verifierRaw, e := json.Marshal(verifier)
	if e != nil {
		return zero, c.ErrExecutionAuthority
	}
	signerPin := PublicationSignerInput{File: core.PublicationSigners.Path, SHA256: hash(signerRaw)}
	verifierPin := PublisherVerifierInput{File: core.PublisherVerifier.Path, SHA256: hash(verifierRaw)}
	if authority.Recheck(ctx) != nil || writeOriginalMaterialFile(signerPin.File, signerRaw) != nil || writeOriginalMaterialFile(verifierPin.File, verifierRaw) != nil {
		return zero, c.ErrExecutionAuthority
	}
	service := &DeploymentService{Config: core, ConfigPath: def.CoreFile, ConfigDigest: def.CoreSHA256, ForwardEnabled: true, Forward: forward, profileHash: profileSHA}
	if service.loadPublicationSignerInput([]PublicationSignerInput{signerPin}) != nil || service.loadPublisherVerifierInput([]PublisherVerifierInput{verifierPin}) != nil || service.validateDescriptionMemoryStartup(m) != nil || service.attachPublicationSigners(ctx, runtimeDB, kube, pod.Name) != nil || checkPrebootstrapPublisherOwner(ctx, runtimeDB, kube, service, verifier) != nil || checkPrebootstrapPublisherCapability(ctx, runtimeDB, verifier) != nil {
		return zero, c.ErrExecutionAuthority
	}
	// Independently delivered bundle digests never enter the parent core/Forward
	// hash. Only the still-unsigned source declaration receives its verifier pin.
	def.PublisherVerifier = []PublisherVerifierInput{verifierPin}
	next, e := json.Marshal(def)
	if e != nil {
		return zero, c.ErrExecutionAuthority
	}
	components.OriginalDefinitionSHA256 = hash(next)
	componentRaw, e := json.Marshal(components)
	if e != nil {
		return zero, c.ErrExecutionAuthority
	}
	for n, p := range pins {
		now, e := install.ReadSourceMaterialFile(p.File)
		if e != nil || hash(now) != hash(raws[n]) {
			return zero, c.ErrExecutionAuthority
		}
	}
	if authority.Recheck(ctx) != nil || writeOriginalMaterialFile(in.OutputDefinitionFile, next) != nil || writeOriginalMaterialFile(in.OutputComponentsFile, componentRaw) != nil {
		return zero, c.ErrExecutionAuthority
	}
	for _, p := range []install.BootstrapSourceFilePin{{File: signerPin.File, SHA256: signerPin.SHA256}, {File: verifierPin.File, SHA256: verifierPin.SHA256}, {File: in.OutputDefinitionFile, SHA256: hash(next)}, {File: in.OutputComponentsFile, SHA256: hash(componentRaw)}} {
		if raw, e := install.ReadSourceMaterialFile(p.File); e != nil || hash(raw) != p.SHA256 {
			return zero, c.ErrExecutionAuthority
		}
	}
	if service.attachPublicationSigners(ctx, runtimeDB, kube, pod.Name) != nil || checkPrebootstrapPublisherOwner(ctx, runtimeDB, kube, service, verifier) != nil || checkPrebootstrapPublisherCapability(ctx, runtimeDB, verifier) != nil || authority.Recheck(ctx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	for n, p := range pins {
		now, e := install.ReadSourceMaterialFile(p.File)
		if e != nil || hash(now) != hash(raws[n]) {
			return zero, c.ErrExecutionAuthority
		}
	}
	lastOwner, e := readOwner()
	if e != nil || !reflect.DeepEqual(lastOwner, issued) {
		return zero, c.ErrExecutionAuthority
	}
	return PublicationRuntimeMaterialReceipt{State: "original_owner_materials_generated_installed_binding_check_pending", Version: "original-publication-runtime-materials-result.v1", Signers: signerPin, Verifier: verifierPin, SourceDefinition: install.BootstrapSourceFilePin{File: in.OutputDefinitionFile, SHA256: hash(next)}, ComponentsTemplate: install.BootstrapSourceFilePin{File: in.OutputComponentsFile, SHA256: hash(componentRaw)}}, nil
}

// Pre-A2 authentication of the ORIGINAL independently signed owner grant and
// actual actor only. This is not installed-KEK verification or task authority.
// Normal NewDeploymentServiceWithInputs still calls attachPublisherVerifier ->
// CheckDeployment after A2 StageAdmission, before readiness/admission/ForPart.
func checkPrebootstrapPublisherOwner(ctx context.Context, db *sql.DB, kube kubernetes.Interface, service *DeploymentService, p PublisherVerifierMaterials) error {
	if service == nil || service.Forward == nil || service.publicationBinding() != nil || p.validate(service.Config) != nil || service.Forward.CheckDeployment(ctx, db) != nil {
		return c.ErrExecutionAuthority
	}
	g := service.Forward.DeploymentBinding()
	w := p.Workload
	if p.KubernetesReads.Check(ctx, kube, w) != nil {
		return c.ErrExecutionAuthority
	}
	cfg := s.PublisherCaptureAuthorityConfig{DB: db, Kubernetes: kube, Deployment: s.PublisherCaptureDeployment{InstallationID: g.InstallationID, ServerUUID: g.ServerUUID, Database: g.Database, DatabaseAccount: g.DatabaseAccount, ControllerOwner: g.ControllerOwner, ConfigVersion: g.ConfigVersion, ConfigSHA256: g.ConfigSHA256, ProfileSHA256: g.ProfileSHA256, DeploymentConfigSHA256: g.DeploymentConfigSHA256, CaptureGrantSHA256: service.Forward.GrantSHA256(), NotBefore: g.NotBefore, Until: g.ExpiresAt}, Workload: s.PublisherCaptureWorkload{Namespace: w.Namespace, NamespaceUID: p.KubernetesReads.NamespaceUID, PodName: w.PodName, PodUID: w.PodUID, ServiceAccountName: w.ServiceAccountName, ServiceAccountUID: w.ServiceAccountUID, PublisherOwner: w.ControllerOwner, GrantSHA256: w.GrantSHA256}, GrantMount: p.Grant}
	return s.CheckPublisherCaptureDeploymentWorkload(ctx, cfg)
}

// Authenticate the exact current signed Unwrap permission's real controller
// actor before A2, without requiring that A2's config binding already exists.
// Inspect returns DATA only; normal factory/ForPart still binds installed KEK.
func checkPrebootstrapPublisherCapability(ctx context.Context, db *sql.DB, p PublisherVerifierMaterials) error {
	var raw []byte
	var sum string
	var size uint64
	var end, now time.Time
	if db == nil || ctx == nil || ctx.Err() != nil {
		return c.ErrExecutionAuthority
	}
	if db.QueryRowContext(ctx, `SELECT inline_payload,content_checksum,content_size_bytes,expires_at,UTC_TIMESTAMP(6) FROM system_backup_v2_evidence WHERE public_id=? AND owner_target_type='system' AND owner_target_public_id=? AND evidence_type='capability_snapshot' AND storage_state='inline' AND observed_health='healthy' AND encryption='none'`, p.UnwrapCapability.Source.RecordID, p.Binding.InstallationID).Scan(&raw, &sum, &size, &end, &now) != nil || len(raw) < 1 || len(raw) > 8192 || uint64(len(raw)) != size || hash(raw) != sum {
		return c.ErrExecutionAuthority
	}
	record, e := a.InspectProviderCapabilityMaterial(raw, p.UnwrapCapability, p.Binding, kms.Unwrap, end, now)
	if e != nil || record.Facts.Permission.ControllerVerifier == nil || *record.Facts.Permission.ControllerVerifier != p.Workload {
		return c.ErrExecutionAuthority
	}
	return nil
}
