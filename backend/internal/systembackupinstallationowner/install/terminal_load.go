package install

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"time"

	evidence "clawreef/internal/systembackupevidence"
	owner "clawreef/internal/systembackupinstallationowner"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

type bootstrapTerminalLoaded struct {
	source            *consumerCaptureState
	mapping           BootstrapOriginalMapping
	bindings          map[string]string
	request           pd.BootstrapConsumptionRequest
	config            sec.BootstrapConfig
	grant             sec.OfflineBootstrapGrant
	registryDirectory string
	files             []consumerPinnedFile
	evidence          *evidence.BootstrapOriginalEvidenceSource
	hostUntil         *pd.Timestamp
}

func (a *BootstrapTerminalOriginal) load(ctx context.Context, grant sec.OfflineBootstrapGrant, config sec.BootstrapConfig, request pd.BootstrapConsumptionRequest) (*bootstrapTerminalLoaded, error) {
	source, e := a.capture.load(ctx)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			source.request.observer.Close()
		}
	}()
	if grant != source.request.grant || config.SHA256() != source.request.config.SHA256() {
		return nil, ErrInstall
	}
	locator, plan, public, e := readBootstrapOriginalPublicSource(ctx, a.capture, source)
	if e != nil {
		return nil, ErrInstall
	}
	recordRaw, e := ReadPrivateFile(locator.RecordFile, 262144)
	var record owner.Record
	if e != nil || decodeExact(recordRaw, &record) != nil {
		return nil, ErrInstall
	}
	mappingRaw, e := ReadPrivateFile(a.files.MappingFile, 262144)
	if e != nil || hash(mappingRaw) != a.files.MappingSHA256 {
		return nil, ErrInstall
	}
	signature, e := ReadPrivateFile(a.files.SignatureFile, 64)
	if e != nil {
		return nil, e
	}
	mapping, e := verifyBootstrapOriginalMapping(mappingRaw, signature, public)
	if e != nil || mapping.PlanSHA256 != locator.PlanSHA256 || mapping.CaptureRecordSHA256 != hash(recordRaw) || mapping.Target != record.Target || mapping.Actor != record.Actor || !mapping.NotBefore.Equal(record.NotBefore) || !mapping.Until.Equal(record.Until) || mapping.Enrollment.DocumentSHA256 == "" {
		return nil, ErrInstall
	}
	enrollmentRaw, e := ReadPrivateFile(locator.EnrollmentPinFile, 262144)
	if e != nil {
		return nil, e
	}
	enrollment, e := DecodeEnrollmentPin(enrollmentRaw, locator.EnrollmentPinSHA256)
	if e != nil || enrollment != mapping.Enrollment {
		return nil, ErrInstall
	}
	selection, e := pd.BootstrapConsumptionHash(request)
	grantRaw, _ := json.Marshal(grant)
	if e != nil || string(selection) != mapping.SelectionSHA256 || mapping.SelectionSHA256 != record.SelectionSHA256 || request.Scope != (pd.Scope{ServerUUID: pd.ServerUUID(record.Target.ServerUUID), Database: pd.Database(record.Target.Database), Installation: pd.Installation(record.Target.InstallationID)}) || string(request.OfflineGrantHash) != hash(grantRaw) || string(request.ConfigHash) != record.ConfigSHA256 || string(request.RegistrySetHash) != record.RegistrySetSHA256 || string(request.RefSetHash) != record.ReferenceSetSHA256 || string(request.ActorID) != strconv.FormatInt(record.Actor.UserID, 10) || request.Username != record.Actor.Username || request.MatrixKey != record.MatrixKey || request.Endpoint != record.Endpoint || request.IdempotencyKey != record.IdempotencyKey {
		return nil, ErrInstall
	}
	for _, candidate := range request.Candidates {
		if candidate.Request.Admission.Unconfigured == nil || !reflect.DeepEqual(candidate.Request.Admission, request.Candidates[0].Request.Admission) {
			return nil, ErrInstall
		}
	}
	requestRaw, e := json.Marshal(request)
	var frozen pd.BootstrapConsumptionRequest
	if e != nil || json.Unmarshal(requestRaw, &frozen) != nil {
		return nil, ErrInstall
	}
	ownedConfig, e := sec.DecodeBootstrapConfig(config.CanonicalJSON())
	if e != nil {
		return nil, e
	}
	loaded := &bootstrapTerminalLoaded{source: source, mapping: mapping, bindings: map[string]string{}, request: frozen, config: ownedConfig, grant: grant, registryDirectory: a.files.RegistryDirectory, files: []consumerPinnedFile{{a.files.MappingFile, a.files.MappingSHA256, 262144}, {a.files.SignatureFile, hash(signature), 64}, {a.files.EvidenceFile, mapping.EvidenceSourceSHA256, 262144}}}
	known := map[string]bool{}
	for _, key := range sec.MissingBootstrapOwnerAdapters(sec.BootstrapOwnerAdapters{}) {
		known[key] = true
	}
	for n, binding := range mapping.Owners {
		if !known[binding.Key] || !digestPattern.MatchString(binding.SHA256) || n > 0 && mapping.Owners[n-1].Key >= binding.Key {
			return nil, ErrInstall
		}
		loaded.bindings[binding.Key] = binding.SHA256
	}
	if loaded.bindings["reference:capture_signing"] != hash(recordRaw) || len(loaded.bindings) != len(known) {
		return nil, ErrInstall
	}
	evidenceRaw, e := ReadPrivateFile(a.files.EvidenceFile, 262144)
	var entries []evidence.BootstrapOriginalEvidenceEntry
	if e != nil || hash(evidenceRaw) != mapping.EvidenceSourceSHA256 || decodeExact(evidenceRaw, &entries) != nil {
		return nil, ErrInstall
	}
	loaded.evidence, e = evidence.NewBootstrapOriginalEvidenceSource(entries)
	if e != nil {
		return nil, ErrInstall
	}
	sourceSHA, e := loaded.evidence.BindingSHA256()
	if e != nil || sourceSHA != mapping.EvidenceSourceSHA256 || !loaded.matchesEvidenceSelection() {
		return nil, ErrInstall
	}
	kube, e := openCaptureConsumerKubernetes(plan, locator.KubeconfigFile, locator.KubeconfigSHA256)
	if e != nil {
		return nil, e
	}
	physical := true
	// Bound the whole API observation, including slow reads, from its start.
	hostObservedAt := time.Now().UTC().Truncate(time.Microsecond)
	for n, host := range mapping.Hosts {
		if !digestPattern.MatchString(host.WorkloadIdentitySHA256) || !digestPattern.MatchString(host.PodSpecSHA256) || n > 0 && mapping.Hosts[n-1].WorkloadIdentitySHA256 >= host.WorkloadIdentitySHA256 || host.Namespace != record.Binding.Namespace || host.NamespaceUID != record.Binding.NamespaceUID || host.Pod != record.Binding.PodName || host.PodUID != record.Binding.PodUID || host.ServiceAccount != record.Binding.ServiceAccountName || host.ServiceAccountUID != record.Binding.ServiceAccountUID {
			return nil, ErrInstall
		}
		observed, e := observeBootstrapOriginalHost(ctx, &Installer{plan: plan, kube: kube}, record, host.WorkloadIdentitySHA256)
		if e != nil || observed != host {
			physical = false
		}
	}
	if physical {
		until := hostObservedAt.Add(time.Minute)
		if mapping.Until.Before(until) {
			until = mapping.Until
		}
		stamp := terminalTimestamp(until)
		loaded.hostUntil = &stamp
	}
	if loaded.currentFiles(ctx) != nil || source.current(ctx) != nil || loaded.authorizeRBAC() != nil {
		return nil, ErrInstall
	}
	ok = true
	return loaded, nil
}

func (s *bootstrapTerminalLoaded) currentFiles(ctx context.Context) error {
	if s == nil || s.source == nil || !consumerSameContext(ctx, s.source.ctx) || ctx.Err() != nil {
		return ErrInstall
	}
	for _, file := range s.files {
		raw, e := ReadPrivateFile(file.path, file.limit)
		if e != nil || hash(raw) != file.sha {
			return ErrInstall
		}
	}
	return nil
}
func (s *bootstrapTerminalLoaded) authorizeRBAC() error {
	if s == nil {
		return ErrInstall
	}
	var rbac sec.BootstrapRegistryRef
	for _, ref := range s.config.Registries() {
		if ref.Kind == "rbac_bindings" {
			rbac = ref
		}
	}
	files := sec.RegistrationFiles{RegistryDirectory: s.registryDirectory}
	authority := sec.PinnedRegistrationAuthority{InstallationID: s.grant.InstallationID, RegistryBytes: files.RegistryBytes}
	return authority.AuthorizeRole(sec.RegistrationActor{UserID: s.grant.UserID, Subject: "user:" + strconv.FormatInt(s.grant.UserID, 10)}, sec.RegistrationConfig{RBACRegistryVersion: rbac.Version, RBACRegistrySHA256: rbac.SHA256})
}
func (s *bootstrapTerminalLoaded) matchesEvidenceSelection() bool {
	expected, e := s.evidence.ExpectedBindings()
	if e != nil {
		return false
	}
	byID := map[pd.EvidenceID]pd.EvidenceBinding{}
	for _, candidate := range s.request.Candidates {
		binding := candidate.Request.Evidence
		if previous, ok := byID[binding.EvidenceID]; ok && !reflect.DeepEqual(previous, binding) {
			return false
		}
		byID[binding.EvidenceID] = binding
	}
	if len(expected) != len(byID) {
		return false
	}
	refs := map[string]sec.BootstrapSecretRef{}
	for _, ref := range s.config.References() {
		refs[ref.Purpose] = ref
	}
	for _, binding := range expected {
		if selected, ok := byID[binding.EvidenceID]; !ok || !reflect.DeepEqual(selected, binding) || string(binding.OwnerID) != s.grant.InstallationID || binding.OwnerType != "system" || string(binding.StoreIdentityHash) != refs["evidence_store"].IdentityHash || string(binding.StoreRefVersion) != refs["evidence_store"].Version || string(binding.WriteIdentityHash) != refs["evidence_write"].IdentityHash || string(binding.WriteRefVersion) != refs["evidence_write"].Version || string(binding.KEKIdentityHash) != refs["evidence_kek"].IdentityHash || string(binding.KEKVersion) != refs["evidence_kek"].Version {
			return false
		}
	}
	return true
}

func sortedTerminalCandidates(facts pd.BootstrapConsumptionFacts) []pd.ResultFacts {
	owned := append([]pd.ResultFacts(nil), facts.Candidates...)
	sort.Slice(owned, func(i, j int) bool {
		if owned[i].Receipt == nil {
			return owned[j].Receipt != nil
		}
		if owned[j].Receipt == nil {
			return false
		}
		return owned[i].Receipt.Request.GrantID < owned[j].Receipt.Request.GrantID
	})
	return owned
}
