package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

const BootstrapOriginalMappingVersion = "system-backup-original-bootstrap-mapping.v1"
const BootstrapOriginalMappingDomain = BootstrapOriginalMappingVersion + "\x00"

type BootstrapOriginalOwnerBinding struct{ Key, SHA256 string }
type BootstrapOriginalHost struct {
	WorkloadIdentitySHA256                                                                 string
	Namespace, NamespaceUID, Pod, PodUID, ServiceAccount, ServiceAccountUID, PodSpecSHA256 string
}
type BootstrapOriginalMapping struct {
	SchemaVersion, PlanSHA256, CaptureRecordSHA256, SelectionSHA256, ProducerIssuerIdentitySHA256, EvidenceSourceSHA256, CapacityReportFile string
	Enrollment                                                                                                                              EnrollmentPin
	Target                                                                                                                                  owner.Target
	Actor                                                                                                                                   owner.Actor
	NotBefore, Until                                                                                                                        time.Time
	Owners                                                                                                                                  []BootstrapOriginalOwnerBinding
	Hosts                                                                                                                                   []BootstrapOriginalHost
}
type SignedBootstrapOriginalMapping struct{ Record, Signature []byte }

// IssueBootstrapOriginalMapping is explicit original association authority.
// It does NOT reinterpret capture permission as a provider/KEK grant. Actual
// compiled resource owners and complete C1 evidence/host reads remain required
// for consumption. Actual C1 grants select workload hashes; actual API reads
// select the enrolled runtime objects in the explicit original association.
func (i *Installer) IssueBootstrapOriginalMapping(ctx context.Context, password []byte, enrollment EnrollmentPin, bundleRaw []byte, bundleSHA string, request pd.BootstrapConsumptionRequest, bindings []BootstrapOriginalOwnerBinding, evidenceSourceSHA, capacityFile string, issuerPrivate []byte) (SignedBootstrapOriginalMapping, error) {
	var zero SignedBootstrapOriginalMapping
	// Freeze all caller-owned association data before authentication/API waits.
	requestRaw, e := json.Marshal(request)
	var frozen pd.BootstrapConsumptionRequest
	if e != nil || len(requestRaw) > 8<<20 || json.Unmarshal(requestRaw, &frozen) != nil {
		return zero, ErrInstall
	}
	request = frozen
	bindings = append([]BootstrapOriginalOwnerBinding(nil), bindings...)
	bundleRaw = bytes.Clone(bundleRaw)
	s, e := i.authenticate(ctx, password)
	if e != nil || s.authority(ctx, enrollment) != nil || !digestPattern.MatchString(evidenceSourceSHA) || !filepath.IsAbs(capacityFile) || filepath.Clean(capacityFile) != capacityFile {
		return zero, ErrInstall
	}
	b, r, _, e := s.decodeBundle(bundleRaw, bundleSHA, enrollment)
	if e != nil || b.SchemaVersion != AuthorityBundleVersion {
		return zero, ErrInstall
	}
	selection, e := pd.BootstrapConsumptionHash(request)
	if e != nil || string(selection) != r.SelectionSHA256 || request.Scope != (pd.Scope{ServerUUID: pd.ServerUUID(r.Target.ServerUUID), Database: pd.Database(r.Target.Database), Installation: pd.Installation(r.Target.InstallationID)}) || string(request.ActorID) != strconv.FormatInt(r.Actor.UserID, 10) || request.Username != r.Actor.Username || request.MatrixKey != r.MatrixKey || request.Endpoint != r.Endpoint || request.IdempotencyKey != r.IdempotencyKey || string(request.OfflineGrantHash) != r.GrantSHA256 || string(request.ConfigHash) != r.ConfigSHA256 || string(request.RegistrySetHash) != r.RegistrySetSHA256 || string(request.RefSetHash) != r.ReferenceSetSHA256 {
		return zero, ErrInstall
	}
	before, now, e := snapshot(ctx, s)
	if e != nil || !exactCommitted(before, b) || now.Before(r.NotBefore) || !now.Before(r.Until) {
		return zero, ErrInstall
	}
	// Snapshot() released ALL admin/head/grant locks before any producer-domain
	// read. No reverse domain -> owner lock nesting or caller-supplied host hash.
	var domain pd.DomainRecord
	found, e := pd.ReadOriginalSharedRecord(ctx, i.db, request.Scope, pd.RecordKey{}, &domain)
	if e != nil || !found || domain.Scope != request.Scope || domain.Admission.Unconfigured == nil || request.Candidates[0].Request.Admission.Unconfigured == nil || !sameOriginalAdmission(domain.Admission, request.Candidates[0].Request.Admission) {
		return zero, ErrInstall
	}
	workloadSet := map[string]bool{}
	for _, candidate := range request.Candidates {
		var original pd.GrantRecord
		found, e := pd.ReadOriginalSharedRecord(ctx, i.db, request.Scope, pd.RecordKey{ID: candidate.Request.GrantID}, &original)
		if e != nil || !found || original.Scope != request.Scope || original.State != "active" || original.Generation != candidate.Request.GrantGeneration || original.IssuerIdentityHash != domain.IssuerIdentityHash || original.Host.Service == nil || original.Host.Job != nil || !sameOriginalAdmission(original.Admission, candidate.Request.Admission) {
			return zero, ErrInstall
		}
		workloadSet[string(original.Host.Service.WorkloadIdentityHash)] = true
	}
	workloads := make([]string, 0, len(workloadSet))
	for workload := range workloadSet {
		workloads = append(workloads, workload)
	}
	if len(workloads) == 0 || len(workloads) > 20 {
		return zero, ErrInstall
	}
	captureBinding := false
	for _, binding := range bindings {
		if binding.Key == "reference:capture_signing" {
			if binding.SHA256 != hash(b.Record) {
				return zero, ErrInstall
			}
			captureBinding = true
		}
	}
	if !captureBinding {
		bindings = append(bindings, BootstrapOriginalOwnerBinding{Key: "reference:capture_signing", SHA256: hash(b.Record)})
	}
	sort.Slice(bindings, func(a, b int) bool { return bindings[a].Key < bindings[b].Key })
	known := map[string]bool{}
	for _, key := range sec.MissingBootstrapOwnerAdapters(sec.BootstrapOwnerAdapters{}) {
		known[key] = true
	}
	if len(bindings) == 0 || len(bindings) > len(known) {
		return zero, ErrInstall
	}
	for n, binding := range bindings {
		if !known[binding.Key] || !digestPattern.MatchString(binding.SHA256) || n > 0 && bindings[n-1].Key == binding.Key {
			return zero, ErrInstall
		}
	}
	sort.Strings(workloads)
	m := BootstrapOriginalMapping{SchemaVersion: BootstrapOriginalMappingVersion, PlanSHA256: i.planHash, CaptureRecordSHA256: hash(b.Record), SelectionSHA256: r.SelectionSHA256, ProducerIssuerIdentitySHA256: string(domain.IssuerIdentityHash), EvidenceSourceSHA256: evidenceSourceSHA, CapacityReportFile: capacityFile, Enrollment: enrollment, Target: r.Target, Actor: r.Actor, NotBefore: r.NotBefore, Until: r.Until, Owners: bindings}
	for n, workload := range workloads {
		if !digestPattern.MatchString(workload) || n > 0 && workloads[n-1] == workload {
			return zero, ErrInstall
		}
		host, e := observeBootstrapOriginalHost(ctx, i, r, workload)
		if e != nil {
			return zero, e
		}
		m.Hosts = append(m.Hosts, host)
	}
	key, e := s.privateKey(issuerPrivate)
	if e != nil {
		return zero, e
	}
	defer clear(key)
	raw, e := canonical(m)
	if e != nil || len(raw) > 262144 {
		return zero, ErrInstall
	}
	// Both original signatures are frozen OUTSIDE SQL locks. No source/config/
	// producer rows are written and no resource observation is declared healthy.
	signature := ed25519.Sign(key, append([]byte(BootstrapOriginalMappingDomain), raw...))
	if s.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	after, now, e := snapshot(ctx, s)
	if e != nil || after.cas != before.cas || !exactCommitted(after, b) || !now.Before(m.Until) || !s.live(ctx) {
		return zero, ErrInstall
	}
	return SignedBootstrapOriginalMapping{Record: raw, Signature: signature}, nil
}

func verifyBootstrapOriginalMapping(raw, signature []byte, public ed25519.PublicKey) (BootstrapOriginalMapping, error) {
	var m BootstrapOriginalMapping
	if len(raw) == 0 || len(raw) > 262144 || len(signature) != ed25519.SignatureSize || len(public) != ed25519.PublicKeySize {
		return m, ErrInstall
	}
	raw, signature, public = bytes.Clone(raw), bytes.Clone(signature), bytes.Clone(public)
	if !ed25519.Verify(public, append([]byte(BootstrapOriginalMappingDomain), raw...), signature) || decodeExact(raw, &m) != nil || m.SchemaVersion != BootstrapOriginalMappingVersion || !m.NotBefore.Before(m.Until) || m.Until.Sub(m.NotBefore) > 24*time.Hour || len(m.Hosts) == 0 || len(m.Hosts) > 20 {
		return m, ErrInstall
	}
	for _, sha := range []string{m.PlanSHA256, m.CaptureRecordSHA256, m.SelectionSHA256, m.ProducerIssuerIdentitySHA256, m.EvidenceSourceSHA256} {
		if !digestPattern.MatchString(sha) {
			return m, ErrInstall
		}
	}
	return m, nil
}
