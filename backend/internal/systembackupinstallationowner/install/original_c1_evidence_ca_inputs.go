package install

import (
	"context"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"

	ca "clawreef/internal/systembackupcatrust"
	sec "clawreef/internal/systembackupsecurity"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Creates public locator DATA inside the same original authenticated pending
// C1 call. Actual ProduceOriginalC1EvidenceCA still performs its own original
// CA/TLS/native Service check and produces evidence on the SAME protected channel.
// No caller descriptor, target IP, native success flag or new CA is accepted.
func (i *Installer) prepareOriginalC1EvidenceCAInputs(ctx context.Context, password []byte, enrollment EnrollmentPin, request RequestFiles, sixPin BootstrapSourceFilePin, directory string) (BootstrapSourceFilePin, error) {
	var zero BootstrapSourceFilePin
	if i == nil || ctx == nil || ctx.Err() != nil {
		return zero, ErrInstall
	}
	op, e := i.authenticate(ctx, password)
	if e != nil || op.authority(ctx, enrollment) != nil || privateDirectory(directory) != nil {
		return zero, ErrInstall
	}
	before, now, e := originalRuntimeAuthoritySnapshot(ctx, op, enrollment)
	if e != nil || before.cas != (HeadCAS{}) {
		return zero, ErrInstall
	}
	r, e := readRequest(i, request)
	if e != nil {
		return zero, ErrInstall
	}
	defer r.observer.Close()
	raw, e := readBootstrapSourcePin(sixPin, 262144)
	var six SixReferenceDefinition
	if e != nil || decodeExact(raw, &six) != nil || validateSixReference(six) != nil || six.S3.Installation != i.plan.Target.InstallationID || six.S3.Namespace != i.plan.Target.Namespace || six.S3.NamespaceUID != i.plan.Target.NamespaceUID {
		return zero, ErrInstall
	}
	var selected sec.BootstrapSecretRef
	count := 0
	for _, ref := range r.config.References() {
		if ref.Purpose == "evidence_ca" {
			selected = ref
			count++
		}
	}
	if count != 1 {
		return zero, ErrInstall
	}
	provider := six.S3.Provider
	svc, e := i.kube.CoreV1().Services(i.plan.Target.Namespace).Get(ctx, provider.Service.Name, metav1.GetOptions{})
	if e != nil || svc == nil {
		return zero, ErrInstall
	}
	ip, parseErr := netip.ParseAddr(svc.Spec.ClusterIP)
	u, urlErr := url.Parse(provider.Endpoint)
	if e != nil || parseErr != nil || urlErr != nil || string(svc.UID) != provider.Service.UID || svc.DeletionTimestamp != nil || len(svc.Spec.Selector) == 0 || string(svc.Spec.Type) == "ExternalName" || !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || u.Scheme != "https" || (u.Hostname() != svc.Name+"."+i.plan.Target.Namespace+".svc" && u.Hostname() != svc.Name+"."+i.plan.Target.Namespace+".svc.cluster.local" && u.Hostname() != svc.Spec.ClusterIP) {
		return zero, ErrInstall
	}
	// Hash native provider/scope coordinates, never certificate or key bytes
	// as the selected reference identity. The original signed Config owns that.
	providerRaw, e := canonical(provider)
	if e != nil {
		return zero, ErrInstall
	}
	scopeRaw, e := canonical(struct{ Installation, NamespaceUID, ServiceUID, Purpose string }{i.plan.Target.InstallationID, i.plan.Target.NamespaceUID, provider.Service.UID, "evidence_ca"})
	if e != nil {
		return zero, ErrInstall
	}
	providerHash, scopeHash := hash(providerRaw), hash(scopeRaw)
	descriptor, e := canonical(map[string]string{"ref_kind": "ca_bundle", "purpose": "evidence_ca", "identity_hash": selected.IdentityHash, "identity_version": selected.Version, "provider_identity_hash": providerHash, "scope_hash": scopeHash, "description_redacted": "original enrolled evidence provider CA"})
	if e != nil {
		return zero, ErrInstall
	}
	inputDirectory := filepath.Join(directory, "original-native-ca-inputs")
	if os.Mkdir(inputDirectory, 0700) != nil {
		return zero, ErrInstall
	}
	until := minTime(op.until, minTime(r.end, six.Until))
	if now.Before(r.start) || !now.Before(until) {
		return zero, ErrInstall
	}
	wire := originalC1CAWire{InstallationID: i.plan.Target.InstallationID, ServerUUID: i.plan.Target.ServerUUID, Database: i.plan.Target.Database, ConfigSHA256: r.config.SHA256(), Purpose: "evidence_ca", ProviderIdentityHash: providerHash, ScopeHash: scopeHash, DescriptorFile: filepath.Join(inputDirectory, "evidence-ca.reference.json"), DescriptorSHA256: hash(descriptor), CAFile: provider.CAFile, CASHA256: provider.CASHA256, Endpoint: provider.Endpoint, TargetIP: ip, NotBefore: r.start, ExpiresAt: until}
	bindingRaw, e := canonical(wire)
	if e != nil || writeNewFiles(inputDirectory, map[string][]byte{"evidence-ca.reference.json": descriptor, "evidence-ca.binding.json": bindingRaw}) != nil {
		return zero, ErrInstall
	}
	v, e := ca.New(ca.Binding(wire))
	if e != nil || v.InspectInputs(ctx, r.grant, r.config) != nil || r.recheck(i) != nil || op.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	current, _, e := originalRuntimeAuthoritySnapshot(ctx, op, enrollment)
	if e != nil || current.cas != before.cas {
		return zero, ErrInstall
	}
	return BootstrapSourceFilePin{File: filepath.Join(inputDirectory, "evidence-ca.binding.json"), SHA256: hash(bindingRaw)}, nil
}
