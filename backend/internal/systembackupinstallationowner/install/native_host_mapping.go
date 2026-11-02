package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"sort"
	"time"

	evidence "clawreef/internal/systembackupevidence"
	owner "clawreef/internal/systembackupinstallationowner"
	pd "clawreef/internal/systembackupproducer"
)

const BootstrapNativeHostMappingVersion = "system-backup-original-native-host-mapping.v1"
const BootstrapNativeHostMappingDomain = BootstrapNativeHostMappingVersion + "\x00"

// Original independently selected source pins, never caller-reported observed
// work identity. The concrete D observer derives work identity from the actual
// mounted peer ConfigMap and the production SystemPeerAuthenticator encoding.
type BootstrapNativeHostBinding struct {
	WorkloadIdentitySHA256, ProducerIssuerIdentitySHA256 string
	Source                                               evidence.BootstrapOriginalHostInput
}

type BootstrapNativeHostMapping struct {
	SchemaVersion, OriginalMappingSHA256, PlanSHA256, SelectionSHA256 string
	Target                                                            owner.Target
	Actor                                                             owner.Actor
	Enrollment                                                        EnrollmentPin
	NotBefore, Until                                                  time.Time
	Bindings                                                          []BootstrapNativeHostBinding
}

type BootstrapNativeHostBundle struct {
	Original, NativeHosts SignedBootstrapOriginalMapping
}

// IssueBootstrapOriginalNativeMapping supplements, without changing, the
// frozen original-mapping protocol. No capture record/known Pod or caller hash
// substitutes for the actual native peer, image and read-only mount observer.
// The returned records remain inert transport; no consumer trust is installed.
func (i *Installer) IssueBootstrapOriginalNativeMapping(ctx context.Context, password []byte, enrollment EnrollmentPin, bundleRaw []byte, bundleSHA string, request pd.BootstrapConsumptionRequest, bindings []BootstrapOriginalOwnerBinding, evidenceSourceSHA, capacityFile string, hosts []BootstrapNativeHostBinding, issuerPrivate []byte) (BootstrapNativeHostBundle, error) {
	var zero BootstrapNativeHostBundle
	hosts = append([]BootstrapNativeHostBinding(nil), hosts...)
	bundleRaw = bytes.Clone(bundleRaw)
	issuerPrivate = bytes.Clone(issuerPrivate)
	defer clear(issuerPrivate)
	sort.Slice(hosts, func(a, b int) bool { return hosts[a].WorkloadIdentitySHA256 < hosts[b].WorkloadIdentitySHA256 })
	original, err := i.IssueBootstrapOriginalMapping(ctx, password, enrollment, bundleRaw, bundleSHA, request, bindings, evidenceSourceSHA, capacityFile, issuerPrivate)
	if err != nil {
		return zero, err
	}
	s, err := i.authenticate(ctx, password)
	if err != nil || s.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	b, record, _, err := s.decodeBundle(bundleRaw, bundleSHA, enrollment)
	if err != nil {
		return zero, ErrInstall
	}
	mapping, err := verifyBootstrapOriginalMapping(original.Record, original.Signature, i.public)
	if err != nil || mapping.CaptureRecordSHA256 != hash(b.Record) || mapping.PlanSHA256 != i.planHash || mapping.Target != record.Target || mapping.Actor != record.Actor || mapping.Enrollment != enrollment || validateNativeHostBindings(mapping, hosts) != nil {
		return zero, ErrInstall
	}
	before, now, err := snapshot(ctx, s)
	if err != nil || !exactCommitted(before, b) || now.Before(mapping.NotBefore) || !now.Before(mapping.Until) {
		return zero, ErrInstall
	}
	// snapshot released every original SQL lock. All native reads/signatures
	// occur outside SQL; the independent final current-source check follows.
	for n, binding := range hosts {
		if _, err := observeNativeMappedBootstrapHost(ctx, i.kube, mapping.Hosts[n], binding); err != nil {
			return zero, ErrInstall
		}
	}
	native := BootstrapNativeHostMapping{SchemaVersion: BootstrapNativeHostMappingVersion, OriginalMappingSHA256: hash(original.Record), PlanSHA256: mapping.PlanSHA256, SelectionSHA256: mapping.SelectionSHA256, Target: mapping.Target, Actor: mapping.Actor, Enrollment: enrollment, NotBefore: mapping.NotBefore, Until: mapping.Until, Bindings: hosts}
	raw, err := canonical(native)
	if err != nil || len(raw) > 262144 {
		return zero, ErrInstall
	}
	key, err := s.privateKey(issuerPrivate)
	if err != nil {
		return zero, err
	}
	defer clear(key)
	signature := ed25519.Sign(key, append([]byte(BootstrapNativeHostMappingDomain), raw...))
	if s.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	after, now, err := snapshot(ctx, s)
	if err != nil || after.cas != before.cas || !exactCommitted(after, b) || now.Before(native.NotBefore) || !now.Before(native.Until) || !s.live(ctx) {
		return zero, ErrInstall
	}
	return BootstrapNativeHostBundle{Original: original, NativeHosts: SignedBootstrapOriginalMapping{Record: raw, Signature: signature}}, nil
}

func validateNativeHostBindings(mapping BootstrapOriginalMapping, bindings []BootstrapNativeHostBinding) error {
	if len(bindings) == 0 || len(bindings) != len(mapping.Hosts) || len(bindings) > 20 {
		return ErrInstall
	}
	wantScope := pd.Scope{ServerUUID: pd.ServerUUID(mapping.Target.ServerUUID), Database: pd.Database(mapping.Target.Database), Installation: pd.Installation(mapping.Target.InstallationID)}
	for n, binding := range bindings {
		host, input := mapping.Hosts[n], binding.Source
		if !digestPattern.MatchString(binding.WorkloadIdentitySHA256) || binding.WorkloadIdentitySHA256 != host.WorkloadIdentitySHA256 || binding.ProducerIssuerIdentitySHA256 != mapping.ProducerIssuerIdentitySHA256 || !digestPattern.MatchString(binding.ProducerIssuerIdentitySHA256) || n > 0 && bindings[n-1].WorkloadIdentitySHA256 >= binding.WorkloadIdentitySHA256 || input.Scope != wantScope || input.ClusterUID != mapping.Target.ClusterID || input.Namespace != mapping.Target.Namespace || input.NamespaceUID != mapping.Target.NamespaceUID || input.Namespace != host.Namespace || input.NamespaceUID != host.NamespaceUID || input.Pod != host.Pod || input.PodUID != host.PodUID || input.ServiceAccount != host.ServiceAccount || input.ServiceAccountUID != host.ServiceAccountUID || !digestPattern.MatchString(input.PodSpecSHA256) || !digestPattern.MatchString(input.PeerSHA256) || input.ContainerImageID == "" {
			return ErrInstall
		}
	}
	return nil
}

func verifyNativeHostMapping(raw, signature []byte, public ed25519.PublicKey, original BootstrapOriginalMapping, originalSHA string) (BootstrapNativeHostMapping, error) {
	var mapping BootstrapNativeHostMapping
	if len(raw) == 0 || len(raw) > 262144 || len(signature) != ed25519.SignatureSize || len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, append([]byte(BootstrapNativeHostMappingDomain), raw...), signature) || decodeExact(raw, &mapping) != nil || mapping.SchemaVersion != BootstrapNativeHostMappingVersion || mapping.OriginalMappingSHA256 != originalSHA || mapping.PlanSHA256 != original.PlanSHA256 || mapping.SelectionSHA256 != original.SelectionSHA256 || mapping.Target != original.Target || mapping.Actor != original.Actor || mapping.Enrollment != original.Enrollment || !mapping.NotBefore.Equal(original.NotBefore) || !mapping.Until.Equal(original.Until) || validateNativeHostBindings(original, mapping.Bindings) != nil {
		return mapping, ErrInstall
	}
	return mapping, nil
}

// SaveFrozenBootstrapNativeHostBundle writes all six create-only transport
// files together. It cannot enroll a key or create original current authority.
func SaveFrozenBootstrapNativeHostBundle(directory string, bundle BootstrapNativeHostBundle) error {
	original, native := bundle.Original, bundle.NativeHosts
	var first BootstrapOriginalMapping
	var second BootstrapNativeHostMapping
	if len(original.Record) == 0 || len(original.Record) > 262144 || len(native.Record) == 0 || len(native.Record) > 262144 || len(original.Signature) != 64 || len(native.Signature) != 64 || decodeExact(original.Record, &first) != nil || decodeExact(native.Record, &second) != nil || first.SchemaVersion != BootstrapOriginalMappingVersion || second.SchemaVersion != BootstrapNativeHostMappingVersion || second.OriginalMappingSHA256 != hash(original.Record) {
		return ErrInstall
	}
	return writeNewFiles(directory, map[string][]byte{
		"bootstrap-original.record.json":     bytes.Clone(original.Record),
		"bootstrap-original.signature":       bytes.Clone(original.Signature),
		"bootstrap-original.sha256":          []byte(hash(original.Record)),
		"bootstrap-native-hosts.record.json": bytes.Clone(native.Record),
		"bootstrap-native-hosts.signature":   bytes.Clone(native.Signature),
		"bootstrap-native-hosts.sha256":      []byte(hash(native.Record)),
	})
}
