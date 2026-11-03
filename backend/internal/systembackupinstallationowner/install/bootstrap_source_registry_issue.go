package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"

	owner "clawreef/internal/systembackupinstallationowner"
	pd "clawreef/internal/systembackupproducer"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func readBootstrapSourcePin(pin BootstrapSourceFilePin, limit int64) ([]byte, error) {
	if !bootstrapSourcePinValid(pin) {
		return nil, ErrInstall
	}
	var raw []byte
	var err error
	// The exact 8 MiB selector is used by V2's signed Materials pin only.
	// Reuse the existing bounded source reader; do not widen ReadPrivateFile
	// or permit arbitrary larger plan/key/DSN bounds through this helper.
	if limit == 8<<20 {
		raw, err = ReadSourceMaterialFile(pin.File)
	} else {
		raw, err = ReadPrivateFile(pin.File, limit)
	}
	if err != nil || hash(raw) != pin.SHA256 {
		clear(raw)
		return nil, ErrInstall
	}
	return raw, nil
}

func bootstrapSourceFiles(d BootstrapSourceRegistryDefinition) []BootstrapSourceFilePin {
	pins := []BootstrapSourceFilePin{d.MetadataGrant, d.MetadataIssuerPublic, d.Deployment, d.Materials, d.ExecutionProfile, d.PartsRegistry, d.SourceWritersRegistry}
	for _, c := range d.Connections {
		pins = append(pins, c.CA, c.Credential)
	}
	if d.RuntimeAgent != nil {
		pins = append(pins, d.RuntimeAgent.CA, d.RuntimeAgent.Credential)
	}
	return pins
}

func checkBootstrapSourceFiles(d BootstrapSourceRegistryDefinition) error {
	for _, pin := range bootstrapSourceFiles(d) {
		raw, err := readBootstrapSourcePin(pin, 262144)
		clear(raw)
		if err != nil {
			return ErrInstall
		}
	}
	return nil
}

// This observes existing controller objects only, outside any owner SQL lock.
// It neither creates a Job/task nor issues a readiness verdict.
func observeBootstrapSourceController(ctx context.Context, kube kubernetes.Interface, target owner.Target, b BootstrapSourceController) error {
	if consumerNil(ctx) || ctx.Err() != nil || nilClient(kube) || b.Namespace != target.Namespace || b.NamespaceUID != target.NamespaceUID {
		return ErrInstall
	}
	for _, pin := range [][2]string{{"kube-system", target.ClusterID}, {b.Namespace, b.NamespaceUID}} {
		ns, err := kube.CoreV1().Namespaces().Get(ctx, pin[0], metav1.GetOptions{})
		if err != nil || string(ns.UID) != pin[1] || ns.DeletionTimestamp != nil {
			return ErrInstall
		}
	}
	pod, err := kube.CoreV1().Pods(b.Namespace).Get(ctx, b.Pod, metav1.GetOptions{})
	if err != nil || string(pod.UID) != b.PodUID || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || pod.Spec.ServiceAccountName != b.ServiceAccount {
		return ErrInstall
	}
	parent := metav1.GetControllerOf(pod)
	if parent == nil || parent.Kind != "ReplicaSet" || parent.Name != b.ReplicaSet || string(parent.UID) != b.ReplicaSetUID {
		return ErrInstall
	}
	rs, err := kube.AppsV1().ReplicaSets(b.Namespace).Get(ctx, b.ReplicaSet, metav1.GetOptions{})
	if err != nil || string(rs.UID) != b.ReplicaSetUID || rs.DeletionTimestamp != nil {
		return ErrInstall
	}
	parent = metav1.GetControllerOf(rs)
	if parent == nil || parent.Kind != "Deployment" || parent.Name != b.Deployment || string(parent.UID) != b.DeploymentUID {
		return ErrInstall
	}
	dep, err := kube.AppsV1().Deployments(b.Namespace).Get(ctx, b.Deployment, metav1.GetOptions{})
	if err != nil || string(dep.UID) != b.DeploymentUID || dep.DeletionTimestamp != nil || dep.Spec.Template.Spec.ServiceAccountName != b.ServiceAccount {
		return ErrInstall
	}
	sa, err := kube.CoreV1().ServiceAccounts(b.Namespace).Get(ctx, b.ServiceAccount, metav1.GetOptions{})
	if err != nil || string(sa.UID) != b.ServiceAccountUID || sa.DeletionTimestamp != nil {
		return ErrInstall
	}
	return ctx.Err()
}

// IssueBootstrapSourceRegistries is an explicit original issuer action under a
// DISTINCT signature domain. Old controller read delegation alone cannot invoke
// this action or become permission for either registry. It authenticates the
// real password, enrollment and currently committed capture record; observes
// the selected existing source controller; and selects exact original bytes.
// It does NOT certify those bytes against physical source completeness.
func (i *Installer) IssueBootstrapSourceRegistries(ctx context.Context, password []byte, enrollment EnrollmentPin, bundleRaw []byte, bundleSHA, definitionFile, definitionSHA string, selection pd.BootstrapConsumptionRequest, files RequestFiles, issuerPrivate []byte) (SignedBootstrapSourceRegistries, error) {
	var zero SignedBootstrapSourceRegistries
	bundleRaw = bytes.Clone(bundleRaw)
	selectionRaw, err := json.Marshal(selection)
	var frozen pd.BootstrapConsumptionRequest
	if err != nil || len(selectionRaw) > 262144 || json.Unmarshal(selectionRaw, &frozen) != nil {
		return zero, ErrInstall
	}
	selection = frozen
	s, err := i.authenticate(ctx, password)
	if err != nil || s.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	bundle, capture, _, err := s.decodeBundle(bundleRaw, bundleSHA, enrollment)
	if err != nil || bundle.SchemaVersion != AuthorityBundleVersion || !functionalSelectionMatches(capture, selection) {
		return zero, ErrInstall
	}
	raw, err := readBootstrapSourcePin(BootstrapSourceFilePin{definitionFile, definitionSHA}, 262144)
	var definition BootstrapSourceRegistryDefinition
	if err != nil || decodeExact(raw, &definition) != nil || validateBootstrapSourceDefinition(definition) != nil {
		return zero, ErrInstall
	}
	request, err := readConsumerCaptureRequest(i, files)
	if err != nil {
		return zero, ErrInstall
	}
	defer request.observer.Close()
	if !request.matchesDraft(capture) {
		return zero, ErrInstall
	}
	parts, writers := bootstrapSourceRegistryPins(request.config)
	metadataRaw, err := readBootstrapSourcePin(definition.MetadataGrant, 65536)
	if err != nil {
		return zero, ErrInstall
	}
	public, err := readBootstrapSourcePin(definition.MetadataIssuerPublic, ed25519.PublicKeySize)
	if err != nil || !bytes.Equal(public, i.public) {
		return zero, ErrInstall
	}
	metadata, metadataSHA, err := decodeBootstrapSourceMetadata(metadataRaw, public)
	if err != nil {
		return zero, ErrInstall
	}
	record := BootstrapSourceRegistryRecord{SchemaVersion: BootstrapSourceRegistryVersion, Profile: BootstrapSourceRegistryProfile, PlanSHA256: i.planHash, CaptureRecordSHA256: hash(bundle.Record), DefinitionSHA256: definitionSHA, Target: capture.Target, Actor: capture.Actor, Enrollment: enrollment, NotBefore: capture.NotBefore, Until: capture.Until, Selection: selection, Parts: parts, SourceWriters: writers, Source: definition, Metadata: metadata, MetadataRecordSHA256: metadataSHA, MetadataIssuerSHA256: hash(public)}
	if validateBootstrapSourceRecord(record) != nil || checkBootstrapSourceFiles(definition) != nil {
		return zero, ErrInstall
	}
	before, now, err := snapshot(ctx, s)
	if err != nil || !exactCommitted(before, bundle) || now.Before(record.NotBefore) || !now.Before(record.Until) {
		return zero, ErrInstall
	}
	if observeBootstrapSourceController(ctx, i.kube, record.Target, definition.Controller) != nil {
		return zero, ErrInstall
	}
	encoded, err := canonical(record)
	if err != nil || len(encoded) > 262144 {
		return zero, ErrInstall
	}
	key, err := s.privateKey(issuerPrivate)
	if err != nil {
		return zero, err
	}
	defer clear(key)
	signature := ed25519.Sign(key, append([]byte(BootstrapSourceRegistryDomain), encoded...))
	// Every original local source is reread, then native identity and current
	// admin/head/grant are confirmed again. No source/config rows are written.
	for _, pin := range []BootstrapSourceFilePin{{definitionFile, definitionSHA}, {files.ConfigFile, files.ConfigFileSHA256}, {files.GrantFile, files.GrantFileSHA256}, {files.ObserverFile, files.ObserverFileSHA256}} {
		actual, err := readBootstrapSourcePin(pin, 262144)
		clear(actual)
		if err != nil {
			return zero, ErrInstall
		}
	}
	if checkBootstrapSourceFiles(definition) != nil || observeBootstrapSourceController(ctx, i.kube, record.Target, definition.Controller) != nil || s.authority(ctx, enrollment) != nil {
		return zero, ErrInstall
	}
	after, now, err := snapshot(ctx, s)
	if err != nil || after.cas != before.cas || !exactCommitted(after, bundle) || now.Before(record.NotBefore) || !now.Before(record.Until) || !s.live(ctx) {
		return zero, ErrInstall
	}
	return SignedBootstrapSourceRegistries{Record: encoded, Signature: signature}, nil
}

// Inert create-only transport; it installs no consumer pin or terminal owner.
func SaveFrozenBootstrapSourceRegistries(directory string, signed SignedBootstrapSourceRegistries) error {
	var record BootstrapSourceRegistryRecord
	if len(signed.Record) == 0 || len(signed.Record) > 262144 || len(signed.Signature) != ed25519.SignatureSize || decodeExact(signed.Record, &record) != nil || validateBootstrapSourceRecord(record) != nil {
		return ErrInstall
	}
	return writeNewFiles(directory, map[string][]byte{"bootstrap-source-registries.record.json": bytes.Clone(signed.Record), "bootstrap-source-registries.signature": bytes.Clone(signed.Signature), "bootstrap-source-registries.sha256": []byte(hash(signed.Record))})
}
