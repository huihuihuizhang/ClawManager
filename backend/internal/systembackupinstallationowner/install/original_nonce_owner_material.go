package install

import (
	"bytes"
	refs "clawreef/internal/systembackupbootstrapsecurity"
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

var ErrOriginalNonceMaterialUnconfirmed = errors.New("original nonce material native outcome unconfirmed; retain original intent and key, do not reissue")

const originalNonceMaterialDomain = "original-installation-nonce-file-material.v1\x00"
const originalNonceMountDomain = "original-installation-nonce-file-mount.v1\x00"
const originalNonceMountDirectory = "/run/system-backup/nonce-materials"

// Explicit FIRST original owner file-provider issuance, not an assertion that
// a caller-selected file belongs to an existing external-secret provider.
// Kubernetes immutable objects are custody/transport for this new controlled
// file version; logical identity comes from its original immutable owner ledger
// object, never key bytes or the Secret's payload digest.
type OriginalNonceMaterialOptions struct {
	OutputDirectory string
	Until           time.Time
}
type originalNonceMaterialIntent struct {
	Version, PlanSHA256                     string
	Enrollment                              EnrollmentPin
	Namespace, NamespaceUID, Secret, Ledger string
	Material                                BootstrapSourceFilePin
	NotBefore, Until                        time.Time
}
type OriginalNonceMaterial struct {
	Version, PlanSHA256                                                                string
	IntentSHA256                                                                       string
	Enrollment                                                                         EnrollmentPin
	Namespace, NamespaceUID                                                            string
	Secret, SecretUID, SecretResourceVersion, Ledger, LedgerUID, LedgerResourceVersion string
	Material, Descriptor                                                               BootstrapSourceFilePin
	Reference                                                                          sec.BootstrapSecretRef
	ProviderIdentityHash, ScopeHash                                                    string
	NotBefore, Until                                                                   time.Time
}
type signedOriginalNonceMaterial struct{ Record, Signature []byte }
type OriginalNonceMaterialReceipt struct {
	Version, State                               string
	Source, Descriptor, Material                 BootstrapSourceFilePin
	Reference                                    sec.BootstrapSecretRef
	Secret, Ledger, MountDirectory, RelativePath string
	PodVolume                                    corev1.Volume
	ContainerMount                               corev1.VolumeMount
}
type OriginalNonceMountBinding struct {
	Version, PlanSHA256                                                                            string
	Enrollment                                                                                     EnrollmentPin
	Source                                                                                         BootstrapSourceFilePin
	Request                                                                                        RequestFiles
	ControllerDeployment, ControllerPod, ControllerPodUID, ControllerSpecSHA256, Container, Volume string
	ControllerDeploymentUID, ServiceAccountName, ServiceAccountUID, ContainerID, ImageID           string
	NonceDirectory                                                                                 string
	NotBefore, Until                                                                               time.Time
}

func (i *Installer) PrepareOriginalNonceMaterial(ctx context.Context, password []byte, enrollment EnrollmentPin, o OriginalNonceMaterialOptions, issuerPrivate []byte) (OriginalNonceMaterialReceipt, error) {
	var zero OriginalNonceMaterialReceipt
	op, err := i.authenticate(ctx, password)
	if err != nil || op.authority(ctx, enrollment) != nil || privateDirectory(o.OutputDirectory) != nil {
		return zero, ErrInstall
	}
	now, err := i.originalNonceFirstIssueGuard(ctx, op, enrollment)
	if err != nil || !now.Before(o.Until) || o.Until.Sub(now) > 24*time.Hour {
		return zero, ErrInstall
	}
	ns, err := i.kube.CoreV1().Namespaces().Get(ctx, i.plan.Target.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != i.plan.Target.NamespaceUID || ns.DeletionTimestamp != nil {
		return zero, ErrInstall
	}
	// Public unique operation names do not reuse any prior version's storage.
	random := make([]byte, 12)
	if _, err = rand.Read(random); err != nil {
		return zero, err
	}
	suffix := hex.EncodeToString(random)
	name := "sbk-nonce-" + suffix
	ledgerName := name + "-owner"
	material := make([]byte, 32)
	if _, err = rand.Read(material); err != nil {
		return zero, err
	}
	defer clear(material)
	materialPin := BootstrapSourceFilePin{File: filepath.Join(o.OutputDirectory, "nonce.raw"), SHA256: hash(material)}
	intent := originalNonceMaterialIntent{Version: "original-nonce-file-first-issue-intent.v1", PlanSHA256: i.planHash, Enrollment: enrollment, Namespace: ns.Name, NamespaceUID: string(ns.UID), Secret: name, Ledger: ledgerName, Material: materialPin, NotBefore: now, Until: o.Until}
	raw, err := canonical(intent)
	if err != nil {
		return zero, ErrInstall
	}
	issuer, err := op.privateKey(issuerPrivate)
	if err != nil {
		return zero, err
	}
	defer clear(issuer)
	signature := ed25519.Sign(issuer, append([]byte(originalNonceMaterialDomain+"intent\x00"), raw...))
	intentHash := hash(raw)
	if writeNewFiles(o.OutputDirectory, map[string][]byte{"nonce.raw": material, "nonce.intent.json": raw, "nonce.intent.signature": signature}) != nil || syncOriginalNonceDirectory(o.OutputDirectory) != nil {
		return zero, ErrInstall
	}
	// Original intent/key are durable before ANY native creation. No upsert,
	// replacement nonce, role binding, task/strong-auth nonce DB row or config.
	immutable := true
	labels := map[string]string{"app.kubernetes.io/managed-by": "clawmanager-installation-owner", "backup.clawreef.io/purpose": "nonce-file"}
	annotations := map[string]string{"backup.clawreef.io/plan-sha256": i.planHash, "backup.clawreef.io/nonce-intent": intentHash}
	if _, err = i.originalNonceFirstIssueGuard(ctx, op, enrollment); err != nil {
		return zero, ErrOriginalNonceMaterialUnconfirmed
	}
	secret, err := i.kube.CoreV1().Secrets(ns.Name).Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns.Name, Labels: labels, Annotations: annotations}, Immutable: &immutable, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"nonce": material}}, metav1.CreateOptions{})
	if err != nil || secret.UID == "" {
		return zero, ErrOriginalNonceMaterialUnconfirmed
	}
	if recordOriginalNonceNative(o.OutputDirectory, "secret", intentHash, secret.Name, string(secret.UID), secret.ResourceVersion) != nil {
		return zero, ErrOriginalNonceMaterialUnconfirmed
	}
	if _, err = i.originalNonceFirstIssueGuard(ctx, op, enrollment); err != nil {
		return zero, ErrOriginalNonceMaterialUnconfirmed
	}
	ledger, err := i.kube.CoreV1().ConfigMaps(ns.Name).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: ledgerName, Namespace: ns.Name, Labels: labels, Annotations: annotations}, Immutable: &immutable, Data: map[string]string{"version": "1", "provider": "original-owner-nonce-file.v1", "secret": name, "secret_uid": string(secret.UID), "material_sha256": materialPin.SHA256, "intent_sha256": intentHash}}, metav1.CreateOptions{})
	if err != nil || ledger.UID == "" {
		return zero, ErrOriginalNonceMaterialUnconfirmed
	}
	return i.finishOriginalNonceMaterial(ctx, op, enrollment, intent, secret, ledger, issuer)
}

// Resume uses the SAME persisted issuer-signed intent, key and unique native
// object names. A lost create reply never authorizes a replacement issuance.
// A missing original object may be created only by this explicit resume call;
// an existing object's mismatched immutable data is never repaired or replaced.
func (i *Installer) ResumeOriginalNonceMaterial(ctx context.Context, password []byte, enrollment EnrollmentPin, directory string, issuerPrivate []byte) (OriginalNonceMaterialReceipt, error) {
	var zero OriginalNonceMaterialReceipt
	op, err := i.authenticate(ctx, password)
	if err != nil || op.authority(ctx, enrollment) != nil || privateDirectory(directory) != nil {
		return zero, ErrInstall
	}
	now, err := i.originalNonceFirstIssueGuard(ctx, op, enrollment)
	if err != nil {
		return zero, ErrInstall
	}
	// Repeated completed issuance only reads back its ORIGINAL object UIDs.
	// Missing/replaced custody after publication can never trigger recreation.
	sourcePath := filepath.Join(directory, "nonce.material.json")
	if _, err := os.Lstat(sourcePath); err == nil {
		sourceRaw, err := ReadPrivateFile(sourcePath, 262144)
		if err != nil {
			return zero, ErrInstall
		}
		pin := BootstrapSourceFilePin{File: sourcePath, SHA256: hash(sourceRaw)}
		if i.repairOriginalNonceDescriptor(ctx, enrollment, pin, directory) != nil {
			return zero, ErrOriginalNonceMaterialUnconfirmed
		}
		source, err := i.readOriginalNonceMaterial(ctx, enrollment, pin)
		if err != nil {
			return zero, ErrOriginalNonceMaterialUnconfirmed
		}
		return originalNonceMaterialReceipt(source, pin), nil
	} else if !os.IsNotExist(err) {
		return zero, ErrInstall
	}
	raw, err := ReadPrivateFile(filepath.Join(directory, "nonce.intent.json"), 262144)
	if err != nil {
		return zero, ErrInstall
	}
	signature, err := ReadPrivateFile(filepath.Join(directory, "nonce.intent.signature"), ed25519.SignatureSize)
	var intent originalNonceMaterialIntent
	if err != nil || !ed25519.Verify(i.public, append([]byte(originalNonceMaterialDomain+"intent\x00"), raw...), signature) || decodeExact(raw, &intent) != nil || intent.Version != "original-nonce-file-first-issue-intent.v1" || intent.PlanSHA256 != i.planHash || intent.Enrollment != enrollment || intent.Namespace != i.plan.Target.Namespace || intent.NamespaceUID != i.plan.Target.NamespaceUID || intent.Material.File != filepath.Join(directory, "nonce.raw") || !regexp.MustCompile(`^sbk-nonce-[0-9a-f]{24}$`).MatchString(intent.Secret) || intent.Ledger != intent.Secret+"-owner" || now.Before(intent.NotBefore) || !now.Before(intent.Until) || intent.Until.Sub(intent.NotBefore) > 24*time.Hour {
		return zero, ErrInstall
	}
	material, err := readBootstrapSourcePin(intent.Material, 32)
	defer clear(material)
	if err != nil || len(material) != 32 || bytes.Equal(material, make([]byte, 32)) {
		return zero, ErrInstall
	}
	ns, err := i.kube.CoreV1().Namespaces().Get(ctx, intent.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != intent.NamespaceUID || ns.DeletionTimestamp != nil {
		return zero, ErrInstall
	}
	issuer, err := op.privateKey(issuerPrivate)
	if err != nil {
		return zero, err
	}
	defer clear(issuer)
	intentHash := hash(raw)
	immutable := true
	labels := map[string]string{"app.kubernetes.io/managed-by": "clawmanager-installation-owner", "backup.clawreef.io/purpose": "nonce-file"}
	annotations := map[string]string{"backup.clawreef.io/plan-sha256": i.planHash, "backup.clawreef.io/nonce-intent": intentHash}
	secret, err := i.kube.CoreV1().Secrets(intent.Namespace).Get(ctx, intent.Secret, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if _, prior := os.Lstat(filepath.Join(directory, "nonce.secret-observed.json")); !os.IsNotExist(prior) {
			return zero, ErrOriginalNonceMaterialUnconfirmed
		}
		if _, err = i.originalNonceFirstIssueGuard(ctx, op, enrollment); err != nil {
			return zero, ErrOriginalNonceMaterialUnconfirmed
		}
		secret, err = i.kube.CoreV1().Secrets(intent.Namespace).Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: intent.Secret, Namespace: intent.Namespace, Labels: labels, Annotations: annotations}, Immutable: &immutable, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"nonce": material}}, metav1.CreateOptions{})
		if err != nil {
			secret, err = i.kube.CoreV1().Secrets(intent.Namespace).Get(ctx, intent.Secret, metav1.GetOptions{})
		}
	}
	if err != nil || secret == nil || secret.UID == "" || secret.Annotations["backup.clawreef.io/nonce-intent"] != intentHash || secret.Annotations["backup.clawreef.io/plan-sha256"] != i.planHash || secret.Immutable == nil || !*secret.Immutable || secret.DeletionTimestamp != nil || len(secret.Data) != 1 || !bytes.Equal(secret.Data["nonce"], material) {
		return zero, ErrOriginalNonceMaterialUnconfirmed
	}
	if recordOriginalNonceNative(directory, "secret", intentHash, secret.Name, string(secret.UID), secret.ResourceVersion) != nil {
		return zero, ErrOriginalNonceMaterialUnconfirmed
	}
	ledger, err := i.kube.CoreV1().ConfigMaps(intent.Namespace).Get(ctx, intent.Ledger, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if _, prior := os.Lstat(filepath.Join(directory, "nonce.ledger-observed.json")); !os.IsNotExist(prior) {
			return zero, ErrOriginalNonceMaterialUnconfirmed
		}
		if _, err = i.originalNonceFirstIssueGuard(ctx, op, enrollment); err != nil {
			return zero, ErrOriginalNonceMaterialUnconfirmed
		}
		ledger, err = i.kube.CoreV1().ConfigMaps(intent.Namespace).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: intent.Ledger, Namespace: intent.Namespace, Labels: labels, Annotations: annotations}, Immutable: &immutable, Data: map[string]string{"version": "1", "provider": "original-owner-nonce-file.v1", "secret": intent.Secret, "secret_uid": string(secret.UID), "material_sha256": intent.Material.SHA256, "intent_sha256": intentHash}}, metav1.CreateOptions{})
		if err != nil {
			ledger, err = i.kube.CoreV1().ConfigMaps(intent.Namespace).Get(ctx, intent.Ledger, metav1.GetOptions{})
		}
	}
	if err != nil {
		return zero, ErrOriginalNonceMaterialUnconfirmed
	}
	return i.finishOriginalNonceMaterial(ctx, op, enrollment, intent, secret, ledger, issuer)
}

func syncOriginalNonceDirectory(directory string) error {
	f, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// Every first creation/resume/final signing uses the same actual head0 and
// config-absence check. This never changes the original intent time or expiry.
func (i *Installer) originalNonceFirstIssueGuard(ctx context.Context, op *authenticatedOperator, enrollment EnrollmentPin) (time.Time, error) {
	current, now, err := originalRuntimeAuthoritySnapshot(ctx, op, enrollment)
	if err != nil || current.cas != (HeadCAS{}) {
		return time.Time{}, ErrInstall
	}
	var installed int64
	if i.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_v2_configs WHERE origin_installation_id=?", i.plan.Target.InstallationID).Scan(&installed) != nil || installed != 0 {
		return time.Time{}, ErrInstall
	}
	return now, nil
}

func originalNonceDescriptor(ref sec.BootstrapSecretRef, provider, scope string) ([]byte, error) {
	return canonical(map[string]string{"ref_kind": "external_secret", "purpose": "strong_auth_nonce_hmac", "identity_hash": ref.IdentityHash, "identity_version": ref.Version, "provider_identity_hash": provider, "scope_hash": scope, "description_redacted": "Original installation-owner controlled nonce file first version", "read_mode": "exact_version_only"})
}

// Repair only the exact descriptor bytes already pinned by a valid ORIGINAL
// issuer-signed source. No source/key/ref/signature/time is regenerated. This
// also resolves an old partial local-write order without recreating custody.
func (i *Installer) repairOriginalNonceDescriptor(ctx context.Context, enrollment EnrollmentPin, pin BootstrapSourceFilePin, directory string) error {
	raw, err := readBootstrapSourcePin(pin, 262144)
	var signed signedOriginalNonceMaterial
	var source OriginalNonceMaterial
	if err != nil || ctx.Err() != nil || decodeExact(raw, &signed) != nil || !ed25519.Verify(i.public, append([]byte(originalNonceMaterialDomain), signed.Record...), signed.Signature) || decodeExact(signed.Record, &source) != nil || source.Version != "original-owner-nonce-file-material.v1" || source.PlanSHA256 != i.planHash || source.Enrollment != enrollment || source.Descriptor.File != filepath.Join(directory, "nonce.descriptor.json") || source.Material.File != filepath.Join(directory, "nonce.raw") || time.Now().Before(source.NotBefore) || !time.Now().Before(source.Until) {
		return ErrInstall
	}
	descriptor, err := originalNonceDescriptor(source.Reference, source.ProviderIdentityHash, source.ScopeHash)
	if err != nil || hash(descriptor) != source.Descriptor.SHA256 {
		return ErrInstall
	}
	return writeOriginalNonceOutput(directory, map[string][]byte{"nonce.descriptor.json": descriptor})
}

func recordOriginalNonceNative(directory, kind, intentHash, name, uid, resourceVersion string) error {
	if (kind != "secret" && kind != "ledger") || uid == "" || resourceVersion == "" {
		return ErrInstall
	}
	raw, err := canonical(struct{ Version, IntentSHA256, Name, UID, ResourceVersion string }{"original-nonce-native-observed.v1", intentHash, name, uid, resourceVersion})
	if err != nil {
		return ErrInstall
	}
	return writeOriginalNonceOutput(directory, map[string][]byte{"nonce." + kind + "-observed.json": raw})
}

// Ed25519 output is deterministic for this exact original record. A resume
// compares existing create-only files; it never overwrites an earlier output.
func writeOriginalNonceOutput(directory string, files map[string][]byte) error {
	if privateDirectory(directory) != nil {
		return ErrInstall
	}
	for name, raw := range files {
		p := filepath.Join(directory, name)
		if _, err := os.Lstat(p); err == nil {
			existing, err := ReadPrivateFile(p, int64(len(raw)))
			if err != nil || !bytes.Equal(existing, raw) {
				return ErrInstall
			}
		} else if !os.IsNotExist(err) || writeNewFiles(directory, map[string][]byte{name: raw}) != nil {
			return ErrInstall
		}
	}
	return syncOriginalNonceDirectory(directory)
}

func (i *Installer) finishOriginalNonceMaterial(ctx context.Context, op *authenticatedOperator, enrollment EnrollmentPin, intent originalNonceMaterialIntent, secret *corev1.Secret, ledger *corev1.ConfigMap, issuer ed25519.PrivateKey) (OriginalNonceMaterialReceipt, error) {
	var zero OriginalNonceMaterialReceipt
	intentRaw, err := canonical(intent)
	intentHash := hash(intentRaw)
	if err != nil || op.authority(ctx, enrollment) != nil || secret == nil || ledger == nil || secret.Name != intent.Secret || secret.Namespace != intent.Namespace || ledger.Name != intent.Ledger || ledger.Namespace != intent.Namespace || secret.Type != corev1.SecretTypeOpaque || secret.Immutable == nil || !*secret.Immutable || ledger.Immutable == nil || !*ledger.Immutable || secret.UID == "" || ledger.UID == "" || secret.ResourceVersion == "" || ledger.ResourceVersion == "" || secret.DeletionTimestamp != nil || ledger.DeletionTimestamp != nil || len(secret.Data) != 1 || len(secret.Data["nonce"]) != 32 || hash(secret.Data["nonce"]) != intent.Material.SHA256 || len(ledger.Data) != 6 || ledger.Data["version"] != "1" || ledger.Data["provider"] != "original-owner-nonce-file.v1" || ledger.Data["secret"] != intent.Secret || ledger.Data["secret_uid"] != string(secret.UID) || ledger.Data["material_sha256"] != intent.Material.SHA256 || ledger.Data["intent_sha256"] != intentHash || secret.Annotations["backup.clawreef.io/plan-sha256"] != i.planHash || ledger.Annotations["backup.clawreef.io/plan-sha256"] != i.planHash || secret.Annotations["backup.clawreef.io/nonce-intent"] != intentHash || ledger.Annotations["backup.clawreef.io/nonce-intent"] != intentHash {
		return zero, ErrOriginalNonceMaterialUnconfirmed
	}
	_, err = i.originalNonceFirstIssueGuard(ctx, op, enrollment)
	if err != nil {
		return zero, ErrOriginalNonceMaterialUnconfirmed
	}
	if recordOriginalNonceNative(filepath.Dir(intent.Material.File), "ledger", intentHash, ledger.Name, string(ledger.UID), ledger.ResourceVersion) != nil {
		return zero, ErrOriginalNonceMaterialUnconfirmed
	}
	ref, provider, scope := i.originalNonceReference(intent.NamespaceUID, string(ledger.UID))
	descriptor, err := originalNonceDescriptor(ref, provider, scope)
	if err != nil {
		return zero, ErrInstall
	}
	descriptorPin := BootstrapSourceFilePin{File: filepath.Join(filepath.Dir(intent.Material.File), "nonce.descriptor.json"), SHA256: hash(descriptor)}
	record := OriginalNonceMaterial{Version: "original-owner-nonce-file-material.v1", PlanSHA256: i.planHash, IntentSHA256: intentHash, Enrollment: enrollment, Namespace: intent.Namespace, NamespaceUID: intent.NamespaceUID, Secret: secret.Name, SecretUID: string(secret.UID), SecretResourceVersion: secret.ResourceVersion, Ledger: ledger.Name, LedgerUID: string(ledger.UID), LedgerResourceVersion: ledger.ResourceVersion, Material: intent.Material, Descriptor: descriptorPin, Reference: ref, ProviderIdentityHash: provider, ScopeHash: scope, NotBefore: intent.NotBefore, Until: intent.Until}
	raw, err := canonical(record)
	if err != nil {
		return zero, ErrInstall
	}
	signed, err := canonical(signedOriginalNonceMaterial{raw, ed25519.Sign(issuer, append([]byte(originalNonceMaterialDomain), raw...))})
	if err != nil {
		return zero, ErrInstall
	}
	if _, err = i.originalNonceFirstIssueGuard(ctx, op, enrollment); err != nil || !time.Now().Before(record.Until) {
		return zero, ErrOriginalNonceMaterialUnconfirmed
	}
	// Descriptor is durable BEFORE the signed source completion marker exists.
	if writeOriginalNonceOutput(filepath.Dir(intent.Material.File), map[string][]byte{"nonce.descriptor.json": descriptor}) != nil || writeOriginalNonceOutput(filepath.Dir(intent.Material.File), map[string][]byte{"nonce.material.json": signed}) != nil {
		return zero, ErrOriginalNonceMaterialUnconfirmed
	}
	// Independent native reread precedes any successful material receipt.
	pin := BootstrapSourceFilePin{File: filepath.Join(filepath.Dir(intent.Material.File), "nonce.material.json"), SHA256: hash(signed)}
	if _, err = i.readOriginalNonceMaterial(ctx, enrollment, pin); err != nil {
		return zero, ErrOriginalNonceMaterialUnconfirmed
	}
	return originalNonceMaterialReceipt(record, pin), nil
}

func originalNonceMaterialReceipt(record OriginalNonceMaterial, pin BootstrapSourceFilePin) OriginalNonceMaterialReceipt {
	mode := int32(0400)
	volume := corev1.Volume{Name: "original-owner-nonce-file", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: record.Secret, DefaultMode: &mode, Items: []corev1.KeyToPath{{Key: "nonce", Path: record.Reference.IdentityHash + "/1"}}}}}
	mount := corev1.VolumeMount{Name: volume.Name, MountPath: originalNonceMountDirectory, ReadOnly: true}
	return OriginalNonceMaterialReceipt{Version: "original-nonce-file-material-result.v1", State: "first-version-issued-native-readback-verified-not-mounted", Source: pin, Descriptor: record.Descriptor, Material: record.Material, Reference: record.Reference, Secret: record.Secret, Ledger: record.Ledger, MountDirectory: originalNonceMountDirectory, RelativePath: record.Reference.IdentityHash + "/1", PodVolume: volume, ContainerMount: mount}
}

func (i *Installer) originalNonceReference(namespaceUID, ledgerUID string) (sec.BootstrapSecretRef, string, string) {
	provider := hash(c1wire(struct{ Version, Installation, Cluster, Namespace, Issuer string }{"original-owner-nonce-file-provider.v1", i.plan.Target.InstallationID, i.plan.Target.ClusterID, namespaceUID, i.plan.IssuerPublicKeySHA256}))
	scope := hash(c1wire(struct{ Version, Installation, Namespace, Object, Purpose string }{"original-owner-nonce-file-scope.v1", i.plan.Target.InstallationID, namespaceUID, ledgerUID, "strong_auth_nonce_hmac"}))
	identity := hash(c1wire(struct{ Version, Provider, Scope, Object string }{"original-owner-nonce-file-identity.v1", provider, scope, ledgerUID}))
	return sec.BootstrapSecretRef{Purpose: "nonce_hmac", IdentityHash: identity, Version: "1"}, provider, scope
}
func (i *Installer) readOriginalNonceMaterial(ctx context.Context, enrollment EnrollmentPin, pin BootstrapSourceFilePin) (OriginalNonceMaterial, error) {
	var zero OriginalNonceMaterial
	raw, err := readBootstrapSourcePin(pin, 262144)
	var signed signedOriginalNonceMaterial
	var r OriginalNonceMaterial
	if err != nil || decodeExact(raw, &signed) != nil || !ed25519.Verify(i.public, append([]byte(originalNonceMaterialDomain), signed.Record...), signed.Signature) || decodeExact(signed.Record, &r) != nil || r.Version != "original-owner-nonce-file-material.v1" || r.PlanSHA256 != i.planHash || r.Enrollment != enrollment || r.Namespace != i.plan.Target.Namespace || r.NamespaceUID != i.plan.Target.NamespaceUID || time.Now().Before(r.NotBefore) || !time.Now().Before(r.Until) {
		return zero, ErrInstall
	}
	material, err := readBootstrapSourcePin(r.Material, 32)
	defer clear(material)
	if err != nil || len(material) != 32 {
		return zero, ErrInstall
	}
	descriptor, err := readBootstrapSourcePin(r.Descriptor, 16384)
	if err != nil {
		return zero, ErrInstall
	}
	expectedRef, provider, scope := i.originalNonceReference(r.NamespaceUID, r.LedgerUID)
	decoded, err := refs.DecodeSecurityReference(descriptor, r.Descriptor.SHA256)
	if err != nil || r.Reference != expectedRef || r.ProviderIdentityHash != provider || r.ScopeHash != scope || decoded.Kind() != "external_secret" || decoded.Purpose() != "strong_auth_nonce_hmac" || decoded.IdentityHash() != expectedRef.IdentityHash || decoded.Version() != expectedRef.Version || decoded.ProviderIdentity() != provider || decoded.ScopeHash() != scope {
		return zero, ErrInstall
	}
	ns, err := i.kube.CoreV1().Namespaces().Get(ctx, r.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != r.NamespaceUID || ns.DeletionTimestamp != nil {
		return zero, ErrInstall
	}
	secret, err := i.kube.CoreV1().Secrets(r.Namespace).Get(ctx, r.Secret, metav1.GetOptions{})
	if err != nil || string(secret.UID) != r.SecretUID || secret.ResourceVersion != r.SecretResourceVersion || secret.Type != corev1.SecretTypeOpaque || secret.DeletionTimestamp != nil || secret.Immutable == nil || !*secret.Immutable || len(secret.Data) != 1 || !bytes.Equal(secret.Data["nonce"], material) || secret.Annotations["backup.clawreef.io/plan-sha256"] != i.planHash || secret.Annotations["backup.clawreef.io/nonce-intent"] != r.IntentSHA256 {
		return zero, ErrInstall
	}
	ledger, err := i.kube.CoreV1().ConfigMaps(r.Namespace).Get(ctx, r.Ledger, metav1.GetOptions{})
	if err != nil || string(ledger.UID) != r.LedgerUID || ledger.ResourceVersion != r.LedgerResourceVersion || ledger.DeletionTimestamp != nil || ledger.Immutable == nil || !*ledger.Immutable || len(ledger.Data) != 6 || ledger.Data["version"] != "1" || ledger.Data["provider"] != "original-owner-nonce-file.v1" || ledger.Data["secret"] != r.Secret || ledger.Data["secret_uid"] != r.SecretUID || ledger.Data["material_sha256"] != r.Material.SHA256 || ledger.Data["intent_sha256"] != r.IntentSHA256 || ledger.Annotations["backup.clawreef.io/plan-sha256"] != i.planHash || ledger.Annotations["backup.clawreef.io/nonce-intent"] != r.IntentSHA256 {
		return zero, ErrInstall
	}
	return r, nil
}
