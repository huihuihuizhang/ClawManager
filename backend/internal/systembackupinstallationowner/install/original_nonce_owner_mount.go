package install

import (
	"bytes"
	nonce "clawreef/internal/systembackupnoncebootstrap"
	"context"
	"crypto/ed25519"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"path/filepath"
	"strings"
	"time"
)

type OriginalNonceMountOptions struct {
	Source                                                                  BootstrapSourceFilePin
	Request                                                                 RequestFiles
	ControllerDeployment, ControllerPod, Container, Volume, OutputDirectory string
}
type signedOriginalNonceMount struct{ Record, Signature []byte }
type OriginalNonceMountReceipt struct {
	Version, State         string
	Binding, OwnerMaterial BootstrapSourceFilePin
}

// Bind only after the real controlled material rollout. It cannot create a
// binding from a self-consistent arbitrary local32B file or an unhashed mount.
func (i *Installer) BindOriginalNonceMaterial(ctx context.Context, password []byte, enrollment EnrollmentPin, o OriginalNonceMountOptions, issuerPrivate []byte) (OriginalNonceMountReceipt, error) {
	var zero OriginalNonceMountReceipt
	op, err := i.authenticate(ctx, password)
	if err != nil || op.authority(ctx, enrollment) != nil || privateDirectory(o.OutputDirectory) != nil {
		return zero, ErrInstall
	}
	current, now, err := originalRuntimeAuthoritySnapshot(ctx, op, enrollment)
	if err != nil || current.cas != (HeadCAS{}) {
		return zero, ErrInstall
	}
	source, err := i.readOriginalNonceMaterial(ctx, enrollment, o.Source)
	if err != nil {
		return zero, err
	}
	request, err := readRequest(i, o.Request)
	if err != nil {
		return zero, err
	}
	defer request.observer.Close()
	matched := false
	for _, ref := range request.config.References() {
		if ref.Purpose == source.Reference.Purpose {
			if ref != source.Reference {
				return zero, ErrInstall
			}
			matched = true
		}
	}
	if !matched {
		return zero, ErrInstall
	}
	actor, err := i.originalPublicationActor(ctx, o.ControllerDeployment, o.ControllerPod)
	if err != nil {
		return zero, err
	}
	pod, err := i.kube.CoreV1().Pods(actor.Namespace).Get(ctx, actor.PodName, metav1.GetOptions{})
	if err != nil || string(pod.UID) != actor.PodUID {
		return zero, ErrInstall
	}
	record := OriginalNonceMountBinding{Version: "original-owner-nonce-file-mount.v1", PlanSHA256: i.planHash, Enrollment: enrollment, Source: o.Source, Request: o.Request, ControllerDeployment: o.ControllerDeployment, ControllerPod: actor.PodName, ControllerPodUID: actor.PodUID, Container: o.Container, Volume: o.Volume, NonceDirectory: originalNonceMountDirectory, NotBefore: now, Until: source.Until}
	dep, err := i.kube.AppsV1().Deployments(actor.Namespace).Get(ctx, o.ControllerDeployment, metav1.GetOptions{})
	if err != nil || dep.UID == "" || dep.DeletionTimestamp != nil {
		return zero, ErrInstall
	}
	record.ControllerDeploymentUID = string(dep.UID)
	record.ServiceAccountName, record.ServiceAccountUID = actor.ServiceAccountName, actor.ServiceAccountUID
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == o.Container {
			if record.ContainerID != "" || status.State.Running == nil || status.ContainerID == "" || status.ImageID == "" {
				return zero, ErrInstall
			}
			record.ContainerID, record.ImageID = status.ContainerID, status.ImageID
		}
	}
	spec, err := canonical(pod.Spec)
	if err != nil {
		return zero, ErrInstall
	}
	record.ControllerSpecSHA256 = hash(spec)
	if verifyOriginalNonceMountPod(pod, source, record) != nil {
		return zero, ErrInstall
	}
	issuer, err := op.privateKey(issuerPrivate)
	if err != nil {
		return zero, err
	}
	defer clear(issuer)
	raw, err := canonical(record)
	if err != nil {
		return zero, ErrInstall
	}
	signed, err := canonical(signedOriginalNonceMount{raw, ed25519.Sign(issuer, append([]byte(originalNonceMountDomain), raw...))})
	if err != nil {
		return zero, ErrInstall
	}
	ownerPin := BootstrapSourceFilePin{File: filepath.Join(o.OutputDirectory, "nonce.mount-owner.json"), SHA256: hash(signed)}
	// Old nonce.Key wire is comparison DATA; only the separately signed actual
	// original material+mount source below authenticates its provenance.
	type keyWire nonce.Key
	binding := struct {
		OwnerMaterial                                      BootstrapSourceFilePin
		InstallationID, ServerUUID, Database, ConfigSHA256 string
		NotBefore, ExpiresAt                               time.Time
		Keys                                               []keyWire
	}{ownerPin, i.plan.Target.InstallationID, i.plan.Target.ServerUUID, i.plan.Target.Database, request.config.SHA256(), now, source.Until, []keyWire{keyWire(nonce.Key{IdentityHash: source.Reference.IdentityHash, Version: source.Reference.Version, ProviderIdentityHash: source.ProviderIdentityHash, ScopeHash: source.ScopeHash, DescriptorFile: source.Descriptor.File, DescriptorSHA256: source.Descriptor.SHA256, MaterialFile: source.Material.File, MaterialSHA256: source.Material.SHA256, ProtectedUntil: source.Until})}}
	bindingRaw, err := canonical(binding)
	if err != nil {
		return zero, ErrInstall
	}
	if op.authority(ctx, enrollment) != nil || request.recheck(i) != nil || writeNewFiles(o.OutputDirectory, map[string][]byte{"nonce.mount-owner.json": signed, "nonce.binding.json": bindingRaw}) != nil || syncOriginalNonceDirectory(o.OutputDirectory) != nil {
		return zero, ErrInstall
	}
	if _, _, err = i.readOriginalNonceMount(ctx, enrollment, ownerPin, o.Request, actor.PodName, actor.PodUID); err != nil {
		return zero, ErrInstall
	}
	return OriginalNonceMountReceipt{Version: "original-nonce-file-mount-result.v1", State: "original-signed-current-native-readonly-mount-verified", Binding: BootstrapSourceFilePin{File: filepath.Join(o.OutputDirectory, "nonce.binding.json"), SHA256: hash(bindingRaw)}, OwnerMaterial: ownerPin}, nil
}
func verifyOriginalNonceMountPod(pod *corev1.Pod, source OriginalNonceMaterial, r OriginalNonceMountBinding) error {
	if pod == nil || pod.DeletionTimestamp != nil || string(pod.UID) != r.ControllerPodUID || pod.Name != r.ControllerPod || pod.Namespace != source.Namespace || pod.Status.Phase != corev1.PodRunning || r.NonceDirectory != originalNonceMountDirectory || r.Volume == "" || r.Container == "" {
		return ErrInstall
	}
	running := false
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == r.Container {
			if running || status.State.Running == nil || status.ContainerID == "" || status.ImageID == "" || status.ContainerID != r.ContainerID || status.ImageID != r.ImageID {
				return ErrInstall
			}
			running = true
		}
	}
	if !running || pod.Spec.ServiceAccountName != r.ServiceAccountName || r.ServiceAccountUID == "" {
		return ErrInstall
	}
	raw, err := canonical(pod.Spec)
	if err != nil || hash(raw) != r.ControllerSpecSHA256 {
		return ErrInstall
	}
	foundVolume := false
	for _, volume := range pod.Spec.Volumes {
		if volume.Name == r.Volume {
			if foundVolume || volume.Secret == nil || volume.Secret.SecretName != source.Secret || volume.Secret.Optional != nil && *volume.Secret.Optional || len(volume.Secret.Items) != 1 || volume.Secret.Items[0].Key != "nonce" || volume.Secret.Items[0].Path != source.Reference.IdentityHash+"/"+source.Reference.Version {
				return ErrInstall
			}
			foundVolume = true
		}
	}
	mounted := false
	for _, container := range pod.Spec.Containers {
		if container.Name == r.Container {
			for _, mount := range container.VolumeMounts {
				// A different child mount must not shadow this original key.
				if mount.Name != r.Volume && (mount.MountPath == r.NonceDirectory || strings.HasPrefix(mount.MountPath, r.NonceDirectory+"/")) {
					return ErrInstall
				}
				if mount.Name == r.Volume {
					if mounted || !mount.ReadOnly || mount.MountPath != r.NonceDirectory || mount.SubPath != "" || mount.SubPathExpr != "" {
						return ErrInstall
					}
					mounted = true
				}
			}
		}
	}
	if !foundVolume || !mounted {
		return ErrInstall
	}
	return nil
}
func (i *Installer) readOriginalNonceMount(ctx context.Context, enrollment EnrollmentPin, pin BootstrapSourceFilePin, request RequestFiles, podName, podUID string) (OriginalNonceMaterial, OriginalNonceMountBinding, error) {
	var sourceZero OriginalNonceMaterial
	var zero OriginalNonceMountBinding
	raw, err := readBootstrapSourcePin(pin, 262144)
	var signed signedOriginalNonceMount
	var r OriginalNonceMountBinding
	if err != nil || decodeExact(raw, &signed) != nil || !ed25519.Verify(i.public, append([]byte(originalNonceMountDomain), signed.Record...), signed.Signature) || decodeExact(signed.Record, &r) != nil || r.Version != "original-owner-nonce-file-mount.v1" || r.PlanSHA256 != i.planHash || r.Enrollment != enrollment || r.Request != request || r.ControllerPod != podName || r.ControllerPodUID != podUID || time.Now().Before(r.NotBefore) || !time.Now().Before(r.Until) {
		return sourceZero, zero, ErrInstall
	}
	source, err := i.readOriginalNonceMaterial(ctx, enrollment, r.Source)
	if err != nil || r.Until.After(source.Until) {
		return sourceZero, zero, ErrInstall
	}
	actor, err := i.originalPublicationActor(ctx, r.ControllerDeployment, r.ControllerPod)
	if err != nil || actor.PodUID != r.ControllerPodUID || actor.ServiceAccountName != r.ServiceAccountName || actor.ServiceAccountUID != r.ServiceAccountUID {
		return sourceZero, zero, ErrInstall
	}
	dep, err := i.kube.AppsV1().Deployments(source.Namespace).Get(ctx, r.ControllerDeployment, metav1.GetOptions{})
	if err != nil || string(dep.UID) != r.ControllerDeploymentUID || dep.DeletionTimestamp != nil {
		return sourceZero, zero, ErrInstall
	}
	pod, err := i.kube.CoreV1().Pods(source.Namespace).Get(ctx, r.ControllerPod, metav1.GetOptions{})
	if err != nil || verifyOriginalNonceMountPod(pod, source, r) != nil {
		return sourceZero, zero, ErrInstall
	}
	// Exact owner-source bytes are fixed independently of the nonce binding wire.
	original, err := readBootstrapSourcePin(source.Material, 32)
	defer clear(original)
	if err != nil || len(original) != 32 || bytes.Equal(original, make([]byte, 32)) {
		return sourceZero, zero, ErrInstall
	}
	return source, r, nil
}
