package systembackupminioauthority

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// This makes comparison DATA from actual native API reads. It does not issue
// a projection or prove B stopped/recovered anything. D's sealed source must
// retain its genuine BEFORE-cold result, never reconstruct it after recovery.
func CollectMinIORecoveryResources(ctx context.Context, k kubernetes.Interface, target Target, p Provider, podID ObjectIdentity, cid string) (MinIORecoveryResources, error) {
	var zero MinIORecoveryResources
	if ctx == nil || ctx.Err() != nil || k == nil || !recoveryCID(cid) {
		return zero, ErrRecord
	}
	ns, e := k.CoreV1().Namespaces().Get(ctx, target.Namespace, metav1.GetOptions{})
	if e != nil || string(ns.UID) != target.NamespaceUID || ns.DeletionTimestamp != nil {
		return zero, ErrRecord
	}
	d, e := k.AppsV1().Deployments(target.Namespace).Get(ctx, p.Deployment.Name, metav1.GetOptions{})
	if e != nil || string(d.UID) != p.Deployment.UID || d.DeletionTimestamp != nil || d.Spec.Replicas == nil || *d.Spec.Replicas != 1 || d.Status.ObservedGeneration < d.Generation || d.Status.ReadyReplicas != 1 {
		return zero, ErrRecord
	}
	rs, e := k.AppsV1().ReplicaSets(target.Namespace).Get(ctx, p.ReplicaSet.Name, metav1.GetOptions{})
	if e != nil || string(rs.UID) != p.ReplicaSet.UID || rs.DeletionTimestamp != nil || !recoveryOwned(rs.OwnerReferences, "Deployment", p.Deployment) {
		return zero, ErrRecord
	}
	pod, e := k.CoreV1().Pods(target.Namespace).Get(ctx, podID.Name, metav1.GetOptions{})
	if e != nil || string(pod.UID) != podID.UID || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || pod.Spec.NodeName != p.Node || pod.Spec.ServiceAccountName != p.ServiceAccount.Name || !recoveryOwned(pod.OwnerReferences, "ReplicaSet", p.ReplicaSet) || len(pod.Spec.EphemeralContainers) != 0 {
		return zero, ErrRecord
	}
	count := 0
	for _, s := range pod.Status.ContainerStatuses {
		if s.Name == p.Container {
			if !s.Ready || s.State.Running == nil || s.ContainerID != cid || s.ImageID != p.ImageID {
				return zero, ErrRecord
			}
			count++
		}
	}
	if count != 1 {
		return zero, ErrRecord
	}
	sa, e := k.CoreV1().ServiceAccounts(target.Namespace).Get(ctx, p.ServiceAccount.Name, metav1.GetOptions{})
	if e != nil || string(sa.UID) != p.ServiceAccount.UID || sa.DeletionTimestamp != nil {
		return zero, ErrRecord
	}
	node, e := k.CoreV1().Nodes().Get(ctx, p.Node, metav1.GetOptions{})
	if e != nil || string(node.UID) != p.NodeUID || node.DeletionTimestamp != nil {
		return zero, ErrRecord
	}
	svc, e := k.CoreV1().Services(target.Namespace).Get(ctx, p.Service.Name, metav1.GetOptions{})
	if e != nil || string(svc.UID) != p.Service.UID || svc.DeletionTimestamp != nil {
		return zero, ErrRecord
	}
	spec, e := stableRecoveryPodSpec(pod.Spec)
	if e != nil {
		return zero, e
	}
	hashValue := func(v any) Digest {
		// Hash deterministic native typed JSON without IEEE-754/JCS integer rounding.
		raw, e := json.Marshal(v)
		if e != nil {
			return ""
		}
		return digest(raw)
	}
	out := MinIORecoveryResources{Version: "original-minio-resource-comparison.v1", NamespaceUID: target.NamespaceUID, Deployment: p.Deployment, ReplicaSet: p.ReplicaSet, Service: p.Service, ServiceAccount: p.ServiceAccount, Node: p.Node, NodeUID: p.NodeUID, DeploymentSpecSHA256: hashValue(d.Spec), ReplicaSetSpecSHA256: hashValue(rs.Spec), ServiceSpecSHA256: hashValue(svc.Spec), ServiceAccountSHA256: hashValue(struct {
		UID         string
		Secrets     []corev1.ObjectReference
		PullSecrets []corev1.LocalObjectReference
		Automount   *bool
	}{string(sa.UID), sa.Secrets, sa.ImagePullSecrets, sa.AutomountServiceAccountToken}), PodSpecSHA256: hashValue(spec), NodeSpecSHA256: hashValue(node.Spec), Materials: []MinIORecoveryMaterial{}, Storage: []MinIORecoveryStorage{}}
	secrets, maps := map[string]bool{}, map[string]bool{}
	storage := map[string]MinIORecoveryStorage{}
	for _, ref := range sa.Secrets {
		secrets[ref.Name] = true
	}
	for _, ref := range sa.ImagePullSecrets {
		secrets[ref.Name] = true
	}
	for _, container := range append(append([]corev1.Container(nil), pod.Spec.Containers...), pod.Spec.InitContainers...) {
		for _, env := range container.Env {
			if env.ValueFrom != nil {
				if r := env.ValueFrom.SecretKeyRef; r != nil {
					secrets[r.Name] = true
				}
				if r := env.ValueFrom.ConfigMapKeyRef; r != nil {
					maps[r.Name] = true
				}
			}
		}
		for _, env := range container.EnvFrom {
			if env.SecretRef != nil {
				secrets[env.SecretRef.Name] = true
			}
			if env.ConfigMapRef != nil {
				maps[env.ConfigMapRef.Name] = true
			}
		}
	}
	for _, pull := range pod.Spec.ImagePullSecrets {
		secrets[pull.Name] = true
	}
	for _, volume := range pod.Spec.Volumes {
		// Fail closed for storage/auth plugins whose live credential material this
		// narrowly scoped original MinIO reader does not enumerate.
		source := volume.VolumeSource
		known := corev1.VolumeSource{HostPath: source.HostPath, EmptyDir: source.EmptyDir, Secret: source.Secret, ConfigMap: source.ConfigMap, Projected: source.Projected, PersistentVolumeClaim: source.PersistentVolumeClaim, DownwardAPI: source.DownwardAPI}
		if !reflect.DeepEqual(source, known) {
			return zero, ErrRecord
		}
		if volume.Secret != nil {
			secrets[volume.Secret.SecretName] = true
		}
		if volume.ConfigMap != nil {
			maps[volume.ConfigMap.Name] = true
		}
		if volume.Projected != nil {
			for _, source := range volume.Projected.Sources {
				known := corev1.VolumeProjection{Secret: source.Secret, ConfigMap: source.ConfigMap, DownwardAPI: source.DownwardAPI, ServiceAccountToken: source.ServiceAccountToken}
				if !reflect.DeepEqual(source, known) {
					return zero, ErrRecord
				}
				if source.Secret != nil {
					secrets[source.Secret.Name] = true
				}
				if source.ConfigMap != nil {
					maps[source.ConfigMap.Name] = true
				}
			}
		}
		if volume.PersistentVolumeClaim != nil {
			claim, e := k.CoreV1().PersistentVolumeClaims(target.Namespace).Get(ctx, volume.PersistentVolumeClaim.ClaimName, metav1.GetOptions{})
			if e != nil || claim.DeletionTimestamp != nil || claim.UID == "" || claim.Status.Phase != corev1.ClaimBound || claim.Spec.VolumeName == "" {
				return zero, ErrRecord
			}
			pv, e := k.CoreV1().PersistentVolumes().Get(ctx, claim.Spec.VolumeName, metav1.GetOptions{})
			if e != nil || pv.DeletionTimestamp != nil || pv.UID == "" || pv.Status.Phase != corev1.VolumeBound || pv.Spec.ClaimRef == nil || pv.Spec.ClaimRef.UID != claim.UID || pv.Spec.ClaimRef.Namespace != target.Namespace || pv.Spec.ClaimRef.Name != claim.Name {
				return zero, ErrRecord
			}
			pvSource := pv.Spec.PersistentVolumeSource
			knownPV := corev1.PersistentVolumeSource{HostPath: pvSource.HostPath, Local: pvSource.Local, NFS: pvSource.NFS}
			if !reflect.DeepEqual(pvSource, knownPV) {
				return zero, ErrRecord
			}
			for _, item := range []MinIORecoveryStorage{{"PersistentVolumeClaim", claim.Name, string(claim.UID), hashValue(claim.Spec)}, {"PersistentVolume", pv.Name, string(pv.UID), hashValue(pv.Spec)}} {
				key := item.Kind + "/" + item.Name
				if old, ok := storage[key]; ok && old != item {
					return zero, ErrRecord
				}
				storage[key] = item
			}
		}
	}
	for name := range secrets {
		secret, e := k.CoreV1().Secrets(target.Namespace).Get(ctx, name, metav1.GetOptions{})
		if e != nil || secret.UID == "" || secret.ResourceVersion == "" || secret.DeletionTimestamp != nil {
			return zero, ErrRecord
		}
		out.Materials = append(out.Materials, MinIORecoveryMaterial{"Secret", name, string(secret.UID), secret.ResourceVersion, hashValue(struct {
			Type      corev1.SecretType
			Immutable *bool
			Data      map[string][]byte
		}{secret.Type, secret.Immutable, secret.Data})})
	}
	for name := range maps {
		cm, e := k.CoreV1().ConfigMaps(target.Namespace).Get(ctx, name, metav1.GetOptions{})
		if e != nil || cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil {
			return zero, ErrRecord
		}
		out.Materials = append(out.Materials, MinIORecoveryMaterial{"ConfigMap", name, string(cm.UID), cm.ResourceVersion, hashValue(struct {
			Immutable  *bool
			Data       map[string]string
			BinaryData map[string][]byte
		}{cm.Immutable, cm.Data, cm.BinaryData})})
	}
	for _, item := range storage {
		out.Storage = append(out.Storage, item)
	}
	sort.Slice(out.Materials, func(i, j int) bool {
		a, b := out.Materials[i], out.Materials[j]
		return a.Kind+"/"+a.Name < b.Kind+"/"+b.Name
	})
	sort.Slice(out.Storage, func(i, j int) bool {
		a, b := out.Storage[i], out.Storage[j]
		return a.Kind+"/"+a.Name < b.Kind+"/"+b.Name
	})
	if ctx.Err() != nil || validateRecoveryResources(out) != nil {
		return zero, ErrRecord
	}
	return out, nil
}

func recoveryOwned(owners []metav1.OwnerReference, kind string, id ObjectIdentity) bool {
	count := 0
	for _, o := range owners {
		if o.Controller != nil && *o.Controller {
			if o.Kind != kind || o.Name != id.Name || string(o.UID) != id.UID {
				return false
			}
			count++
		}
	}
	return count == 1
}

// Normalize ONLY Kubernetes' autogenerated, exact standard projected SA mount
// name. Its CA ConfigMap identity/version/data are still separately compared.
// Every other PodSpec field and application credential mount stays exact.
func stableRecoveryPodSpec(in corev1.PodSpec) (corev1.PodSpec, error) {
	s := *in.DeepCopy()
	s.NodeName = ""
	rename := map[string]bool{}
	for n, volume := range s.Volumes {
		if !strings.HasPrefix(volume.Name, "kube-api-access-") {
			continue
		}
		if volume.Projected == nil || len(volume.Projected.Sources) != 3 || len(rename) != 0 {
			return corev1.PodSpec{}, ErrRecord
		}
		token, ca, namespace := false, false, false
		for _, source := range volume.Projected.Sources {
			// An API union must contain exactly one alternative. Unknown alternatives
			// cannot be hidden beside a standard projected service-account source.
			value := reflect.ValueOf(source)
			alternatives := 0
			for field := 0; field < value.NumField(); field++ {
				if value.Field(field).Kind() == reflect.Pointer && !value.Field(field).IsNil() {
					alternatives++
				}
			}
			if alternatives != 1 {
				return corev1.PodSpec{}, ErrRecord
			}
			switch {
			case source.ServiceAccountToken != nil:
				if source.ServiceAccountToken.Path != "token" || source.ServiceAccountToken.Audience != "" {
					return corev1.PodSpec{}, ErrRecord
				}
				token = true
			case source.ConfigMap != nil:
				if source.ConfigMap.Name != "kube-root-ca.crt" || len(source.ConfigMap.Items) != 1 || source.ConfigMap.Items[0].Key != "ca.crt" || source.ConfigMap.Items[0].Path != "ca.crt" {
					return corev1.PodSpec{}, ErrRecord
				}
				ca = true
			case source.DownwardAPI != nil:
				if len(source.DownwardAPI.Items) != 1 {
					return corev1.PodSpec{}, ErrRecord
				}
				field := source.DownwardAPI.Items[0]
				if field.Path != "namespace" || field.FieldRef == nil || field.FieldRef.FieldPath != "metadata.namespace" {
					return corev1.PodSpec{}, ErrRecord
				}
				namespace = true
			default:
				return corev1.PodSpec{}, ErrRecord
			}
		}
		if !token || !ca || !namespace {
			return corev1.PodSpec{}, ErrRecord
		}
		rename[volume.Name] = true
		s.Volumes[n].Name = "kube-api-access-original"
	}
	fix := func(containers []corev1.Container) error {
		for n := range containers {
			for m, mount := range containers[n].VolumeMounts {
				if rename[mount.Name] {
					if mount.MountPath != "/var/run/secrets/kubernetes.io/serviceaccount" || !mount.ReadOnly || mount.SubPath != "" || mount.SubPathExpr != "" {
						return ErrRecord
					}
					containers[n].VolumeMounts[m].Name = "kube-api-access-original"
				}
			}
		}
		return nil
	}
	if fix(s.Containers) != nil || fix(s.InitContainers) != nil {
		return corev1.PodSpec{}, ErrRecord
	}
	return s, nil
}

func (v *VerifiedMinIORecoveryProjection) CompareCurrentResources(actual MinIORecoveryResources) error {
	if v == nil || v.origin != v || !reflect.DeepEqual(actual, v.record.Transition.OriginalResources) {
		return ErrRecord
	}
	return nil
}
