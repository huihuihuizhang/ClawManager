package kube

import (
	"path"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// These are only refs. D must verify every mounted ConfigMap/Secret UID/hash
// through the existing worker mount observer before granting this original Job.
type FormalInputMount struct {
	Volume, Kind, Name, Directory string
	Items                         []corev1.KeyToPath
}

type FormalJobMaterials struct {
	ConfigMap string
	Inputs    []FormalInputMount
}

func attachFormalMaterials(job *batchv1.Job, materials *FormalJobMaterials) error {
	if job == nil || materials == nil || len(job.Spec.Template.Spec.Containers) != 1 || len(validation.IsDNS1123Subdomain(materials.ConfigMap)) != 0 || len(materials.Inputs) < 1 || len(materials.Inputs) > 32 {
		return ErrResource
	}
	mode := int32(0400)
	volumes := map[string]bool{"formal-mapping": true}
	dirs := map[string]bool{}
	for _, x := range materials.Inputs {
		if !strings.HasPrefix(x.Volume, "formal-") || len(validation.IsDNS1123Label(x.Volume)) != 0 || volumes[x.Volume] || dirs[x.Directory] || path.Dir(x.Directory) != "/run/backup/materials" || len(validation.IsDNS1123Label(path.Base(x.Directory))) != 0 || len(validation.IsDNS1123Subdomain(x.Name)) != 0 || len(x.Items) < 1 || len(x.Items) > 32 {
			return ErrResource
		}
		volumes[x.Volume], dirs[x.Directory] = true, true
		seen := map[string]bool{}
		for _, item := range x.Items {
			if len(validation.IsConfigMapKey(item.Key)) != 0 || item.Path == "" || path.Base(item.Path) != item.Path || item.Path == "." || item.Path == ".." || strings.ContainsAny(item.Path, "\\\x00\r\n:") || seen[item.Path] || item.Mode != nil {
				return ErrResource
			}
			seen[item.Path] = true
		}
		v := corev1.Volume{Name: x.Volume}
		switch x.Kind {
		case "Secret":
			v.Secret = &corev1.SecretVolumeSource{SecretName: x.Name, Items: append([]corev1.KeyToPath(nil), x.Items...), DefaultMode: &mode}
		case "ConfigMap":
			v.ConfigMap = &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: x.Name}, Items: append([]corev1.KeyToPath(nil), x.Items...), DefaultMode: &mode}
		default:
			return ErrResource
		}
		job.Spec.Template.Spec.Volumes = append(job.Spec.Template.Spec.Volumes, v)
		job.Spec.Template.Spec.Containers[0].VolumeMounts = append(job.Spec.Template.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: x.Volume, MountPath: x.Directory, ReadOnly: true})
	}
	job.Spec.Template.Spec.Volumes = append(job.Spec.Template.Spec.Volumes, corev1.Volume{Name: "formal-mapping", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: materials.ConfigMap}, Items: []corev1.KeyToPath{{Key: "materials.json", Path: "materials.json"}}, DefaultMode: &mode}}})
	container := &job.Spec.Template.Spec.Containers[0]
	container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{Name: "formal-mapping", MountPath: "/run/backup/formal", ReadOnly: true})
	container.Command = append(container.Command, "--formal-config", "/run/backup/formal/materials.json")
	return nil
}
