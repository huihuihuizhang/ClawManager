package profile

import (
	"clawreef/internal/systembackup/kube"
	"context"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (d *Driver) sharedClaim(ctx context.Context, ns string, c Claim) (string, error) {
	binding, e := d.claim(ctx, ns, c)
	if e != nil {
		return "", e
	}
	p, e := d.Client.CoreV1().PersistentVolumeClaims(ns).Get(ctx, c.Name, metav1.GetOptions{})
	if e != nil {
		return "", ErrProfile
	}
	rwx := false
	for _, mode := range p.Spec.AccessModes {
		rwx = rwx || mode == corev1.ReadWriteMany
	}
	if !rwx {
		return "", ErrProfile
	}
	pv, e := d.Client.CoreV1().PersistentVolumes().Get(ctx, binding.PVName, metav1.GetOptions{})
	if e != nil {
		return "", ErrProfile
	}
	if pv.Spec.NFS != nil {
		return kube.ContentHash(pv.Spec.NFS), nil
	}
	if pv.Spec.CSI != nil {
		return kube.ContentHash([]string{pv.Spec.CSI.Driver, pv.Spec.CSI.VolumeHandle}), nil
	}
	return "", ErrProfile
}

// VerifyControllerRoots joins the controller's actual mounted claim to every
// worker staging claim, and its evidence root to the target evidence claim.
// A path string or coincidentally equal PVC name alone is insufficient.
func (d *Driver) VerifyControllerRoots(ctx context.Context, namespace, podName, podUID, stagingPath, evidencePath string) error {
	pod, e := d.Client.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if e != nil || podUID == "" || string(pod.UID) != podUID || pod.DeletionTimestamp != nil {
		return ErrProfile
	}
	find := func(path string) (string, error) {
		var volume string
		for _, c := range pod.Spec.Containers {
			if c.Name != "controller" {
				continue
			}
			for _, m := range c.VolumeMounts {
				if m.MountPath == path && m.SubPath == "" && m.SubPathExpr == "" && !m.ReadOnly {
					volume = m.Name
				}
			}
		}
		for _, v := range pod.Spec.Volumes {
			if v.Name == volume && v.PersistentVolumeClaim != nil {
				p, e := d.Client.CoreV1().PersistentVolumeClaims(namespace).Get(ctx, v.PersistentVolumeClaim.ClaimName, metav1.GetOptions{})
				if e != nil {
					return "", ErrProfile
				}
				return d.sharedClaim(ctx, namespace, Claim{p.Name, string(p.UID)})
			}
		}
		return "", ErrProfile
	}
	stage, e := find(stagingPath)
	if e != nil {
		return e
	}
	evidence, e := find(evidencePath)
	if e != nil {
		return e
	}
	if stage == evidence {
		return ErrProfile
	}
	for ns, c := range d.Config.Staging {
		actual, e := d.sharedClaim(ctx, ns, c)
		if e != nil || actual != stage {
			return ErrProfile
		}
	}
	actual, e := d.sharedClaim(ctx, d.Config.TargetNamespace, d.Config.Evidence)
	if e != nil || actual != evidence {
		return ErrProfile
	}
	return nil
}
