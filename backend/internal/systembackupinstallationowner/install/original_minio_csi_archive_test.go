package install

import (
	corev1 "k8s.io/api/core/v1"
	"testing"
)

func TestOriginalMinIOCSIArchiveProfileIsNarrow(t *testing.T) {
	makePair := func() (*corev1.PersistentVolume, *corev1.PersistentVolumeClaim) {
		return &corev1.PersistentVolume{Spec: corev1.PersistentVolumeSpec{PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: "driver.longhorn.io", FSType: "ext4", VolumeHandle: "pvc-12345678-1234-1234-1234-123456789abc"}}, AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}}}, &corev1.PersistentVolumeClaim{Spec: corev1.PersistentVolumeClaimSpec{AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}}}
	}
	pv, claim := makePair()
	if h, e := originalMinIOCSIHandle(pv, claim); e != nil || h != pv.Spec.CSI.VolumeHandle {
		t.Fatal("exact original Longhorn ext4 RWO profile rejected")
	}
	cases := map[string]func(*corev1.PersistentVolume, *corev1.PersistentVolumeClaim){
		"hostpath": func(p *corev1.PersistentVolume, c *corev1.PersistentVolumeClaim) {
			p.Spec.HostPath = &corev1.HostPathVolumeSource{Path: "/old/hostpath"}
		},
		"other-driver": func(p *corev1.PersistentVolume, c *corev1.PersistentVolumeClaim) { p.Spec.CSI.Driver = "other" },
		"xfs":          func(p *corev1.PersistentVolume, c *corev1.PersistentVolumeClaim) { p.Spec.CSI.FSType = "xfs" },
		"readonly":     func(p *corev1.PersistentVolume, c *corev1.PersistentVolumeClaim) { p.Spec.CSI.ReadOnly = true },
		"path-as-handle": func(p *corev1.PersistentVolume, c *corev1.PersistentVolumeClaim) {
			p.Spec.CSI.VolumeHandle = "../../source"
		},
		"block": func(p *corev1.PersistentVolume, c *corev1.PersistentVolumeClaim) {
			v := corev1.PersistentVolumeBlock
			p.Spec.VolumeMode = &v
		},
		"claim-block": func(p *corev1.PersistentVolume, c *corev1.PersistentVolumeClaim) {
			v := corev1.PersistentVolumeBlock
			c.Spec.VolumeMode = &v
		},
		"rwx": func(p *corev1.PersistentVolume, c *corev1.PersistentVolumeClaim) {
			p.Spec.AccessModes = []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany}
		},
		"claim-rwx": func(p *corev1.PersistentVolume, c *corev1.PersistentVolumeClaim) {
			c.Spec.AccessModes = []corev1.PersistentVolumeAccessMode{corev1.ReadWriteMany}
		},
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			p, c := makePair()
			alter(p, c)
			if _, e := originalMinIOCSIHandle(p, c); e == nil {
				t.Fatal("foreign or partial source profile accepted")
			}
		})
	}
}
