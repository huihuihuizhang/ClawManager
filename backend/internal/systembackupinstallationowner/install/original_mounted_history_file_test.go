package install

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// Native client fixture, not an actual administrator, complete original hold,
// installed-history authority or proof that every historical source is known.
func originalMountedFileFixture(t *testing.T, mutate func(*corev1.Pod)) (context.Context, *originalMountedHistoryInputs, *fake.Clientset) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "original", UID: "ns-uid"}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: "original", UID: "cm-uid", ResourceVersion: "5"}, Data: map[string]string{"config.json": `{"original":"scope"}`}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "credential", Namespace: "original", UID: "secret-uid", ResourceVersion: "6"}, Data: map[string][]byte{"credential": []byte("PRIVATE_MOUNT_CANARY")}}
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "writer", Namespace: "original", UID: "pod-uid", ResourceVersion: "7"}, Spec: corev1.PodSpec{
		Volumes:    []corev1.Volume{{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "config"}}}}, {Name: "credential", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "credential"}}}},
		Containers: []corev1.Container{{Name: "app", VolumeMounts: []corev1.VolumeMount{{Name: "config", MountPath: "/etc/config"}, {Name: "credential", MountPath: "/etc/identity/read.json", SubPath: "credential"}}}},
	}}
	if mutate != nil {
		mutate(&pod)
	}
	dep := appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "controller", Namespace: "original", UID: "dep-uid", ResourceVersion: "8"}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: *pod.Spec.DeepCopy()}}}
	client := fake.NewSimpleClientset(ns, cm, secret, &pod, &dep)
	i := &Installer{kube: client}
	i.plan.Target.Namespace = "original"
	i.plan.Target.NamespaceUID = "ns-uid"
	s, err := readOriginalMountedHistoryInputs(ctx, i, []corev1.Pod{pod}, []appsv1.Deployment{dep}, time.Now().Add(30*time.Second))
	if err != nil {
		t.Fatal("actual mounted native capture refused", err)
	}
	t.Cleanup(s.close)
	return ctx, s, client
}

func TestOriginalMountedHistoryFileReadsOriginalFixedBytes(t *testing.T) {
	ctx, s, client := originalMountedFileFixture(t, nil)
	for _, kind := range []string{"Pod", "Deployment"} {
		for _, secret := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/secret=%t", kind, secret), func(t *testing.T) {
				owner, uid := "writer", "pod-uid"
				if kind == "Deployment" {
					owner, uid = "controller", "dep-uid"
				}
				name, expected := "/etc/config/config.json", []byte(`{"original":"scope"}`)
				if secret {
					name, expected = "/etc/identity/read.json", []byte("PRIVATE_MOUNT_CANARY")
				}
				f, err := readOriginalMountedHistoryFile(ctx, s, kind, owner, uid, "app", name)
				if err != nil || !bytes.Equal(f.body, expected) || f.fileSHA != hash(expected) || !f.until.Equal(s.until) {
					t.Fatal("actual original mount bytes changed", err)
				}
				defer f.close()
				if _, err = json.Marshal(f); err == nil || strings.Contains(fmt.Sprintf("%#v", f), "PRIVATE_MOUNT_CANARY") {
					t.Fatal("private file disclosed")
				}
				copy := *f
				if copy.recheckBeforeOriginalSQL(ctx) == nil {
					t.Fatal("copied private read source accepted")
				}
				if f.recheckBeforeOriginalSQL(ctx) != nil {
					t.Fatal("copy rejection damaged original")
				}
			})
		}
	}
	if client.CoreV1().Pods("original").Delete(ctx, "writer", metav1.DeleteOptions{}) != nil {
		t.Fatal("delete original Pod fixture")
	}
	if f, err := readOriginalMountedHistoryFile(ctx, s, "Pod", "writer", "pod-uid", "app", "/etc/config/config.json"); err != nil {
		t.Fatal("held original Pod removal lost fixed original input", err)
	} else {
		f.close()
	}
}

func TestOriginalMountedHistoryFileProjectedAndAmbiguousKeys(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		t.Run(fmt.Sprintf("ambiguous=%t", ambiguous), func(t *testing.T) {
			ctx, s, _ := originalMountedFileFixture(t, func(p *corev1.Pod) {
				secretPath := "credential"
				if ambiguous {
					secretPath = "config.json"
				}
				p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: "projected", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{
					{ConfigMap: &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "config"}, Items: []corev1.KeyToPath{{Key: "config.json", Path: "config.json"}}}},
					{Secret: &corev1.SecretProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "credential"}, Items: []corev1.KeyToPath{{Key: "credential", Path: secretPath}}}},
				}}}})
				p.Spec.Containers[0].VolumeMounts = append(p.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "projected", MountPath: "/etc/projected"})
			})
			f, err := readOriginalMountedHistoryFile(ctx, s, "Pod", "writer", "pod-uid", "app", "/etc/projected/config.json")
			if ambiguous {
				if err == nil || f != nil {
					t.Fatal("ambiguous projected identity accepted")
				}
			} else {
				if err != nil || string(f.body) != `{"original":"scope"}` {
					t.Fatal("projected exact key refused", err)
				}
				f.close()
			}
		})
	}
}

func TestOriginalMountedHistoryFileRefusesUnsupportedOriginalPaths(t *testing.T) {
	for _, mode := range []string{"path-alias", "wrong-owner", "unmounted", "missing-key", "subpath-expression", "overlap", "mixed-volume"} {
		t.Run(mode, func(t *testing.T) {
			ctx, s, _ := originalMountedFileFixture(t, func(p *corev1.Pod) {
				if mode == "subpath-expression" {
					p.Spec.Containers[0].VolumeMounts[0].SubPathExpr = "$(DYNAMIC)"
				}
				if mode == "overlap" {
					p.Spec.Containers[0].VolumeMounts = append(p.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "credential", MountPath: "/etc"})
				}
				if mode == "mixed-volume" {
					p.Spec.Volumes[0].HostPath = &corev1.HostPathVolumeSource{Path: "/original-unrelated"}
				}
			})
			name, uid := "/etc/config/config.json", "pod-uid"
			switch mode {
			case "path-alias":
				name = "/etc/config/../config/config.json"
			case "wrong-owner":
				uid = "another-pod"
			case "unmounted":
				name = "/original/host-path"
			case "missing-key":
				name = "/etc/config/not-present"
			}
			if f, err := readOriginalMountedHistoryFile(ctx, s, "Pod", "writer", uid, "app", name); err == nil || f != nil {
				t.Fatal("unsupported path/identity became original config")
			}
		})
	}
}

func TestOriginalMountedHistoryFileRejectsMaterialDriftAndClosesBytes(t *testing.T) {
	ctx, s, client := originalMountedFileFixture(t, nil)
	f, err := readOriginalMountedHistoryFile(ctx, s, "Pod", "writer", "pod-uid", "app", "/etc/identity/read.json")
	if err != nil {
		t.Fatal(err)
	}
	old := f.body
	secret, err := client.CoreV1().Secrets("original").Get(ctx, "credential", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	secret.ResourceVersion = "99"
	secret.Data["credential"] = []byte("different")
	if _, err = client.CoreV1().Secrets("original").Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if f.recheckBeforeOriginalSQL(ctx) == nil || !f.closed || f.body != nil || !bytes.Equal(old, make([]byte, len(old))) {
		t.Fatal("changed source retained usable private bytes")
	}
}

func TestOriginalMountedHistoryFileCannotExtendOriginalCaptureCap(t *testing.T) {
	ctx, s, _ := originalMountedFileFixture(t, nil)
	f, err := readOriginalMountedHistoryFile(ctx, s, "Pod", "writer", "pod-uid", "app", "/etc/identity/read.json")
	if err != nil {
		t.Fatal(err)
	}
	old := f.body
	f.until = s.until.Add(time.Hour)
	if f.recheckBeforeOriginalSQL(ctx) == nil || !f.closed || !bytes.Equal(old, make([]byte, len(old))) {
		t.Fatal("file reader extended original authority or retained expired bytes")
	}
}

func TestOriginalMountedHistoryFileHeldEntryRequiresGenuineOwners(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"missing-preparation", "missing-hold", "unprepared-owners"} {
		t.Run(mode, func(t *testing.T) {
			p := &PreparedOriginalAdoptionSQLCut{}
			h := &OriginalWriterHold{set: &PreparedOriginalWriterSet{}}
			if mode == "missing-preparation" {
				p = nil
			}
			if mode == "missing-hold" {
				h = nil
			}
			if f, err := readOriginalHeldMountedHistoryFile(ctx, p, h, "Pod", "writer", "uid", "app", "/etc/config/config.json"); err == nil || f != nil {
				t.Fatal("unprepared original holder minted file read")
			}
		})
	}
}
