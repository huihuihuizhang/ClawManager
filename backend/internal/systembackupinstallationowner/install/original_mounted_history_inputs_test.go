package install

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	kt "k8s.io/client-go/testing"
)

// These exercise the concrete native read/retention layer, not authenticated
// administrator preflight, a complete history authority or successful adoption.
func mountedHistoryFixture(t *testing.T) (context.Context, *Installer, *fake.Clientset, []corev1.Pod, []appsv1.Deployment) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: "original", UID: "cm-uid", ResourceVersion: "8"}, Data: map[string]string{"config.json": `{"scope":"original"}`}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "credential", Namespace: "original", UID: "secret-uid", ResourceVersion: "9"}, Data: map[string][]byte{"credential": []byte("original-private-value")}}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "original", UID: "namespace-uid"}}
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "writer", Namespace: "original", UID: "pod-uid", ResourceVersion: "10"}, Spec: corev1.PodSpec{
		Volumes:    []corev1.Volume{{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "config"}}}}, {Name: "projected", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{{Secret: &corev1.SecretProjection{LocalObjectReference: corev1.LocalObjectReference{Name: "credential"}}}}}}}},
		Containers: []corev1.Container{{Name: "app", Env: []corev1.EnvVar{{Name: "CREDENTIAL", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "credential"}, Key: "credential"}}}}}},
	}}
	zero := int32(0)
	deployment := appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "stopped-controller", Namespace: "original", UID: "deployment-uid", ResourceVersion: "11"}, Spec: appsv1.DeploymentSpec{Replicas: &zero, Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "controller", EnvFrom: []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "config"}}}}}}}}}}
	client := fake.NewSimpleClientset(ns, cm, secret, &pod, &deployment)
	i := &Installer{kube: client}
	i.plan.Target.Namespace, i.plan.Target.NamespaceUID = "original", "namespace-uid"
	return ctx, i, client, []corev1.Pod{pod}, []appsv1.Deployment{deployment}
}

func TestOriginalMountedHistoryRetainsActualReferencedBytesBeforePodDeletion(t *testing.T) {
	ctx, i, client, pods, deps := mountedHistoryFixture(t)
	s, err := readOriginalMountedHistoryInputs(ctx, i, pods, deps, time.Now().Add(10*time.Second))
	if err != nil {
		t.Fatal("native original mounted read rejected")
	}
	defer s.close()
	if len(s.objects) != 4 || len(s.bindings) != 4 || len(s.revision) != 64 {
		t.Fatal("original owners/references were omitted")
	}
	o := s.objects["Secret/original/credential"]
	var actual corev1.Secret
	if o == nil || o.uid != "secret-uid" || o.resourceVersion != "9" || json.Unmarshal(o.body, &actual) != nil || string(actual.Data["credential"]) != "original-private-value" {
		t.Fatal("actual original private bytes not retained")
	}
	if err = client.CoreV1().Pods("original").Delete(ctx, "writer", metav1.DeleteOptions{}); err != nil {
		t.Fatal("fixture Pod removal failed")
	}
	if s.recheckReferences(ctx) != nil || len(s.objects["Pod/original/writer"].body) == 0 {
		t.Fatal("expected Pod removal erased original bytes")
	}
	if _, err = json.Marshal(s); err == nil || strings.Contains(fmt.Sprintf("%#v", s), "original-private-value") {
		t.Fatal("private snapshot serialized")
	}
	retained := o.body
	s.close()
	if !bytes.Equal(retained, make([]byte, len(retained))) || s.objects != nil || s.revision != "" {
		t.Fatal("retained private buffer not cleared")
	}
}

func TestOriginalMountedHistoryRefusesMaterialDriftAndPoisons(t *testing.T) {
	for _, change := range []string{"body-with-same-rv", "uid", "resource-version", "missing", "namespace-replaced"} {
		t.Run(change, func(t *testing.T) {
			ctx, i, client, pods, deps := mountedHistoryFixture(t)
			s, err := readOriginalMountedHistoryInputs(ctx, i, pods, deps, time.Now().Add(10*time.Second))
			if err != nil {
				t.Fatal("fixture read rejected")
			}
			defer s.close()
			retained := s.objects["Secret/original/credential"].body
			if change == "missing" {
				err = client.CoreV1().Secrets("original").Delete(ctx, "credential", metav1.DeleteOptions{})
			} else if change == "namespace-replaced" {
				ns, _ := client.CoreV1().Namespaces().Get(ctx, "original", metav1.GetOptions{})
				ns.UID = "replacement-namespace"
				_, err = client.CoreV1().Namespaces().Update(ctx, ns, metav1.UpdateOptions{})
			} else {
				cm, _ := client.CoreV1().ConfigMaps("original").Get(ctx, "config", metav1.GetOptions{})
				switch change {
				case "body-with-same-rv":
					cm.Data["config.json"] = `{"scope":"changed"}`
				case "uid":
					cm.UID = "replacement"
				case "resource-version":
					cm.ResourceVersion = "12"
				}
				_, err = client.CoreV1().ConfigMaps("original").Update(ctx, cm, metav1.UpdateOptions{})
			}
			if err != nil {
				t.Fatal("fixture mutation failed")
			}
			if s.recheckReferences(ctx) == nil || !s.closed || !bytes.Equal(retained, make([]byte, len(retained))) {
				t.Fatal("changed original material accepted or retained after failure")
			}
			if s.recheckReferences(ctx) == nil {
				t.Fatal("failed original snapshot revived")
			}
		})
	}
}

func TestOriginalMountedHistoryRefusesDriftDuringInitialRead(t *testing.T) {
	ctx, i, client, pods, deps := mountedHistoryFixture(t)
	reads := 0
	client.PrependReactor("get", "configmaps", func(action kt.Action) (bool, runtime.Object, error) {
		reads++
		if reads < 2 {
			return false, nil, nil
		}
		return true, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: "original", UID: "cm-uid", ResourceVersion: "8"}, Data: map[string]string{"config.json": "changed"}}, nil
	})
	if s, err := readOriginalMountedHistoryInputs(ctx, i, pods, deps, time.Now().Add(10*time.Second)); err == nil || s != nil {
		t.Fatal("mixed original configuration read accepted")
	}
}

func TestOriginalMountedHistoryRejectsMissingOptionalOversizeAndForeignOwner(t *testing.T) {
	for _, failure := range []string{"optional-missing", "oversize", "foreign-owner", "missing-version", "expired", "cancelled"} {
		t.Run(failure, func(t *testing.T) {
			ctx, i, client, pods, deps := mountedHistoryFixture(t)
			until := time.Now().Add(10 * time.Second)
			switch failure {
			case "optional-missing":
				optional := true
				pods[0].Spec.Volumes[1].Projected.Sources[0].Secret.Optional = &optional
				_ = client.CoreV1().Secrets("original").Delete(ctx, "credential", metav1.DeleteOptions{})
			case "oversize":
				secret, _ := client.CoreV1().Secrets("original").Get(ctx, "credential", metav1.GetOptions{})
				secret.Data["credential"] = make([]byte, originalMountedHistoryMaxObjectBytes)
				_, _ = client.CoreV1().Secrets("original").Update(ctx, secret, metav1.UpdateOptions{})
			case "foreign-owner":
				pods[0].Namespace = "other"
			case "missing-version":
				deps[0].ResourceVersion = ""
			case "expired":
				until = time.Now().Add(-time.Second)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if s, err := readOriginalMountedHistoryInputs(ctx, i, pods, deps, until); err == nil || s != nil {
				t.Fatal("incomplete original mounted input accepted")
			}
		})
	}
}

func TestOriginalMountedHistoryRejectsForeignContextAndCopiedHandle(t *testing.T) {
	ctx, i, _, pods, deps := mountedHistoryFixture(t)
	s, err := readOriginalMountedHistoryInputs(ctx, i, pods, deps, time.Now().Add(10*time.Second))
	if err != nil {
		t.Fatal("fixture read rejected")
	}
	defer s.close()
	other, cancel := context.WithCancel(ctx)
	defer cancel()
	if s.recheckReferences(other) == nil {
		t.Fatal("replacement context accepted")
	}
	copy := *s
	if copy.recheckReferences(ctx) == nil {
		t.Fatal("copied private snapshot accepted")
	}
}

func TestOriginalMountedHistoryActualTLSReadStopsAtOriginalCap(t *testing.T) {
	ctx, i, _, pods, _ := mountedHistoryFixture(t)
	started, cancelled := make(chan struct{}), make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/original":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(&corev1.Namespace{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: metav1.ObjectMeta{Name: "original", UID: "namespace-uid"}})
		case "/api/v1/namespaces/original/configmaps/config":
			close(started)
			<-r.Context().Done()
			close(cancelled)
		default:
			http.Error(w, "unexpected fixture request", http.StatusNotFound)
		}
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: ca}})
	if err != nil {
		t.Fatal("native TLS fixture client failed")
	}
	i.kube = client
	start := time.Now()
	if s, err := readOriginalMountedHistoryInputs(ctx, i, pods, nil, start.Add(300*time.Millisecond)); err == nil || s != nil {
		t.Fatal("unread native material accepted")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("native request escaped original finite cap")
	}
	select {
	case <-started:
	default:
		t.Fatal("fixture did not reach the actual native material request")
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("actual native TLS request was not cancelled at original cap")
	}
}
