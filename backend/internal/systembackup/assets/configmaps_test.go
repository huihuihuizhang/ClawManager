package assets

import (
	"context"
	"testing"

	"clawreef/internal/systembackup/domain"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestConfigMapCaptureRequiresExactIdentityAndCompleteFields(t *testing.T) {
	r := ConfigMapRef{Namespace: "source", Name: "agent", UID: "uid", ResourceVersion: "1", Rules: map[string]DocumentRules{"agent.json": {Format: "json", Fields: []domain.JSONRule{{Path: []string{"token"}, Action: "stub", Required: true}}}}}
	i := Inventory{Namespace: "source", ConfigMaps: []ConfigMapRef{r}}
	for _, failure := range []string{"", "revision", "field", "key"} {
		t.Run(failure, func(t *testing.T) {
			c := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "source", Name: "agent", UID: "uid", ResourceVersion: "1"}, Data: map[string]string{"agent.json": `{"token":"original-private-value"}`}}
			switch failure {
			case "revision":
				c.ResourceVersion = "2"
			case "field":
				c.Data["agent.json"] = `{"token":"original-private-value","new-trigger":true}`
			case "key":
				c.Data["new.json"] = `{}`
			}
			set, e := Capture(context.Background(), fake.NewSimpleClientset(c), i, nil)
			defer set.Clear()
			if (e == nil) != (failure == "") {
				t.Fatal("incorrect capture acceptance", e)
			}
			if e == nil && string(set.ConfigMaps[0].Data["agent.json"]) != c.Data["agent.json"] {
				t.Fatal("source credential was normalized before encryption")
			}
		})
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "source"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "agent", EnvFrom: []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "unregistered"}}}}}}}}
	if i.CheckPod(pod) == nil {
		t.Fatal("unregistered business ConfigMap ignored")
	}
}
