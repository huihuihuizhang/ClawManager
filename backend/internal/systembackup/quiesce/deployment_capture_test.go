package quiesce

import (
	"bytes"
	"encoding/json"
	"testing"

	c "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/flow"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestDeploymentCapturePreservesOriginalCheckpointAlongsidePausedObject(t *testing.T) {
	f := newDeploymentFixture(t, 1)
	ctx := testDeadline(t)
	original, err := f.writer.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := f.writer.Pause(ctx, original)
	if err != nil || !ack.Stopped || f.writer.CheckPaused(ctx, original) != nil {
		t.Fatal("actual writer did not quiesce", err)
	}
	paused, err := f.client.AppsV1().Deployments("fixture").Get(ctx, "agent", metav1.GetOptions{})
	if err != nil || *paused.Spec.Replicas != 0 {
		t.Fatal("capture view must be paused", err)
	}
	paused.APIVersion, paused.Kind = "apps/v1", "Deployment"
	object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(paused)
	if err != nil {
		t.Fatal(err)
	}
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), &unstructured.Unstructured{Object: object})
	var history bytes.Buffer
	ref := c.KubernetesSelection{Group: "apps", Version: "v1", Resource: "deployments", Name: "agent", UID: original.UID}
	if err = c.CaptureKubernetesResources(ctx, client, &history, "fixture", "original-namespace", "deployment_resources", []c.KubernetesSelection{ref}, c.ObjectBudget{MaxBytes: 4 << 20, MaxItems: 10}); err != nil {
		t.Fatal(err)
	}
	// Serialize the exact original checkpoint with the paused history, as the
	// task-bound resource scope header does. Never infer original replicas from 0.
	raw, err := json.Marshal(struct {
		Original flow.State
		History  []byte
	}{original, history.Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	var restored struct {
		Original flow.State
		History  []byte
	}
	if json.Unmarshal(raw, &restored) != nil || restored.Original != original {
		t.Fatal("checkpoint bytes changed")
	}
	count, err := DeploymentOriginalReplicas("fixture", "agent", restored.Original)
	if err != nil || count != 1 {
		t.Fatal("archive lost pre-pause desired replicas", err)
	}
	if err = c.ReadKubernetesHistory(ctx, bytes.NewReader(restored.History), "deployment_resources", c.ObjectBudget{MaxBytes: 4 << 20, MaxItems: 10}, func(_ c.KubernetesSelection, raw json.RawMessage) error {
		var value unstructured.Unstructured
		if json.Unmarshal(raw, &value.Object) != nil {
			t.Fatal("object readback")
		}
		zero, _, _ := unstructured.NestedInt64(value.Object, "spec", "replicas")
		if zero != 0 {
			t.Fatal("archive misrepresented actual paused capture view")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = f.writer.Resume(ctx, original); err != nil {
		t.Fatal(err)
	}
	current, _ := f.client.AppsV1().Deployments("fixture").Get(ctx, "agent", metav1.GetOptions{})
	if *current.Spec.Replicas != count {
		t.Fatal("original desired state was not restored")
	}
}
