package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
)

func TestLegacyRuntimeMutationsRejectNativeLayout(t *testing.T) {
	ctx := context.Background()
	for _, layout := range []string{"annotation", "roles", "containers"} {
		for _, operation := range []string{"scale", "rollout", "upgrade-clone", "lab-clone", "upgrade-existing", "lab-existing", "schedule", "upgrade-delete", "lab-delete"} {
			t.Run(layout+"/"+operation, func(t *testing.T) {
				d := BuildRuntimeDeployment(RuntimeDeploymentSpec{Name: "source", Namespace: "ns", Image: "registry/image@sha256:" + strings.Repeat("a", 64), Replicas: 0})
				d.Labels[runtimePoolRoleLabel] = "upgrade-target"
				d.Labels[runtimeUpgradeIDLabel] = "run"
				d.Labels[runtimeSourceLabel] = "other"
				d.Labels[upgradeLabPurposeLabel] = upgradeLabPurposeValue
				d.Labels[upgradeLabRunLabel] = "run"
				switch layout {
				case "annotation":
					d.Spec.Template.Annotations = map[string]string{"clawmanager.io/runtime-layout": "pool-slot-v1"}
				case "roles":
					d.Spec.Template.Spec.Containers[0].Env = append(d.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{Name: "RUNTIME_AGENT_ROLE", Value: "pool"})
				case "containers":
					d.Spec.Template.Spec.Containers = []corev1.Container{{Name: "pool", Image: d.Spec.Template.Spec.Containers[0].Image}, {Name: "slot", Image: d.Spec.Template.Spec.Containers[0].Image}}
				}
				client := fake.NewSimpleClientset(d)
				s := &runtimeDeploymentService{client: client}
				var err error
				switch operation {
				case "scale":
					err = s.Scale(ctx, "ns", "source", 0)
				case "rollout":
					err = s.RolloutImage(ctx, "ns", "source", "registry/image:new", "run", 0, 1)
				case "upgrade-clone":
					err = s.EnsureUpgradePool(ctx, "ns", "source", "new", d.Spec.Template.Spec.Containers[0].Image, "run")
				case "lab-clone":
					err = s.EnsureUpgradeLabPool(ctx, "ns", "source", "new", d.Spec.Template.Spec.Containers[0].Image, "run", 1)
				case "upgrade-existing":
					err = s.EnsureUpgradePool(ctx, "ns", "other", "source", d.Spec.Template.Spec.Containers[0].Image, "run")
				case "lab-existing":
					err = s.EnsureUpgradeLabPool(ctx, "ns", "other", "source", d.Spec.Template.Spec.Containers[0].Image, "run", 1)
				case "schedule":
					err = s.SetUpgradePoolActive(ctx, "ns", "other", "source", "run", true)
				case "upgrade-delete":
					err = s.DeleteUpgradePool(ctx, "ns", "other", "source", "run")
				case "lab-delete":
					err = s.DeleteUpgradeLabPool(ctx, "ns", "source", "run")
				}
				if err == nil || !strings.Contains(err.Error(), "native pool/slot") {
					t.Fatalf("native mutation allowed: %v", err)
				}
				for _, a := range client.Actions() {
					if a.GetVerb() != "get" {
						t.Fatalf("mutation before refusal: %s %s", a.GetVerb(), a.GetResource().Resource)
					}
				}
			})
		}
	}
}

func TestRuntimeScaleRefusesDeniedInspectionAndConcurrentCutover(t *testing.T) {
	for _, fault := range []string{"forbidden", "cutover", "replacement"} {
		t.Run(fault, func(t *testing.T) {
			d := BuildRuntimeDeployment(RuntimeDeploymentSpec{Name: "source", Namespace: "ns", Replicas: 1})
			d.UID, d.ResourceVersion = "old-uid", "1"
			client := fake.NewSimpleClientset(d)
			updates := 0
			if fault == "forbidden" {
				client.PrependReactor("get", "deployments", func(kt.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "deployments"}, "source", fmt.Errorf("denied"))
				})
			}
			client.PrependReactor("patch", "deployments", func(a kt.Action) (bool, runtime.Object, error) {
				updates++
				var patch struct {
					Metadata struct{ UID, ResourceVersion string }
				}
				if json.Unmarshal(a.(kt.PatchAction).GetPatch(), &patch) != nil || patch.Metadata.UID != "old-uid" || patch.Metadata.ResourceVersion != "1" {
					t.Fatal("scale patch lacks original identity preconditions")
				}
				if updates != 1 {
					t.Fatal("scale retried mutation after identity/layout changed")
				}
				changed := d.DeepCopy()
				changed.ResourceVersion = "2"
				if fault == "replacement" {
					changed.UID = "replacement"
				} else {
					changed.Spec.Template.Annotations = map[string]string{"clawmanager.io/runtime-layout": "pool-slot-v1"}
				}
				if err := client.Tracker().Update(appsv1.SchemeGroupVersion.WithResource("deployments"), changed, "ns"); err != nil {
					t.Fatal(err)
				}
				return true, nil, apierrors.NewConflict(schema.GroupResource{Group: "apps", Resource: "deployments"}, "source", fmt.Errorf("concurrent change"))
			})
			if err := (&runtimeDeploymentService{client: client}).Scale(context.Background(), "ns", "source", 0); err == nil {
				t.Fatal("unsafe scale succeeded")
			}
			if fault == "forbidden" && updates != 0 {
				t.Fatal("permission denied but mutation attempted")
			}
			if fault != "forbidden" {
				current, err := client.AppsV1().Deployments("ns").Get(context.Background(), "source", metav1.GetOptions{})
				if err != nil || *current.Spec.Replicas != 1 {
					t.Fatal("original running count changed", err)
				}
			}
		})
	}
}

func TestLegacyRuntimeDeletionBindsInspectedIdentity(t *testing.T) {
	for _, lab := range []bool{false, true} {
		t.Run(fmt.Sprintf("lab=%v", lab), func(t *testing.T) {
			d := BuildRuntimeDeployment(RuntimeDeploymentSpec{Name: "target", Namespace: "ns", Replicas: 0})
			d.UID, d.ResourceVersion = "original", "17"
			d.Labels[runtimePoolRoleLabel], d.Labels[runtimeUpgradeIDLabel], d.Labels[runtimeSourceLabel] = "upgrade-target", "run", "source"
			d.Labels[upgradeLabPurposeLabel], d.Labels[upgradeLabRunLabel] = upgradeLabPurposeValue, "run"
			client := fake.NewSimpleClientset(d)
			deletes := 0
			client.PrependReactor("delete", "deployments", func(a kt.Action) (bool, runtime.Object, error) {
				deletes++
				p := a.(kt.DeleteAction).GetDeleteOptions().Preconditions
				if p == nil || p.UID == nil || *p.UID != "original" || p.ResourceVersion == nil || *p.ResourceVersion != "17" {
					t.Fatal("delete lacks original UID/version")
				}
				// The API server rejects this if an intervening cutover/replace
				// changed either precondition; the caller must retain the object.
				return true, nil, apierrors.NewConflict(schema.GroupResource{Group: "apps", Resource: "deployments"}, "target", fmt.Errorf("precondition failed"))
			})
			s := &runtimeDeploymentService{client: client}
			var err error
			if lab {
				err = s.DeleteUpgradeLabPool(context.Background(), "ns", "target", "run")
			} else {
				err = s.DeleteUpgradePool(context.Background(), "ns", "source", "target", "run")
			}
			if err == nil || deletes != 1 {
				t.Fatal("conflicted delete reported success/retried", err, deletes)
			}
			if _, err = client.AppsV1().Deployments("ns").Get(context.Background(), "target", metav1.GetOptions{}); err != nil {
				t.Fatal("uncertain target lost", err)
			}
		})
	}
}
