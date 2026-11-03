package systembackupexecution

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

// Real A Installer + bcrypt/Ed25519 + real B sequence/consumer. SQL and API
// remain isolated protocol models: no source stop, storage or migration claim.
func TestOriginalInstanceMountAuthenticatedSequenceComponent(t *testing.T) {
	for _, fault := range []string{"none", "pod-replaced", "scope-rewrite", "expired", "definition-revoked", "pre-materialize-drift"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			f := newMaterialProducerComponent(t, ctx)
			var m productionCaptureMaterials
			if json.Unmarshal(f.definition.Materials, &m) != nil {
				t.Fatal("original fixture")
			}
			directory := corev1.HostPathDirectory
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: f.core.Namespace, Name: "original-mount-runtime", UID: "original-mount-pod"}, Spec: corev1.PodSpec{NodeName: f.core.Workspace.Node, Containers: []corev1.Container{{Name: "agent", VolumeMounts: []corev1.VolumeMount{{Name: "documents", MountPath: "/persist"}}}}, Volumes: []corev1.Volume{{Name: "documents", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/fixture-original/documents", Type: &directory}}}}}}
			mapping := productionPersistentMountBinding{InstanceID: 7, UserID: 2, Generation: 3, MountID: "documents", Container: "agent", Volume: "documents", MountPath: "/persist", DataPath: "/persist/2/7", Namespace: pod.Namespace, Pod: pod.Name, PodUID: string(pod.UID), PodSpecSHA256: kube.ContentHash(pod.Spec), Node: pod.Spec.NodeName, NodeUID: f.core.Security.NodeUIDs[pod.Spec.NodeName], VolumeSourceSHA256: kube.ContentHash(pod.Spec.Volumes[0].VolumeSource)}
			m.Discovery.PersistentMounts = &productionPersistentMountScope{Version: persistentMountScopeVersion, Mounts: []productionPersistentMountBinding{mapping}}
			f.definition.Materials, _ = json.Marshal(m)
			definitionRaw, _ := json.Marshal(f.definition)
			f.definitionSHA = hash(definitionRaw)
			if os.WriteFile(f.definitionFile, definitionRaw, 0600) != nil {
				t.Fatal("original pre-Begin selection")
			}
			sequence, err := BeginOriginalCaptureSequence(ctx, f.installer, f.password, f.enrollment, f.definitionFile, f.definitionSHA, f.privateFile)
			if err != nil {
				t.Fatal("real original Begin", err)
			}
			client, file, digest := materializeSequenceFixture(t, ctx, sequence)
			if err := client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("pods"), pod, pod.Namespace); err != nil {
				t.Fatal(err)
			}
			node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: mapping.Node, UID: types.UID(mapping.NodeUID), Labels: map[string]string{corev1.LabelOSStable: "linux"}}}
			if err := client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("nodes"), node, ""); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "pod-replaced", "pre-materialize-drift":
				pod = pod.DeepCopy()
				pod.UID = "replacement"
				if err := client.Tracker().Update(schema.GroupVersionResource{Version: "v1", Resource: "pods"}, pod, pod.Namespace); err != nil {
					t.Fatal(err)
				}
			case "scope-rewrite":
				raw, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				var material productionCaptureMaterials
				if json.Unmarshal(raw, &material) != nil {
					t.Fatal("fixture")
				}
				material.Discovery.PersistentMounts.Mounts[0].UserID++
				raw, _ = json.Marshal(material)
				digest = hash(raw)
				if os.WriteFile(file, raw, 0600) != nil {
					t.Fatal("test-owned material mutation")
				}
			case "expired":
				f.model.clockBeyondOriginalWindow.Store(true)
			case "definition-revoked":
				if os.WriteFile(f.definitionFile, append(definitionRaw, '\n'), 0600) != nil {
					t.Fatal("test-owned pin replacement")
				}
			}
			start := len(client.Actions())
			if fault == "pre-materialize-drift" {
				_, err := sequence.MaterializeMappings(ctx, client, filepath.Join(filepath.Dir(file), "not-read-components.json"), hash([]byte("not-read")), filepath.Join(filepath.Dir(file), "not-created-intermediate.json"))
				var missing *InstanceMountInputError
				if !errors.As(err, &missing) || missing.Code != "original_mount_pin_changed" {
					t.Fatal("stale source reached component loading/create", err)
				}
				if _, _, err := sequence.WorkerSourceMounts(ctx); err == nil {
					t.Fatal("failed original sequence resumed")
				}
			} else {
				receipt, err := sequence.Finalize(ctx, client, file, digest)
				if fault == "none" {
					if err != nil || receipt.SHA256 == "" {
						t.Fatal("original signed mount material rejected", err)
					}
					generated, _ := checkComponentMaterialOutputs(t, f)
					if generated.Discovery.PersistentMounts.Mounts[0] != mapping {
						t.Fatal("signed scope lost original owner/generation/volume")
					}
				} else if err == nil || receipt != (ProductionMaterialReceipt{}) {
					t.Fatal("invalid/withdrawn source produced final receipt", fault, err)
				}
			}
			if fault != "none" {
				if _, err := os.Stat(f.core.CaptureModules.Path); !os.IsNotExist(err) {
					t.Fatal("failed original sequence published final material")
				}
			}
			for _, a := range client.Actions()[start:] {
				if a.GetVerb() != "get" {
					t.Fatal("final verification mutated original API")
				}
			}
			if f.model.executions.Load() != 0 || f.model.openTx.Load() != 0 {
				t.Fatal("mount integration wrote/retained SQL")
			}
		})
	}
}
