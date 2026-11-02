package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/worker"
	k "clawreef/internal/systembackupkms"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

// Concrete A installer/signatures and original consumer; Kubernetes is a
// component API model. No test claims actual source data or live readiness.
func materializeSequenceFixture(t *testing.T, ctx context.Context, s *OriginalCaptureSequence) (*fake.Clientset, string, string) {
	t.Helper()
	client := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: s.core.Namespace, UID: types.UID(s.core.NamespaceUID)}})
	raw, _ := json.Marshal(s.materials)
	var m productionCaptureMaterials
	if json.Unmarshal(raw, &m) != nil {
		t.Fatal("detached declaration")
	}
	projectionKeys := map[string]map[string]bool{}
	for _, operation := range m.Operations {
		for _, input := range operation.Workload.FormalMaterials.Inputs {
			key := input.Kind + "/" + input.Name
			if projectionKeys[key] == nil {
				projectionKeys[key] = map[string]bool{}
			}
			for _, item := range input.Items {
				projectionKeys[key][item.Key] = true
			}
		}
	}
	yes := true
	for name, operation := range m.Operations {
		formal := worker.FormalCaptureMaterials{Version: worker.FormalCaptureVersion, KMS: k.Config{InstallationID: s.core.InstallationID, Endpoint: operation.Provider.Endpoint, KeyName: operation.Provider.KeyName, Key: operation.Provider.Request.Key}, PermitDelivery: operation.Formal.PermitDelivery}
		if name == "capture-source-redis" {
			formal.Sources = &m.Redis
		}
		if name == "capture-skill-objects" {
			formal.Sources = &m.Objects
		}
		mapping, err := json.Marshal(formal)
		if err != nil {
			t.Fatal(err)
		}
		operation.Formal.ConfigSHA256 = hash(mapping)
		operation.MountIdentities = nil
		cmName := operation.Workload.FormalMaterials.ConfigMap
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: cmName, Namespace: s.core.Namespace, UID: types.UID("actual-" + name + "-mapping")}, Immutable: &yes, Data: map[string]string{"materials.json": string(mapping)}}
		if _, err := client.CoreV1().ConfigMaps(s.core.Namespace).Create(ctx, cm, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		operation.MountIdentities = append(operation.MountIdentities, kube.MountIdentity{Volume: "formal-mapping", Kind: "ConfigMap", Name: cmName, UID: string(cm.UID), SHA256: kube.ContentHash([]any{cm.Data, cm.BinaryData})})
		for _, input := range operation.Workload.FormalMaterials.Inputs {
			pin := kube.MountIdentity{Volume: input.Volume, Kind: input.Kind, Name: input.Name}
			if input.Kind == "ConfigMap" {
				object, err := client.CoreV1().ConfigMaps(s.core.Namespace).Get(ctx, input.Name, metav1.GetOptions{})
				if err != nil {
					object = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: input.Name, Namespace: s.core.Namespace, UID: types.UID("actual-" + input.Name)}, Immutable: &yes, Data: map[string]string{}}
					for key := range projectionKeys[input.Kind+"/"+input.Name] {
						object.Data[key] = "component-projection"
					}
					object, err = client.CoreV1().ConfigMaps(s.core.Namespace).Create(ctx, object, metav1.CreateOptions{})
				}
				if err != nil {
					t.Fatal(err)
				}
				pin.UID, pin.SHA256 = string(object.UID), kube.ContentHash([]any{object.Data, object.BinaryData})
			} else {
				object, err := client.CoreV1().Secrets(s.core.Namespace).Get(ctx, input.Name, metav1.GetOptions{})
				if err != nil {
					object = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: input.Name, Namespace: s.core.Namespace, UID: types.UID("actual-" + input.Name)}, Immutable: &yes, Data: map[string][]byte{}}
					for key := range projectionKeys[input.Kind+"/"+input.Name] {
						object.Data[key] = []byte("component-projection")
					}
					object, err = client.CoreV1().Secrets(s.core.Namespace).Create(ctx, object, metav1.CreateOptions{})
				}
				if err != nil {
					t.Fatal(err)
				}
				pin.UID, pin.SHA256 = string(object.UID), kube.ContentHash(object.Data)
			}
			operation.MountIdentities = append(operation.MountIdentities, pin)
		}
		m.Operations[name] = operation
	}
	raw, _ = json.Marshal(m)
	file := filepath.Join(filepath.Dir(s.core.CaptureModules.Path), "materialized-declaration.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return client, file, hash(raw)
}

func TestOriginalCaptureSequenceGrantsThenActualMappingsThenMetadataComponent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := newMaterialProducerComponent(t, ctx)
	s, err := BeginOriginalCaptureSequence(ctx, f.installer, f.password, f.enrollment, f.definitionFile, f.definitionSHA, f.privateFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{f.core.CaptureModules.Path, s.materials.Discovery.GrantFile} {
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Fatal("metadata published before materialization", err)
		}
	}
	redis, objects, err := s.WorkerSourceMounts(ctx)
	if err != nil || redis.GrantSHA256 == "" || objects.GrantSHA256 == "" {
		t.Fatal("actual source grants unavailable", err)
	}
	redis.RedisPrefixes = append(redis.RedisPrefixes, "changed")
	if !s.definition.Until.Equal(f.definition.Until) {
		t.Fatal("begin changed absolute window")
	}
	client, file, digest := materializeSequenceFixture(t, ctx, s)
	receipt, err := s.Finalize(ctx, client, file, digest)
	if err != nil || receipt.Purpose != "functional_test" || !receipt.Until.Equal(f.definition.Until) || !receipt.NotBefore.Equal(f.definition.NotBefore) {
		t.Fatal("ordered actual owner/signature/consumer composition", err)
	}
	materials, raw := checkComponentMaterialOutputs(t, f)
	if receipt.SHA256 != hash(raw) || materials.Operations["capture-source-redis"].Formal.ConfigSHA256 == s.materials.Operations["capture-source-redis"].Formal.ConfigSHA256 {
		t.Fatal("final metadata omitted materialized mapping bytes")
	}
	if f.model.executions.Load() != 0 || f.model.openTx.Load() != 0 {
		t.Fatal("sequence changed SQL or retained a transaction")
	}
	queries := f.model.queries.Load()
	if again, err := s.Finalize(ctx, client, file, digest); err == nil || again != (ProductionMaterialReceipt{}) || f.model.queries.Load() != queries {
		t.Fatal("completed one-shot sequence resumed signing/authority checks", err)
	}
	after, err := os.ReadFile(receipt.File)
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("second finalization changed successful output", err)
	}
}

func TestOriginalCaptureSequenceRejectsWideningAndForgedObservedUIDComponent(t *testing.T) {
	for _, fault := range []string{"scope", "uid", "mapping", "template", "definition-window", "expired"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			f := newMaterialProducerComponent(t, ctx)
			s, err := BeginOriginalCaptureSequence(ctx, f.installer, f.password, f.enrollment, f.definitionFile, f.definitionSHA, f.privateFile)
			if err != nil {
				t.Fatal(err)
			}
			client, file, digest := materializeSequenceFixture(t, ctx, s)
			originalMaterial, _ := os.ReadFile(file)
			originalDefinition, _ := os.ReadFile(f.definitionFile)
			if fault == "expired" {
				f.model.clockBeyondOriginalWindow.Store(true)
			} else if fault == "definition-window" {
				changed := f.definition
				changed.Until = changed.Until.Add(time.Minute)
				raw, _ := json.Marshal(changed)
				if err := os.WriteFile(f.definitionFile, raw, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				raw, _ := os.ReadFile(file)
				var m productionCaptureMaterials
				_ = json.Unmarshal(raw, &m)
				operation := m.Operations["capture-source-redis"]
				switch fault {
				case "scope":
					m.Redis.RedisPrefixes = append(m.Redis.RedisPrefixes, "wider:")
				case "uid":
					operation.MountIdentities[0].UID = "claimed-unobserved-uid"
				case "mapping":
					operation.Formal.ConfigSHA256 = hash([]byte("unobserved-mapping"))
				case "template":
					operation.Workload.StagingClaim = "unselected-staging"
				}
				m.Operations["capture-source-redis"] = operation
				raw, _ = json.Marshal(m)
				digest = hash(raw)
				if err := os.WriteFile(file, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if receipt, err := s.Finalize(ctx, client, file, digest); err == nil || receipt != (ProductionMaterialReceipt{}) {
				t.Fatal("unobserved/widened/expired material produced receipt", err)
			}
			if _, err := os.Stat(f.core.CaptureModules.Path); !os.IsNotExist(err) {
				t.Fatal("rejected stage published bundle", err)
			}
			// Remove the injected cause. Rejection must still be permanent for
			// THIS original sequence; none of its authority/windows is replaced.
			f.model.clockBeyondOriginalWindow.Store(false)
			if err := os.WriteFile(file, originalMaterial, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.definitionFile, originalDefinition, 0600); err != nil {
				t.Fatal(err)
			}
			queries := f.model.queries.Load()
			if again, err := s.Finalize(ctx, client, file, hash(originalMaterial)); err == nil || again != (ProductionMaterialReceipt{}) || f.model.queries.Load() != queries {
				t.Fatal("failed sequence recovered after original inputs were restored", err)
			}
		})
	}
}

func TestOriginalCaptureSequenceRejectsForeignContextPermanentlyComponent(t *testing.T) {
	for _, entry := range []string{"mounts", "finalize"} {
		for _, kind := range []string{"nil", "child", "canceled-child"} {
			t.Run(entry+"/"+kind, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				f := newMaterialProducerComponent(t, ctx)
				s, err := BeginOriginalCaptureSequence(ctx, f.installer, f.password, f.enrollment, f.definitionFile, f.definitionSHA, f.privateFile)
				if err != nil {
					t.Fatal(err)
				}
				client, file, digest := materializeSequenceFixture(t, ctx, s)
				originalAuthority := s.authority
				files := map[string][]byte{}
				for _, name := range []string{s.materials.Redis.GrantFile, s.materials.Objects.GrantFile, f.definitionFile, file} {
					files[name], err = os.ReadFile(name)
					if err != nil {
						t.Fatal(err)
					}
				}
				var foreign context.Context
				if kind != "nil" {
					var stop context.CancelFunc
					foreign, stop = context.WithCancel(ctx)
					defer stop()
					if kind == "canceled-child" {
						stop()
					}
				}
				queries := f.model.queries.Load()
				if entry == "mounts" {
					if _, _, err := s.WorkerSourceMounts(foreign); err == nil {
						t.Fatal("foreign context acquired mounts")
					}
				} else if _, err := s.Finalize(foreign, client, file, digest); err == nil {
					t.Fatal("foreign context finalized metadata")
				}
				if _, _, err := s.WorkerSourceMounts(ctx); err == nil {
					t.Fatal("original context resurrected rejected sequence")
				}
				if again, err := s.Finalize(ctx, client, file, digest); err == nil || again != (ProductionMaterialReceipt{}) {
					t.Fatal("original context recovered signing", err)
				}
				if s.authority != originalAuthority || !s.definition.Until.Equal(f.definition.Until) || !s.definition.NotBefore.Equal(f.definition.NotBefore) || f.model.queries.Load() != queries {
					t.Fatal("rejection replaced original authority/window or touched owner SQL")
				}
				for name, before := range files {
					after, err := os.ReadFile(name)
					if err != nil || !bytes.Equal(before, after) {
						t.Fatal("context rejection changed original bytes", err)
					}
				}
				for _, name := range []string{f.core.CaptureModules.Path, s.materials.Discovery.GrantFile} {
					if _, err := os.Stat(name); !os.IsNotExist(err) {
						t.Fatal("context rejection published metadata", err)
					}
				}
			})
		}
	}
}

func TestOriginalCaptureSequencePostOutputFailureNeverResignsComponent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f := newMaterialProducerComponent(t, ctx)
	s, err := BeginOriginalCaptureSequence(ctx, f.installer, f.password, f.enrollment, f.definitionFile, f.definitionSHA, f.privateFile)
	if err != nil {
		t.Fatal(err)
	}
	client, file, digest := materializeSequenceFixture(t, ctx, s)
	f.armTail.Store(true)
	if receipt, err := s.Finalize(ctx, client, file, digest); err == nil || receipt != (ProductionMaterialReceipt{}) || !f.tailReached.Load() {
		t.Fatal("post-output original window failure was not exercised", err)
	}
	checkComponentMaterialOutputs(t, f)
	files := map[string][]byte{}
	for _, name := range f.outputs {
		files[name], err = os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
	}
	f.armTail.Store(false)
	f.model.clockBeyondOriginalWindow.Store(false)
	queries := f.model.queries.Load()
	if _, err := s.Finalize(ctx, client, file, digest); err == nil || f.model.queries.Load() != queries {
		t.Fatal("post-output failure resumed owner signing", err)
	}
	for name, before := range files {
		after, err := os.ReadFile(name)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("failed finalization overwrote/deleted original signed output", err)
		}
	}
}
