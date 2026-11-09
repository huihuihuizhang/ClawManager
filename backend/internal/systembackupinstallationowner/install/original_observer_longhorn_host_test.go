package install

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"clawreef/internal/systembackup/quiesce"
	owner "clawreef/internal/systembackupinstallationowner"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// This tests the real install validator with an HTTP Kubernetes fixture, not
// Installer.authenticate, real scheduling, Node/CRI mount or native hold.
// The positive case deliberately isolates namespace-coordinate resolution:
// it is not proof a cross-namespace Pod can mount the source PVC.
func TestOriginalLonghornObserverVolumeNamespaceCoordinates(t *testing.T) {
	for _, name := range []string{"separate-resource-and-provider-pod-namespace", "wrong-resource-namespace-uid", "wrong-resource-namespace", "wrong-provider-pod-uid", "tenant-source-still-requires-install-authorization"} {
		t.Run(name, func(t *testing.T) {
			var mu sync.Mutex
			var reads []string
			writes := 0
			objects := map[string]string{
				"/api/v1/namespaces/test-system":                                      `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"test-system","uid":"system-uid"}}`,
				"/api/v1/namespaces/test-user-1":                                      `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"test-user-1","uid":"tenant-uid"}}`,
				"/api/v1/namespaces/longhorn-system":                                  `{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"longhorn-system","uid":"longhorn-uid"}}`,
				"/api/v1/nodes/node":                                                  `{"apiVersion":"v1","kind":"Node","metadata":{"name":"node","uid":"node-uid"},"status":{"nodeInfo":{"operatingSystem":"linux"}}}`,
				"/api/v1/namespaces/test-system/persistentvolumeclaims/source":        `{"apiVersion":"v1","kind":"PersistentVolumeClaim","metadata":{"name":"source","namespace":"test-system","uid":"pvc-uid"},"spec":{"volumeName":"pv"}}`,
				"/api/v1/namespaces/test-user-1/persistentvolumeclaims/source":        `{"apiVersion":"v1","kind":"PersistentVolumeClaim","metadata":{"name":"source","namespace":"test-user-1","uid":"tenant-pvc-uid"},"spec":{"volumeName":"tenant-pv"}}`,
				"/api/v1/persistentvolumes/pv":                                        `{"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":"pv","uid":"pv-uid"},"spec":{"csi":{"driver":"driver.longhorn.io","volumeHandle":"volume"},"claimRef":{"namespace":"test-system","name":"source","uid":"pvc-uid"}}}`,
				"/api/v1/persistentvolumes/tenant-pv":                                 `{"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":"tenant-pv","uid":"tenant-pv-uid"},"spec":{"csi":{"driver":"driver.longhorn.io","volumeHandle":"volume"},"claimRef":{"namespace":"test-user-1","name":"source","uid":"tenant-pvc-uid"}}}`,
				"/apis/longhorn.io/v1beta2/namespaces/longhorn-system/volumes/volume": `{"apiVersion":"longhorn.io/v1beta2","kind":"Volume","metadata":{"name":"volume","namespace":"longhorn-system","uid":"volume-uid"}}`,
				"/api/v1/namespaces/test-user-1/pods/keeper":                          `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"keeper","namespace":"test-user-1","uid":"keeper-uid"},"spec":{"nodeName":"node"},"status":{"containerStatuses":[{"name":"keeper","containerID":"containerd://keeper","state":{"running":{}}}]}}`,
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.Method != http.MethodGet {
					writes++
					http.Error(w, "unexpected mutation", http.StatusMethodNotAllowed)
					return
				}
				reads = append(reads, r.URL.Path)
				body, ok := objects[r.URL.Path]
				if !ok {
					http.Error(w, "unknown read", http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			installer := &Installer{kube: client, plan: Plan{Target: owner.Target{InstallationID: "installation", Namespace: "test-system", NamespaceUID: "system-uid"}}}
			material := quiesce.LonghornExt4Materials{Version: quiesce.LonghornExt4Protocol, Sources: []quiesce.LonghornExt4SourceCoordinates{{
				LonghornNamespace: "longhorn-system", ProviderNamespaceUID: "longhorn-uid", OriginalSourceSHA256: strings.Repeat("a", 64),
				Binding: quiesce.ObservationBinding{Kind: quiesce.LonghornExt4Protocol, InstallationID: "installation", Namespace: "test-system", NamespaceUID: "system-uid", Node: "node", NodeUID: "node-uid"},
				PVCName: "source", PVCUID: "pvc-uid", PVUID: "pv-uid", VolumeHandle: "volume", ProviderNamespace: "test-user-1", ProviderPodName: "keeper", ProviderPodUID: "keeper-uid", ProviderContainerID: "containerd://keeper",
			}}}
			source := &material.Sources[0]
			switch name {
			case "wrong-resource-namespace-uid":
				source.ProviderNamespaceUID = "replacement-longhorn-uid"
			case "wrong-resource-namespace":
				source.LonghornNamespace = source.ProviderNamespace
			case "wrong-provider-pod-uid":
				source.ProviderPodUID = "replacement-keeper-uid"
			case "tenant-source-still-requires-install-authorization":
				source.Binding.Namespace, source.Binding.NamespaceUID = "test-user-1", "tenant-uid"
				source.PVCUID, source.PVUID = "tenant-pvc-uid", "tenant-pv-uid"
			}
			raw, err := canonical(material)
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "longhorn-grants.json")
			if err := os.WriteFile(file, raw, 0600); err != nil {
				t.Fatal(err)
			}
			err = installer.validateOriginalLonghornObserverVolumes(context.Background(), BootstrapSourceFilePin{File: file, SHA256: hash(raw)})
			mu.Lock()
			defer mu.Unlock()
			if name == "separate-resource-and-provider-pod-namespace" {
				if err != nil {
					t.Fatal("distinct Longhorn resource / keeper Pod namespaces rejected", err, reads)
				}
				joined := strings.Join(reads, "\n")
				if !strings.Contains(joined, "/namespaces/longhorn-system/volumes/volume") || !strings.Contains(joined, "/namespaces/test-user-1/pods/keeper") {
					t.Fatal("did not read both independent namespaces", joined)
				}
			} else if !errors.Is(err, ErrInstall) {
				t.Fatal("changed coordinates accepted", err)
			}
			if name == "tenant-source-still-requires-install-authorization" && len(reads) != 0 {
				t.Fatal("unadmitted tenant source reached API observation", reads)
			}
			if name != "tenant-source-still-requires-install-authorization" && len(reads) == 0 {
				t.Fatal("valid material did not reach actual API identity checks", err)
			}
			if writes != 0 {
				t.Fatal("validator issued mutations", writes)
			}
		})
	}
}
