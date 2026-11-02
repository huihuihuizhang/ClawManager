package systembackupexecution

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"clawreef/internal/services"
	b "clawreef/internal/systembackup/publicadapter"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Independently declared protocol state. HTTP responses are served through
// actual pinned TLS/credentials and parsed by real production clients. This
// model is not a native stopped witness or certification of a deployed site.
type sourceProtocolScenario struct {
	mu        sync.Mutex
	empty     bool
	fault     string
	server    *httptest.Server
	core      DeploymentConfig
	objects   map[string]runtime.Object
	reads     map[string]int
	mutations int
	version2  bool
	sequence  int
	events    map[string][]int
}

func newSourceProtocolScenario(t *testing.T, empty bool) *sourceProtocolScenario {
	t.Helper()
	s := &sourceProtocolScenario{empty: empty, objects: map[string]runtime.Object{}, reads: map[string]int{}, events: map[string][]int{}}
	s.server = httptest.NewUnstartedServer(http.HandlerFunc(s.serveHTTP))
	s.server.TLS = sourceProtocolOriginalTLS(t)
	s.server.StartTLS()
	t.Cleanup(s.server.Close)
	return s
}

func (s *sourceProtocolScenario) configureCore(t *testing.T, f *dOriginalSixPartTask, cfg *DeploymentConfig) {
	t.Helper()
	if cfg.Namespace != "backup" {
		t.Fatal("explicit protocol namespace changed")
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.server.Certificate().Raw})
	cfg.RuntimeSources.Supported = append(cfg.RuntimeSources.Supported, b.AgentKind{Type: "openclaw", Mode: "lite", Variant: "linux", OS: "linux"})
	cfg.RuntimeSources.AgentTokenFile = filepath.Join(f.directory, "protocol-agent-token")
	cfg.RuntimeSources.AgentCAFile = filepath.Join(f.directory, "protocol-agent-ca.pem")
	cfg.RuntimeSources.AgentCASHA256 = hash(ca)
	if err := os.WriteFile(cfg.RuntimeSources.AgentTokenFile, []byte("source-protocol-native-token"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.RuntimeSources.AgentCAFile, ca, 0600); err != nil {
		t.Fatal(err)
	}
	if !s.empty {
		cfg.RuntimeSources.Deployments = []PlatformDeployment{{Namespace: cfg.Namespace, Name: "source-agent", UID: "source-agent-dep-uid"}}
	}
	s.core = *cfg
}

func protocolType(object runtime.Object) (string, string, string, error) {
	access, err := meta.Accessor(object)
	if err != nil {
		return "", "", "", err
	}
	kind, version := "", "v1"
	switch object.(type) {
	case *corev1.Namespace:
		kind = "Namespace"
	case *corev1.Node:
		kind = "Node"
	case *corev1.Pod:
		kind = "Pod"
	case *corev1.ServiceAccount:
		kind = "ServiceAccount"
	case *corev1.PersistentVolumeClaim:
		kind = "PersistentVolumeClaim"
	case *corev1.PersistentVolume:
		kind = "PersistentVolume"
	case *corev1.ConfigMap:
		kind = "ConfigMap"
	case *corev1.Secret:
		kind = "Secret"
	case *appsv1.Deployment:
		kind, version = "Deployment", "apps/v1"
	case *appsv1.ReplicaSet:
		kind, version = "ReplicaSet", "apps/v1"
	default:
		return "", "", "", fmt.Errorf("unsupported protocol object %T", object)
	}
	object.GetObjectKind().SetGroupVersionKind(schema.FromAPIVersionAndKind(version, kind))
	if access.GetResourceVersion() == "" {
		access.SetResourceVersion("protocol-object-r1")
	}
	return kind, access.GetNamespace(), access.GetName(), nil
}

func (s *sourceProtocolScenario) addObject(object runtime.Object) error {
	object = object.DeepCopyObject()
	// This is explicit fixture setup before signing the metadata envelope,
	// never normalization of an observed production API response.
	if deployment, ok := object.(*appsv1.Deployment); ok && deployment.Name == "d-source-controller" {
		one := int32(1)
		deployment.Spec.Replicas = &one
		deployment.Generation = 1
		deployment.Status = appsv1.DeploymentStatus{ObservedGeneration: 1, Replicas: 1, ReadyReplicas: 1}
	}
	if pod, ok := object.(*corev1.Pod); ok && pod.Name == "d-source-pod" {
		pod.Spec.NodeName = "node"
		pod.Spec.Containers = []corev1.Container{{Name: s.core.StagingLocation.Container, Image: s.core.WorkerImage, VolumeMounts: []corev1.VolumeMount{{Name: s.core.StagingLocation.Volume, MountPath: s.core.StagingLocation.ContainerPath}}}}
		pod.Spec.Volumes = []corev1.Volume{{Name: s.core.StagingLocation.Volume, VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: s.core.StagingClaim}}}}
		pod.Status.ContainerStatuses = protocolRunningStatus(s.core.StagingLocation.Container)
		pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	}
	kind, namespace, name, err := protocolType(object)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[kind+"/"+namespace+"/"+name] = object
	return nil
}

func protocolRunningStatus(name string) []corev1.ContainerStatus {
	return []corev1.ContainerStatus{{Name: name, Ready: true, ContainerID: "containerd://protocol-" + name, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))}}}}
}

func (s *sourceProtocolScenario) installAPI(t *testing.T, cfg DeploymentConfig) kubernetes.Interface {
	t.Helper()
	one, controller := int32(1), true
	objects := []runtime.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: cfg.Namespace, UID: types.UID(cfg.NamespaceUID)}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node", UID: "node-uid", Labels: map[string]string{corev1.LabelOSStable: "linux"}}},
		&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: cfg.Namespace, UID: "source-uid"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "source-pv"}},
		&corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "source-pv", UID: "source-pv-uid"}, Spec: corev1.PersistentVolumeSpec{ClaimRef: &corev1.ObjectReference{Name: "source", Namespace: cfg.Namespace, UID: "source-uid"}}},
	}
	node, claim, pv := publicationStagingFixtureObjects(t, cfg)
	objects = append(objects, node, claim, pv)
	labels := map[string]string{"app": "source-platform"}
	objects = append(objects,
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "source", Namespace: cfg.Namespace, UID: "dep-uid", Generation: 1}, Spec: appsv1.DeploymentSpec{Replicas: &one, Selector: &metav1.LabelSelector{MatchLabels: labels}}, Status: appsv1.DeploymentStatus{ObservedGeneration: 1, Replicas: 1, ReadyReplicas: 1}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "source-rs", Namespace: cfg.Namespace, UID: "source-rs-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "source", UID: "dep-uid", Controller: &controller}}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "source-platform-pod", Namespace: cfg.Namespace, UID: "source-platform-pod-uid", Labels: labels, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "source-rs", UID: "source-rs-uid", Controller: &controller}}}, Spec: corev1.PodSpec{NodeName: "node", Containers: []corev1.Container{{Name: "platform", Image: cfg.WorkerImage}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: protocolRunningStatus("platform")}},
	)
	if !s.empty {
		labels = map[string]string{"app": "source-agent"}
		objects = append(objects,
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "source-agent", Namespace: cfg.Namespace, UID: "source-agent-dep-uid", Generation: 1}, Spec: appsv1.DeploymentSpec{Replicas: &one, Selector: &metav1.LabelSelector{MatchLabels: labels}}, Status: appsv1.DeploymentStatus{ObservedGeneration: 1, Replicas: 1, ReadyReplicas: 1}},
			&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "source-agent-rs", Namespace: cfg.Namespace, UID: "source-agent-rs-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "source-agent", UID: "source-agent-dep-uid", Controller: &controller}}}},
		)
		for _, name := range []string{"source-agent-pod", "source-protocol-pro-109"} {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: cfg.Namespace, UID: types.UID(name + "-uid"), Labels: labels}, Spec: corev1.PodSpec{NodeName: "node", Containers: []corev1.Container{{Name: "runtime", Image: "original/openclaw@sha256:" + strings.Repeat("a", 64), VolumeMounts: []corev1.VolumeMount{{Name: "workspace", MountPath: "/workspaces", SubPath: cfg.Workspace.SubPath}}}}, Volumes: []corev1.Volume{{Name: "workspace", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "source"}}}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "127.0.0.1", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: protocolRunningStatus("runtime")}}
			if name == "source-agent-pod" {
				pod.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "source-agent-rs", UID: "source-agent-rs-uid", Controller: &controller}}
			}
			objects = append(objects, pod)
		}
		objects = append(objects, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "application-original", Namespace: cfg.Namespace, UID: "application-cm-uid"}, Data: map[string]string{"original": "protocol source"}}, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "original", Namespace: cfg.Namespace, UID: "application-secret-uid"}, Type: corev1.SecretTypeOpaque})
	}
	for _, object := range objects {
		if err := s.addObject(object); err != nil {
			t.Fatal(err)
		}
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.server.Certificate().Raw})
	client, err := kubernetes.NewForConfig(&rest.Config{Host: s.server.URL, BearerToken: "source-protocol-controller-token", TLSClientConfig: rest.TLSClientConfig{CAData: ca}, QPS: 10000, Burst: 10000, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func (s *sourceProtocolScenario) installPublicCA(f *dOriginalSixPartTask) {
	immutable := true
	if err := s.addObject(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "d-original-kms-ca", Namespace: s.core.Namespace, UID: "d-original-kms-ca-uid"}, Immutable: &immutable, Data: map[string]string{"ca.pem": string(f.owner.Issuer.ServerRoots)}}); err != nil {
		panic(err)
	}
}

func (s *sourceProtocolScenario) serveHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	s.reads[r.Method+" "+r.URL.Path]++
	s.sequence++
	if r.Method != "GET" && !(r.Method == "POST" && strings.HasSuffix(r.URL.Path, "reviews")) {
		s.mutations++
		http.Error(w, "protocol source is read-only", http.StatusForbidden)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v1/") {
		s.serveNative(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/skill-bucket") {
		s.serveObjects(w, r)
		return
	}
	metadataToken := r.Header.Get("Authorization") == "Bearer named-d-metadata-token"
	controllerToken := r.Header.Get("Authorization") == "Bearer source-protocol-controller-token"
	if !metadataToken && !controllerToken {
		http.Error(w, "original API principal required", http.StatusForbidden)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/selfsubjectreviews") && metadataToken {
		json.NewEncoder(w).Encode(map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview", "status": map[string]any{"userInfo": map[string]any{"username": "system:serviceaccount:backup:d-metadata", "uid": "d-metadata-uid"}}})
		return
	}
	if strings.HasSuffix(r.URL.Path, "/selfsubjectrulesreviews") && metadataToken {
		json.NewEncoder(w).Encode(map[string]any{"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview", "status": map[string]any{"resourceRules": []any{map[string]any{"apiGroups": []string{""}, "resources": []string{"configmaps", "secrets"}, "verbs": []string{"get", "list"}}}}})
		return
	}
	if metadataToken && s.fault == "metadata-permission" {
		s.events["metadata-permission"] = append(s.events["metadata-permission"], s.sequence)
		http.Error(w, "metadata permission revoked", http.StatusForbidden)
		return
	}
	s.serveKubernetes(w, r, metadataToken)
}

func (s *sourceProtocolScenario) serveNative(w http.ResponseWriter, r *http.Request) {
	if s.empty || r.Header.Get("X-ClawManager-Control-Token") != "source-protocol-native-token" || s.fault == "native-permission" {
		if s.fault == "native-permission" {
			s.events["native-permission"] = append(s.events["native-permission"], s.sequence)
		}
		http.Error(w, "native principal unavailable", http.StatusForbidden)
		return
	}
	switch r.URL.Path {
	case "/v1/backup/capabilities":
		if r.URL.Query().Get("gateway_port") != "21007" {
			http.Error(w, "wrong slot", http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(services.RuntimeBackupCapabilities{Protocol: services.RuntimeBackupProtocol, Scope: services.RuntimeBackupStopScope, Namespace: "backup", PodUID: "source-agent-pod-uid", AgentEpoch: strings.Repeat("a", 32), Slot: "independent-protocol-slot", GatewayPort: 21007, Supported: true, DurableReservation: true, AgentRestartReconciliation: true})
	case "/v1/gateways/gw-107-5":
		generation := 5
		if s.fault == "native-generation" {
			generation++
			s.events["native-generation"] = append(s.events["native-generation"], s.sequence)
		}
		if s.fault == "final-metadata" && !s.version2 {
			s.version2 = true
			s.events["final-native-trigger"] = append(s.events["final-native-trigger"], s.sequence)
		}
		json.NewEncoder(w).Encode(services.RuntimeAgentGatewayState{UserID: 42, PID: 32107, Port: 21007, GatewayID: "gw-107-5", InstanceID: 107, Generation: generation, State: "running"})
	default:
		http.NotFound(w, r)
	}
}

func (s *sourceProtocolScenario) serveObjects(w http.ResponseWriter, r *http.Request) {
	if !strings.Contains(r.Header.Get("Authorization"), "Credential=d-object-access/") {
		http.Error(w, "object principal unavailable", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	switch {
	case r.URL.Query().Has("location"):
		fmt.Fprint(w, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`)
	case r.URL.Query().Has("versioning"):
		fmt.Fprint(w, `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`)
	case r.URL.Query().Has("versions") && r.URL.Query().Get("prefix") == "packages/":
		fmt.Fprint(w, `<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>skill-bucket</Name><Prefix>packages/</Prefix><IsTruncated>false</IsTruncated>`)
		if !s.empty {
			version := "source-protocol-v1"
			if s.version2 {
				version = "source-protocol-v2"
			}
			fmt.Fprintf(w, `<Version><Key>packages/original.zip</Key><VersionId>%s</VersionId><IsLatest>true</IsLatest><Size>3</Size></Version>`, version)
		}
		fmt.Fprint(w, `</ListVersionsResult>`)
		key := "initial-metadata-response"
		if s.version2 {
			key = "final-metadata-response"
		}
		s.events[key] = append(s.events[key], s.sequence)
	default:
		http.Error(w, "unexpected object operation", http.StatusForbidden)
	}
}

func (s *sourceProtocolScenario) serveKubernetes(w http.ResponseWriter, r *http.Request, metadataToken bool) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	version, namespace, resource, name := "v1", "", "", ""
	if len(parts) >= 5 && parts[0] == "apis" {
		version, parts = parts[1]+"/"+parts[2], parts[3:]
	} else if len(parts) >= 3 && parts[0] == "api" {
		parts = parts[2:]
	} else {
		http.NotFound(w, r)
		return
	}
	if len(parts) >= 3 && parts[0] == "namespaces" {
		namespace, parts = parts[1], parts[2:]
	}
	if len(parts) >= 1 {
		resource = parts[0]
	}
	if len(parts) == 2 {
		name = parts[1]
	}
	kinds := map[string]string{"namespaces": "Namespace", "nodes": "Node", "pods": "Pod", "serviceaccounts": "ServiceAccount", "persistentvolumeclaims": "PersistentVolumeClaim", "persistentvolumes": "PersistentVolume", "deployments": "Deployment", "replicasets": "ReplicaSet", "statefulsets": "StatefulSet", "daemonsets": "DaemonSet", "jobs": "Job", "cronjobs": "CronJob", "horizontalpodautoscalers": "HorizontalPodAutoscaler", "configmaps": "ConfigMap", "secrets": "Secret"}
	kind := kinds[resource]
	if kind == "" || namespace != "" && namespace != s.core.Namespace || metadataToken && resource != "configmaps" && resource != "secrets" {
		http.Error(w, "outside original API scope", http.StatusForbidden)
		return
	}
	if name != "" {
		if object := s.objects[kind+"/"+namespace+"/"+name]; object != nil {
			json.NewEncoder(w).Encode(object)
		} else {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(metav1.Status{Status: "Failure", Reason: metav1.StatusReasonNotFound, Code: 404})
		}
		return
	}
	keys := []string{}
	selector := r.URL.Query().Get("labelSelector")
	for key, object := range s.objects {
		if !strings.HasPrefix(key, kind+"/"+namespace+"/") {
			continue
		}
		access, _ := meta.Accessor(object)
		if selector != "" {
			pair := strings.SplitN(selector, "=", 2)
			if len(pair) != 2 || access.GetLabels()[pair[0]] != pair[1] {
				continue
			}
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	start := 0
	if value := r.URL.Query().Get("continue"); value != "" {
		var err error
		start, err = strconv.Atoi(strings.TrimPrefix(value, "page-"))
		if err != nil || start < 0 || start > len(keys) {
			http.Error(w, "invalid continuation", 400)
			return
		}
		s.reads["continued "+resource]++
	}
	end := len(keys)
	if r.URL.Query().Get("limit") != "" && start < end {
		end = start + 1
	}
	continuation, rv := "", "source-list-r1"
	if end < len(keys) {
		continuation = "page-" + strconv.Itoa(end)
	}
	if metadataToken && start > 0 && s.fault == "metadata-rv" {
		rv = "source-list-changed"
		s.events["metadata-rv"] = append(s.events["metadata-rv"], s.sequence)
	}
	if !metadataToken && start > 0 && s.fault == "writer-token" {
		continuation = r.URL.Query().Get("continue")
		s.events["writer-token"] = append(s.events["writer-token"], s.sequence)
	}
	items := []any{}
	partial := strings.Contains(r.Header.Get("Accept"), "as=PartialObjectMetadataList")
	for _, key := range keys[start:end] {
		if !metadataToken && key == "Deployment/backup/unknown-controller" {
			s.events["unknown-controller"] = append(s.events["unknown-controller"], s.sequence)
		}
		object := s.objects[key]
		if partial {
			access, _ := meta.Accessor(object)
			items = append(items, metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: access.GetName(), Namespace: access.GetNamespace(), UID: access.GetUID(), ResourceVersion: access.GetResourceVersion()}})
		} else {
			items = append(items, object)
		}
	}
	if partial {
		version, kind = "meta.k8s.io/v1", "PartialObjectMetadata"
	}
	json.NewEncoder(w).Encode(map[string]any{"apiVersion": version, "kind": kind + "List", "metadata": map[string]any{"resourceVersion": rv, "continue": continuation}, "items": items})
}

func (s *sourceProtocolScenario) seedSource(ctx context.Context, t *testing.T, f *dOriginalSixPartTask) {
	t.Helper()
	if s.empty {
		return // New schema: no users, instances, Teams, Skills or runtime rows.
	}
	queries := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO users(id,username,email,password_hash,role,is_active) VALUES(42,'protocol-source-owner','protocol@example.invalid','source-protocol-only','admin',TRUE)`, nil},
		{`INSERT INTO instances(id,user_id,name,type,instance_mode,runtime_type,runtime_variant,os_type,os_version,cpu_cores,memory_gb,disk_gb,status,runtime_generation,pod_name,pod_namespace,workspace_path,image_registry) VALUES(107,42,'independent-native-running','openclaw','lite','gateway','linux','linux','protocol',2,4,10,'running',5,'source-agent-pod','backup','/workspaces/42/107',?),(109,42,'independent-pro-running','openclaw','pro','desktop','linux','linux','protocol',2,4,10,'running',6,'source-protocol-pro-109','backup','/workspaces/42/109',?)`, []any{"original/openclaw@sha256:" + strings.Repeat("a", 64), "original/openclaw@sha256:" + strings.Repeat("a", 64)}},
		{`INSERT INTO runtime_pods(id,runtime_type,namespace,pod_name,pod_uid,pod_ip,node_name,deployment_name,image_ref,agent_endpoint,state) VALUES(71,'openclaw','backup','source-agent-pod','source-agent-pod-uid','127.0.0.1','node','source-agent',?,?,'ready')`, []any{"original/openclaw@sha256:" + strings.Repeat("a", 64), s.server.URL}},
		{`INSERT INTO instance_runtime_bindings(instance_id,runtime_pod_id,runtime_type,gateway_id,gateway_port,gateway_pid,workspace_path,state,generation) VALUES(107,71,'openclaw','gw-107-5',21007,32107,'/workspaces/42/107','running',5)`, nil},
		{`INSERT INTO teams(id,user_id,name,status,communication_mode,redis_events_last_id,resource_scope) VALUES(120,42,'independent-running-team','running','redis','0-0','cm')`, nil},
		{`INSERT INTO team_members(id,team_id,instance_id,user_id,member_key,display_name,role,runtime_type,instance_mode,status,progress,availability) VALUES(121,120,107,42,'protocol-member','Protocol member','worker','openclaw','lite','running',0,'available')`, nil},
		{`INSERT INTO skills(id,user_id,skill_key,name) VALUES(111,42,'independent-protocol-skill','Protocol skill')`, nil},
		{`INSERT INTO skill_blobs(id,content_hash,archive_hash,object_key,file_name,size_bytes) VALUES(112,?,?,'original.zip','original.zip',3)`, []any{strings.Repeat("a", 32), strings.Repeat("b", 64)}},
		{`INSERT INTO skill_versions(id,skill_id,blob_id,version_no,manifest_json) VALUES(113,111,112,1,'{}')`, nil},
		{`UPDATE skills SET current_version_id=113 WHERE id=111`, nil},
	}
	for _, query := range queries {
		if _, err := f.db.ExecContext(ctx, query.query, query.args...); err != nil {
			t.Fatal("independent source declaration", err)
		}
	}
}
