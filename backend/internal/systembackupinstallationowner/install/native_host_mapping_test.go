package install

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	evidence "clawreef/internal/systembackupevidence"
	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

// Existing actual bcrypt/signature/protocol fixtures and explicit SQL model;
// Kubernetes responses are controlled. No full bootstrap/native SQL claim.
func nativeMappedHostFixture(t *testing.T, ctx context.Context, f *authorityFixture, source *terminalIssueConnector, request pd.BootstrapConsumptionRequest) BootstrapNativeHostBinding {
	t.Helper()
	raw, err := ReadPrivateFile(f.files.ObserverFile, 262144)
	var observer observerDocument
	if err != nil || decodeExact(raw, &observer) != nil {
		t.Fatal("original public CA source")
	}
	ca, err := ReadPrivateFile(observer.CAFile, 65536)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	for _, row := range source.rows {
		if strings.HasSuffix(row.Table, "_domains") {
			var domain pd.DomainRecord
			if pd.DecodeStoredRecord(row, request.Scope, &domain) != nil {
				t.Fatal("original domain")
			}
			issuer = string(domain.IssuerIdentityHash)
		}
	}
	peer := evidence.SystemPeerConfig{Scope: request.Scope, IssuerIdentityHash: issuer, Subject: "original-bootstrap-service", ClientCAPEM: ca, ClientCASHA256: hash(ca), CertificateSHA256: strings.Repeat("d", 64), ExpiresAt: f.record.Until}
	peerRaw, err := json.Marshal(peer)
	if err != nil {
		t.Fatal(err)
	}
	b := f.record.Binding
	pod, err := f.i.kube.CoreV1().Pods(b.Namespace).Get(ctx, b.PodName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pod.ResourceVersion = "native-host-version-1"
	pod.Spec.Containers = []corev1.Container{{Name: "service", Image: "original.invalid/service@sha256:" + strings.Repeat("a", 64), VolumeMounts: []corev1.VolumeMount{{Name: "peer", MountPath: "/run/peer", ReadOnly: true}}}}
	pod.Spec.Volumes = []corev1.Volume{{Name: "peer", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "original-peer"}, Items: []corev1.KeyToPath{{Key: "peer.json", Path: "peer.json"}}}}}}
	image := "docker-pullable://original.invalid/service@sha256:" + strings.Repeat("a", 64)
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "service", ImageID: image, ContainerID: "containerd://actual-controlled-container", Ready: true, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}
	if _, err := f.i.kube.CoreV1().Pods(b.Namespace).Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	yes := true
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "original-peer", Namespace: b.Namespace, UID: types.UID("original-peer-uid"), ResourceVersion: "native-peer-version-1"}, Immutable: &yes, Data: map[string]string{"peer.json": string(peerRaw)}}
	// Seed this distinct native source directly in the controlled tracker.
	// The existing enrollment-create reactor intentionally assigns enrollment's
	// fixed UID; it is not a native peer ConfigMap creation fixture.
	if err := f.i.kube.(*kubefake.Clientset).Tracker().Create(corev1.SchemeGroupVersion.WithResource("configmaps"), cm, b.Namespace); err != nil {
		t.Fatal(err)
	}
	specRaw, err := json.Marshal(pod.Spec)
	if err != nil {
		t.Fatal(err)
	}
	input := evidence.BootstrapOriginalHostInput{Scope: request.Scope, ClusterUID: f.i.plan.Target.ClusterID, Namespace: b.Namespace, NamespaceUID: b.NamespaceUID, Pod: b.PodName, PodUID: b.PodUID, ServiceAccount: b.ServiceAccountName, ServiceAccountUID: b.ServiceAccountUID, Container: "service", Volume: "peer", PeerPath: "/run/peer/peer.json", PodSpecSHA256: hash(specRaw), ContainerImageID: image, PeerConfigMap: cm.Name, PeerConfigMapUID: string(cm.UID), PeerKey: "peer.json", PeerSHA256: hash(peerRaw)}
	observed, err := evidence.ObserveBootstrapOriginalHost(ctx, f.i.kube, input)
	if err != nil {
		t.Fatal("actual production peer encoding/native observer", err)
	}
	for table, row := range source.rows {
		if !strings.HasSuffix(table, "_grants") {
			continue
		}
		var grant pd.GrantRecord
		if pd.DecodeStoredRecord(row, request.Scope, &grant) != nil {
			t.Fatal("original grant")
		}
		grant.Host.Service.WorkloadIdentityHash = pd.Hash(observed.WorkloadIdentitySHA256)
		source.rows[table], err = pd.EncodeStoredRecord(&grant)
		if err != nil {
			t.Fatal(err)
		}
	}
	return BootstrapNativeHostBinding{WorkloadIdentitySHA256: observed.WorkloadIdentitySHA256, ProducerIssuerIdentitySHA256: issuer, Source: input}
}

func TestOriginalNativeHostMappingActuallyDerivesC1WorkloadAndBridgesProfiles(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f, source, request, pack := terminalMappingIssueFixture(t, ctx)
	binding := nativeMappedHostFixture(t, ctx, f, source, request)
	bundle, err := f.i.IssueBootstrapOriginalNativeMapping(ctx, f.password, f.enrollment, pack, hash(pack), request, nil, strings.Repeat("e", 64), filepath.Join(t.TempDir(), "capacity"), []BootstrapNativeHostBinding{binding}, f.key)
	if err != nil {
		t.Fatal(err)
	}
	original, err := verifyBootstrapOriginalMapping(bundle.Original.Record, bundle.Original.Signature, f.i.public)
	if err != nil {
		t.Fatal(err)
	}
	native, err := verifyNativeHostMapping(bundle.NativeHosts.Record, bundle.NativeHosts.Signature, f.i.public, original, hash(bundle.Original.Record))
	if err != nil || len(native.Bindings) != 1 || native.Bindings[0] != binding || source.reads != 2 {
		t.Fatal("signed native association", err)
	}
	if original.Hosts[0].PodSpecSHA256 == binding.Source.PodSpecSHA256 {
		t.Fatal("fixture failed to distinguish JCS and raw Go JSON profiles")
	}
	observed, err := observeNativeMappedBootstrapHost(ctx, f.i.kube, original.Hosts[0], binding)
	if err != nil || observed.WorkloadIdentitySHA256 != original.Hosts[0].WorkloadIdentitySHA256 || observed.Until.Sub(observed.ObservedAt) > 15*time.Second {
		t.Fatal("real native source/production identity not used", err)
	}
	for _, mode := range []string{"workload", "issuer", "peer", "image", "raw-spec-profile"} {
		wrong := binding
		switch mode {
		case "workload":
			wrong.WorkloadIdentitySHA256 = strings.Repeat("f", 64)
		case "issuer":
			wrong.ProducerIssuerIdentitySHA256 = strings.Repeat("f", 64)
		case "peer":
			wrong.Source.PeerSHA256 = strings.Repeat("f", 64)
		case "image":
			wrong.Source.ContainerImageID = "different-actual-image"
		case "raw-spec-profile":
			wrong.Source.PodSpecSHA256 = original.Hosts[0].PodSpecSHA256
		}
		if _, err := observeNativeMappedBootstrapHost(ctx, f.i.kube, original.Hosts[0], wrong); err == nil {
			t.Fatal("native source accepted mismatched association", mode)
		}
	}
}

func TestNativeHostTerminalStillRefusesTwentyThreeMissingOwners(t *testing.T) {
	capture, files, resources := terminalSevenConcreteSources(t)
	native, err := NewNativeHostBootstrapTerminalOriginal(capture, files, resources, BootstrapNativeHostFiles{RecordFile: "absent", RecordSHA256: strings.Repeat("a", 64), SignatureFile: "absent"})
	if err != nil || len(native.MissingTerminalResources()) != 23 {
		t.Fatal("native host source invented another owner", err)
	}
	if prepared, err := native.PrepareBootstrapCandidates(context.Background(), sec.OfflineBootstrapGrant{}, sec.BootstrapConfig{}, pd.BootstrapConsumptionRequest{}); err != ErrInstall || prepared.Session != nil {
		t.Fatal("missing owners reached input/native preparation", err)
	}
}

func TestNativeHostCheckCopiesCannotReviveOriginal(t *testing.T) {
	original := &nativeBootstrapHostCheck{ctx: context.Background()}
	original.origin = original
	copy := reflect.New(reflect.TypeOf(original).Elem())
	copy.Elem().Set(reflect.ValueOf(original).Elem())
	if _, err := copy.Interface().(*nativeBootstrapHostCheck).AuthorizeIdentity(original.ctx, nil); err == nil || !original.failed.Load() || original.DependencyDeadline() != nil {
		t.Fatal("reflected copy revived host authority")
	}
	if original.RecheckIdentity(original.ctx, nil) == nil {
		t.Fatal("restored context revived failed native host check")
	}
}
