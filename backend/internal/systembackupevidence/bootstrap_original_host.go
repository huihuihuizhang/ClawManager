package systembackupevidence

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path"
	"reflect"
	"strings"
	"time"

	pd "clawreef/internal/systembackupproducer"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// BootstrapOriginalHostInput is an ORIGINAL owner-selected mapping. A must
// authenticate/sign these exact source pins before bootstrap. It is not a
// candidate-supplied workload hash, admission, or a provider permission.
// PeerPath is the actual SystemPeerConfig JSON file inside the named container.
type BootstrapOriginalHostInput struct {
	Scope                                                pd.Scope
	ClusterUID, Namespace, NamespaceUID                  string
	Pod, PodUID, ServiceAccount, ServiceAccountUID       string
	Container, Volume, PeerPath                          string
	PodSpecSHA256, ContainerImageID                      string
	PeerConfigMap, PeerConfigMapUID, PeerKey, PeerSHA256 string
}

// BootstrapOriginalHostObservation contains detached comparison facts from
// real GETs. Only A's authenticated original mapping and current same-tx owner
// guard can authorize their association with candidate service-host hashes.
// Observation freshness is short and is never extended at L4/final Guard.
type BootstrapOriginalHostObservation struct {
	Input                                               BootstrapOriginalHostInput
	WorkloadIdentitySHA256, PodSpecSHA256, SourceSHA256 string
	ObservedAt, Until                                   time.Time
}

// ObserveBootstrapOriginalHost is PREPARE-only native I/O. No enabled config,
// operation, future task/Job, producer receipt or caller Passed flag is used.
// Exact current immutable ConfigMap bytes are bound to the actual original
// Pod's read-only volume projection and to the production peer constructor.
func ObserveBootstrapOriginalHost(ctx context.Context, client kubernetes.Interface, original BootstrapOriginalHostInput) (BootstrapOriginalHostObservation, error) {
	var zero BootstrapOriginalHostObservation
	if ctx == nil || ctx.Err() != nil || nilSystemAdapter(client) || original.ClusterUID == "" || original.Namespace == "" || original.NamespaceUID == "" || original.Pod == "" || original.PodUID == "" || original.ServiceAccount == "" || original.ServiceAccountUID == "" || original.Container == "" || original.Volume == "" || original.PeerConfigMap == "" || original.PeerConfigMapUID == "" || original.PeerKey == "" || !digestPattern.MatchString(original.PeerSHA256) || !path.IsAbs(original.PeerPath) || path.Clean(original.PeerPath) != original.PeerPath || strings.ContainsAny(original.PeerPath, "\\\x00\r\n") {
		return zero, ErrDenied
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return zero, ErrDenied
	}
	if !digestPattern.MatchString(original.PodSpecSHA256) || original.ContainerImageID == "" {
		return zero, ErrDenied
	}
	observed := time.Now().UTC().Truncate(time.Microsecond)
	first, peer, err := readBootstrapOriginalHost(ctx, client, original)
	if err != nil {
		return zero, ErrDenied
	}
	authenticator, err := NewSystemPeerAuthenticator(peer)
	if err != nil || peer.Scope != original.Scope {
		return zero, ErrDenied
	}
	// Use the actual production identity encoding. Do not invent another hash
	// of Pod labels, SQL status, receipt primary keys or the observed health.
	workload := authenticator.workload
	authenticator.Close()
	second, again, err := readBootstrapOriginalHost(ctx, client, original)
	if err != nil || !reflect.DeepEqual(first, second) || !reflect.DeepEqual(peer, again) || ctx.Err() != nil || !time.Now().Before(peer.ExpiresAt) {
		return zero, ErrDenied
	}
	until := observed.Add(15 * time.Second)
	if peer.ExpiresAt.Before(until) {
		until = peer.ExpiresAt
	}
	if !time.Now().Before(until) {
		return zero, ErrDenied
	}
	return BootstrapOriginalHostObservation{Input: original, WorkloadIdentitySHA256: workload, PodSpecSHA256: first.podSpecSHA, SourceSHA256: first.sourceSHA, ObservedAt: observed, Until: until}, nil
}

type bootstrapOriginalHostNative struct{ podSpecSHA, sourceSHA string }

func readBootstrapOriginalHost(ctx context.Context, client kubernetes.Interface, input BootstrapOriginalHostInput) (bootstrapOriginalHostNative, SystemPeerConfig, error) {
	var zero bootstrapOriginalHostNative
	var noPeer SystemPeerConfig
	for _, pin := range [][2]string{{"kube-system", input.ClusterUID}, {input.Namespace, input.NamespaceUID}} {
		ns, err := client.CoreV1().Namespaces().Get(ctx, pin[0], metav1.GetOptions{})
		if err != nil || string(ns.UID) != pin[1] || ns.DeletionTimestamp != nil {
			return zero, noPeer, ErrDenied
		}
	}
	sa, err := client.CoreV1().ServiceAccounts(input.Namespace).Get(ctx, input.ServiceAccount, metav1.GetOptions{})
	if err != nil || string(sa.UID) != input.ServiceAccountUID || sa.DeletionTimestamp != nil {
		return zero, noPeer, ErrDenied
	}
	pod, err := client.CoreV1().Pods(input.Namespace).Get(ctx, input.Pod, metav1.GetOptions{})
	if err != nil || string(pod.UID) != input.PodUID || pod.Namespace != input.Namespace || pod.ResourceVersion == "" || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning || pod.Spec.ServiceAccountName != input.ServiceAccount {
		return zero, noPeer, ErrDenied
	}
	imageFound := false
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name != input.Container {
			continue
		}
		if imageFound || status.ImageID != input.ContainerImageID || status.ContainerID == "" || !status.Ready || status.State.Running == nil {
			return zero, noPeer, ErrDenied
		}
		imageFound = true
	}
	if !imageFound {
		return zero, noPeer, ErrDenied
	}
	cm, err := client.CoreV1().ConfigMaps(input.Namespace).Get(ctx, input.PeerConfigMap, metav1.GetOptions{})
	if err != nil || string(cm.UID) != input.PeerConfigMapUID || cm.Namespace != input.Namespace || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil || cm.Immutable == nil || !*cm.Immutable {
		return zero, noPeer, ErrDenied
	}
	data, text := cm.Data[input.PeerKey]
	binary, bin := cm.BinaryData[input.PeerKey]
	if text == bin {
		return zero, noPeer, ErrDenied
	}
	raw := binary
	if text {
		raw = []byte(data)
	}
	if len(raw) == 0 || len(raw) > 262144 || hash(raw) != input.PeerSHA256 {
		return zero, noPeer, ErrDenied
	}
	var peer SystemPeerConfig
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&peer) != nil || decoder.Decode(new(any)) != io.EOF {
		return zero, noPeer, ErrDenied
	}
	canonical, err := json.Marshal(peer)
	if err != nil || !bytes.Equal(canonical, raw) || peer.Scope != input.Scope {
		return zero, noPeer, ErrDenied
	}
	// Ordinary ConfigMap volume only. Projected overlays, subpaths, env-derived
	// config, init containers and alternate mount aliases cannot establish this
	// exact immutable peer source relationship.
	var volume *corev1.ConfigMapVolumeSource
	for _, v := range pod.Spec.Volumes {
		if v.Name == input.Volume {
			if volume != nil || v.ConfigMap == nil || v.ConfigMap.Name != input.PeerConfigMap || v.ConfigMap.Optional != nil && *v.ConfigMap.Optional {
				return zero, noPeer, ErrDenied
			}
			volume = v.ConfigMap
		}
	}
	if volume == nil {
		return zero, noPeer, ErrDenied
	}
	relative := input.PeerKey
	if len(volume.Items) != 0 {
		relative = ""
		paths := map[string]bool{}
		for _, item := range volume.Items {
			if item.Path == "" || path.IsAbs(item.Path) || path.Clean(item.Path) != item.Path || item.Path == ".." || strings.HasPrefix(item.Path, "../") || paths[item.Path] {
				return zero, noPeer, ErrDenied
			}
			paths[item.Path] = true
			if item.Key == input.PeerKey {
				if relative != "" {
					return zero, noPeer, ErrDenied
				}
				relative = item.Path
			}
		}
	}
	if relative == "" {
		return zero, noPeer, ErrDenied
	}
	found := false
	for _, container := range pod.Spec.Containers {
		if container.Name != input.Container {
			continue
		}
		for _, mount := range container.VolumeMounts {
			if mount.Name != input.Volume {
				continue
			}
			if found || !mount.ReadOnly || mount.SubPath != "" || mount.SubPathExpr != "" || mount.MountPropagation != nil || !path.IsAbs(mount.MountPath) || path.Clean(mount.MountPath) != mount.MountPath || path.Join(mount.MountPath, relative) != input.PeerPath {
				return zero, noPeer, ErrDenied
			}
			found = true
		}
		for _, mount := range container.VolumeMounts {
			if mount.Name != input.Volume && (input.PeerPath == mount.MountPath || strings.HasPrefix(input.PeerPath, strings.TrimSuffix(mount.MountPath, "/")+"/")) {
				return zero, noPeer, ErrDenied
			}
		}
	}
	if !found {
		return zero, noPeer, ErrDenied
	}
	spec, err := json.Marshal(pod.Spec)
	if err != nil || hash(spec) != input.PodSpecSHA256 {
		return zero, noPeer, ErrDenied
	}
	// Bind immutable source, exact resource versions and mounted bytes. The
	// signed original pin remains input.PeerSHA256, not this observed digest.
	source, err := json.Marshal(struct {
		Input                                                   BootstrapOriginalHostInput
		PodResourceVersion, ConfigResourceVersion, ConfigSHA256 string
	}{input, pod.ResourceVersion, cm.ResourceVersion, hash(raw)})
	if err != nil {
		return zero, noPeer, ErrDenied
	}
	return bootstrapOriginalHostNative{podSpecSHA: hash(spec), sourceSHA: hash(source)}, peer, nil
}
