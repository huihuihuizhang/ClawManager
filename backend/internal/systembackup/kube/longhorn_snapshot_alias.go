package kube

import (
	"context"
	"reflect"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const longhornAliasOriginAnnotation = "backup.clawmanager.io/snapshot-origin-sha256"

// LonghornSnapshotAliasPin binds the worker namespace's reference to the
// original cut. Content is journaled by the separate cluster content owner.
type LonghornSnapshotAliasPin struct {
	NamespaceUID      string
	Snapshot, Content ResourceRecord
}

func retainedContentNamespace(content *unstructured.Unstructured) (string, bool) {
	const prefix = "sbk-ref-"
	spec := func(fields ...string) string {
		return longhornSnapshotString(content, append([]string{"spec"}, fields...)...)
	}
	namespace := spec("volumeSnapshotRef", "namespace")
	source, _, _ := strings.Cut(strings.TrimPrefix(spec("source", "snapshotHandle"), "snap://"), "/")
	return namespace, content.GetNamespace() == "" && strings.HasPrefix(content.GetName(), prefix) &&
		len(content.GetName()) == len(prefix)+48 && len(content.GetAnnotations()[longhornAliasOriginAnnotation]) == 64 &&
		spec("driver") == longhornSnapshotDriver && spec("deletionPolicy") == "Retain" && spec("sourceVolumeMode") == "Filesystem" &&
		spec("volumeSnapshotRef", "apiVersion") == longhornSnapshotGroup+"/v1" && spec("volumeSnapshotRef", "kind") == "VolumeSnapshot" &&
		namespace != "" && spec("volumeSnapshotRef", "uid") != "" && spec("volumeSnapshotRef", "name") != "" &&
		spec("source", "volumeHandle") == "" && longhornLocalSnapshotHandle(source, spec("source", "snapshotHandle"))
}

// BuildLonghornSnapshotAlias prepares the namespaced request for Runner.Ensure.
// The source cut must already have been verified under the original authority.
func BuildLonghornSnapshotAlias(ctx context.Context, client kubernetes.Interface, api dynamic.Interface, pin LonghornSnapshotPin, target Identity, targetNamespaceUID string) (*unstructured.Unstructured, error) {
	if _, err := verifyLonghornSourceCut(ctx, client, api, pin); err != nil {
		return nil, err
	}
	return longhornAliasRequest(ctx, client, pin, target, targetNamespaceUID)
}

// BuildLonghornSnapshotAliasContent prepares a cluster-scoped request. It does
// not dispatch it or confer authority to create arbitrary snapshot content.
func BuildLonghornSnapshotAliasContent(ctx context.Context, client kubernetes.Interface, api dynamic.Interface, pin LonghornSnapshotPin) (*unstructured.Unstructured, error) {
	cut, err := verifyLonghornSourceCut(ctx, client, api, pin)
	if err != nil {
		return nil, err
	}
	_, content, err := longhornAliasObjects(ctx, client, api, pin, cut)
	return content, err
}

func longhornAliasRequest(ctx context.Context, client kubernetes.Interface, pin LonghornSnapshotPin, target Identity, targetNamespaceUID string) (*unstructured.Unstructured, error) {
	source := pin.Snapshot.Intent.Identity
	if pin.AccessMode != corev1.ReadWriteOnce || !target.valid() || target.Namespace == source.Namespace || target.Owner != source.Owner || targetNamespaceUID == "" || targetNamespaceUID == pin.NamespaceUID {
		return nil, ErrResource
	}
	ns, err := client.CoreV1().Namespaces().Get(ctx, target.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != targetNamespaceUID || ns.DeletionTimestamp != nil {
		return nil, ErrOwnership
	}
	contentName := "sbk-ref-" + ContentHash([]string{pin.NamespaceUID, pin.Snapshot.UID, targetNamespaceUID, target.Name, target.Owner})[:48]
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": longhornSnapshotGroup + "/v1", "kind": "VolumeSnapshot",
		"metadata": map[string]any{"name": target.Name, "namespace": target.Namespace, "labels": map[string]any{OwnerLabel: target.Owner}},
		"spec":     map[string]any{"source": map[string]any{"volumeSnapshotContentName": contentName}},
	}}, nil
}

func longhornAliasObjects(ctx context.Context, client kubernetes.Interface, api dynamic.Interface, pin LonghornSnapshotPin, cut longhornSourceCut) (*unstructured.Unstructured, *unstructured.Unstructured, error) {
	alias := pin.Alias
	if alias == nil || !longhornOwnedRecord(alias.Snapshot, "VolumeSnapshot") {
		return nil, nil, ErrResource
	}
	id := alias.Snapshot.Intent.Identity
	request, err := longhornAliasRequest(ctx, client, pin, id, alias.NamespaceUID)
	if err != nil {
		return nil, nil, err
	}
	intent, err := Intent("VolumeSnapshot", request)
	if err != nil || !sameIntent(intent, alias.Snapshot.Intent) {
		return nil, nil, ErrOwnership
	}
	name := longhornSnapshotString(request, "spec", "source", "volumeSnapshotContentName")
	snapshot, err := api.Resource(longhornSnapshotResource("volumesnapshots")).Namespace(id.Namespace).Get(ctx, id.Name, metav1.GetOptions{})
	if err != nil || !owned(alias.Snapshot, snapshot) || snapshot.GetDeletionTimestamp() != nil ||
		!reflect.DeepEqual(snapshot.Object["spec"], request.Object["spec"]) {
		return nil, nil, ErrOwnership
	}
	spec := map[string]any{
		"driver": longhornSnapshotDriver, "deletionPolicy": "Retain", "sourceVolumeMode": "Filesystem",
		"source": map[string]any{"snapshotHandle": pin.BackendSnapshotHandle},
		"volumeSnapshotRef": map[string]any{"apiVersion": longhornSnapshotGroup + "/v1", "kind": "VolumeSnapshot",
			"name": id.Name, "namespace": id.Namespace, "uid": alias.Snapshot.UID},
	}
	content := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": longhornSnapshotGroup + "/v1", "kind": "VolumeSnapshotContent",
		"metadata": map[string]any{"name": name, "labels": map[string]any{OwnerLabel: id.Owner},
			"annotations": map[string]any{longhornAliasOriginAnnotation: ContentHash([]any{name, id.Owner, cut.contentUID, cut.contentSHA256, spec})}},
		"spec": spec,
	}}
	return snapshot, content, nil
}

func verifyLonghornSnapshotAlias(ctx context.Context, client kubernetes.Interface, api dynamic.Interface, pin LonghornSnapshotPin, cut longhornSourceCut) error {
	snapshot, expected, err := longhornAliasObjects(ctx, client, api, pin, cut)
	if err != nil {
		return err
	}
	record := pin.Alias.Content
	if !longhornOwnedRecord(record, "VolumeSnapshotContent") || record.UID == cut.contentUID {
		return ErrResource
	}
	intent, err := Intent("VolumeSnapshotContent", expected)
	if err != nil || !sameIntent(intent, record.Intent) {
		return ErrOwnership
	}
	content, err := api.Resource(longhornSnapshotResource("volumesnapshotcontents")).Get(ctx, expected.GetName(), metav1.GetOptions{})
	if err != nil || !owned(record, content) || content.GetDeletionTimestamp() != nil {
		return ErrOwnership
	}
	for _, obj := range []*unstructured.Unstructured{snapshot, content} {
		ready, _, err := unstructured.NestedBool(obj.Object, "status", "readyToUse")
		if err != nil {
			return ErrOwnership
		}
		if !ready {
			return ErrPending
		}
		if _, present, err := unstructured.NestedFieldNoCopy(obj.Object, "status", "error"); present || err != nil {
			return ErrOwnership
		}
	}
	// The sidecar can supply the alias creation timestamp locally. The original
	// dynamic snapshot timestamp remains the only timestamp checked against the cut.
	if longhornSnapshotString(snapshot, "status", "boundVolumeSnapshotContentName") != content.GetName() ||
		longhornSnapshotString(content, "status", "snapshotHandle") != pin.BackendSnapshotHandle || ctx.Err() != nil {
		return ErrOwnership
	}
	return nil
}
