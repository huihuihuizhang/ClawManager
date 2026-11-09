package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
)

// The task runners use the existing controller SA and the original SQL
// journal. The signed source scope supplies the finite namespace set.
type originalLonghornExecutionClient struct {
	service *DeploymentService
	owner   *PublicJobOwner
}

func (s *DeploymentService) attachOriginalLonghornExecution(owner *PublicJobOwner) error {
	if !s.ForwardEnabled {
		return nil
	}
	if s.captureMaterials == nil || s.captureMaterials.Discovery == nil || len(s.captureMaterials.Discovery.LonghornSources) == 0 {
		return nil
	}
	if owner == nil || owner.longhornExecutor != nil || s.checkProductionCaptureMaterials() != nil {
		return kube.ErrOwnership
	}
	owner.longhornExecutor = &originalLonghornExecutionClient{service: s, owner: owner}
	return nil
}

func (c *originalLonghornExecutionClient) SourceRunner(ctx context.Context, in d.Input, plan plannedLonghornClone) (kube.Runner, error) {
	if _, _, err := c.frozenPlan(ctx, in, plan, false); err != nil {
		return kube.Runner{}, err
	}
	runner, err := c.owner.runner(in.Authority, false)
	if err != nil {
		return runner, err
	}
	runner.Client = longhornExecutionDynamic{Interface: c.owner.Dynamic, client: c, input: in, plan: plan}
	return runner, nil
}

func (c *originalLonghornExecutionClient) ContentRunner(ctx context.Context, in d.Input, plan plannedLonghornClone, pin kube.LonghornSnapshotPin) (kube.Runner, error) {
	if _, _, err := c.frozenPlan(ctx, in, plan, false); err != nil {
		return kube.Runner{}, err
	}
	if !originalLonghornPinMatches(pin, plan) || pin.Snapshot.Intent.Identity != plan.Snapshot || pin.Snapshot.UID == "" ||
		pin.BackendSnapshotHandle == "" || pin.ProviderSnapshotUID == "" {
		return kube.Runner{}, kube.ErrOwnership
	}
	runner, err := c.owner.runner(in.Authority, false)
	if err != nil {
		return runner, err
	}
	runner.Client = longhornExecutionDynamic{Interface: c.owner.Dynamic, client: c, input: in, plan: plan, content: true}
	runner.AuthorizeRetainedContent = func(ctx context.Context, intent kube.ResourceIntent) error {
		_, discovery, err := c.frozenPlan(ctx, in, plan, false)
		if err != nil {
			return err
		}
		expected, err := c.contentIntent(ctx, in, discovery, plan)
		if err != nil || !sameLonghornExecutionIntent(intent, expected) {
			return kube.ErrOwnership
		}
		return nil
	}
	return runner, nil
}

func (c *originalLonghornExecutionClient) frozenPlan(ctx context.Context, in d.Input, plan plannedLonghornClone, recovery bool) (d.Input, b.Discovery, error) {
	var empty d.Input
	var discovery b.Discovery
	if c == nil || c.owner == nil || c.service == nil || ctx == nil || ctx.Err() != nil || in.Authority.TaskType != "backup" ||
		plan != plan.Original.plan(in.Authority, c.owner.Namespace, c.owner.NamespaceUID) {
		return empty, discovery, kube.ErrOwnership
	}
	if !recovery {
		if !c.service.ForwardEnabled || c.owner.Gate.ValidateCollectors(ctx, in.Authority) != nil || c.service.checkProductionCaptureMaterials() != nil {
			return empty, discovery, kube.ErrOwnership
		}
		materials := c.service.captureMaterials
		if _, err := requiredSignedSourceAccess(c.service.Config, c.service.ConfigDigest, c.service.controllerActor.ServiceAccountName, materials); err != nil {
			return empty, discovery, err
		}
		found := false
		for _, original := range materials.Discovery.LonghornSources {
			found = found || original == plan.Original
		}
		if !found {
			return empty, discovery, kube.ErrOwnership
		}
	}
	original, _, discovery, err := c.owner.input(ctx, in.Authority, recovery)
	if err != nil {
		return empty, discovery, err
	}
	var inventory b.SourceInventory
	var metadata productionCaptureMetadata
	if json.Unmarshal(discovery.Source, &inventory) != nil || decodeMetadataCanonical(inventory.CaptureMetadata, &metadata) != nil {
		return empty, discovery, kube.ErrOwnership
	}
	for _, selected := range metadata.LonghornClones {
		if selected == plan {
			return original, discovery, nil
		}
	}
	return empty, discovery, kube.ErrOwnership
}

func (c *originalLonghornExecutionClient) row(ctx context.Context, in d.Input, kind, namespace, name string) (kube.ResourceRecord, error) {
	rows, err := c.owner.rows(in.Authority)
	if err != nil {
		return kube.ResourceRecord{}, err
	}
	tx, err := c.owner.Gate.Authority.DB.BeginTx(ctx, nil)
	if err != nil {
		return kube.ResourceRecord{}, err
	}
	defer tx.Rollback()
	return rows.Load(ctx, tx, kube.ResourceIntent{Kind: kind, Identity: kube.Identity{Namespace: namespace, Name: name}})
}

func sameLonghornExecutionIntent(a, b kube.ResourceIntent) bool {
	return a.Identity == b.Identity && a.Kind == b.Kind && a.RequestSHA256 == b.RequestSHA256 && bytes.Equal(a.RequestJSON, b.RequestJSON)
}

func longhornExecutionIntent(kind string, object *unstructured.Unstructured) (kube.ResourceIntent, error) {
	raw, err := json.Marshal(object)
	if err != nil {
		return kube.ResourceIntent{}, err
	}
	copy := object.DeepCopy()
	annotations := copy.GetAnnotations()
	delete(annotations, kube.RequestHashAnnotation)
	copy.SetAnnotations(annotations)
	intent, err := kube.Intent(kind, copy)
	if err != nil || !bytes.Equal(raw, intent.RequestJSON) {
		return intent, kube.ErrOwnership
	}
	return intent, nil
}

func (c *originalLonghornExecutionClient) cutPin(ctx context.Context, in d.Input, discovery b.Discovery, plan plannedLonghornClone, recovery bool) (kube.LonghornSnapshotPin, error) {
	var empty kube.LonghornSnapshotPin
	row, err := c.row(ctx, in, "ConfigMap", c.owner.Namespace, longhornCutSetName(in.Authority, discovery))
	if err != nil || !row.CreateDispatched || row.UID == "" || !recovery && (row.Deleting || row.Deleted) {
		return empty, kube.ErrOwnership
	}
	var config struct {
		Data map[string]string `json:"data"`
	}
	var saved heldLonghornCutsRecord
	if json.Unmarshal(row.Intent.RequestJSON, &config) != nil || json.Unmarshal([]byte(config.Data["cuts.json"]), &saved) != nil ||
		saved.Task != in.Authority.TaskPublicID || saved.Attempt != in.Authority.AttemptNo ||
		saved.Generation != in.Authority.MaintenanceFencingToken || saved.SourceSHA256 != discovery.SourceSHA256 ||
		len(saved.Plans) != len(saved.Pins) {
		return empty, kube.ErrOwnership
	}
	expected, err := kube.Intent("ConfigMap", longhornCutSetConfig(in.Authority, discovery, saved.Plans, saved.Pins, c.owner.Namespace))
	if err != nil || !sameLonghornExecutionIntent(expected, row.Intent) {
		return empty, kube.ErrOwnership
	}
	for index, selected := range saved.Plans {
		if selected != plan {
			continue
		}
		pin := saved.Pins[index]
		if !originalLonghornPinMatches(pin, plan) || pin.Snapshot.Intent.Identity != plan.Snapshot || pin.Snapshot.UID == "" ||
			pin.ProviderSnapshotUID == "" || pin.BackendSnapshotHandle == "" || pin.CutStart.IsZero() || !pin.CutObservedAt.After(pin.CutStart) {
			return empty, kube.ErrOwnership
		}
		return pin, nil
	}
	return empty, kube.ErrOwnership
}

func (c *originalLonghornExecutionClient) contentIntent(ctx context.Context, in d.Input, discovery b.Discovery, plan plannedLonghornClone) (kube.ResourceIntent, error) {
	pin, err := c.cutPin(ctx, in, discovery, plan, false)
	if err != nil {
		return kube.ResourceIntent{}, err
	}
	alias, err := c.row(ctx, in, "VolumeSnapshot", plan.Target.Alias.Namespace, plan.Target.Alias.Name)
	if err != nil || !alias.CreateDispatched || alias.UID == "" || alias.Deleting || alias.Deleted ||
		alias.Intent.Identity != plan.Target.Alias {
		return kube.ResourceIntent{}, kube.ErrOwnership
	}
	pin.Alias = &kube.LonghornSnapshotAliasPin{NamespaceUID: plan.Target.NamespaceUID, Snapshot: alias}
	content, err := kube.BuildLonghornSnapshotAliasContent(ctx, c.owner.Client, c.owner.Dynamic, pin)
	if err != nil {
		return kube.ResourceIntent{}, err
	}
	return kube.Intent("VolumeSnapshotContent", content)
}

// Recovery derives only the exact journaled retained reference. It can still
// delete that UID after the alias or original snapshot has been removed.
func (c *originalLonghornExecutionClient) recordedContentIntent(ctx context.Context, in d.Input, discovery b.Discovery, plan plannedLonghornClone) (kube.ResourceIntent, error) {
	pin, err := c.cutPin(ctx, in, discovery, plan, true)
	if err != nil {
		return kube.ResourceIntent{}, err
	}
	alias, err := c.row(ctx, in, "VolumeSnapshot", plan.Target.Alias.Namespace, plan.Target.Alias.Name)
	if err != nil || !alias.CreateDispatched || alias.UID == "" || alias.Intent.Identity != plan.Target.Alias {
		return kube.ResourceIntent{}, kube.ErrOwnership
	}
	name := "sbk-ref-" + kube.ContentHash([]string{pin.NamespaceUID, pin.Snapshot.UID, plan.Target.NamespaceUID,
		plan.Target.Alias.Name, in.Authority.TaskPublicID})[:48]
	aliasObject := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "snapshot.storage.k8s.io/v1", "kind": "VolumeSnapshot",
		"metadata": map[string]any{"name": plan.Target.Alias.Name, "namespace": plan.Target.Alias.Namespace,
			"labels": map[string]any{kube.OwnerLabel: in.Authority.TaskPublicID}},
		"spec": map[string]any{"source": map[string]any{"volumeSnapshotContentName": name}},
	}}
	expectedAlias, err := kube.Intent("VolumeSnapshot", aliasObject)
	if err != nil || !sameLonghornExecutionIntent(expectedAlias, alias.Intent) {
		return kube.ResourceIntent{}, kube.ErrOwnership
	}
	content, err := c.row(ctx, in, "VolumeSnapshotContent", plan.Target.Alias.Namespace, name)
	if err != nil || !content.CreateDispatched || content.UID == "" {
		return kube.ResourceIntent{}, kube.ErrOwnership
	}
	var object unstructured.Unstructured
	if json.Unmarshal(content.Intent.RequestJSON, &object) != nil {
		return kube.ResourceIntent{}, kube.ErrOwnership
	}
	intent, err := longhornExecutionIntent("VolumeSnapshotContent", &object)
	if err != nil || !sameLonghornExecutionIntent(intent, content.Intent) {
		return kube.ResourceIntent{}, kube.ErrOwnership
	}
	spec := map[string]any{"driver": "driver.longhorn.io", "deletionPolicy": "Retain", "sourceVolumeMode": "Filesystem",
		"source": map[string]any{"snapshotHandle": pin.BackendSnapshotHandle},
		"volumeSnapshotRef": map[string]any{"apiVersion": "snapshot.storage.k8s.io/v1", "kind": "VolumeSnapshot",
			"name": plan.Target.Alias.Name, "namespace": plan.Target.Alias.Namespace, "uid": alias.UID}}
	if intent.Identity != (kube.Identity{Namespace: plan.Target.Alias.Namespace, Name: name, Owner: in.Authority.TaskPublicID}) ||
		object.GetNamespace() != "" || !reflect.DeepEqual(object.Object["spec"], spec) {
		return kube.ResourceIntent{}, kube.ErrOwnership
	}
	return intent, nil
}

type longhornExecutionDynamic struct {
	dynamic.Interface
	client  *originalLonghornExecutionClient
	input   d.Input
	plan    plannedLonghornClone
	content bool
}

func (c longhornExecutionDynamic) Resource(gvr schema.GroupVersionResource) dynamic.NamespaceableResourceInterface {
	api := c.Interface.Resource(gvr)
	return longhornExecutionResource{longhornExecutionNamespaced: longhornExecutionNamespaced{ResourceInterface: api,
		client: c.client, input: c.input, plan: c.plan, gvr: gvr, content: c.content}, resource: api}
}

type longhornExecutionResource struct {
	longhornExecutionNamespaced
	resource dynamic.NamespaceableResourceInterface
}

func (c longhornExecutionResource) Namespace(namespace string) dynamic.ResourceInterface {
	child := c.longhornExecutionNamespaced
	child.ResourceInterface, child.namespace = c.resource.Namespace(namespace), namespace
	return child
}

type longhornExecutionNamespaced struct {
	dynamic.ResourceInterface
	client    *originalLonghornExecutionClient
	input     d.Input
	plan      plannedLonghornClone
	gvr       schema.GroupVersionResource
	namespace string
	content   bool
}

func (c longhornExecutionNamespaced) kind() string {
	resource, kind := "volumesnapshots", "VolumeSnapshot"
	if c.content {
		resource, kind = "volumesnapshotcontents", "VolumeSnapshotContent"
	}
	if c.gvr.Group != "snapshot.storage.k8s.io" || c.gvr.Version != "v1" || c.gvr.Resource != resource {
		return ""
	}
	return kind
}

func (c longhornExecutionNamespaced) expected(ctx context.Context, recovery bool) (kube.ResourceIntent, error) {
	_, discovery, err := c.client.frozenPlan(ctx, c.input, c.plan, recovery)
	if err != nil {
		return kube.ResourceIntent{}, err
	}
	switch c.kind() {
	case "VolumeSnapshot":
		if c.namespace != c.plan.Snapshot.Namespace {
			return kube.ResourceIntent{}, kube.ErrOwnership
		}
		object, err := kube.Snapshot(c.plan.Snapshot, c.plan.Original.Source.Name, c.plan.Original.SnapshotClass, true)
		if err != nil {
			return kube.ResourceIntent{}, err
		}
		return kube.Intent("VolumeSnapshot", object)
	case "VolumeSnapshotContent":
		if c.namespace != "" {
			return kube.ResourceIntent{}, kube.ErrOwnership
		}
		if recovery {
			return c.client.recordedContentIntent(ctx, c.input, discovery, c.plan)
		}
		return c.client.contentIntent(ctx, c.input, discovery, c.plan)
	}
	return kube.ResourceIntent{}, kube.ErrOwnership
}

func (c longhornExecutionNamespaced) Create(ctx context.Context, object *unstructured.Unstructured, options metav1.CreateOptions, subresources ...string) (*unstructured.Unstructured, error) {
	if c.kind() == "" || object == nil || len(subresources) != 0 || len(options.DryRun) != 0 || options.FieldManager != "" {
		return nil, kube.ErrOwnership
	}
	expected, err := c.expected(ctx, false)
	if err != nil {
		return nil, err
	}
	intent, err := longhornExecutionIntent(c.kind(), object)
	if err != nil || !sameLonghornExecutionIntent(intent, expected) {
		return nil, kube.ErrOwnership
	}
	row, err := c.client.row(ctx, c.input, intent.Kind, intent.Identity.Namespace, intent.Identity.Name)
	if err != nil || !row.CreateDispatched || row.Deleting || row.Deleted || !sameLonghornExecutionIntent(row.Intent, expected) {
		return nil, kube.ErrOwnership
	}
	if c.client.owner.Gate.ValidateCollectors(ctx, c.input.Authority) != nil {
		return nil, kube.ErrOwnership
	}
	return c.ResourceInterface.Create(ctx, object, options)
}

func (c longhornExecutionNamespaced) Delete(ctx context.Context, name string, options metav1.DeleteOptions, subresources ...string) error {
	if c.kind() == "" || len(subresources) != 0 || len(options.DryRun) != 0 {
		return kube.ErrOwnership
	}
	expected, err := c.expected(ctx, true)
	if err != nil || name != expected.Identity.Name {
		return kube.ErrOwnership
	}
	row, err := c.client.row(ctx, c.input, expected.Kind, expected.Identity.Namespace, name)
	pre := options.Preconditions
	if err != nil || !row.CreateDispatched || !row.Deleting || row.Deleted || row.UID == "" ||
		!sameLonghornExecutionIntent(row.Intent, expected) || pre == nil || pre.UID == nil || string(*pre.UID) != row.UID ||
		pre.ResourceVersion == nil || *pre.ResourceVersion == "" {
		return kube.ErrOwnership
	}
	current, err := c.ResourceInterface.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if string(current.GetUID()) != row.UID || current.GetResourceVersion() != *pre.ResourceVersion ||
		current.GetLabels()[kube.OwnerLabel] != expected.Identity.Owner ||
		current.GetAnnotations()[kube.RequestHashAnnotation] != expected.RequestSHA256 {
		return kube.ErrOwnership
	}
	var wanted unstructured.Unstructured
	if json.Unmarshal(expected.RequestJSON, &wanted) != nil || !reflect.DeepEqual(current.Object["spec"], wanted.Object["spec"]) {
		return kube.ErrOwnership
	}
	if c.client.owner.Gate.Recovery.Check(ctx, c.input.Authority) != nil {
		return kube.ErrOwnership
	}
	return c.ResourceInterface.Delete(ctx, name, options)
}

// The executor exposes the two journaled operations. Other mutations cannot
// escape through methods promoted by dynamic.ResourceInterface.
func (c longhornExecutionNamespaced) Update(context.Context, *unstructured.Unstructured, metav1.UpdateOptions, ...string) (*unstructured.Unstructured, error) {
	return nil, kube.ErrOwnership
}
func (c longhornExecutionNamespaced) UpdateStatus(context.Context, *unstructured.Unstructured, metav1.UpdateOptions) (*unstructured.Unstructured, error) {
	return nil, kube.ErrOwnership
}
func (c longhornExecutionNamespaced) DeleteCollection(context.Context, metav1.DeleteOptions, metav1.ListOptions) error {
	return kube.ErrOwnership
}
func (c longhornExecutionNamespaced) Patch(context.Context, string, types.PatchType, []byte, metav1.PatchOptions, ...string) (*unstructured.Unstructured, error) {
	return nil, kube.ErrOwnership
}
func (c longhornExecutionNamespaced) Apply(context.Context, string, *unstructured.Unstructured, metav1.ApplyOptions, ...string) (*unstructured.Unstructured, error) {
	return nil, kube.ErrOwnership
}
func (c longhornExecutionNamespaced) ApplyStatus(context.Context, string, *unstructured.Unstructured, metav1.ApplyOptions) (*unstructured.Unstructured, error) {
	return nil, kube.ErrOwnership
}
