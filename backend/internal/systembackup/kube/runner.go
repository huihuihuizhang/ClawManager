package kube

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
)

const RequestHashAnnotation = "backup.clawmanager.io/request-sha256"

var (
	ErrJournal   = errors.New("backup resource journal or fence unavailable")
	ErrOwnership = errors.New("backup resource ownership or request identity conflicts")
	ErrPending   = errors.New("backup resource operation requires reconciliation")
	ErrJobFailed = errors.New("backup worker Job failed")
)

type ResourceIntent struct {
	Identity      Identity
	Kind          string
	RequestSHA256 string
	RequestJSON   []byte // frozen full request, including request-hash annotation
}
type ResourceRecord struct {
	Intent           ResourceIntent
	Revision         int64 // durable journal row version, distinct from Kubernetes RV
	CreateDispatched bool
	UID              string
	ResourceVersion  string
	Deleting         bool
	Deleted          bool
}

// ResourceJournal is a projection of the shared staging/drill resource ledger,
// NOT a second task state machine. Implementations must durably CAS each call,
// enforce fencing and reject payload/UID changes. RecordDelete must complete
// before sending DELETE; a crash after either API call is reconciled by GET.
type ResourceJournal interface {
	Prepare(context.Context, ResourceIntent) (ResourceRecord, error)
	RecordCreate(context.Context, ResourceRecord) (ResourceRecord, error)
	Observe(context.Context, ResourceRecord, string, string) (ResourceRecord, error)
	RecordDelete(context.Context, ResourceRecord) (ResourceRecord, error)
	RecordAbsent(context.Context, ResourceRecord) error
}
type Runner struct {
	Client     dynamic.Interface
	Journal    ResourceJournal
	CheckFence func(context.Context) error
}

func (r Runner) ready(ctx context.Context) error {
	if r.Client == nil || r.Journal == nil || r.CheckFence == nil || r.CheckFence(ctx) != nil {
		return ErrJournal
	}
	return ctx.Err()
}
func resourceType(kind string) (schema.GroupVersionResource, string, error) {
	switch kind {
	case "Job":
		return schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}, "batch/v1", nil
	case "PersistentVolumeClaim":
		return schema.GroupVersionResource{Version: "v1", Resource: "persistentvolumeclaims"}, "v1", nil
	case "VolumeSnapshot":
		return schema.GroupVersionResource{Group: "snapshot.storage.k8s.io", Version: "v1", Resource: "volumesnapshots"}, "snapshot.storage.k8s.io/v1", nil
	case "NetworkPolicy":
		return schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"}, "networking.k8s.io/v1", nil
	case "ConfigMap":
		return schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}, "v1", nil
	default:
		return schema.GroupVersionResource{}, "", ErrResource
	}
}

func freeze(kind string, obj any) (ResourceIntent, *unstructured.Unstructured, error) {
	_, version, e := resourceType(kind)
	if e != nil {
		return ResourceIntent{}, nil, e
	}
	b, e := json.Marshal(obj)
	if e != nil || len(b) > 1<<20 {
		return ResourceIntent{}, nil, ErrResource
	}
	u := &unstructured.Unstructured{}
	if json.Unmarshal(b, &u.Object) != nil {
		return ResourceIntent{}, nil, ErrResource
	}
	i := Identity{Namespace: u.GetNamespace(), Name: u.GetName(), Owner: u.GetLabels()[OwnerLabel]}
	if !i.valid() || u.GetUID() != "" || u.GetResourceVersion() != "" || u.GetGenerateName() != "" || u.GetDeletionTimestamp() != nil || len(u.GetOwnerReferences()) > 0 {
		return ResourceIntent{}, nil, ErrResource
	}
	u.SetAPIVersion(version)
	u.SetKind(kind)
	delete(u.Object, "status")
	a := u.GetAnnotations()
	if a == nil {
		a = map[string]string{}
	}
	if a[RequestHashAnnotation] != "" {
		return ResourceIntent{}, nil, ErrResource
	}
	if len(a) == 0 {
		u.SetAnnotations(nil)
	}
	b, e = json.Marshal(u.Object)
	if e != nil {
		return ResourceIntent{}, nil, ErrResource
	}
	sum := sha256.Sum256(b)
	hash := hex.EncodeToString(sum[:])
	a[RequestHashAnnotation] = hash
	u.SetAnnotations(a)
	b, e = json.Marshal(u.Object)
	if e != nil {
		return ResourceIntent{}, nil, ErrResource
	}
	return ResourceIntent{Identity: i, Kind: kind, RequestSHA256: hash, RequestJSON: b}, u, nil
}

// Intent freezes a request without issuing an API call. Recovery uses it to
// load an existing journal record; it must never rediscover a mutable template.
func Intent(kind string, obj any) (ResourceIntent, error) {
	i, _, e := freeze(kind, obj)
	return i, e
}

// Ensure creates a Job/PVC/snapshot/policy only after its exact request has been
// journaled. Uncertain creates are resolved by reading and checking the recorded
// identity; existing foreign resources are never adopted, patched or deleted.
func (r Runner) Ensure(ctx context.Context, kind string, obj any) (ResourceRecord, error) {
	if e := r.ready(ctx); e != nil {
		return ResourceRecord{}, e
	}
	intent, wanted, e := freeze(kind, obj)
	if e != nil {
		return ResourceRecord{}, e
	}
	record, e := r.Journal.Prepare(ctx, intent)
	if e != nil || !sameIntent(record.Intent, intent) {
		return ResourceRecord{}, ErrJournal
	}
	if record.Deleting || record.Deleted {
		return record, ErrOwnership
	}
	gvr, _, _ := resourceType(kind)
	api := r.Client.Resource(gvr).Namespace(intent.Identity.Namespace)
	observed, e := api.Get(ctx, intent.Identity.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(e) {
		if record.UID != "" {
			return record, ErrOwnership
		} // lost resource, never silently recreate
		if record.CreateDispatched {
			return record, ErrPending
		}
		if e = r.ready(ctx); e != nil {
			return record, e
		}
		record, e = r.Journal.RecordCreate(ctx, record)
		if e != nil {
			return record, ErrJournal
		}
		if e = r.ready(ctx); e != nil {
			return record, e
		}
		observed, e = api.Create(ctx, wanted, metav1.CreateOptions{})
		if e != nil {
			observed, e = api.Get(ctx, intent.Identity.Name, metav1.GetOptions{})
			if e != nil {
				return record, ErrPending
			}
		}
	} else if e != nil {
		return record, ErrPending
	}
	if !owned(record, observed) {
		return record, ErrOwnership
	}
	if e = r.ready(ctx); e != nil {
		return record, e
	}
	record, e = r.Journal.Observe(ctx, record, string(observed.GetUID()), observed.GetResourceVersion())
	if e != nil {
		return record, ErrJournal
	}
	return record, nil
}
func sameIntent(a, b ResourceIntent) bool {
	return a.Identity == b.Identity && a.Kind == b.Kind && a.RequestSHA256 == b.RequestSHA256 && string(a.RequestJSON) == string(b.RequestJSON)
}

func owned(record ResourceRecord, obj *unstructured.Unstructured) bool {
	if !record.CreateDispatched && record.UID == "" {
		return false
	}
	i := record.Intent.Identity
	if obj == nil || obj.GetUID() == "" || obj.GetResourceVersion() == "" || obj.GetName() != i.Name || obj.GetNamespace() != i.Namespace || obj.GetLabels()[OwnerLabel] != i.Owner || obj.GetAnnotations()[RequestHashAnnotation] != record.Intent.RequestSHA256 {
		return false
	}
	if record.UID != "" && record.UID != string(obj.GetUID()) {
		return false
	}
	var desired map[string]any
	if json.Unmarshal(record.Intent.RequestJSON, &desired) != nil {
		return false
	}
	// Do not trust a hash annotation after an operator mutates the live spec.
	if !subset(desired["spec"], obj.Object["spec"]) {
		return false
	}
	if record.Intent.Kind == "ConfigMap" {
		for _, key := range []string{"data", "binaryData", "immutable"} {
			if !reflect.DeepEqual(desired[key], obj.Object[key]) {
				return false
			}
		}
	}
	if record.Intent.Kind == "Job" {
		expected, _, _ := unstructured.NestedMap(desired, "spec", "template", "spec")
		actual, _, _ := unstructured.NestedMap(obj.Object, "spec", "template", "spec")
		if !podSpecMatches(expected, actual, false) {
			return false
		}
	}
	return true
}
func subset(wanted, actual any) bool {
	switch w := wanted.(type) {
	case map[string]any:
		a, ok := actual.(map[string]any)
		if !ok {
			return false
		}
		for k, v := range w {
			if !subset(v, a[k]) {
				return false
			}
		}
		return true
	case []any:
		a, ok := actual.([]any)
		if !ok || len(w) != len(a) {
			return false
		}
		for i, v := range w {
			if !subset(v, a[i]) {
				return false
			}
		}
		return true
	default:
		// JSON decoding uses float64, dynamic clients may carry int64.
		if wf, ok := number(wanted); ok {
			af, ok := number(actual)
			return ok && wf == af
		}
		return reflect.DeepEqual(wanted, actual)
	}
}
func number(v any) (string, bool) {
	switch n := v.(type) {
	case float64:
		return strconv.FormatFloat(n, 'f', -1, 64), true
	case int64:
		return strconv.FormatInt(n, 10), true
	case int32:
		return strconv.FormatInt(int64(n), 10), true
	case int:
		return strconv.Itoa(n), true
	default:
		return "", false
	}
}

// JobComplete checks the recorded Job UID and conditions. A succeeded counter,
// missing Job, or accepted create request alone is not proof of completion.
func (r Runner) JobComplete(ctx context.Context, record ResourceRecord) (bool, error) {
	if e := r.ready(ctx); e != nil {
		return false, e
	}
	if record.Intent.Kind != "Job" || record.UID == "" || record.Deleting || record.Deleted {
		return false, ErrResource
	}
	gvr, _, _ := resourceType("Job")
	o, e := r.Client.Resource(gvr).Namespace(record.Intent.Identity.Namespace).Get(ctx, record.Intent.Identity.Name, metav1.GetOptions{})
	if e != nil {
		return false, ErrPending
	}
	if !owned(record, o) {
		return false, ErrOwnership
	}
	conditions, _, _ := unstructured.NestedSlice(o.Object, "status", "conditions")
	complete := false
	for _, v := range conditions {
		c, ok := v.(map[string]any)
		if !ok {
			return false, ErrResource
		}
		if c["status"] != "True" {
			continue
		}
		if c["type"] == "Failed" || c["type"] == "FailureTarget" {
			return false, ErrJobFailed
		}
		if c["type"] == "Complete" {
			complete = true
		}
	}
	return complete, nil
}

// Cleanup is a reconcile step: false means deletion is still in flight. Only
// a matching UID/resourceVersion can be deleted, and absence must be observed.
// PVC deletion is not proof of underlying PV data erasure; the common cleanup
// verifier must independently check reclaim/wipe before drill acceptance.
func (r Runner) Cleanup(ctx context.Context, record ResourceRecord) (bool, error) {
	if e := r.ready(ctx); e != nil {
		return false, e
	}
	gvr, _, e := resourceType(record.Intent.Kind)
	if e != nil {
		return false, e
	}
	// Re-read the journal authority instead of trusting a supplied stale record.
	current, e := r.Journal.Prepare(ctx, record.Intent)
	if e != nil || !sameIntent(current.Intent, record.Intent) {
		return false, ErrJournal
	}
	record = current
	if record.Deleted {
		return true, nil
	}
	api := r.Client.Resource(gvr).Namespace(record.Intent.Identity.Namespace)
	o, e := api.Get(ctx, record.Intent.Identity.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(e) {
		// A timed-out CREATE can still complete after this GET. Without an
		// observed UID or authoritative non-dispatch proof, 404 is not cleanup.
		if record.UID == "" && record.CreateDispatched {
			return false, ErrPending
		}
		if r.Journal.RecordAbsent(ctx, record) != nil {
			return false, ErrJournal
		}
		return true, nil
	}
	if e != nil {
		return false, ErrPending
	}
	if !owned(record, o) {
		return false, ErrOwnership
	}
	if record.UID == "" {
		record, e = r.Journal.Observe(ctx, record, string(o.GetUID()), o.GetResourceVersion())
		if e != nil {
			return false, ErrJournal
		}
	}
	if o.GetDeletionTimestamp() == nil {
		record, e = r.Journal.RecordDelete(ctx, record)
		if e != nil {
			return false, ErrJournal
		}
		if e = r.ready(ctx); e != nil {
			return false, e
		}
		uid := types.UID(record.UID)
		rv := o.GetResourceVersion()
		foreground := metav1.DeletePropagationForeground
		e = api.Delete(ctx, record.Intent.Identity.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}, PropagationPolicy: &foreground})
		if e != nil && !apierrors.IsNotFound(e) {
			return false, ErrPending
		}
	}
	_, e = api.Get(ctx, record.Intent.Identity.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(e) {
		if r.Journal.RecordAbsent(ctx, record) != nil {
			return false, ErrJournal
		}
		return true, nil
	}
	if e != nil {
		return false, ErrPending
	}
	return false, nil
}
