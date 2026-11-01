package systembackupexecution

import (
	"context"
	"errors"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	kubefake "k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
)

// Actual fake-API transport only; no SQL authority, dispatch record, complete
// cleanup receipt or acceptance is manufactured by this fixture.
func TestPublicationNativeCleanupAPIUsesOriginalUIDRVAndGracefulDeletion(t *testing.T) {
	for _, kind := range []string{"Secret", "Pod", "Job"} {
		t.Run(kind, func(t *testing.T) {
			object := publicationNativeCleanupObject{Kind: kind, Namespace: "backup", Name: "original", UID: "original-uid", ResourceVersion: "17"}
			meta := metav1.ObjectMeta{Namespace: object.Namespace, Name: object.Name, UID: types.UID(object.UID), ResourceVersion: object.ResourceVersion}
			var native runtime.Object
			var resource schema.GroupVersionResource
			switch kind {
			case "Secret":
				native = &corev1.Secret{ObjectMeta: meta}
				resource = corev1.SchemeGroupVersion.WithResource("secrets")
			case "Pod":
				native = &corev1.Pod{ObjectMeta: meta}
				resource = corev1.SchemeGroupVersion.WithResource("pods")
			case "Job":
				native = &batchv1.Job{ObjectMeta: meta}
				resource = batchv1.SchemeGroupVersion.WithResource("jobs")
			}
			client := kubefake.NewSimpleClientset(native)
			sends := 0
			client.PrependReactor("delete", "*", func(action kt.Action) (bool, runtime.Object, error) {
				request := action.(kt.DeleteAction)
				opts := request.GetDeleteOptions()
				if opts.Preconditions == nil || opts.Preconditions.UID == nil || string(*opts.Preconditions.UID) != object.UID || opts.Preconditions.ResourceVersion == nil || *opts.Preconditions.ResourceVersion != object.ResourceVersion || opts.PropagationPolicy == nil || *opts.PropagationPolicy != metav1.DeletePropagationForeground || opts.GracePeriodSeconds != nil {
					t.Fatal("native DELETE lost exact UID/RV or forced grace")
				}
				sends++
				return true, nil, client.Tracker().Delete(resource, object.Namespace, object.Name)
			})
			p := &publicationNativeCleanup{candidate: &publicationCandidateCleanup{exit: &publicationUploadExit{service: &DeploymentService{Runtime: &PublicCapture{Owner: &PublicJobOwner{Client: client}}}}}}
			get, arm, remove, err := p.kubeOperations(object)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			stream, err := arm(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Stop()
			if err = remove(ctx); err != nil {
				t.Fatal(err)
			}
			if err = publicationObserveNativeAbsence(ctx, object, get, stream); err != nil || sends != 1 {
				t.Fatal("actual UID deletion and API absence", err, sends)
			}
			object.UID = ""
			if _, _, _, err = p.kubeOperations(object); !errors.Is(err, c.ErrExecutionAuthority) {
				t.Fatal("unbound native delete adapter accepted")
			}
		})
	}
}

func TestPublicationNativeCleanupWatchNeverConvertsUnknownToAbsence(t *testing.T) {
	for _, mode := range []string{"actual-delete-event", "denied", "retained-no-deletion", "replacement-uid", "closed-watch", "foreign-delete-event", "still-present-after-delete-event"} {
		t.Run(mode, func(t *testing.T) {
			object := publicationNativeCleanupObject{Kind: "Pod", Namespace: "backup", Name: "original", UID: "original-uid", ResourceVersion: "17"}
			at := metav1.Now()
			meta := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Namespace: object.Namespace, Name: object.Name, UID: types.UID(object.UID), ResourceVersion: object.ResourceVersion, DeletionTimestamp: &at}}
			stream := watch.NewRaceFreeFake()
			defer stream.Stop()
			calls := 0
			get := func(context.Context) (metav1.Object, error) {
				calls++
				if mode == "denied" {
					return nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, object.Name, errors.New("denied"))
				}
				if calls > 1 && mode != "still-present-after-delete-event" {
					return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, object.Name)
				}
				return meta, nil
			}
			switch mode {
			case "retained-no-deletion":
				meta.DeletionTimestamp = nil
			case "replacement-uid":
				meta.UID = "replacement"
			case "closed-watch":
				stream.Stop()
			case "foreign-delete-event":
				foreign := meta.DeepCopy()
				foreign.UID = "foreign"
				stream.Delete(foreign)
			default:
				stream.Delete(meta.DeepCopy())
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := publicationObserveNativeAbsence(ctx, object, get, stream)
			if (err == nil) != (mode == "actual-delete-event") {
				t.Fatal("unknown native state accepted", mode, err)
			}
		})
	}
}

func TestPublicationNativeCleanupExpiredSecretIsOwnershipDataOnly(t *testing.T) {
	yes, no := true, false
	requestSHA := hash([]byte("original request DATA"))
	exit := &publicationUploadExit{material: publicationMaterialIntent{Namespace: "backup", Name: "original-secret", RequestSHA256: requestSHA, Deadline: time.Now().Add(-time.Minute)}, activation: publicationActivation{SecretUID: "secret-original", JobUID: "job-original"}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: exit.material.Namespace, Name: exit.material.Name, UID: types.UID(exit.activation.SecretUID), ResourceVersion: "17", OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: "sbp-" + requestSHA[:32], UID: types.UID(exit.activation.JobUID), Controller: &yes, BlockOwnerDeletion: &no}}}, Immutable: &yes, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{}}
	for _, name := range []string{"request.json", "credential.json", "artifact-ca.crt", "ca.crt", "tls.crt", "tls.key"} {
		secret.Data[name] = []byte("expired material ownership DATA; never a usable credential")
	}
	body, err := publicationMaterialBody(secret)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	exit.material.BodySHA256 = hash(body)
	if !publicationNativeCleanupSecret(body, secret, exit) {
		t.Fatal("immutable expired material ownership cannot be checked without reopening grant")
	}
	for _, mode := range []string{"foreign-uid", "foreign-job-owner", "foreign-body", "deleting", "empty-request"} {
		copy := secret.DeepCopy()
		material := *exit
		raw := body
		switch mode {
		case "foreign-uid":
			copy.UID = "foreign"
		case "foreign-job-owner":
			copy.OwnerReferences[0].UID = "foreign"
		case "foreign-body":
			raw = []byte("foreign")
		case "deleting":
			at := metav1.Now()
			copy.DeletionTimestamp = &at
		case "empty-request":
			material.material.RequestSHA256 = ""
		}
		if publicationNativeCleanupSecret(raw, copy, &material) {
			t.Fatal("foreign secret ownership accepted", mode)
		}
	}
}

func TestPublicationNativeCleanupCannotUsePreparedCandidate(t *testing.T) {
	service := &DeploymentService{}
	for _, candidate := range []*publicationCandidateCleanup{nil, {}, {deleted: true}} {
		if result, err := service.prepareOriginalNativeCleanup(context.Background(), candidate); !errors.Is(err, c.ErrExecutionAuthority) || result != nil {
			t.Fatal("prepared candidate substituted for actual cleanup", err)
		}
	}
}

func aInstallOriginalNativeCleanupDeleteAPI(t *testing.T, client *kubefake.Clientset, exit *publicationUploadExit) *int {
	t.Helper()
	sends := new(int)
	expected := map[string]string{exit.material.Name: exit.activation.SecretUID, exit.process.Pod.Name: exit.process.Pod.UID, "sbp-" + exit.material.RequestSHA256[:32]: exit.activation.JobUID}
	client.PrependReactor("delete", "*", func(action kt.Action) (bool, runtime.Object, error) {
		request := action.(kt.DeleteAction)
		uid, owned := expected[request.GetName()]
		if !owned {
			return false, nil, nil
		}
		original, err := client.Tracker().Get(action.GetResource(), action.GetNamespace(), request.GetName())
		if err != nil {
			return true, nil, err
		}
		metadata, ok := original.(metav1.Object)
		opts := request.GetDeleteOptions()
		if !ok || string(metadata.GetUID()) != uid || opts.Preconditions == nil || opts.Preconditions.UID == nil || string(*opts.Preconditions.UID) != uid || opts.Preconditions.ResourceVersion == nil || *opts.Preconditions.ResourceVersion != metadata.GetResourceVersion() || opts.PropagationPolicy == nil || *opts.PropagationPolicy != metav1.DeletePropagationForeground || opts.GracePeriodSeconds != nil {
			t.Fatal("actual original cleanup UID/RV/foreground mismatch")
		}
		*sends++
		return true, nil, client.Tracker().Delete(action.GetResource(), action.GetNamespace(), request.GetName())
	})
	return sends
}
