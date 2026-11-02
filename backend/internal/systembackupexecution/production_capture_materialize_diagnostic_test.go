package systembackupexecution

import (
	"context"
	"errors"
	"testing"

	"clawreef/internal/systembackup/kube"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestOriginalMaterializationDiagnosticSeparatesCreatedReusedAndUnknown(t *testing.T) {
	for _, outcome := range []string{"created", "reused", "create-unknown"} {
		t.Run(outcome, func(t *testing.T) {
			s := &OriginalCaptureSequence{core: DeploymentConfig{Namespace: "original", NamespaceUID: "original-ns-uid"}}
			client := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: s.core.Namespace, UID: types.UID(s.core.NamespaceUID)}})
			client.PrependReactor("create", "configmaps", func(action ktesting.Action) (bool, runtime.Object, error) {
				cm := action.(ktesting.CreateAction).GetObject().(*corev1.ConfigMap).DeepCopy()
				cm.UID, cm.ResourceVersion = "actual-independent-uid", "1"
				if err := client.Tracker().Create(action.GetResource(), cm, s.core.Namespace); err != nil {
					return true, nil, err
				}
				if outcome == "create-unknown" {
					return true, nil, errors.New("unknown create ACK")
				}
				if outcome == "reused" {
					return true, nil, apierrors.NewAlreadyExists(corev1.Resource("configmaps"), cm.Name)
				}
				return true, cm, nil
			})
			diagnostic := &originalMaterializationDiagnostic{}
			expected := &originalMappingObject{kind: "ConfigMap", name: "original-mapping", mapping: true, data: map[string][]byte{"materials.json": []byte("component-fixed-bytes")}}
			pin, err := s.createOriginalMappingObject(context.Background(), client, expected, diagnostic)
			if (outcome == "create-unknown") != (err != nil) || len(diagnostic.Assets) != 1 {
				t.Fatal("unknown creation became success or omitted diagnostics", err)
			}
			asset := diagnostic.Assets[0]
			if asset.Disposition != outcome || !asset.Observed || asset.UID != "actual-independent-uid" || !formalCandidateDigest(asset.ContentSHA256) {
				t.Fatal("creation provenance inferred from matching metadata", asset)
			}
			if outcome != "create-unknown" && asset.ContentSHA256 != pin.SHA256 {
				t.Fatal("diagnostic did not record full independent content hash")
			}
			cm, err := client.CoreV1().ConfigMaps(s.core.Namespace).Get(context.Background(), expected.name, metav1.GetOptions{})
			if err != nil || asset.ContentSHA256 != kube.ContentHash([]any{cm.Data, cm.BinaryData}) {
				t.Fatal("unknown outcome resource not preserved/read back", err)
			}
			for _, action := range client.Actions() {
				if action.GetVerb() != "get" && action.GetVerb() != "create" {
					t.Fatal("diagnostics mutated/deleted residuals")
				}
			}
		})
	}
}
