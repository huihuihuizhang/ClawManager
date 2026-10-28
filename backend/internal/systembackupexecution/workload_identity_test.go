package systembackupexecution

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"clawreef/internal/systembackup/kube"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktest "k8s.io/client-go/testing"
)

func TestWorkloadIdentityRequiresCurrentAPIConfirmedPodAndSA(t *testing.T) {
	for _, scenario := range []string{"valid", "no-tls", "no-token", "review-error", "revoked", "wrong-audience", "wrong-sa", "replaced-sa", "replaced-pod", "unbound-token", "deleting-pod"} {
		t.Run(scenario, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "worker-pod", Namespace: "backup", UID: types.UID("pod-original")}, Spec: corev1.PodSpec{ServiceAccountName: "worker"}}
			sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "worker", Namespace: "backup", UID: types.UID("sa-original")}}
			status := authv1.TokenReviewStatus{Authenticated: true, Audiences: []string{kube.WorkerTokenAudience}, User: authv1.UserInfo{Username: "system:serviceaccount:backup:worker", UID: "sa-original", Extra: map[string]authv1.ExtraValue{"authentication.kubernetes.io/pod-name": {"worker-pod"}, "authentication.kubernetes.io/pod-uid": {"pod-original"}}}}
			switch scenario {
			case "revoked":
				status.Authenticated = false
			case "wrong-audience":
				status.Audiences = []string{"https://kubernetes.default.svc"}
			case "wrong-sa":
				status.User.Username = "system:serviceaccount:other:worker"
			case "replaced-sa":
				sa.UID = "sa-new"
			case "replaced-pod":
				pod.UID = "pod-new"
			case "unbound-token":
				delete(status.User.Extra, "authentication.kubernetes.io/pod-uid")
			case "deleting-pod":
				now := metav1.Now()
				pod.DeletionTimestamp = &now
			}
			client := fake.NewSimpleClientset(pod, sa)
			reviews := 0
			client.PrependReactor("create", "tokenreviews", func(action ktest.Action) (bool, runtime.Object, error) {
				reviews++
				r := action.(ktest.CreateAction).GetObject().(*authv1.TokenReview)
				if r.Spec.Token != "synthetic-bound-token" || len(r.Spec.Audiences) != 1 || r.Spec.Audiences[0] != kube.WorkerTokenAudience {
					t.Fatal("review did not pin token audience")
				}
				if scenario == "review-error" {
					return true, nil, errors.New("unavailable")
				}
				return true, &authv1.TokenReview{Status: status}, nil
			})
			called := false
			handler := WorkloadIdentity{Client: client, Namespace: "backup", ServiceAccount: "worker", ServiceAccountUID: "sa-original", Next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				p, ok := boundPod(r.Context())
				if !ok || p.UID != "pod-original" || p.ServiceAccountUID != "sa-original" {
					t.Fatal("unbound context")
				}
				w.WriteHeader(204)
			})}
			request := httptest.NewRequest(http.MethodPost, "https://control/worker/v1", nil)
			request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}
			request.Header.Set("Authorization", "Bearer synthetic-bound-token")
			if scenario == "no-tls" {
				request.TLS = nil
			}
			if scenario == "no-token" {
				request.Header.Del("Authorization")
			}
			result := httptest.NewRecorder()
			handler.ServeHTTP(result, request)
			if scenario == "valid" {
				if result.Code != 204 || !called || reviews != 1 {
					t.Fatal(result.Code, called, reviews)
				}
			} else if result.Code != 403 || called {
				t.Fatal("unverified identity reached worker", result.Code, called)
			}
		})
	}
}
