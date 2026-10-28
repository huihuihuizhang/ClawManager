package systembackupexecution

import (
	"context"
	"net/http"
	"strings"

	"clawreef/internal/systembackup/kube"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type boundPodKey struct{}
type BoundPod struct{ Namespace, Name, UID, ServiceAccountUID string }

// WorkloadIdentity requires BOTH mTLS and a current API-authenticated bound Pod
// token. A certificate copied to a different Pod cannot borrow its Job identity.
// API errors deny; no JWT parsing, self-reported Pod fields, proxy certificate
// headers or bearer-only fallback grants execution authority.
type WorkloadIdentity struct {
	Client                                       kubernetes.Interface
	Namespace, ServiceAccount, ServiceAccountUID string
	Next                                         http.Handler
}

func (h WorkloadIdentity) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if h.Client == nil || h.Next == nil || h.Namespace == "" || h.ServiceAccount == "" || h.ServiceAccountUID == "" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		w.WriteHeader(403)
		return
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") || len(auth) > 16400 {
		w.WriteHeader(403)
		return
	}
	reviewed, e := h.Client.AuthenticationV1().TokenReviews().Create(r.Context(), &authv1.TokenReview{Spec: authv1.TokenReviewSpec{Token: strings.TrimPrefix(auth, "Bearer "), Audiences: []string{kube.WorkerTokenAudience}}}, metav1.CreateOptions{})
	if e != nil || !reviewed.Status.Authenticated || reviewed.Status.Error != "" || reviewed.Status.User.Username != "system:serviceaccount:"+h.Namespace+":"+h.ServiceAccount || reviewed.Status.User.UID != h.ServiceAccountUID {
		w.WriteHeader(403)
		return
	}
	audience := false
	for _, a := range reviewed.Status.Audiences {
		audience = audience || a == kube.WorkerTokenAudience
	}
	if !audience {
		w.WriteHeader(403)
		return
	}
	names, uids := reviewed.Status.User.Extra["authentication.kubernetes.io/pod-name"], reviewed.Status.User.Extra["authentication.kubernetes.io/pod-uid"]
	if len(names) != 1 || len(uids) != 1 || names[0] == "" || uids[0] == "" {
		w.WriteHeader(403)
		return
	}
	pod, e := h.Client.CoreV1().Pods(h.Namespace).Get(r.Context(), names[0], metav1.GetOptions{})
	if e != nil || string(pod.UID) != uids[0] || pod.DeletionTimestamp != nil || pod.Spec.ServiceAccountName != h.ServiceAccount {
		w.WriteHeader(403)
		return
	}
	sa, e := h.Client.CoreV1().ServiceAccounts(h.Namespace).Get(r.Context(), h.ServiceAccount, metav1.GetOptions{})
	if e != nil || string(sa.UID) != h.ServiceAccountUID || sa.DeletionTimestamp != nil {
		w.WriteHeader(403)
		return
	}
	ctx := context.WithValue(r.Context(), boundPodKey{}, BoundPod{h.Namespace, names[0], uids[0], h.ServiceAccountUID})
	h.Next.ServeHTTP(w, r.WithContext(ctx))
}
func boundPod(ctx context.Context) (BoundPod, bool) {
	p, ok := ctx.Value(boundPodKey{}).(BoundPod)
	return p, ok
}
