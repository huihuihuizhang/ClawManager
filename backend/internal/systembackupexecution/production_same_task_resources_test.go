package systembackupexecution

import (
	"encoding/json"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
)

// The two resource actors have separate credentials and GET-only named scopes;
// neither can reuse the metadata actor's list credential or the other part.
func (f *dOriginalSixPartTask) handleOriginalResourceAPI(out http.ResponseWriter, r *http.Request) bool {
	actor, resource := "", ""
	switch r.Header.Get("Authorization") {
	case "Bearer named-d-resources-token":
		actor, resource = "d-resources", "configmaps"
	case "Bearer named-d-secrets-token":
		actor, resource = "d-secrets", "secrets"
	default:
		return false
	}
	out.Header().Set("Content-Type", "application/json")
	ns := f.service.Config.Namespace
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/apis/authentication.k8s.io/v1/selfsubjectreviews":
		_ = json.NewEncoder(out).Encode(authnv1.SelfSubjectReview{TypeMeta: metav1.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}, Status: authnv1.SelfSubjectReviewStatus{UserInfo: authnv1.UserInfo{Username: "system:serviceaccount:" + ns + ":" + actor, UID: actor + "-uid"}}})
	case r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews":
		_ = json.NewEncoder(out).Encode(authzv1.SelfSubjectRulesReview{TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectRulesReview"}, Status: authzv1.SubjectRulesReviewStatus{ResourceRules: []authzv1.ResourceRule{{APIGroups: []string{""}, Resources: []string{resource}, ResourceNames: []string{"original"}, Verbs: []string{"get"}}}}})
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/"+ns+"/"+resource+"/original" && (r.URL.RawQuery == "" || len(r.URL.Query()) == 1 && r.URL.Query().Get("timeout") == "5s"):
		meta := metav1.ObjectMeta{Name: "original", Namespace: ns, UID: "original-six-resource-uid", ResourceVersion: "1"}
		if resource == "configmaps" {
			_ = json.NewEncoder(out).Encode(corev1.ConfigMap{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta, Data: map[string]string{"original-config": "bounded actual source bytes"}})
		} else {
			_ = json.NewEncoder(out).Encode(corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"original-secret": []byte("bounded actual local source secret")}})
		}
	default:
		out.WriteHeader(http.StatusForbidden)
	}
	return true
}
