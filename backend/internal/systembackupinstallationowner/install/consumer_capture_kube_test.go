package install

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCaptureConsumerKubernetesStaticPinnedTLSWithoutSQL(t *testing.T) {
	for _, mode := range []string{"valid", "wrong_ca", "exec", "proxy", "insecure", "basic_auth"} {
		t.Run(mode, func(t *testing.T) {
			i, state, _, password := enrollmentFixture(t, "")
			clear(password)
			plan := i.plan
			cluster := map[string]any{"server": plan.KubernetesAPI, "certificate-authority-data": base64.StdEncoding.EncodeToString(state.ca)}
			user := map[string]any{"token": "original-owner-token"}
			switch mode {
			case "wrong_ca":
				plan.KubernetesCASHA256 = hash([]byte("foreign CA"))
			case "exec":
				user["exec"] = map[string]any{"apiVersion": "client.authentication.k8s.io/v1", "command": "must-not-execute", "interactiveMode": "Never"}
			case "proxy":
				cluster["proxy-url"] = "http://127.0.0.1:1"
			case "insecure":
				cluster["insecure-skip-tls-verify"] = true
			case "basic_auth":
				user["username"], user["password"] = "foreign", "must-not-read"
			}
			raw, e := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "Config", "current-context": "consumer", "clusters": []any{map[string]any{"name": "consumer", "cluster": cluster}}, "users": []any{map[string]any{"name": "consumer", "user": user}}, "contexts": []any{map[string]any{"name": "consumer", "context": map[string]string{"cluster": "consumer", "user": "consumer"}}}})
			if e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(t.TempDir(), "kubeconfig")
			if os.WriteFile(path, raw, 0600) != nil {
				t.Fatal("controlled pinned input")
			}
			kube, e := openCaptureConsumerKubernetes(plan, path, hash(raw))
			if mode != "valid" {
				if e == nil || kube != nil || state.queries != 0 {
					t.Fatal("untrusted transport accepted or SQL touched")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			review, e := kube.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
			if e != nil || review.Status.UserInfo.Username != plan.OwnerUsername || state.queries != 0 {
				t.Fatal("consumer actual TLS protocol identity", e)
			}
		})
	}
}
