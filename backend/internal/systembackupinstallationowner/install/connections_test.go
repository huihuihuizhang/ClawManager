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

func TestOwnerEnrollPinnedConnectionsAndIdentitySubstitution(t *testing.T) {
	for _, mode := range []string{"valid", "wrong_ca", "impersonation", "proxy", "exec", "insecure"} {
		t.Run(mode, func(t *testing.T) {
			i, state, _, password := enrollmentFixture(t, "")
			clear(password)
			p := i.plan
			p.DatabaseCASHA256 = hash(state.ca)
			cluster := map[string]any{"server": p.KubernetesAPI, "certificate-authority-data": base64.StdEncoding.EncodeToString(state.ca)}
			user := map[string]any{"token": "original-owner-token"}
			switch mode {
			case "wrong_ca":
				p.KubernetesCASHA256 = hash([]byte("wrong CA"))
			case "impersonation":
				user["as"] = "other-owner"
			case "proxy":
				cluster["proxy-url"] = "http://127.0.0.1:1"
			case "exec":
				user = map[string]any{"exec": map[string]any{"apiVersion": "client.authentication.k8s.io/v1", "command": "must-never-execute-owner-plugin", "interactiveMode": "Never"}}
			case "insecure":
				cluster["insecure-skip-tls-verify"] = true
			}
			doc := map[string]any{"apiVersion": "v1", "kind": "Config", "current-context": "original", "clusters": []any{map[string]any{"name": "original", "cluster": cluster}}, "users": []any{map[string]any{"name": "original", "user": user}}, "contexts": []any{map[string]any{"name": "original", "context": map[string]any{"cluster": "original", "user": "original"}}}}
			raw, e := json.Marshal(doc)
			if e != nil {
				t.Fatal(e)
			}
			dir := t.TempDir()
			kubePath, dsnPath, caPath := filepath.Join(dir, "kubeconfig"), filepath.Join(dir, "dsn"), filepath.Join(dir, "ca")
			for path, body := range map[string][]byte{kubePath: raw, dsnPath: []byte("installer:private-only-test-password@tcp(127.0.0.1:65000)/owner_fixture"), caPath: state.ca} {
				if e := os.WriteFile(path, body, 0600); e != nil {
					t.Fatal(e)
				}
			}
			db, kube, e := OpenConnections(p, kubePath, hash(raw), dsnPath, caPath)
			if mode != "valid" {
				if db != nil {
					db.Close()
				}
				if e == nil || kube != nil {
					t.Fatal("untrusted transport identity accepted")
				}
				return
			}
			if e != nil {
				t.Fatal("original pinned transport rejected", e)
			}
			defer db.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			review, e := kube.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
			if e != nil || review.Status.UserInfo.Username != p.OwnerUsername || state.queries != 0 {
				t.Fatal("actual pinned TLS client identity protocol", e)
			}
		})
	}
}
