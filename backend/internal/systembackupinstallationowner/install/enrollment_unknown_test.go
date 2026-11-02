package install

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// A real TLS front end drops the CREATE response after the original TLS API
// has persisted the object. Neither a callback nor a fabricated success DTO
// replaces the production resolver or its final SQL/current-owner checks.
func TestOwnerEnrollUnknownCreateUsesOriginalReadbackOnly(t *testing.T) {
	for _, mode := range []string{"lost_response", "query_unavailable", "foreign_bytes", "foreign_attempt", "mutable", "uid_changed_after_readback", "permission_revoked", "original_deadline_expired", "known_forbidden"} {
		t.Run(mode, func(t *testing.T) {
			original, state, created, password := enrollmentFixture(t, "")
			defer clear(password)
			ctxTimeout := time.Minute
			if mode == "original_deadline_expired" {
				ctxTimeout = 5 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
			defer cancel()
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(state.ca) {
				t.Fatal("original API CA")
			}
			transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DisableCompression: true}
			defer transport.CloseIdleConnections()
			backend := &http.Client{Transport: transport, Timeout: 10 * time.Second}
			var posts, readbacks atomic.Int32
			front := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				isCreate := r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/configmaps")
				isReadback := r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/configmaps/owner-enrollment") && posts.Load() > 0
				w.Header().Set("Content-Type", "application/json")
				status := func(code int, reason metav1.StatusReason) {
					w.WriteHeader(code)
					_ = json.NewEncoder(w).Encode(&metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Failure", Reason: reason, Code: int32(code)})
				}
				if isCreate {
					posts.Add(1)
					if mode == "known_forbidden" {
						status(403, metav1.StatusReasonForbidden)
						return
					}
				}
				if isReadback && mode == "query_unavailable" {
					status(503, metav1.StatusReasonServiceUnavailable)
					return
				}
				if posts.Load() > 0 && mode == "permission_revoked" && strings.HasSuffix(r.URL.Path, "/selfsubjectaccessreviews") {
					_, _ = w.Write([]byte(`{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","status":{"allowed":false,"denied":true}}`))
					return
				}
				request, e := http.NewRequestWithContext(r.Context(), r.Method, original.plan.KubernetesAPI+r.URL.RequestURI(), r.Body)
				if e != nil {
					t.Error(e)
					status(500, metav1.StatusReasonInternalError)
					return
				}
				request.Header = r.Header.Clone()
				response, e := backend.Do(request)
				if e != nil {
					status(502, metav1.StatusReasonInternalError)
					return
				}
				body, e := io.ReadAll(io.LimitReader(response.Body, 1<<20))
				response.Body.Close()
				if e != nil {
					status(502, metav1.StatusReasonInternalError)
					return
				}
				if isCreate && response.StatusCode >= 200 && response.StatusCode < 300 {
					if mode == "original_deadline_expired" {
						<-r.Context().Done()
					}
					// The original object exists, but no successful response or UID
					// reaches the caller of ConfigMaps.Create.
					conn, _, e := w.(http.Hijacker).Hijack()
					if e == nil {
						conn.Close()
					}
					return
				}
				if isReadback && response.StatusCode == 200 {
					read := readbacks.Add(1)
					var cm corev1.ConfigMap
					if json.Unmarshal(body, &cm) != nil {
						t.Error("original object response")
						status(500, metav1.StatusReasonInternalError)
						return
					}
					switch mode {
					case "foreign_bytes":
						cm.Data["enrollment.json"] = "{}"
					case "foreign_attempt":
						cm.UID = "foreign-object"
						cm.Annotations[enrollmentAttemptAnnotation] = "foreign-attempt"
					case "mutable":
						immutable := false
						cm.Immutable = &immutable
					case "uid_changed_after_readback":
						if read > 1 {
							cm.UID = "replacement-after-original-readback"
						}
					}
					body, e = json.Marshal(cm)
					if e != nil {
						t.Error(e)
						status(500, metav1.StatusReasonInternalError)
						return
					}
				}
				w.WriteHeader(response.StatusCode)
				_, _ = w.Write(body)
			}))
			t.Cleanup(front.Close)
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: front.Certificate().Raw})
			p := original.plan
			p.KubernetesAPI = front.URL
			p.KubernetesCASHA256 = hash(ca)
			state.plan = p
			kube, e := kubernetes.NewForConfig(&rest.Config{Host: front.URL, BearerToken: "original-owner-token", TLSClientConfig: rest.TLSClientConfig{CAData: ca}, Timeout: 10 * time.Second})
			if e != nil {
				t.Fatal(e)
			}
			raw, e := canonical(p)
			if e != nil {
				t.Fatal(e)
			}
			i, e := New(original.db, kube, raw, hash(raw), original.public, hash(original.public))
			if e != nil {
				t.Fatal(e)
			}
			receipt, e := i.Enroll(ctx, password)
			if posts.Load() != 1 {
				t.Fatal("uncertain CREATE was repeated", posts.Load())
			}
			if mode == "lost_response" {
				if e != nil || receipt.Pin.ConfigMapUID != "original-enrollment-uid" || *created != 1 || state.commits != 1 {
					t.Fatal("original verified readback did not recover", e)
				}
				return
			}
			if mode == "known_forbidden" {
				if !errors.Is(e, ErrInstall) || errors.Is(e, ErrCommitUnknown) || *created != 0 || receipt.Pin.ConfigMapUID != "" {
					t.Fatal("definite refusal became unknown or success", e)
				}
				return
			}
			if !errors.Is(e, ErrCommitUnknown) || receipt.Pin.ConfigMapUID != "" || *created != 1 || state.commits != 0 {
				t.Fatal("unknown foreign/expired/unauthorized result misreported", e)
			}
		})
	}
}
