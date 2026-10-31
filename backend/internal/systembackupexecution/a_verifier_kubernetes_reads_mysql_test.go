package systembackupexecution

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	a "clawreef/internal/systembackupkekadapter"
	w "clawreef/internal/systembackupwire"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Real original SQL and TLS provider, plus real client-go HTTP 403 responses
// from an isolated API fixture. No live cluster authorization is claimed.
func TestAVerifierNamedOwner403PreventsProviderCalls(t *testing.T) {
	aControllerVerifierOriginalSQLAndTLS(t, false, func(f aOriginalIssuerFixture) {
		cfg := f.cfg
		workload := cfg.Workload
		reads := a.VerifierKubernetesReads{Version: a.VerifierKubernetesReadsVersion, Namespace: workload.Namespace, NamespaceUID: "controller-ns-uid", PodName: workload.PodName, PodUID: workload.PodUID, ServiceAccountName: workload.ServiceAccountName, ServiceAccountUID: workload.ServiceAccountUID, OwnerKind: workload.OwnerKind, OwnerName: "controller-deployment", OwnerUID: workload.OwnerUID, ReplicaSetName: "controller-rs", ReplicaSetUID: "controller-rs-uid"}
		deny := ""
		var fetched []string
		var apiMu sync.Mutex
		// API replies are fixed original objects; a 403 cannot become a successful
		// owner observation. Provider counters count login and decrypt together.
		api := httptest.NewServer(http.HandlerFunc(func(wr http.ResponseWriter, r *http.Request) {
			apiMu.Lock()
			fetched = append(fetched, r.URL.Path)
			deniedResource := deny
			apiMu.Unlock()
			wr.Header().Set("Content-Type", "application/json")
			if deniedResource != "" && strings.Contains(r.URL.Path, "/"+deniedResource+"/") {
				wr.WriteHeader(http.StatusForbidden)
				fmt.Fprint(wr, `{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Forbidden","code":403}`)
				return
			}
			var object any
			var err error
			switch r.URL.Path {
			case "/api/v1/namespaces/" + workload.Namespace:
				object = &corev1.Namespace{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: metav1.ObjectMeta{Name: workload.Namespace, UID: "controller-ns-uid"}}
			case "/api/v1/namespaces/" + workload.Namespace + "/pods/" + workload.PodName:
				object, err = f.cfg.Kubernetes.CoreV1().Pods(workload.Namespace).Get(f.ctx, workload.PodName, metav1.GetOptions{})
			case "/api/v1/namespaces/" + workload.Namespace + "/serviceaccounts/" + workload.ServiceAccountName:
				object, err = f.cfg.Kubernetes.CoreV1().ServiceAccounts(workload.Namespace).Get(f.ctx, workload.ServiceAccountName, metav1.GetOptions{})
			case "/apis/apps/v1/namespaces/" + workload.Namespace + "/replicasets/" + reads.ReplicaSetName:
				object, err = f.cfg.Kubernetes.AppsV1().ReplicaSets(workload.Namespace).Get(f.ctx, reads.ReplicaSetName, metav1.GetOptions{})
			case "/apis/apps/v1/namespaces/" + workload.Namespace + "/deployments/" + reads.OwnerName:
				object, err = f.cfg.Kubernetes.AppsV1().Deployments(workload.Namespace).Get(f.ctx, reads.OwnerName, metav1.GetOptions{})
			default:
				wr.WriteHeader(http.StatusNotFound)
				return
			}
			if err != nil {
				wr.WriteHeader(http.StatusInternalServerError)
				return
			}
			json.NewEncoder(wr).Encode(object)
		}))
		defer api.Close()
		client, err := kubernetes.NewForConfig(&rest.Config{Host: api.URL})
		if err != nil {
			t.Fatal(err)
		}
		cfg.Kubernetes = client
		cfg.KubernetesReads = &reads
		factory, err := a.NewControllerVerifierFactory(cfg)
		if err != nil {
			t.Fatal(err)
		}
		scope := a.ControllerVerifierCandidate{Input: f.in, Job: f.job, Invocation: f.invocation, CandidateSHA256: strings.Repeat("d", 64), CaptureGrantSHA256: cfg.CaptureGrantSHA256}
		verifier, err := factory.ForCandidate(f.ctx, scope)
		if err != nil {
			t.Fatal("exact mapped actor rejected", err)
		}
		defer verifier.Close()
		request := f.invocation.ProviderKey.Request
		wrapped := w.WrappedKey{Request: request, Algorithm: "provider-native", Ciphertext: []byte("vault:v1:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 60)))}
		used := 0
		if err = verifier.Unwrap(f.ctx, request, wrapped, func(key []byte) error {
			used++
			if !bytes.Equal(key, f.dek) {
				t.Fatal("wrong DEK")
			}
			return verifier.Recheck(f.ctx)
		}); err != nil || used != 1 {
			t.Fatal("mapped SQL/TLS unwrap failed", err)
		}
		for _, resource := range []string{"replicasets", "deployments"} {
			apiMu.Lock()
			deny = resource
			fetched = nil
			apiMu.Unlock()
			before := f.providerCalls()
			if verifier.Recheck(f.ctx) == nil {
				t.Fatal("real HTTP 403 accepted")
			}
			if err = verifier.Unwrap(f.ctx, request, wrapped, func([]byte) error { used++; return nil }); err == nil {
				t.Fatal("403 reached DEK callback")
			}
			if _, err = factory.ForCandidate(f.ctx, scope); err == nil {
				t.Fatal("403 accepted by new candidate construction")
			}
			if f.providerCalls() != before || used != 1 {
				t.Fatal("denied owner read reached provider or callback")
			}
			apiMu.Lock()
			fetchedCount := len(fetched)
			apiMu.Unlock()
			if fetchedCount == 0 {
				t.Fatal("negative did not issue actual Kubernetes HTTP request")
			}
		}
	})
}
