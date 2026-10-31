package worker

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// This mapping is SHA-pinned by FormalCaptureSpec. It names a dedicated source
// API credential mount, never the worker-control JWT, KMS token, or kubeconfig.
type ResourceSourceMount struct {
	Server    string `json:"server"`
	CAFile    string `json:"ca_file"`
	CASHA256  string `json:"ca_sha256"`
	TokenFile string `json:"token_file"`
}

func resourceMountedFile(path string, private bool, max int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrNotReady
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrNotReady
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > max || (private && runtime.GOOS == "linux" && st.Mode().Perm()&0077 != 0) {
		return nil, ErrNotReady
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(raw)) != st.Size() {
		clear(raw)
		return nil, ErrNotReady
	}
	return raw, nil
}

// ResourceSourceRules admits no mutation/list/watch/wildcard on source data.
// The only CREATE operations are the API's own self-review endpoints.
func ResourceSourceRules(s ResourceCaptureSpec, rules authzv1.SubjectRulesReviewStatus) bool {
	if rules.Incomplete || rules.EvaluationError != "" {
		return false
	}
	allowed := map[string]bool{}
	covered := map[string]bool{}
	for _, x := range s.Selections {
		allowed[x.Group+"/"+x.Resource+"/"+x.Name] = true
	}
	for _, r := range rules.ResourceRules {
		if len(r.Verbs) == 0 || len(r.APIGroups) == 0 || len(r.Resources) == 0 {
			return false
		}
		for _, verb := range r.Verbs {
			for _, group := range r.APIGroups {
				for _, resource := range r.Resources {
					if SourceSelfReviewRule(verb, group, resource, r.ResourceNames) {
						continue
					}
					if verb != "get" || len(r.ResourceNames) == 0 {
						return false
					}
					for _, name := range r.ResourceNames {
						if !allowed[group+"/"+resource+"/"+name] {
							return false
						}
						covered[group+"/"+resource+"/"+name] = true
					}
				}
			}
		}
	}
	// Exact known discovery patterns only. Their '*' is scoped by RBAC to
	// non-resource discovery requests, never resource objects under /apis.
	if !SourceDiscoveryNonResourceRules(rules.NonResourceRules) {
		return false
	}
	// This is the API's view of THIS namespace, not proof about bindings in
	// other namespaces. Installation admission owns that independent inventory.
	return len(covered) == len(allowed)
}

// SourceSelfReviewRule recognizes only the API's non-mutating self reviews.
func SourceSelfReviewRule(verb, group, resource string, names []string) bool {
	self := (group == "authentication.k8s.io" && resource == "selfsubjectreviews") || (group == "authorization.k8s.io" && (resource == "selfsubjectaccessreviews" || resource == "selfsubjectrulesreviews"))
	return verb == "create" && self && len(names) == 0
}

// Exact Kubernetes v1.32.3 basic-user, discovery, public-info and service-account
// issuer-discovery defaults. None of these RBAC non-resource URLs authorize a
// resource object. The issuer URLs come from system:service-account-issuer-discovery:
// https://github.com/kubernetes/kubernetes/blob/v1.32.3/plugin/pkg/auth/authorizer/rbac/bootstrappolicy/policy.go
func SourceDiscoveryNonResourceRules(rules []authzv1.NonResourceRule) bool {
	discovery := map[string]bool{"/api": true, "/api/*": true, "/apis": true, "/apis/*": true, "/openapi": true, "/openapi/*": true, "/version": true, "/version/": true, "/healthz": true, "/livez": true, "/readyz": true, "/.well-known/openid-configuration": true, "/.well-known/openid-configuration/": true, "/openid/v1/jwks": true, "/openid/v1/jwks/": true}
	for _, r := range rules {
		if len(r.Verbs) == 0 || len(r.NonResourceURLs) == 0 {
			return false
		}
		for _, v := range r.Verbs {
			if v != "get" {
				return false
			}
		}
		for _, u := range r.NonResourceURLs {
			if !discovery[u] {
				return false
			}
		}
	}
	return true
}

func OpenResourceCaptureSources(ctx context.Context, i Invocation, mount *ResourceSourceMount) (*ResourceCaptureSources, error) {
	if ctx == nil || ctx.Err() != nil || mount == nil || !validResourceCapture(i.Request) || !ValidateRecordedInvocation(i) || !time.Now().Before(i.Request.Deadline) {
		return nil, ErrNotReady
	}
	raw, err := json.Marshal(i)
	var frozen Invocation
	if err != nil || len(raw) > 1<<20 || json.Unmarshal(raw, &frozen) != nil {
		return nil, ErrNotReady
	}
	i = frozen
	u, err := url.Parse(mount.Server)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery {
		return nil, ErrNotReady
	}
	ca, err := resourceMountedFile(mount.CAFile, false, 1<<20)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(ca)
	pool := x509.NewCertPool()
	if hex.EncodeToString(sum[:]) != mount.CASHA256 || !pool.AppendCertsFromPEM(ca) {
		return nil, ErrNotReady
	}
	token, err := resourceMountedFile(mount.TokenFile, true, 64<<10)
	if err != nil {
		return nil, err
	}
	defer clear(token)
	value := strings.TrimSpace(string(token))
	if value == "" || strings.ContainsAny(value, " \t\r\n\x00") {
		return nil, ErrNotReady
	}
	cfg := &rest.Config{Host: mount.Server, BearerToken: value, TLSClientConfig: rest.TLSClientConfig{CAData: ca}, Timeout: 5 * time.Second, QPS: 5, Burst: 5}
	transport, err := rest.TransportFor(cfg)
	if err != nil {
		return nil, ErrNotReady
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	api, err := kubernetes.NewForConfigAndClient(cfg, client)
	if err != nil {
		client.CloseIdleConnections()
		return nil, ErrNotReady
	}
	dyn, err := dynamic.NewForConfigAndClient(cfg, client)
	if err != nil {
		client.CloseIdleConnections()
		return nil, ErrNotReady
	}
	hash, err := i.Hash()
	if err != nil {
		client.CloseIdleConnections()
		return nil, ErrNotReady
	}
	var closed atomic.Bool
	result := &ResourceCaptureSources{Client: dyn, close: func() { closed.Store(true); client.CloseIdleConnections() }}
	result.Authorize = func(ctx context.Context, original Invocation) error {
		got, e := original.Hash()
		if ctx == nil || ctx.Err() != nil || closed.Load() || e != nil || got != hash || !time.Now().Before(i.Request.Deadline) {
			return ErrNotReady
		}
		ctx, cancel := context.WithDeadline(ctx, i.Request.Deadline)
		defer cancel()
		identity, e := api.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authnv1.SelfSubjectReview{}, metav1.CreateOptions{})
		s := i.Request.Resources
		if e != nil || identity.Status.UserInfo.Username != "system:serviceaccount:"+s.Namespace+":"+s.ServiceAccountName || identity.Status.UserInfo.UID != s.ServiceAccountUID {
			return ErrNotReady
		}
		rules, e := api.AuthorizationV1().SelfSubjectRulesReviews().Create(ctx, &authzv1.SelfSubjectRulesReview{Spec: authzv1.SelfSubjectRulesReviewSpec{Namespace: s.Namespace}}, metav1.CreateOptions{})
		if e != nil || !ResourceSourceRules(*s, rules.Status) || closed.Load() || ctx.Err() != nil {
			return ErrNotReady
		}
		return nil
	}
	if result.Authorize(ctx, i) != nil {
		result.Close()
		return nil, ErrNotReady
	}
	return result, nil
}
