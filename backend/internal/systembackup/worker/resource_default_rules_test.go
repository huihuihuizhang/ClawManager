package worker

import (
	"testing"

	root "clawreef/internal/systembackup"
	authzv1 "k8s.io/api/authorization/v1"
)

// Kubernetes v1.32.3 bootstrappolicy/policy.go supplies these exact defaults
// to authenticated service accounts, alongside the original named GET role.
// This pure rule test does not claim a live cluster's actual SSR response.
func TestResourceSourceRulesAcceptExactDefaultOIDCAndSelfReviewsOnly(t *testing.T) {
	spec := ResourceCaptureSpec{Selections: []root.KubernetesSelection{{Version: "v1", Resource: "configmaps", Name: "original"}}}
	baseline := func() authzv1.SubjectRulesReviewStatus {
		rules := sourceRules(spec)
		rules.ResourceRules = append(rules.ResourceRules,
			authzv1.ResourceRule{Verbs: []string{"create"}, APIGroups: []string{"authorization.k8s.io"}, Resources: []string{"selfsubjectaccessreviews", "selfsubjectrulesreviews"}},
			authzv1.ResourceRule{Verbs: []string{"create"}, APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"selfsubjectreviews"}})
		rules.NonResourceRules = append(rules.NonResourceRules, authzv1.NonResourceRule{Verbs: []string{"get"}, NonResourceURLs: []string{"/.well-known/openid-configuration", "/.well-known/openid-configuration/", "/openid/v1/jwks", "/openid/v1/jwks/"}})
		return rules
	}
	for _, mode := range []string{"valid", "wildcard-url", "openid-wildcard", "resource-url", "metrics", "url-write", "source-list", "source-write", "source-wildcard", "token-review", "foreign-subject-review", "named-self-review", "incomplete", "empty-url-rule"} {
		t.Run(mode, func(t *testing.T) {
			rules := baseline()
			switch mode {
			case "wildcard-url":
				rules.NonResourceRules[1].NonResourceURLs = []string{"*"}
			case "openid-wildcard":
				rules.NonResourceRules[1].NonResourceURLs = []string{"/openid/*"}
			case "resource-url":
				rules.NonResourceRules[1].NonResourceURLs = []string{"/api/v1/namespaces/*/secrets"}
			case "metrics":
				rules.NonResourceRules[1].NonResourceURLs = []string{"/metrics"}
			case "url-write":
				rules.NonResourceRules[1].Verbs = []string{"post"}
			case "source-list":
				rules.ResourceRules[0].Verbs = []string{"get", "list"}
			case "source-write":
				rules.ResourceRules[0].Verbs = []string{"patch"}
			case "source-wildcard":
				rules.ResourceRules[0].ResourceNames = nil
			case "token-review":
				rules.ResourceRules[2].Resources = []string{"tokenreviews"}
			case "foreign-subject-review":
				rules.ResourceRules[1].Resources = []string{"subjectaccessreviews"}
			case "named-self-review":
				rules.ResourceRules[1].ResourceNames = []string{"foreign"}
			case "incomplete":
				rules.Incomplete = true
			case "empty-url-rule":
				rules.NonResourceRules = append(rules.NonResourceRules, authzv1.NonResourceRule{})
			}
			if ResourceSourceRules(spec, rules) != (mode == "valid") {
				t.Fatal("default/non-default permission classification", mode)
			}
		})
	}
}
