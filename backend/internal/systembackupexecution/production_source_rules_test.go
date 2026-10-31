package systembackupexecution

import (
	"testing"

	authzv1 "k8s.io/api/authorization/v1"
)

func TestProductionMetadataPermissionsIncludeRealDefaultRulesAndRejectDataWrites(t *testing.T) {
	types := []productionResourceType{{Part: "deployment_resources", Version: "v1", Resource: "configmaps"}, {Part: "secret_bundle", Version: "v1", Resource: "secrets"}}
	for _, fault := range []string{"valid", "write", "watch", "wildcard-resource", "foreign-resource", "foreign-review", "wildcard-url", "extra-url", "named-list", "incomplete", "missing-list"} {
		t.Run(fault, func(t *testing.T) {
			rules := authzv1.SubjectRulesReviewStatus{ResourceRules: []authzv1.ResourceRule{{Verbs: []string{"get", "list"}, APIGroups: []string{""}, Resources: []string{"configmaps", "secrets"}}, {Verbs: []string{"create"}, APIGroups: []string{"authorization.k8s.io"}, Resources: []string{"selfsubjectaccessreviews", "selfsubjectrulesreviews"}}, {Verbs: []string{"create"}, APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"selfsubjectreviews"}}}, NonResourceRules: []authzv1.NonResourceRule{{Verbs: []string{"get"}, NonResourceURLs: []string{"/api", "/api/*", "/apis", "/apis/*", "/openapi", "/openapi/*", "/healthz", "/livez", "/readyz", "/version", "/version/", "/.well-known/openid-configuration", "/.well-known/openid-configuration/", "/openid/v1/jwks", "/openid/v1/jwks/"}}}}
			switch fault {
			case "write":
				rules.ResourceRules[0].Verbs = []string{"get", "list", "patch"}
			case "watch":
				rules.ResourceRules[0].Verbs = []string{"get", "list", "watch"}
			case "wildcard-resource":
				rules.ResourceRules[0].Resources = []string{"*"}
			case "foreign-resource":
				rules.ResourceRules[0].Resources = append(rules.ResourceRules[0].Resources, "pods")
			case "foreign-review":
				rules.ResourceRules[1].Resources = []string{"subjectaccessreviews"}
			case "wildcard-url":
				rules.NonResourceRules[0].NonResourceURLs = []string{"*"}
			case "extra-url":
				rules.NonResourceRules[0].NonResourceURLs = append(rules.NonResourceRules[0].NonResourceURLs, "/metrics")
			case "named-list":
				rules.ResourceRules[0].ResourceNames = []string{"original"}
			case "incomplete":
				rules.Incomplete = true
			case "missing-list":
				rules.ResourceRules[0].Verbs = []string{"get"}
			}
			if sourceMetadataResourceRules(types, rules) != (fault == "valid") {
				t.Fatal("metadata permission mismatch", fault)
			}
		})
	}
}
