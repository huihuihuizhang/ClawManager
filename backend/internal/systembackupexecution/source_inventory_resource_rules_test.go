package systembackupexecution

import (
	"context"
	"testing"

	"clawreef/internal/systembackup/kube"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
)

func TestSourceInventoryRulesKeepCapturedCoverageAndFiniteTopology(t *testing.T) {
	types := []productionResourceType{{Resource: "configmaps"}, {Resource: "secrets"}}
	for _, fault := range []string{"valid", "watch", "write", "foreign-node", "foreign-pv", "foreign-namespace", "unbounded-nodes", "named-list", "foreign-resource", "wildcard", "foreign-review", "missing-capture", "incomplete", "evaluation-error"} {
		t.Run(fault, func(t *testing.T) {
			rules := authzv1.SubjectRulesReviewStatus{ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"get", "list"}, APIGroups: []string{""}, Resources: []string{"configmaps", "secrets"}},
				{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"nodes"}, ResourceNames: []string{"node1"}},
				{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"persistentvolumes"}, ResourceNames: []string{"source-pv"}},
				{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{"source"}},
				{Verbs: []string{"get", "list"}, APIGroups: []string{"apps"}, Resources: []string{"statefulsets", "daemonsets", "replicasets"}},
				{Verbs: []string{"create"}, APIGroups: []string{"authorization.k8s.io"}, Resources: []string{"selfsubjectrulesreviews"}},
			}}
			switch fault {
			case "watch":
				rules.ResourceRules[4].Verbs = []string{"watch"}
			case "write":
				rules.ResourceRules[4].Verbs = []string{"patch"}
			case "foreign-node":
				rules.ResourceRules[1].ResourceNames = []string{"foreign"}
			case "foreign-pv":
				rules.ResourceRules[2].ResourceNames = []string{"foreign"}
			case "foreign-namespace":
				rules.ResourceRules[3].ResourceNames = []string{"foreign"}
			case "unbounded-nodes":
				rules.ResourceRules[1].ResourceNames = nil
			case "named-list":
				rules.ResourceRules[1].Verbs = []string{"list"}
			case "foreign-resource":
				rules.ResourceRules[4].Resources = []string{"controllerrevisions"}
			case "wildcard":
				rules.ResourceRules[4].Resources = []string{"*"}
			case "foreign-review":
				rules.ResourceRules[5].Resources = []string{"subjectaccessreviews"}
			case "missing-capture":
				rules.ResourceRules[0].Resources = []string{"configmaps"}
			case "incomplete":
				rules.Incomplete = true
			case "evaluation-error":
				rules.EvaluationError = "not complete"
			}
			got := sourceInventoryRuleProjection(types, rules, map[string]bool{"source": true}, map[string]string{"node1": "node-uid"}, map[string]bool{"source-pv": true})
			if got != (fault == "valid") {
				t.Fatal("source graph permission mismatch", fault)
			}
			if fault == "valid" && sourceMetadataResourceRules(types, rules) {
				t.Fatal("per-part strict check was weakened")
			}
		})
	}
}

func TestSourceInventoryPVPermissionsComeFromCompleteLiveSourceClaims(t *testing.T) {
	for _, fault := range []string{"valid", "foreign-pv", "missing-list-version", "foreign-namespace", "deleting-claim"} {
		t.Run(fault, func(t *testing.T) {
			api := fake.NewSimpleClientset()
			api.PrependReactor("list", "persistentvolumeclaims", func(action kt.Action) (bool, runtime.Object, error) {
				items := &corev1.PersistentVolumeClaimList{ListMeta: metav1.ListMeta{ResourceVersion: "10"}}
				if action.GetNamespace() == "source" {
					claim := corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "source", UID: "claim-uid"}, Spec: corev1.PersistentVolumeClaimSpec{VolumeName: "source-pv"}}
					if fault == "foreign-namespace" {
						claim.Namespace = "foreign"
					}
					if fault == "deleting-claim" {
						now := metav1.Now()
						claim.DeletionTimestamp = &now
					}
					items.Items = append(items.Items, claim)
				}
				if fault == "missing-list-version" {
					items.ResourceVersion = ""
				}
				return true, items, nil
			})
			cfg := DeploymentConfig{Namespace: "source", Security: kube.WorkerSecurity{NodeUIDs: map[string]string{"node1": "node-uid"}}}
			m := productionCaptureMaterials{ResourceTypes: []productionResourceType{{Resource: "configmaps"}}, Discovery: &productionSourceDiscovery{LonghornSources: map[string]originalLonghornSource{"part": {Namespace: "source", NamespaceUID: "source-uid", ProviderNamespace: "provider", ProviderUID: "provider-uid"}}}}
			pv := "source-pv"
			if fault == "foreign-pv" {
				pv = "other-pv"
			}
			rules := authzv1.SubjectRulesReviewStatus{ResourceRules: []authzv1.ResourceRule{{Verbs: []string{"get", "list"}, APIGroups: []string{""}, Resources: []string{"configmaps"}}, {Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"persistentvolumes"}, ResourceNames: []string{pv}}}}
			if sourceInventoryResourceRules(context.Background(), api, cfg, m, rules) != (fault == "valid") {
				t.Fatal("live claim policy mismatch", fault)
			}
		})
	}
}
