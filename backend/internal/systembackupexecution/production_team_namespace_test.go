package systembackupexecution

import (
	"context"
	"testing"

	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/team"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestTenantTeamSourceNamespaceAndCloneOwnership(t *testing.T) {
	ctx := context.Background()
	cfg := DeploymentConfig{Namespace: "test-system", NamespaceUID: "system-uid"}
	fact := team.TeamSQLFacts{ID: 1, UserID: 1, ResourceScope: "cm", Namespace: "test-user-1", PVC: "team-shared"}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: fact.Namespace, UID: "tenant-uid", Labels: map[string]string{"app": "clawreef", "managed-by": "clawreef", "user-id": "1"}}}
	source := originalLonghornSource{Namespace: fact.Namespace, NamespaceUID: string(ns.UID), AccessMode: corev1.ReadWriteMany, Source: kube.MountIdentity{Name: fact.PVC}}
	api := fake.NewSimpleClientset(ns)
	facts := &team.SourceFacts{Teams: []team.TeamSQLFacts{fact}}
	if err := verifyTenantTeamLonghornSource(ctx, api, cfg, "team_1_workspace", source, facts); err != nil {
		t.Fatalf("SQL-owned tenant RWX team rejected: %v", err)
	}
	for _, mutate := range []func(*team.TeamSQLFacts){
		func(f *team.TeamSQLFacts) { f.UserID = 2 },
		func(f *team.TeamSQLFacts) { f.ResourceScope = "northbound" },
		func(f *team.TeamSQLFacts) { f.Owner = "foreign" },
		func(f *team.TeamSQLFacts) { f.ID = 2 },
		func(f *team.TeamSQLFacts) { f.PVC = "other" },
		func(f *team.TeamSQLFacts) { f.Namespace = "other-user-1" },
	} {
		changed := fact
		mutate(&changed)
		if verifyTenantTeamLonghornSource(ctx, api, cfg, "team_1_workspace", source, &team.SourceFacts{Teams: []team.TeamSQLFacts{changed}}) == nil {
			t.Fatal("changed SQL owner/claim admitted")
		}
	}
	for _, part := range []string{"instance_1_workspace", "team_01_workspace", "team_2_workspace"} {
		if verifyTenantTeamLonghornSource(ctx, api, cfg, part, source, facts) == nil {
			t.Fatal("non-team or different part admitted")
		}
	}
	if verifyTenantTeamLonghornSource(ctx, api, cfg, "team_1_workspace", source, &team.SourceFacts{Teams: []team.TeamSQLFacts{fact, fact}}) == nil {
		t.Fatal("ambiguous SQL team admitted")
	}
	for _, mutate := range []func(*corev1.Namespace){
		func(n *corev1.Namespace) { n.UID = "replacement" },
		func(n *corev1.Namespace) { n.Labels["user-id"] = "2" },
		func(n *corev1.Namespace) { delete(n.Labels, "app") },
		func(n *corev1.Namespace) { delete(n.Labels, "managed-by") },
		func(n *corev1.Namespace) { now := metav1.Now(); n.DeletionTimestamp = &now },
	} {
		changed := ns.DeepCopy()
		mutate(changed)
		if verifyTenantTeamLonghornSource(ctx, fake.NewSimpleClientset(changed), cfg, "team_1_workspace", source, facts) == nil {
			t.Fatal("namespace replacement or ownership drift admitted")
		}
	}
	legacy := fact
	legacy.Namespace = cfg.Namespace
	system := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: cfg.Namespace, UID: "system-uid"}}
	if _, err := observeTeamSourceNamespace(ctx, fake.NewSimpleClientset(system), cfg, legacy); err != nil {
		t.Fatal("pinned system namespace rejected")
	}
	system.UID = "replacement"
	if _, err := observeTeamSourceNamespace(ctx, fake.NewSimpleClientset(system), cfg, legacy); err == nil {
		t.Fatal("system namespace replacement admitted")
	}
}
