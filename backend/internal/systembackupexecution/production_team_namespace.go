package systembackupexecution

import (
	"context"
	"strconv"

	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/team"
	d "clawreef/internal/systembackupdispatch"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// The SQL team owner selects the tenant namespace; a caller-supplied namespace
// alone is never authority to include another tenant's PVC. Return the live UID
// so the Longhorn source pin also binds the namespace observed here.
func observeTeamSourceNamespace(ctx context.Context, api kubernetes.Interface, cfg DeploymentConfig, fact team.TeamSQLFacts) (string, error) {
	if api == nil || fact.Namespace == "" {
		return "", d.ErrNotReady
	}
	tenant := fact.Namespace != cfg.Namespace
	if tenant && (fact.ID <= 0 || fact.ResourceScope != "cm" || fact.Owner != "" ||
		!validTenantProNamespace(cfg.Namespace, b.InstanceIdentity{UserID: fact.UserID, Namespace: fact.Namespace})) {
		return "", d.ErrNotReady
	}
	ns, err := api.CoreV1().Namespaces().Get(ctx, fact.Namespace, metav1.GetOptions{})
	if err != nil || ns.UID == "" || ns.DeletionTimestamp != nil {
		return "", d.ErrNotReady
	}
	if tenant {
		if ns.Labels["app"] != "clawreef" || ns.Labels["managed-by"] != "clawreef" || ns.Labels["user-id"] != strconv.Itoa(fact.UserID) {
			return "", d.ErrNotReady
		}
	} else if string(ns.UID) != cfg.NamespaceUID {
		return "", d.ErrNotReady
	}
	return string(ns.UID), nil
}

// Cross-namespace RWX clones are admitted only for an exact SQL-owned team
// part. Other cross-namespace RWX sources remain unsupported.
func verifyTenantTeamLonghornSource(ctx context.Context, api kubernetes.Interface, cfg DeploymentConfig, part string, source originalLonghornSource, facts *team.SourceFacts) error {
	if facts == nil || source.AccessMode != corev1.ReadWriteMany {
		return d.ErrNotReady
	}
	matches := 0
	for _, fact := range facts.Teams {
		if part != "team_"+strconv.Itoa(fact.ID)+"_workspace" {
			continue
		}
		matches++
		if fact.PVC == "" || fact.PVC != source.Source.Name || fact.Namespace != source.Namespace {
			return d.ErrNotReady
		}
		uid, err := observeTeamSourceNamespace(ctx, api, cfg, fact)
		if err != nil || uid != source.NamespaceUID {
			return d.ErrNotReady
		}
	}
	if matches != 1 {
		return d.ErrNotReady
	}
	return nil
}
