package install

import (
	"context"
	"strconv"
	"strings"

	"clawreef/internal/systembackup/domain"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

type OriginalInitialTenantProCoordinates struct {
	InstanceID                                                                  int
	Namespace, NamespaceUID, PodUID, ReplicaSetUID, DeploymentUID, SourceSHA256 string
}

func originalInitialTenantNamespace(system string, source domain.SourceInstance) string {
	stem, ok := strings.CutSuffix(system, "-system")
	if !ok || stem == "" || source.UserID <= 0 || source.ID <= 0 || source.Mode != "pro" ||
		source.Status != "running" || source.Pod == "" || len(validation.IsDNS1123Subdomain(source.Pod)) != 0 {
		return ""
	}
	name := stem + "-user-" + strconv.Itoa(source.UserID)
	if name != source.Namespace || len(validation.IsDNS1123Label(name)) != 0 {
		return ""
	}
	return name
}

func (p *OriginalWriterMaintenance) readInitialTenantPro(ctx context.Context, source domain.SourceInstance) (
	OriginalInitialTenantProCoordinates, *core.Pod, *apps.Deployment, []core.PersistentVolumeClaim, error,
) {
	var zero OriginalInitialTenantProCoordinates
	i := p.operator.installer
	namespace := originalInitialTenantNamespace(i.plan.Target.Namespace, source)
	if namespace == "" {
		return zero, nil, nil, nil, ErrInstall
	}
	k := i.kube
	user := strconv.Itoa(source.UserID)
	instance := strconv.Itoa(source.ID)
	ns, err := k.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return zero, nil, nil, nil, nil
	}
	if err != nil || ns.UID == "" || ns.DeletionTimestamp != nil || ns.Labels["app"] != "clawreef" ||
		ns.Labels["managed-by"] != "clawreef" || ns.Labels["user-id"] != user {
		return zero, nil, nil, nil, ErrInstall
	}
	labels := func(m map[string]string) bool {
		return m["app"] == "clawreef" && m["managed-by"] == "clawreef" && m["user-id"] == user && m["instance-id"] == instance
	}
	pod, err := k.CoreV1().Pods(namespace).Get(ctx, source.Pod, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return zero, nil, nil, nil, nil
	}
	if err != nil || pod.UID == "" || pod.DeletionTimestamp != nil || !labels(pod.Labels) {
		return zero, nil, nil, nil, ErrInstall
	}
	ref := metav1.GetControllerOf(pod)
	if ref == nil || ref.APIVersion != "apps/v1" || ref.Kind != "ReplicaSet" || ref.Name == "" || ref.UID == "" {
		return zero, nil, nil, nil, ErrInstall
	}
	rs, err := k.AppsV1().ReplicaSets(namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil || rs.UID != ref.UID || rs.DeletionTimestamp != nil || !labels(rs.Spec.Template.Labels) {
		return zero, nil, nil, nil, ErrInstall
	}
	ref = metav1.GetControllerOf(rs)
	if ref == nil || ref.APIVersion != "apps/v1" || ref.Kind != "Deployment" || ref.Name == "" || ref.UID == "" {
		return zero, nil, nil, nil, ErrInstall
	}
	deploy, err := k.AppsV1().Deployments(namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil || deploy.UID != ref.UID || deploy.DeletionTimestamp != nil || !labels(deploy.Labels) ||
		!labels(deploy.Spec.Template.Labels) {
		return zero, nil, nil, nil, ErrInstall
	}
	var claims []core.PersistentVolumeClaim
	seen := map[string]bool{}
	for _, v := range pod.Spec.Volumes {
		ref := v.PersistentVolumeClaim
		if ref == nil || seen[ref.ClaimName] {
			continue
		}
		claim, err := k.CoreV1().PersistentVolumeClaims(namespace).Get(ctx, ref.ClaimName, metav1.GetOptions{})
		if err != nil || claim.UID == "" || claim.DeletionTimestamp != nil || claim.Status.Phase != core.ClaimBound {
			return zero, nil, nil, nil, ErrInstall
		}
		seen[ref.ClaimName] = true
		claims = append(claims, *claim)
	}
	data := struct {
		Pod        *core.Pod
		ReplicaSet *apps.ReplicaSet
		Deployment *apps.Deployment
		Claims     []core.PersistentVolumeClaim
	}{pod, rs, deploy, claims}
	return OriginalInitialTenantProCoordinates{source.ID, namespace, string(ns.UID), string(pod.UID),
		string(rs.UID), string(deploy.UID), originalObjectSHA(data)}, pod, deploy, claims, nil
}
