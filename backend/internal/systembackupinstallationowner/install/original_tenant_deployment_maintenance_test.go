package install

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/domain"
	authorizationv1 "k8s.io/api/authorization/v1"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// Authenticated Installer/SQL protocol fixture and real journal; Kubernetes is
// a protocol model. Preparation is not a physical CSI stop or recovery proof.
func TestOriginalTenantDeploymentUsesAuthenticatedNamespace(t *testing.T) {
	for _, mode := range []string{"valid", "unregistered", "duplicate-source", "changed-selection", "denied", "foreign-journal", "namespace-replaced", "unowned-pod"} {
		t.Run(mode, func(t *testing.T) {
			f := newAuthorityFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			op, err := f.i.authenticate(ctx, f.password)
			if err != nil {
				t.Fatal(err)
			}
			head, _, err := snapshot(ctx, op)
			if err != nil {
				t.Fatal(err)
			}
			_, source, tenant := tenantSelectionFixture()
			oldNamespace := source.Namespace
			source.Namespace = "backup-user-1"
			k := f.i.kube.(*kubefake.Clientset)
			ns, err := tenant.CoreV1().Namespaces().Get(ctx, oldNamespace, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			ns.Name = source.Namespace
			if _, err = k.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			dep, err := tenant.AppsV1().Deployments(oldNamespace).Get(ctx, "instance-2", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			dep.Namespace, dep.ResourceVersion = source.Namespace, "1"
			if _, err = k.AppsV1().Deployments(source.Namespace).Create(ctx, dep, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			rs, err := tenant.AppsV1().ReplicaSets(oldNamespace).Get(ctx, "instance-2-rs", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			rs.Namespace = source.Namespace
			if _, err = k.AppsV1().ReplicaSets(source.Namespace).Create(ctx, rs, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			pod, err := tenant.CoreV1().Pods(oldNamespace).Get(ctx, source.Pod, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			pod.Namespace = source.Namespace
			if _, err = k.CoreV1().Pods(source.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			p := &OriginalWriterMaintenance{ctx: ctx, operator: op, enrollment: f.enrollment, initial: head.cas, operation: strings.Repeat("a", 32), until: op.until, instances: []domain.SourceInstance{source}}
			p.origin = p
			if err = p.check(ctx); err != nil {
				t.Fatal("fixture maintenance authority", err)
			}
			directory := filepath.Clean(t.TempDir())
			if err = os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			journal, err := newOriginalWriterJournal(ctx, p, directory, strings.Repeat("b", 64))
			if err != nil {
				t.Fatal(err)
			}
			defer journal.close()
			identity, actualPod, actualDep, _, err := p.readInitialTenantPro(ctx, source)
			if err != nil {
				t.Fatal(err)
			}
			selected, err := originalTenantProCapture(source, identity, actualPod, actualDep)
			if err != nil {
				t.Fatal(err)
			}
			reviews := 0
			k.PrependReactor("create", "selfsubjectaccessreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
				r := action.(ktesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview).Spec.ResourceAttributes
				if r == nil || r.Resource != "deployments" {
					return false, nil, nil
				}
				reviews++
				allowed := mode != "denied" && r.Namespace == source.Namespace && r.Group == "apps" && r.Name == dep.Name && r.Verb == "patch"
				return true, &authorizationv1.SelfSubjectAccessReview{Status: authorizationv1.SubjectAccessReviewStatus{Allowed: allowed, Denied: !allowed}}, nil
			})
			switch mode {
			case "unregistered":
				p.instances = nil
			case "duplicate-source":
				p.instances = append(p.instances, source)
			case "changed-selection":
				selected.Identity.DeploymentUID = "other"
			case "foreign-journal":
				journal.operation = "other"
			case "unowned-pod":
				rogue := pod.DeepCopy()
				rogue.Name = "other-pod"
				rogue.UID = "other-uid"
				rogue.OwnerReferences = nil
				if _, err = k.CoreV1().Pods(source.Namespace).Create(ctx, rogue, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			k.ClearActions()
			writer, err := p.prepareTenantDeployment(ctx, selected, journal)
			if mode != "valid" && mode != "namespace-replaced" {
				if err == nil || writer != nil {
					t.Fatal("unauthorized tenant actor admitted")
				}
				return
			}
			if err != nil || writer.ID() != "deployment/backup-user-1/instance-2" || writer.namespaceUID != "tenant-uid" || reviews != 1 {
				t.Fatal("tenant actor lost actual scope", err)
			}
			var checkpoint map[string]any
			if json.Unmarshal([]byte(writer.original.Checkpoint), &checkpoint) != nil || checkpoint["NamespaceUID"] != "tenant-uid" {
				t.Fatal("checkpoint lost tenant namespace")
			}
			if mode == "namespace-replaced" {
				ns.UID = "replacement"
				if _, err = k.CoreV1().Namespaces().Update(ctx, ns, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
				if _, err = writer.current(ctx); err == nil {
					t.Fatal("namespace replacement accepted")
				}
			} else if _, err = writer.current(ctx); err != nil {
				t.Fatal(err)
			}
			for _, action := range k.Actions() {
				if action.GetResource().Resource == "deployments" && action.GetVerb() != "get" && action.GetVerb() != "list" {
					t.Fatal("preparation mutated a deployment")
				}
			}
			if mode == "valid" {
				census, _, _, _, err := p.readKubernetesNamespaceCensus(ctx, writer.namespace, writer.namespaceUID)
				if err != nil {
					t.Fatal(err)
				}
				set := &PreparedOriginalWriterSet{owner: p, deployments: []*originalDeploymentMaintenance{writer}, selection: OriginalWriterSetSelection{TenantPro: []OriginalTenantProSelection{selected}, TenantNamespaces: []originalMaintenanceKubernetesCensus{census}}}
				if err := set.recheckTenantPreflight(ctx); err != nil {
					t.Fatal(err)
				}
				if err := set.recheckTenantLifecycle(ctx, nil, nil); err == nil {
					t.Fatal("running tenant accepted as held")
				}
				rogue := pod.DeepCopy()
				rogue.Name, rogue.UID = "unexpected-census-pod", "unexpected-census-uid"
				if _, err := k.CoreV1().Pods(writer.namespace).Create(ctx, rogue, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
				if err := set.recheckTenantPreflight(ctx); err == nil {
					t.Fatal("extra tenant Pod escaped complete census")
				}
				for _, name := range []string{pod.Name, rogue.Name} {
					if err := k.CoreV1().Pods(writer.namespace).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
						t.Fatal(err)
					}
				}
				stopped := dep.DeepCopy()
				*stopped.Spec.Replicas = 0
				stopped.Status.Replicas, stopped.Status.ReadyReplicas = 0, 0
				stopped.Status.ObservedGeneration = stopped.Generation
				if _, err := k.AppsV1().Deployments(writer.namespace).Update(ctx, stopped, metav1.UpdateOptions{}); err != nil {
					t.Fatal(err)
				}
				if err := set.recheckTenantLifecycle(ctx, nil, nil); err != nil {
					t.Fatal("stopped tenant census rejected", err)
				}
				job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "unregistered-keeper", Namespace: writer.namespace, UID: "rogue-job"}}
				if _, err := k.BatchV1().Jobs(writer.namespace).Create(ctx, job, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
				if err := set.recheckTenantLifecycle(ctx, nil, nil); err == nil {
					t.Fatal("unregistered keeper Job escaped complete census")
				}
			}
			if f.s.writes != 0 || f.signs.Load() != 0 {
				t.Fatal("preparation fabricated SQL/issuer authority")
			}
			requireNoOpenAuthorityTx(t, f.s)
		})
	}
}
