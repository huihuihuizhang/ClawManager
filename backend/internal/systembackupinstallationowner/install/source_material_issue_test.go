package install

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/worker"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Component coverage uses the existing explicit SQL transaction/Kubernetes
// protocol model. It is not native SQL execution or source permission proof.
func sourceMaterialFixture(t *testing.T) (*authorityFixture, context.Context, SourceMaterialIntent) {
	t.Helper()
	f := newAuthorityFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	p := f.i.plan
	raw := []byte(`{"original":"independent source declaration"}`)
	file := filepath.Join(t.TempDir(), "definition.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	i := SourceMaterialIntent{DefinitionFile: file, DefinitionSHA256: hash(raw), InstallationID: p.Target.InstallationID, Namespace: p.Target.Namespace, NamespaceUID: p.Target.NamespaceUID, Purpose: "functional_test", ServerUUID: p.Target.ServerUUID, Database: p.Target.Database, DatabaseAccount: p.Target.DatabaseAccount, DeploymentConfigSHA256: strings.Repeat("a", 64), CaptureGrantSHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64), ControllerOwner: "original-controller-owner", ControllerDeployment: "original-controller", ControllerDeploymentUID: "original-controller-uid", ControllerServiceAccount: "controller", ControllerServiceAccountUID: "controller-sa-uid", WorkerServiceAccount: "original-worker", WorkerServiceAccountUID: "original-worker-uid", SourceServiceAccount: "original-source", SourceServiceAccountUID: "original-source-uid", RedisScopeSHA256: strings.Repeat("d", 64), RedisCredentialSHA256: strings.Repeat("e", 64), ObjectScopeSHA256: strings.Repeat("f", 64), ObjectCredentialSHA256: strings.Repeat("1", 64), NotBefore: now.Add(-time.Second), Until: now.Add(2 * time.Minute)}
	_, err := f.i.kube.AppsV1().Deployments(i.Namespace).Create(ctx, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: i.ControllerDeployment, Namespace: i.Namespace, UID: types.UID(i.ControllerDeploymentUID)}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: i.ControllerServiceAccount}}}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, actor := range [][2]string{{i.WorkerServiceAccount, i.WorkerServiceAccountUID}, {i.SourceServiceAccount, i.SourceServiceAccountUID}} {
		if _, err := f.i.kube.CoreV1().ServiceAccounts(i.Namespace).Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: actor[0], Namespace: i.Namespace, UID: types.UID(actor[1])}}, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	return f, ctx, i
}

func TestSourceMaterialAuthenticatedIssuerSignsExactOriginalScope(t *testing.T) {
	f, ctx, i := sourceMaterialFixture(t)
	p, err := f.i.PrepareSourceMaterialIssue(ctx, f.password, f.enrollment, i)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"capture-source-redis", "capture-skill-objects"} {
		scope, credential := i.RedisScopeSHA256, i.RedisCredentialSHA256
		if operation == "capture-skill-objects" {
			scope, credential = i.ObjectScopeSHA256, i.ObjectCredentialSHA256
		}
		g := worker.FormalSourceGrant{Version: worker.FormalSourceGrantVersion, InstallationID: i.InstallationID, ConfigSHA256: i.ConfigSHA256, WorkerNamespace: i.Namespace, WorkerServiceAccountUID: i.WorkerServiceAccountUID, Operation: operation, ScopeSHA256: scope, CredentialSHA256: credential, NotBefore: i.NotBefore, Until: i.Until}
		raw, err := p.SignWorkerSource(ctx, g, f.key)
		var envelope worker.SignedFormalSourceGrant
		var actual worker.FormalSourceGrant
		if err != nil || json.Unmarshal(raw, &envelope) != nil || json.Unmarshal(envelope.Record, &actual) != nil || actual != g || !ed25519.Verify(f.i.public, append([]byte(worker.FormalSourceGrantDomain), envelope.Record...), envelope.Signature) {
			t.Fatal("original worker source signature", err)
		}
		g.Until = g.Until.Add(time.Second)
		if _, err := p.SignWorkerSource(ctx, g, f.key); err == nil {
			t.Fatal("renewed original absolute window")
		}
	}
	g := ControllerSourceMetadataGrant{Version: "system-backup-original-source-metadata-grant.v1", InstallationID: i.InstallationID, ControllerOwner: i.ControllerOwner, DeploymentConfigSHA256: i.DeploymentConfigSHA256, CaptureGrantSHA256: i.CaptureGrantSHA256, ConfigSHA256: i.ConfigSHA256, ScopeSHA256: strings.Repeat("2", 64), Namespace: i.Namespace, NamespaceUID: i.NamespaceUID, ControllerDeployment: i.ControllerDeployment, ControllerDeploymentUID: i.ControllerDeploymentUID, ControllerServiceAccount: i.ControllerServiceAccount, ControllerServiceAccountUID: i.ControllerServiceAccountUID, NotBefore: i.NotBefore, Until: i.Until}
	raw, err := p.SignControllerMetadata(ctx, g, f.key)
	var envelope worker.SignedFormalSourceGrant
	if err != nil || json.Unmarshal(raw, &envelope) != nil || !ed25519.Verify(f.i.public, append([]byte("system-backup-controller-source-metadata.v1\x00"), envelope.Record...), envelope.Signature) || ed25519.Verify(f.i.public, append([]byte(worker.FormalSourceGrantDomain), envelope.Record...), envelope.Signature) || f.s.writes != 0 || f.signs.Load() != 0 {
		t.Fatal("separate metadata domain, no capture probe or ledger writes", err)
	}
	if _, err := json.Marshal(p); err == nil {
		t.Fatal("serialized authenticated capability")
	}
	if err := os.WriteFile(i.DefinitionFile, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if p.Recheck(ctx) == nil {
		t.Fatal("accepted changed original definition")
	}
}

func TestSourceMaterialIssuerRejectsUnauthenticatedOrDifferentOriginalInputs(t *testing.T) {
	for _, name := range []string{"password", "enrollment", "purpose", "database", "worker-uid", "controller-uid", "permission", "expired"} {
		t.Run(name, func(t *testing.T) {
			f, ctx, i := sourceMaterialFixture(t)
			password, pin := f.password, f.enrollment
			switch name {
			case "password":
				password = []byte("incorrect")
			case "enrollment":
				pin.ConfigMapUID = "different"
			case "purpose":
				i.Purpose = "acceptance"
			case "database":
				i.Database = "different"
			case "worker-uid":
				i.WorkerServiceAccountUID = "different"
			case "controller-uid":
				i.ControllerDeploymentUID = "different"
			case "permission":
				f.permissionDenied.Store(true)
			case "expired":
				i.NotBefore, i.Until = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
			}
			if p, err := f.i.PrepareSourceMaterialIssue(ctx, password, pin, i); err == nil || p != nil || f.s.writes != 0 || f.signs.Load() != 0 {
				t.Fatal("accepted invalid original inputs or performed mutation", err)
			}
		})
	}
}
