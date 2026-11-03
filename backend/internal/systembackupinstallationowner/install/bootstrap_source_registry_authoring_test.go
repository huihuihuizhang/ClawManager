package install

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Actual Installer.New/Enroll/password/admin/head/enrollment methods with the
// existing explicit SQL/Kube protocol fixture. These tests prove authoring
// capability provenance/pin/window/latch, NOT full native census or V2 success.
func sourceRegistryAuthoringFixture(t *testing.T) (*authorityFixture, context.Context, BootstrapSourceAuthoringSelection, string, string) {
	t.Helper()
	f := newAuthorityFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	ns := f.i.plan.Target.Namespace
	controller := true
	pod, err := f.i.kube.CoreV1().Pods(ns).Get(ctx, "controller", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pod.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "controller-rs", UID: "controller-rs-uid", Controller: &controller}}
	if _, err = f.i.kube.CoreV1().Pods(ns).Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.i.kube.AppsV1().ReplicaSets(ns).Create(ctx, &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "controller-rs", Namespace: ns, UID: "controller-rs-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "controller-deployment", UID: "controller-deployment-uid", Controller: &controller}}}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.i.kube.AppsV1().Deployments(ns).Create(ctx, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "controller-deployment", Namespace: ns, UID: "controller-deployment-uid"}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: "controller"}}}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, raw []byte) BootstrapSourceFilePin {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return BootstrapSourceFilePin{path, hash(raw)}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	s := BootstrapSourceAuthoringSelection{Version: BootstrapSourceAuthoringSelectionVersion, Deployment: write("core.json", []byte(`{}`)), MaterialsTemplate: write("template.json", append(append([]byte(`{"payload":"`), bytes.Repeat([]byte("x"), 300000)...), []byte(`"}`)...)), ExecutionProfile: write("profile.json", []byte(`{}`)), Controller: BootstrapSourceController{Namespace: ns, NamespaceUID: f.i.plan.Target.NamespaceUID, Deployment: "controller-deployment", DeploymentUID: "controller-deployment-uid", ReplicaSet: "controller-rs", ReplicaSetUID: "controller-rs-uid", Pod: "controller", PodUID: string(pod.UID), ServiceAccount: "controller", ServiceAccountUID: "controller-sa-uid"}, ApplicationScope: "original-app", PartsVersion: "original-parts-1", SourceWritersVersion: "original-writers-1", PartsFile: filepath.Join(dir, "parts.json"), SourceWritersFile: filepath.Join(dir, "writers.json"), NotBefore: now.Add(-time.Second), Until: now.Add(time.Minute)}
	for n, purpose := range []string{"control_sql", "source_api", "source_objects", "source_redis", "source_sql"} {
		scheme := "https"
		if strings.HasSuffix(purpose, "sql") {
			scheme = "mysql+tls"
		}
		if purpose == "source_redis" {
			scheme = "rediss"
		}
		c := BootstrapSourceConnection{Purpose: purpose, Endpoint: scheme + "://selected.invalid:443", Account: purpose + "@localhost", CA: write(purpose+".ca", []byte("selected-ca")), Credential: write(purpose+".credential", []byte("selected-private-credential"))}
		if n == 0 {
			c.ServerUUID = f.i.plan.Target.ServerUUID
			c.Database = f.i.plan.Target.Database
		}
		if n == 4 {
			c.ServerUUID = "source-server"
			c.Database = "business"
		}
		s.Connections = append(s.Connections, c)
	}
	raw, err := canonical(s)
	if err != nil {
		t.Fatal(err)
	}
	pin := write("selection.json", raw)
	return f, ctx, s, pin.File, pin.SHA256
}

func TestBootstrapSourceRegistryAuthoringUsesActualEnrollmentWithoutFinalDigests(t *testing.T) {
	f, ctx, s, file, sha := sourceRegistryAuthoringFixture(t)
	p, err := f.i.PrepareBootstrapSourceRegistryAuthoring(ctx, f.password, f.enrollment, file, sha)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	data, target, err := p.Selection(ctx)
	if err != nil || target != f.i.plan.Target || data.PartsFile != s.PartsFile || f.s.writes != 0 || f.signs.Load() != 0 {
		t.Fatal("did not use original authentication/read-only authority", err)
	}
	raw, err := p.Read(ctx, s.MaterialsTemplate)
	if err != nil || len(raw) <= 262144 {
		t.Fatal("original 8 MiB material path rejected by small private-file helper", err)
	}
	clear(raw)
	if _, err = json.Marshal(p); err == nil {
		t.Fatal("serialized opaque authoring capability")
	}
	data.Connections[0].Account = "changed"
	data2, _, err := p.Selection(ctx)
	if err != nil || data2.Connections[0].Account == "changed" {
		t.Fatal("selection getter aliases private original")
	}
	if _, err = os.Stat(s.PartsFile); !os.IsNotExist(err) {
		t.Fatal("authentication fabricated facts")
	}
}

func TestBootstrapSourceRegistryAuthoringRefusalsAreSticky(t *testing.T) {
	for _, mode := range []string{"foreign-context", "changed-file", "copied-handle", "revoked-permission", "wrong-password", "wrong-enrollment", "selected-final-scope", "expired"} {
		t.Run(mode, func(t *testing.T) {
			f, ctx, s, file, sha := sourceRegistryAuthoringFixture(t)
			password, pin := f.password, f.enrollment
			if mode == "wrong-password" {
				password = []byte("wrong")
			}
			if mode == "wrong-enrollment" {
				pin.ConfigMapUID = "other"
			}
			if mode == "selected-final-scope" || mode == "expired" {
				if mode == "selected-final-scope" {
					s.Connections[0].ScopeSHA256 = strings.Repeat("a", 64)
				} else {
					s.NotBefore = time.Now().Add(-time.Hour)
					s.Until = time.Now().Add(-time.Minute)
				}
				raw, err := canonical(s)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(file, raw, 0600); err != nil {
					t.Fatal(err)
				}
				sha = hash(raw)
			}
			p, err := f.i.PrepareBootstrapSourceRegistryAuthoring(ctx, password, pin, file, sha)
			if mode == "wrong-password" || mode == "wrong-enrollment" || mode == "selected-final-scope" || mode == "expired" {
				if err == nil || p != nil {
					t.Fatal("unauthenticated/final/cross-window source accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			switch mode {
			case "foreign-context":
				child, cancel := context.WithCancel(ctx)
				defer cancel()
				if p.Check(child) == nil {
					t.Fatal("foreign context accepted")
				}
			case "changed-file":
				original, err := os.ReadFile(s.Deployment.File)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(s.Deployment.File, []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
				if p.Check(ctx) == nil {
					t.Fatal("file drift accepted")
				}
				if err = os.WriteFile(s.Deployment.File, original, 0600); err != nil {
					t.Fatal(err)
				}
			case "copied-handle":
				detached := &BootstrapSourceRegistryAuthoring{origin: p}
				detached.Close()
			case "revoked-permission":
				f.permissionDenied.Store(true)
				if p.RecheckAuthority(ctx) == nil {
					t.Fatal("current revoked permission accepted")
				}
				f.permissionDenied.Store(false)
			}
			if p.Check(ctx) == nil || p.RecheckAuthority(ctx) == nil || f.s.writes != 0 || f.signs.Load() != 0 {
				t.Fatal("failed original source resurrected or mutated ledger")
			}
		})
	}
}
