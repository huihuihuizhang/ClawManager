package install

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// Protocol fixture only; root runs this independently. No live MySQL/MinIO
// compatibility or native permission assertion is supplied by this test.
func minioPermissionOwnerFixture(t *testing.T) (*authorityFixture, context.Context, string, string, MinIOPermissionDefinition) {
	t.Helper()
	f := newAuthorityFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	dir := t.TempDir()
	write := func(name string, raw []byte) string {
		file := filepath.Join(dir, name)
		if e := os.WriteFile(file, raw, 0600); e != nil {
			t.Fatal(e)
		}
		return file
	}
	config, target, credential := []byte(`{"original":"config"}`), []byte(`{"original":"target"}`), []byte(`{"original":"observer"}`)
	now := time.Now().UTC().Truncate(time.Microsecond)
	d := MinIOPermissionDefinition{Version: MinIOPermissionDefinitionVersion, ConfigFile: write("config", config), ConfigSHA256: hash(config), TargetFile: write("target", target), TargetSHA256: hash(target), GrantName: "zhanghui08-minio-grant-new", HeadName: "zhanghui08-minio-head-new", ObserverCredentialFile: write("observer", credential), ObserverCredentialSHA256: hash(credential), ObserverAccountSHA256: hash([]byte("observer")), ObserverPolicyName: "zhanghui08-observer", ObserverPolicySHA256: hash([]byte("observer-policy")), Grant: MinIOPermissionGrant{Version: "minio-permission-grant.v1", Installation: f.i.plan.Target.InstallationID, Namespace: f.i.plan.Target.Namespace, NamespaceUID: f.i.plan.Target.NamespaceUID, ConfigSHA256: hash(config), Profile: MinIOPermissionProfileV2, Epoch: 1, NotBefore: now.Add(-time.Second), Until: now.Add(time.Minute), Provider: MinIOPermissionProvider{CASHA256: hash([]byte("ca")), SPKISHA256: hash([]byte("spki"))}}}
	for _, purpose := range []string{"artifact_read", "artifact_write", "artifact_delete", "catalog_read", "catalog_append"} {
		d.Grant.Principals = append(d.Grant.Principals, MinIOPermissionPrincipal{purpose, hash([]byte("identity-" + purpose)), "original-1", hash([]byte(purpose)), "zhanghui08-" + purpose, hash([]byte("policy-" + purpose))})
	}
	raw, e := canonical(d)
	if e != nil {
		t.Fatal(e)
	}
	return f, ctx, write("definition", raw), hash(raw), d
}

func TestMinIOPermissionOwnerCreatesOnlyEnrolledOriginalSources(t *testing.T) {
	f, ctx, file, sha, d := minioPermissionOwnerFixture(t)
	p, e := f.i.PrepareMinIOPermissionIssue(ctx, f.password, f.enrollment, file, sha)
	if e != nil {
		t.Fatal(e)
	}
	committed, e := p.CreateOriginal(ctx, f.key)
	if e != nil {
		t.Fatal(e)
	}
	if committed.Epoch != 1 || committed.Grant.UID == "" || committed.Head.UID == "" || f.s.writes != 0 || f.signs.Load() != 0 {
		t.Fatal("wrong original source mutation")
	}
	for _, v := range []struct{ name, domain, sha string }{{d.GrantName, minioGrantDomain, committed.GrantSHA256}, {d.HeadName, minioHeadDomain, committed.HeadSHA256}} {
		cm, e := f.i.kube.CoreV1().ConfigMaps(d.Grant.Namespace).Get(ctx, v.name, metav1.GetOptions{})
		if e != nil || hash([]byte(cm.Data["record.json"])) != v.sha || !ed25519.Verify(f.i.public, append([]byte(v.domain), cm.Data["record.json"]...), cm.BinaryData["signature"]) || ed25519.Verify(f.i.public, []byte(cm.Data["record.json"]), cm.BinaryData["signature"]) {
			t.Fatal("missing original domain-separated signature", e)
		}
	}
	if _, e = f.i.PrepareMinIOPermissionIssue(ctx, f.password, f.enrollment, file, sha); e == nil {
		t.Fatal("overwrote original names")
	}
}

func TestMinIOPermissionOwnerRefusesSubstitutionAndPartialCommit(t *testing.T) {
	for _, scenario := range []string{"password", "enrollment", "foreign-key", "definition-drift", "actor-revoked", "head-create-fails"} {
		t.Run(scenario, func(t *testing.T) {
			f, ctx, file, sha, d := minioPermissionOwnerFixture(t)
			password, pin := f.password, f.enrollment
			if scenario == "password" {
				password = []byte("wrong")
			}
			if scenario == "enrollment" {
				pin.ConfigMapUID = "other"
			}
			p, e := f.i.PrepareMinIOPermissionIssue(ctx, password, pin, file, sha)
			if scenario == "password" || scenario == "enrollment" {
				if e == nil {
					t.Fatal("unauthenticated issuer")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			key := f.key
			switch scenario {
			case "foreign-key":
				key = make([]byte, ed25519.PrivateKeySize)
			case "definition-drift":
				if e = os.WriteFile(file, []byte(`{}`), 0600); e != nil {
					t.Fatal(e)
				}
			case "actor-revoked":
				f.permissionDenied.Store(true)
			case "head-create-fails":
				f.i.kube.(*fake.Clientset).PrependReactor("create", "configmaps", func(a ktesting.Action) (bool, runtime.Object, error) {
					if a.(ktesting.CreateAction).GetObject().(*corev1.ConfigMap).Name == d.HeadName {
						return true, nil, errors.New("unknown head commit")
					}
					return false, nil, nil
				})
			}
			_, e = p.CreateOriginal(ctx, key)
			if e == nil {
				t.Fatal("substitution accepted")
			}
			if scenario == "head-create-fails" {
				if !errors.Is(e, ErrCommitUnknown) {
					t.Fatal("partial commit not explicit")
				}
				if _, e = f.i.kube.CoreV1().ConfigMaps(d.Grant.Namespace).Get(ctx, d.GrantName, metav1.GetOptions{}); e != nil {
					t.Fatal("lost original partial resource")
				}
			}
			if f.s.writes != 0 || f.signs.Load() != 0 {
				t.Fatal("unexpected SQL or capture-signing mutation")
			}
		})
	}
}
