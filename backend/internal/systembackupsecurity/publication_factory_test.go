package systembackupsecurity

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func publicationFactoryFixture(t *testing.T, f *installationSigningFixture, db *sql.DB) (*SQLPublicationSignerFactory, *fake.Clientset, PublicationSignerRuntime, PublicationSignerInput) {
	t.Helper()
	g := f.record.Permissions[0].SQLOwner
	r := PublicationSignerRuntime{InstallationID: f.pin.InstallationID, ServerUUID: g.ServerUUID, Database: g.Database, PublisherOwner: g.ControllerOwner, Namespace: f.task.Workload.Namespace, NamespaceUID: "original-namespace-uid", PodName: "original-controller-pod", PodUID: f.task.Workload.PodUID, ServiceAccountName: "original-publisher-sa", ServiceAccountUID: f.task.Workload.ServiceAccountUID}
	k := fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: r.Namespace, UID: types.UID(r.NamespaceUID)}}, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: r.PodName, Namespace: r.Namespace, UID: types.UID(r.PodUID)}, Spec: corev1.PodSpec{ServiceAccountName: r.ServiceAccountName}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: r.ServiceAccountName, Namespace: r.Namespace, UID: types.UID(r.ServiceAccountUID)}})
	dir := t.TempDir()
	m := PublicationSignerMaterials{Version: PublicationSignerMaterialsVersion, Record: f.reader, Pin: f.pin}
	for _, mount := range f.mounts {
		ca := filepath.Join(dir, mount.Binding.Purpose+".ca")
		if err := os.WriteFile(ca, mount.CAPEM, 0600); err != nil {
			t.Fatal(err)
		}
		m.Mounts = append(m.Mounts, PublicationSigningMount{Binding: mount.Binding, AuthMount: mount.AuthMount, Role: mount.Role, Policy: mount.Policy, JWTFile: mount.JWTFile, CAFile: ca, CASHA256: mount.CASHA256})
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	input := PublicationSignerInput{File: filepath.Join(dir, "publication-materials.json")}
	sum := sha256.Sum256(raw)
	input.SHA256 = hex.EncodeToString(sum[:])
	if err = os.WriteFile(input.File, raw, 0600); err != nil {
		t.Fatal(err)
	}
	factory, err := NewSQLPublicationSignerFactory(context.Background(), db, k, r, input)
	if err != nil {
		t.Fatal("production publication factory", err)
	}
	if f.login != 0 {
		t.Fatal("factory logged into provider")
	}
	k.PrependReactor("*", "*", func(ktesting.Action) (bool, kruntime.Object, error) {
		if db.Stats().InUse != 0 {
			t.Error("Kubernetes I/O while original SQL connection/transaction is held")
		}
		return false, nil, nil
	})
	return factory, k, r, input
}

func TestPublicationFactoryOriginalTaskAndLiveWorkload(t *testing.T) {
	f, state, db, _ := newSigningSQLFixture(t)
	ctx := context.Background()
	factory, k, r, _ := publicationFactoryFixture(t, f, db)
	if q, err := factory.ForTask(ctx, f.task.BackupPublicID, SQLSigningClaim{ControllerOwner: r.PublisherOwner, RowVersion: 10}); err == nil || q != nil {
		t.Fatal("stale original claim admitted")
	}
	q, err := factory.ForTask(ctx, f.task.BackupPublicID, state.claim)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	for _, mount := range f.mounts {
		key, err := q.PublicationSigningKey(ctx, mount.Binding.Purpose)
		if err != nil || key.KeyID != mount.Binding.KeyID {
			t.Fatal("active key binding", err)
		}
		p, err := q.PreparePublicationRecord(ctx, mount.Binding.Purpose, publicationFixturePayload(t, f, mount.Binding))
		if err != nil {
			t.Fatal(err)
		}
		stagePreparedPublication(t, db, p, true)
		before := f.login
		pod, _ := k.CoreV1().Pods(r.Namespace).Get(ctx, r.PodName, metav1.GetOptions{})
		pod.UID = "replaced-pod"
		if _, err = k.CoreV1().Pods(r.Namespace).Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		if raw, _, err := p.SignCommitted(ctx); err == nil || raw != nil || f.login != before {
			t.Fatal("replaced live controller reached provider")
		}
		pod.UID = types.UID(r.PodUID)
		k.CoreV1().Pods(r.Namespace).Update(ctx, pod, metav1.UpdateOptions{})
		raw, expected, err := p.SignCommitted(ctx)
		if err != nil {
			t.Fatal(err)
		}
		history, err := q.History(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := history.VerifyPublicationRecord(raw, f.task, mount.Binding.Purpose); err != nil || got != expected {
			t.Fatal("production factory signed record readback", err)
		}
	}
	if f.login != 3 || f.signed != 3 {
		t.Fatal("production factory did not use all three purpose-specific JWT/signers")
	}
	state.claim.RowVersion++
	if _, err = q.PublicationSigningKey(ctx, "catalog_record"); err == nil {
		t.Fatal("task wrapper silently adopted renewed row version")
	}
	newTask, err := factory.ForTask(ctx, f.task.BackupPublicID, state.claim)
	if err != nil {
		t.Fatal("explicit current original claim could not rebind", err)
	}
	newTask.Close()
	if _, err := q.History(ctx); err != nil {
		t.Fatal("claim release destroyed public verification history", err)
	}
}

func TestPublicationFactoryMaterialAndPostSignRevocation(t *testing.T) {
	t.Run("claim version changes during JWT login", func(t *testing.T) {
		f, state, db, _ := newSigningSQLFixture(t)
		factory, _, _, _ := publicationFactoryFixture(t, f, db)
		ctx := context.Background()
		q, err := factory.ForTask(ctx, f.task.BackupPublicID, state.claim)
		if err != nil {
			t.Fatal(err)
		}
		defer q.Close()
		p, err := q.PreparePublicationRecord(ctx, "capture_certificate", publicationFixturePayload(t, f, f.mounts[0].Binding))
		if err != nil {
			t.Fatal(err)
		}
		stagePreparedPublication(t, db, p, true)
		f.afterLogin = func() { state.claim.RowVersion++ }
		if raw, _, err := p.SignCommitted(ctx); err == nil || raw != nil || f.login != 1 || f.signed != 0 {
			t.Fatal("changed claim version during login reached Transit Sign")
		}
	})
	for _, kind := range []string{"Pod", "SA"} {
		t.Run("replacement during JWT login "+kind, func(t *testing.T) {
			f, state, db, _ := newSigningSQLFixture(t)
			factory, k, r, _ := publicationFactoryFixture(t, f, db)
			ctx := context.Background()
			q, err := factory.ForTask(ctx, f.task.BackupPublicID, state.claim)
			if err != nil {
				t.Fatal(err)
			}
			defer q.Close()
			p, err := q.PreparePublicationRecord(ctx, "capture_certificate", publicationFixturePayload(t, f, f.mounts[0].Binding))
			if err != nil {
				t.Fatal(err)
			}
			stagePreparedPublication(t, db, p, true)
			f.afterLogin = func() {
				if kind == "Pod" {
					pod, _ := k.CoreV1().Pods(r.Namespace).Get(ctx, r.PodName, metav1.GetOptions{})
					pod.UID = "replacement-after-login"
					if _, e := k.CoreV1().Pods(r.Namespace).Update(ctx, pod, metav1.UpdateOptions{}); e != nil {
						t.Error(e)
					}
				} else {
					if e := k.CoreV1().ServiceAccounts(r.Namespace).Delete(ctx, r.ServiceAccountName, metav1.DeleteOptions{}); e != nil {
						t.Error(e)
					}
				}
			}
			if raw, sum, err := p.SignCommitted(ctx); err == nil || raw != nil || sum != "" || f.login != 1 || f.signed != 0 {
				t.Fatal("workload lost during JWT login reached Transit Sign")
			}
		})
	}
	t.Run("material replacement", func(t *testing.T) {
		f, state, db, _ := newSigningSQLFixture(t)
		factory, k, r, input := publicationFactoryFixture(t, f, db)
		ctx := context.Background()
		q, err := factory.ForTask(ctx, f.task.BackupPublicID, state.claim)
		if err != nil {
			t.Fatal(err)
		}
		defer q.Close()
		p, err := q.PreparePublicationRecord(ctx, "capture_certificate", publicationFixturePayload(t, f, f.mounts[0].Binding))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(input.File, []byte(`{"schema_version":"substituted"}`), 0600); err != nil {
			t.Fatal(err)
		}
		tx, _ := db.BeginTx(ctx, nil)
		defer tx.Rollback()
		if p.Stage(ctx, tx) == nil || state.writes != 0 || f.login != 0 {
			t.Fatal("material replacement admitted Stage")
		}
		if got, err := NewSQLPublicationSignerFactory(ctx, db, k, r, input); err == nil || got != nil {
			t.Fatal("replacement bundle accepted with old deployment pin")
		}
	})
	t.Run("deleted SA during provider signing", func(t *testing.T) {
		f, state, db, _ := newSigningSQLFixture(t)
		factory, k, r, _ := publicationFactoryFixture(t, f, db)
		ctx := context.Background()
		q, err := factory.ForTask(ctx, f.task.BackupPublicID, state.claim)
		if err != nil {
			t.Fatal(err)
		}
		defer q.Close()
		p, err := q.PreparePublicationRecord(ctx, "capture_certificate", publicationFixturePayload(t, f, f.mounts[0].Binding))
		if err != nil {
			t.Fatal(err)
		}
		stagePreparedPublication(t, db, p, true)
		f.afterSign = func() {
			if e := k.CoreV1().ServiceAccounts(r.Namespace).Delete(ctx, r.ServiceAccountName, metav1.DeleteOptions{}); e != nil {
				t.Error(e)
			}
		}
		if raw, sum, err := p.SignCommitted(ctx); err == nil || raw != nil || sum != "" || f.signed != 1 {
			t.Fatal("workload lost during provider call returned artifact")
		}
	})
}

func TestPublicationFactoryHistoryIndependentOfSigningLifetime(t *testing.T) {
	f, state, db, _ := newSigningSQLFixture(t)
	factory, k, r, _ := publicationFactoryFixture(t, f, db)
	ctx := context.Background()
	state.claim.RowVersion++
	state.status = "succeeded"
	if err := k.CoreV1().Pods(r.Namespace).Delete(ctx, r.PodName, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(factory.materials.Mounts[0].CAFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.mounts[0].JWTFile); err != nil {
		t.Fatal(err)
	}
	if h, err := factory.History(ctx); err != nil || len(h.PurposeKeys("capture_certificate")) != 1 {
		t.Fatal("signing dependency loss destroyed public history", err)
	}
	f.record.Until = time.Now().Add(-time.Minute)
	f.writeRecord(true)
	m := factory.materials
	m.Pin = f.pin
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	input := PublicationSignerInput{File: filepath.Join(t.TempDir(), "current-expired-signing-materials.json")}
	sum := sha256.Sum256(raw)
	input.SHA256 = hex.EncodeToString(sum[:])
	if err = os.WriteFile(input.File, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if h, err := LoadPublicationSignerHistory(ctx, input); err != nil || len(h.PurposeKeys("catalog_record")) != 1 {
		t.Fatal("expired signing permission destroyed independently pinned public history", err)
	}
	if f.login != 0 {
		t.Fatal("public history called JWT provider")
	}
}

func TestPublicationFactoryIndependentDeploymentRejects(t *testing.T) {
	f, _, db, _ := newSigningSQLFixture(t)
	factory, k, r, input := publicationFactoryFixture(t, f, db)
	ctx := context.Background()
	for name, mutate := range map[string]func(*PublicationSignerRuntime){
		"database":        func(r *PublicationSignerRuntime) { r.Database = "other" },
		"server":          func(r *PublicationSignerRuntime) { r.ServerUUID = "other" },
		"installation":    func(r *PublicationSignerRuntime) { r.InstallationID = "installation_other" },
		"publisher owner": func(r *PublicationSignerRuntime) { r.PublisherOwner = "other" },
		"Pod UID":         func(r *PublicationSignerRuntime) { r.PodUID = "other" },
		"namespace UID":   func(r *PublicationSignerRuntime) { r.NamespaceUID = "other" },
		"SA UID":          func(r *PublicationSignerRuntime) { r.ServiceAccountUID = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			wrong := r
			mutate(&wrong)
			if q, err := NewSQLPublicationSignerFactory(ctx, db, k, wrong, input); err == nil || q != nil || f.login != 0 {
				t.Fatal("wrong independent runtime scope admitted")
			}
		})
	}
	for name, mutate := range map[string]func(*PublicationSignerMaterials){
		"purpose missing":   func(m *PublicationSignerMaterials) { m.Mounts = m.Mounts[:2] },
		"purpose duplicate": func(m *PublicationSignerMaterials) { m.Mounts[1] = m.Mounts[0] },
		"relative JWT":      func(m *PublicationSignerMaterials) { m.Mounts[0].JWTFile = "relative.jwt" },
		"root policy":       func(m *PublicationSignerMaterials) { m.Mounts[0].Policy = "root" },
		"other role":        func(m *PublicationSignerMaterials) { m.Mounts[0].Role = "other-role" },
		"other key":         func(m *PublicationSignerMaterials) { m.Mounts[0].Binding.KeyID = "other" },
		"wrong CA":          func(m *PublicationSignerMaterials) { m.Mounts[0].CASHA256 = hex.EncodeToString(make([]byte, 32)) },
		"wrong issuer":      func(m *PublicationSignerMaterials) { m.Pin.Issuer = make([]byte, 32) },
		"wrong revision":    func(m *PublicationSignerMaterials) { m.Pin.Revision++ },
	} {
		t.Run(name, func(t *testing.T) {
			var m PublicationSignerMaterials
			raw, _ := json.Marshal(factory.materials)
			if json.Unmarshal(raw, &m) != nil {
				t.Fatal("fixture")
			}
			mutate(&m)
			raw, _ = json.Marshal(m)
			path := filepath.Join(t.TempDir(), "independently-deployed.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(raw)
			if q, err := NewSQLPublicationSignerFactory(ctx, db, k, r, PublicationSignerInput{File: path, SHA256: hex.EncodeToString(sum[:])}); err == nil || q != nil || f.login != 0 {
				t.Fatal("bundle pin substituted original signing authority")
			}
		})
	}
}
