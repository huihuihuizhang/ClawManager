package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	s "clawreef/internal/systembackupsecurity"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
)

func aStartPublisherVerifierSamePod(t *testing.T, x *aPublisherVerifierFixture) DeploymentStartupInputs {
	t.Helper()
	h := x.history
	ctx := context.Background()
	cfg := h.service.Config
	core, err := os.ReadFile(h.service.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	pod, err := h.owner.Client.CoreV1().Pods(cfg.Namespace).Get(ctx, "publisher", metav1.GetOptions{})
	if err != nil || pod.Status.Phase != corev1.PodPending {
		t.Fatal("bootstrap did not start with pre-existing Pending Pod UID", err)
	}
	uid := pod.UID
	spec, _ := json.Marshal(pod.Spec)
	secret, err := h.owner.Client.CoreV1().Secrets(cfg.Namespace).Get(ctx, "publisher-materials", metav1.GetOptions{})
	if err != nil || secret.UID != "owner-bootstrap-secret-uid" || len(secret.Data) != 0 {
		t.Fatal("independent owner must hold empty pin Secret before Pod/bootstrap", err)
	}
	secretUID := secret.UID
	// Independent owner supplies signed materials AND a separate pin after
	// observing this Pod/RS UID; the application never trusts its own hash.
	material, err := json.Marshal(x.materials)
	if err != nil {
		t.Fatal(err)
	}
	secret.Data = map[string][]byte{"materials.json": material, "materials_sha256": []byte(hash(material))}
	if _, err = h.owner.Client.CoreV1().Secrets(cfg.Namespace).Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	currentSecret, err := h.owner.Client.CoreV1().Secrets(cfg.Namespace).Get(ctx, secret.Name, metav1.GetOptions{})
	if err != nil || currentSecret.UID != secretUID || !bytes.Equal(currentSecret.Data["materials_sha256"], secret.Data["materials_sha256"]) {
		t.Fatal("bootstrap replaced owner-held Secret instead of updating same object")
	}
	// Local projection/Kubelet simulation only. Real files/env parser, fixed
	// Pod spec/UID and production Running checks are exercised below.
	if os.WriteFile(cfg.PublisherVerifier.Path, secret.Data["materials.json"], 0600) != nil {
		t.Fatal("projected materials fixture")
	}
	for _, env := range pod.Spec.Containers[0].Env {
		value := env.Value
		if env.ValueFrom != nil {
			ref := env.ValueFrom.SecretKeyRef
			if ref == nil || ref.Name != secret.Name || ref.Optional != nil && *ref.Optional {
				t.Fatal("pin is not fixed mandatory SecretKeyRef")
			}
			value = string(secret.Data[ref.Key])
		}
		t.Setenv(env.Name, value)
	}
	inputs := DeploymentStartupInputs{PublisherVerifier: PublisherVerifierInputsFromEnvironment(), ControllerPodName: pod.Name}
	if len(inputs.PublisherVerifier) != 1 || inputs.PublisherVerifier[0].SHA256 != string(secret.Data["materials_sha256"]) {
		t.Fatal("real CLI startup parser lost independent pin")
	}
	if _, err = s.NewSQLPublisherCaptureAuthority(ctx, h.cfg, h.scope); err == nil {
		t.Fatal("Pending Pod became task authority")
	}
	pod.Status.Phase = corev1.PodRunning
	if _, err = h.owner.Client.CoreV1().Pods(cfg.Namespace).UpdateStatus(ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	after, err := h.owner.Client.CoreV1().Pods(cfg.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	afterSpec, _ := json.Marshal(after.Spec)
	if after.UID != uid || !bytes.Equal(spec, afterSpec) {
		t.Fatal("derived pin changed Pod template/spec or UID")
	}
	if err = h.service.bindDeploymentStartupInputs(inputs); err != nil {
		t.Fatal("production full core/profile/Forward/Recovery/material binding", err)
	}
	if err = h.service.attachPublicationSigners(ctx, h.db, h.owner.Client, pod.Name); err != nil {
		t.Fatal("actual startup controller observation", err)
	}
	if err = h.service.attachPublisherVerifier(ctx, h.db, h.owner.Client, h.owner.Gate.Records); err != nil {
		t.Fatal("production publisher attach", err)
	}
	currentCore, _ := os.ReadFile(h.service.ConfigPath)
	if !bytes.Equal(core, currentCore) || hash(core) != h.service.ConfigDigest || h.service.Forward.DeploymentBinding().DeploymentConfigSHA256 != hash(core) {
		t.Fatal("derived UID/material pin changed original full core hash")
	}
	if x.logins.Load() != 0 || x.decrypts.Load() != 0 {
		t.Fatal("startup contacted provider")
	}
	return inputs
}

func TestAPublisherVerifierActualServiceSamePodStartupAndUse(t *testing.T) {
	x := newAPublisherVerifierFixture(t, true)
	h := x.history
	ctx := context.Background()
	aStartPublisherVerifierSamePod(t, x)
	if err := h.service.CheckPublisherVerifierReadiness(ctx); err != nil {
		t.Fatal("current deployment readiness", err)
	}
	verifier, err := h.service.PublisherVerifierForPart(ctx, h.token, h.original.AttemptNo, "workspace")
	if err != nil {
		t.Fatal("actual service current token consumer", err)
	}
	defer verifier.Close()
	used := 0
	if err = verifier.WithDEK(ctx, x.envelope, func(key []byte) error {
		used++
		if !bytes.Equal(key, bytes.Repeat([]byte{9}, 32)) {
			t.Fatal("wrong original DEK")
		}
		return verifier.Recheck(ctx)
	}); err != nil || used != 1 {
		t.Fatal("full startup/service/original SQL/TLS use", err)
	}
	if x.logins.Load() != 1 || x.decrypts.Load() != 1 {
		t.Fatal("provider use count")
	}
	wrong := h.token
	wrong.Owner = "public:other-pod"
	if _, err = h.service.PublisherVerifierForPart(ctx, wrong, h.original.AttemptNo, "workspace"); err == nil {
		t.Fatal("service substituted actual owner")
	}
	if _, err = c.RenewClaimInInstallation(ctx, h.db, h.original.InstallationID, h.token, c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second}); err != nil {
		t.Fatal(err)
	}
	if _, err = h.service.PublisherVerifierForPart(ctx, h.token, h.original.AttemptNo, "workspace"); err == nil {
		t.Fatal("service accepted stale token")
	}
	if verifier.WithDEK(ctx, x.envelope, func([]byte) error { used++; return nil }) == nil || used != 1 || x.logins.Load() != 1 {
		t.Fatal("old service object adopted renewed token")
	}
}

func TestAPublisherVerifierCurrentServiceReadinessAndRecovery(t *testing.T) {
	x := newAPublisherVerifierFixture(t, true)
	h := x.history
	ctx := context.Background()
	inputs := aStartPublisherVerifierSamePod(t, x)
	if h.service.CheckPublisherVerifierReadiness(ctx) != nil {
		t.Fatal("initial readiness")
	}
	for _, fault := range []string{"materials", "business-grant", "SA", "owner", "original-grant", "core", "missing-pin"} {
		t.Run(fault, func(t *testing.T) {
			var restore func()
			switch fault {
			case "materials", "business-grant", "original-grant", "core":
				path := inputs.PublisherVerifier[0].File
				if fault == "business-grant" {
					path = x.materials.Grant.File
				}
				if fault == "original-grant" {
					path = h.service.Config.ForwardGrant.Path
				}
				if fault == "core" {
					path = h.service.ConfigPath
				}
				saved, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if os.WriteFile(path, append(append([]byte{}, saved...), byte(' ')), 0600) != nil {
					t.Fatal("source mutation")
				}
				restore = func() { os.WriteFile(path, saved, 0600) }
			case "SA":
				sa, err := h.owner.Client.CoreV1().ServiceAccounts(h.cfg.Workload.Namespace).Get(ctx, h.cfg.Workload.ServiceAccountName, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				old := sa.UID
				sa.UID = "changed"
				h.owner.Client.CoreV1().ServiceAccounts(sa.Namespace).Update(ctx, sa, metav1.UpdateOptions{})
				restore = func() {
					sa.UID = old
					h.owner.Client.CoreV1().ServiceAccounts(sa.Namespace).Update(ctx, sa, metav1.UpdateOptions{})
				}
			case "owner":
				dep, err := h.owner.Client.AppsV1().Deployments(h.cfg.Workload.Namespace).Get(ctx, x.cfg.KubernetesReads.OwnerName, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				old := dep.UID
				dep.UID = "changed"
				h.owner.Client.AppsV1().Deployments(dep.Namespace).Update(ctx, dep, metav1.UpdateOptions{})
				restore = func() {
					dep.UID = old
					h.owner.Client.AppsV1().Deployments(dep.Namespace).Update(ctx, dep, metav1.UpdateOptions{})
				}
			case "missing-pin":
				saved := h.service.publisherVerifierInput
				h.service.publisherVerifierInput = nil
				restore = func() { h.service.publisherVerifierInput = saved }
			}
			defer restore()
			if h.service.CheckPublisherVerifierReadiness(ctx) == nil {
				t.Fatal("stale deployment readiness after", fault)
			}
			if _, err := h.service.PublisherVerifierForPart(ctx, h.token, h.original.AttemptNo, "workspace"); err == nil {
				t.Fatal("stale material reached service consumer", fault)
			}
		})
	}
	if x.logins.Load() != 0 || x.decrypts.Load() != 0 {
		t.Fatal("readiness contacted provider")
	}
	for _, path := range []string{inputs.PublisherVerifier[0].File, x.materials.Grant.File, x.materials.CAFile, x.materials.JWTFile} {
		if os.Remove(path) != nil {
			t.Fatal("remove owned forward materials")
		}
	}
	recovery := &DeploymentService{ConfigPath: h.service.ConfigPath, ConfigDigest: h.service.ConfigDigest, Forward: h.service.Recovery, Recovery: h.service.Recovery, ForwardEnabled: false}
	if recovery.bindDeploymentStartupInputs(inputs) != nil || recovery.attachPublisherVerifier(ctx, h.db, h.owner.Client, h.owner.Gate.Records) != nil || recovery.publisherVerifierFactory != nil {
		t.Fatal("publisher materials blocked independent Recovery")
	}
}

func TestAPublisherVerifierServiceRevocationPurposeAndCurrentRegistry(t *testing.T) {
	for _, mode := range []string{"owner-generate", "owner-unwrap", "registry-generate", "registry-unwrap"} {
		t.Run(mode, func(t *testing.T) {
			x := newAPublisherVerifierFixture(t, true)
			h := x.history
			ctx := context.Background()
			aStartPublisherVerifierSamePod(t, x)
			if h.service.CheckPublisherVerifierReadiness(ctx) != nil {
				t.Fatal("initial readiness")
			}
			if strings.HasPrefix(mode, "owner-") {
				original := x.original
				original.Revision = "owner-r2"
				original.GenerateRevoked = mode == "owner-generate"
				original.UnwrapRevoked = mode == "owner-unwrap"
				x.putOriginal(original, 1)
			} else {
				purpose, column := reg.GenerateRevocation, "generate_revocation_json"
				if mode == "registry-unwrap" {
					purpose, column = reg.UnwrapRevocation, "unwrap_revocation_json"
				}
				revocation := reg.Revocation{Purpose: purpose, Source: reg.SourceRecord{SourceID: "original-local-revocation-observer", RecordID: "original-purpose-revocation", RecordVersion: "v2", ContentSHA256: strings.Repeat("d", 64)}, SourceRevision: "v2", ObservedAt: time.Now().UTC().Add(-time.Millisecond)}
				raw, _ := json.Marshal(revocation)
				tx, err := h.admin.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				if _, err = tx.ExecContext(ctx, "UPDATE system_backup_v2_kek_fences SET epoch=epoch+1 WHERE installation_id=?", h.original.InstallationID); err != nil {
					t.Fatal(err)
				}
				result, err := tx.ExecContext(ctx, "UPDATE system_backup_v2_kek_bindings SET "+column+"=?,row_version=row_version+1 WHERE installation_id=? AND identity_hash=? AND registry_version=?", raw, h.original.InstallationID, x.cfg.Binding.Key.IdentityHash, x.cfg.Binding.Key.RegistryVersion)
				if err != nil {
					t.Fatal(err)
				}
				if n, e := result.RowsAffected(); e != nil || n != 1 {
					t.Fatal("revocation did not change original binding")
				}
				if tx.Commit() != nil {
					t.Fatal("revocation commit")
				}
			}
			unwrapAllowed := strings.HasSuffix(mode, "generate")
			if err := h.service.CheckPublisherVerifierReadiness(ctx); (err == nil) != unwrapAllowed {
				t.Fatal("readiness confused revocation purposes", err)
			}
			verifier, err := h.service.PublisherVerifierForPart(ctx, h.token, h.original.AttemptNo, "workspace")
			if (err == nil) != unwrapAllowed {
				t.Fatal("service confused revocation purposes", err)
			}
			if verifier != nil {
				defer verifier.Close()
				if verifier.WithDEK(ctx, x.envelope, func([]byte) error { return nil }) != nil {
					t.Fatal("Generate-only revoke prevented retained exact unwrap")
				}
			}
			if !unwrapAllowed && (x.logins.Load() != 0 || x.decrypts.Load() != 0) {
				t.Fatal("Unwrap revoke reached provider")
			}
		})
	}
}

func TestAPublisherVerifierIndependentInputsNamedRBACAndActualAdmission(t *testing.T) {
	x := newAPublisherVerifierFixture(t, true)
	h := x.history
	ctx := context.Background()
	inputs := aStartPublisherVerifierSamePod(t, x)
	cfg := h.service.Config
	for _, mode := range []string{"absent", "wrong-path", "wrong-pin", "extra"} {
		t.Run(mode, func(t *testing.T) {
			bad := append([]PublisherVerifierInput{}, inputs.PublisherVerifier...)
			switch mode {
			case "absent":
				bad = nil
			case "wrong-path":
				bad[0].File += ".other"
			case "wrong-pin":
				bad[0].SHA256 = strings.Repeat("0", 64)
			case "extra":
				bad = append(bad, bad[0])
			}
			if _, err := loadPublisherVerifierMaterials(cfg, bad); err == nil {
				t.Fatal("invalid independent material input accepted")
			}
		})
	}
	objects, err := CaptureKubernetesGrantsWithInputs(cfg, h.cfg.Workload.ServiceAccountName, inputs)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, object := range objects {
		if role, ok := object.(*rbacv1.Role); ok {
			for _, rule := range role.Rules {
				for _, resource := range rule.Resources {
					if resource == "secrets" {
						for _, verb := range rule.Verbs {
							if verb != "get" && verb != "create" {
								t.Fatal("controller can change owner-held pin Secret")
							}
						}
					}
				}
				if len(rule.Resources) == 1 && rule.Resources[0] == "replicasets" && len(rule.ResourceNames) == 1 && rule.ResourceNames[0] == x.cfg.KubernetesReads.ReplicaSetName {
					if role.Namespace != cfg.Namespace || len(rule.Verbs) != 1 || rule.Verbs[0] != "get" {
						t.Fatal("publisher RS role widened")
					}
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("publisher actual named GET absent from official role")
	}
	client := h.owner.Client.(*fake.Clientset)
	client.PrependReactor("create", "selfsubjectaccessreviews", func(action kt.Action) (bool, runtime.Object, error) {
		review := action.(kt.CreateAction).GetObject().(*authv1.SelfSubjectAccessReview)
		attr := review.Spec.ResourceAttributes
		review.Status.Allowed = true
		if attr.Resource == "replicasets" && attr.Name == x.cfg.KubernetesReads.ReplicaSetName {
			review.Status.Allowed = false
			review.Status.Denied = true
		}
		return true, review, nil
	})
	h.service.Runtime = &PublicCapture{Owner: h.owner}
	record, err := h.owner.Gate.Records.LoadPublisherCapture(ctx, mustAPublisherServiceAuthority(t, h))
	if err != nil {
		t.Fatal(err)
	}
	input := d.Input{Authority: h.original, ProfileID: h.service.profile.Profile, ProfileRevision: h.service.profile.Revision, Backup: &record.Input.Backup}
	if h.service.admit(ctx, input) == nil {
		t.Fatal("actual service admission ignored named RS denial")
	}
	if x.logins.Load() != 0 || x.decrypts.Load() != 0 {
		t.Fatal("input/role/readiness checks reached provider")
	}
	for _, mode := range []string{"invalid-CA", "http-endpoint", "mutable-key-version"} {
		bad := x.cfg
		switch mode {
		case "invalid-CA":
			bad.CAPEM = []byte("not a certificate")
			bad.Binding.Provider.CAPEMSHA256 = hash(bad.CAPEM)
		case "http-endpoint":
			bad.Binding.Provider.Endpoint = "http://127.0.0.1"
		case "mutable-key-version":
			bad.Binding.Key.ProviderVersion = "latest"
		}
		if _, err := a.NewPublisherVerifierFactory(bad); err == nil {
			t.Fatal("startup accepted transport rejected by actual Unwrap", mode)
		}
	}
}

func mustAPublisherServiceAuthority(t *testing.T, h *publisherHistoryFixture) *s.SQLPublisherCaptureAuthority {
	t.Helper()
	authority, err := s.NewSQLPublisherCaptureAuthority(context.Background(), h.cfg, h.scope)
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func TestAPublisherVerifierEarlyDatabaseUsesIndependentInputAndRole(t *testing.T) {
	x := newAPublisherVerifierFixture(t, true)
	h := x.history
	inputs := aStartPublisherVerifierSamePod(t, x)
	g := h.service.Forward.DeploymentBinding()
	cfg := h.service.Config
	forward, _ := os.ReadFile(cfg.ForwardGrant.Path)
	recovery, _ := os.ReadFile(cfg.RecoveryGrant.Path)
	user := strings.Split(g.DatabaseAccount, "@")[0]
	for _, mode := range []string{"valid", "base-role-only", "missing-pin", "wrong-pin", "recovery"} {
		t.Run(mode, func(t *testing.T) {
			grants, err := c.FormalCaptureGrantSQL(g.Database, user, "127.0.0.1", false, false)
			if mode == "base-role-only" {
				grants, err = c.PublicCaptureGrantSQL(g.Database, user, "127.0.0.1", false)
			}
			if err != nil {
				t.Fatal(err)
			}
			for i := range grants {
				grants[i] = strings.TrimSuffix(grants[i], ";")
			}
			pool := sql.OpenDB(providerAdmissionConnector{grant: g, grants: grants})
			defer pool.Close()
			supplied := inputs
			supplied.PublisherVerifier = append([]PublisherVerifierInput{}, inputs.PublisherVerifier...)
			if mode == "missing-pin" {
				supplied.PublisherVerifier = nil
			}
			if mode == "wrong-pin" {
				supplied.PublisherVerifier[0].SHA256 = strings.Repeat("0", 64)
			}
			err = CheckDeploymentDatabaseWithInputs(context.Background(), pool, h.service.ConfigPath, h.service.ConfigDigest, hash(forward), hash(recovery), mode != "recovery", supplied)
			if (err == nil) != (mode == "valid" || mode == "recovery") {
				t.Fatal("real early database input/role mode", err)
			}
		})
	}
}
