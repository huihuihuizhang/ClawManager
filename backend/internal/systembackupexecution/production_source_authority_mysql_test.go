package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackup/kube"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/worker"
	api "clawreef/internal/systembackupdeployment"
	d "clawreef/internal/systembackupdispatch"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Real original SQL claim/deployment wrapper and owner signature. Kubernetes
// GETs and TLS endpoints are named local protocol fixtures, not a live cluster.
type dProductionSourceFixture struct {
	base    *aControlEvidenceSourceFixture
	server  *httptest.Server
	grant   originalSourceMetadataGrant
	private ed25519.PrivateKey
}

func newDProductionSourceFixture(t *testing.T, handler http.Handler) *dProductionSourceFixture {
	t.Helper()
	f := &dProductionSourceFixture{base: newAControlEvidenceSourceFixture(t)}
	h := f.base.x.history
	s := h.service
	if handler == nil {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })
	}
	f.server = httptest.NewTLSServer(handler)
	t.Cleanup(f.server.Close)
	u, _ := url.Parse(f.server.URL)
	dir := filepath.Dir(s.ConfigPath)
	write := func(name string, raw []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw})
	caFile := write("d-source-ca.pem", ca)
	token := []byte("named-d-metadata-token")
	tokenFile := write("d-source-token", token)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.private = private
	t.Cleanup(func() { clear(private) })
	_, source, _, _, _ := productionModuleFixture(t)
	var metadata productionCaptureMetadata
	if json.Unmarshal(source.CaptureMetadata, &metadata) != nil {
		t.Fatal("module metadata fixture")
	}
	m := f.base.materials
	units := b.TeamsWorkUnits()
	w := s.Config.Writers[0]
	discovery := &productionSourceDiscovery{GrantFile: filepath.Join(dir, "d-source-grant.json"), GrantSHA256: strings.Repeat("a", 64), Issuer: public,
		ControllerDeployment: "d-source-controller", ControllerDeploymentUID: "d-controller-uid", ControllerServiceAccount: "d-controller", ControllerServiceAccountUID: "d-controller-sa-uid",
		SourceAPI: worker.ResourceSourceMount{Server: f.server.URL, CAFile: caFile, CASHA256: hash(ca), TokenFile: tokenFile}, SourceAPITokenSHA256: hash(token), SourceAPIServiceAccount: "d-metadata", SourceAPIServiceAccountUID: "d-metadata-uid",
		Redis: metadata.Redis, RuntimePolicies: []worker.RuntimePolicy{metadata.Mounts[0].Policy}, ResourceActors: map[string]productionSourceActor{"deployment_resources": {Name: "d-resources", UID: "d-resources-uid"}, "secret_bundle": {Name: "d-secrets", UID: "d-secrets-uid"}},
		TeamPlatformUnits: map[string][]string{"deployment/" + w.Namespace + "/" + w.Name: append([]string{}, units...)}}
	m.Discovery = discovery
	for name, operation := range m.Operations {
		operation.MountIdentities = []kube.MountIdentity{{Volume: "formal-mapping", Kind: "ConfigMap", Name: operation.Workload.FormalMaterials.ConfigMap, UID: name + "-mapping-uid", SHA256: hash([]byte(name))}}
		m.Operations[name] = operation
	}
	for _, object := range []bool{false, true} {
		credential := metadataSourceCredential{Username: "d-redis", Password: []byte("named-local-fixture")}
		name := "redis"
		if object {
			name = "objects"
			credential = metadataSourceCredential{AccessKey: "d-object-access", SecretKey: []byte("named-local-fixture")}
		}
		raw, _ := json.Marshal(credential)
		grant := []byte("named worker grant bytes; controller scope signed separately")
		mount := worker.FormalSourceMount{CredentialFile: write("d-"+name+"-credential.json", raw), CredentialSHA256: hash(raw), GrantFile: write("d-"+name+"-worker-grant", grant), GrantSHA256: hash(grant)}
		mapping := &worker.SourceTLSMapping{Address: u.Host, ServerName: u.Hostname(), CAFile: caFile, CASHA256: hash(ca)}
		if object {
			mount.Objects = mapping
			m.Objects = mount
		} else {
			mount.Redis = mapping
			m.Redis = mount
		}
	}
	s.captureMaterials = &m
	scope, err := sourceMetadataScope(m)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	f.grant = originalSourceMetadataGrant{Version: sourceMetadataGrantVersion, InstallationID: s.Config.InstallationID, ControllerOwner: s.Config.ControllerOwner, DeploymentConfigSHA256: s.ConfigDigest, CaptureGrantSHA256: s.Forward.GrantSHA256(), ConfigSHA256: f.base.in.Authority.ConfigSHA256, ScopeSHA256: scope, Namespace: s.Config.Namespace, NamespaceUID: s.Config.NamespaceUID,
		ControllerDeployment: discovery.ControllerDeployment, ControllerDeploymentUID: discovery.ControllerDeploymentUID, ControllerServiceAccount: discovery.ControllerServiceAccount, ControllerServiceAccountUID: discovery.ControllerServiceAccountUID, NotBefore: now.Add(-time.Minute), Until: now.Add(5 * time.Minute)}
	f.writeGrant(t)
	controller := true
	ctx := context.Background()
	create := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = h.owner.Client.CoreV1().ServiceAccounts(s.Config.Namespace).Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: discovery.ControllerServiceAccount, UID: types.UID(discovery.ControllerServiceAccountUID)}}, metav1.CreateOptions{})
	create(err)
	_, err = h.owner.Client.CoreV1().ServiceAccounts(s.Config.Namespace).Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: discovery.SourceAPIServiceAccount, UID: types.UID(discovery.SourceAPIServiceAccountUID)}}, metav1.CreateOptions{})
	create(err)
	_, err = h.owner.Client.AppsV1().Deployments(s.Config.Namespace).Create(ctx, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: discovery.ControllerDeployment, UID: types.UID(discovery.ControllerDeploymentUID)}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{ServiceAccountName: discovery.ControllerServiceAccount}}}}, metav1.CreateOptions{})
	create(err)
	_, err = h.owner.Client.AppsV1().ReplicaSets(s.Config.Namespace).Create(ctx, &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "d-source-rs", UID: "d-source-rs-uid", OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: discovery.ControllerDeployment, UID: types.UID(discovery.ControllerDeploymentUID), Controller: &controller}}}}, metav1.CreateOptions{})
	create(err)
	_, err = h.owner.Client.CoreV1().Pods(s.Config.Namespace).Create(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "d-source-pod", UID: "d-source-pod-uid", OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "d-source-rs", UID: "d-source-rs-uid", Controller: &controller}}}, Spec: corev1.PodSpec{ServiceAccountName: discovery.ControllerServiceAccount}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}, metav1.CreateOptions{})
	create(err)
	s.controllerActor.PodName, s.controllerActor.PodUID, s.controllerActor.ServiceAccountName = "d-source-pod", "d-source-pod-uid", discovery.ControllerServiceAccount
	return f
}

func (f *dProductionSourceFixture) writeGrant(t *testing.T) {
	t.Helper()
	s := f.base.x.history.service
	p := s.captureMaterials.Discovery
	raw, _ := json.Marshal(f.grant)
	envelope, _ := json.Marshal(signedSourceMetadataGrant{Record: raw, Signature: ed25519.Sign(f.private, append([]byte(sourceMetadataGrantDomain), raw...))})
	if os.WriteFile(p.GrantFile, envelope, 0600) != nil {
		t.Fatal("source grant write")
	}
	p.GrantSHA256 = hash(envelope)
	material, _ := json.Marshal(s.captureMaterials)
	if os.WriteFile(s.Config.CaptureModules.Path, material, 0600) != nil {
		t.Fatal("source material write")
	}
	if err := s.loadProductionCapture([]ProductionCaptureInput{{File: s.Config.CaptureModules.Path, SHA256: hash(material)}}); err != nil {
		t.Fatal("original source loader", err)
	}
}

func TestProductionSourceOriginalMetadataAuthorityMySQL(t *testing.T) {
	f := newDProductionSourceFixture(t, nil)
	h, ctx := f.base.x.history, context.Background()
	s := h.service
	authority, err := s.sourceMetadataAuthority(ctx, h.owner, f.base.in)
	if err != nil {
		t.Fatal("actual signed current preparing authority", err)
	}
	if authority.Recheck(ctx) != nil {
		t.Fatal("current original authority recheck")
	}
	// A separately valid owner signature cannot authorize another original
	// configuration, time window, deployment, source scope or revoked grant.
	original := f.grant
	for _, fault := range []string{"config", "scope", "revoked", "expired", "future", "workload"} {
		t.Run(fault, func(t *testing.T) {
			f.grant = original
			switch fault {
			case "config":
				f.grant.ConfigSHA256 = strings.Repeat("f", 64)
			case "scope":
				f.grant.ScopeSHA256 = strings.Repeat("f", 64)
			case "revoked":
				f.grant.Revoked = true
			case "expired":
				f.grant.Until = time.Now().UTC().Add(-time.Second)
			case "future":
				f.grant.NotBefore = time.Now().UTC().Add(time.Minute)
			case "workload":
				f.grant.ControllerDeploymentUID = "replacement"
			}
			f.writeGrant(t)
			if _, err := s.sourceMetadataAuthority(ctx, h.owner, f.base.in); err == nil {
				t.Fatal("foreign source authority accepted")
			}
			if authority.Recheck(ctx) == nil {
				t.Fatal("already-open source authority survived original envelope replacement")
			}
		})
	}
	f.grant = original
	f.writeGrant(t)
	if _, err := s.sourceMetadataAuthority(ctx, h.owner, f.base.in); err != nil {
		t.Fatal("restored original grant", err)
	}
	// Loss of the actual original claim must close a previously admitted object.
	if _, err := h.admin.Exec("UPDATE system_backup_v2_backups SET controller_lease_expires_at=UTC_TIMESTAMP(6) WHERE public_id=?", f.base.in.Authority.TaskPublicID); err != nil {
		t.Fatal(err)
	}
	if authority.Recheck(ctx) == nil {
		t.Fatal("original SQL claim loss accepted")
	}
}

func TestProductionSourceBindingCannotBeAttachedWithoutOriginalRuntime(t *testing.T) {
	s := &DeploymentService{Config: DeploymentConfig{CaptureScope: "six-part"}}
	if _, _, err := s.attachProductionSources(&PublicJobOwner{}, b.LinuxProfileConfig{}); err == nil {
		t.Fatal("six-part source attached without original Runtime")
	}
	if (&PublicJobOwner{}).supportsCapture(d.Input{}) == nil {
		t.Fatal("unbound owner widened capture")
	}
}

func TestDeploymentProductionCompositionUsesOriginalRuntimeAndSourceHooksMySQL(t *testing.T) {
	f := newDProductionSourceFixture(t, nil)
	h := f.base.x.history
	s := h.service
	// Construction never reads this pool. Source observations remain subject
	// to the real census/grant and remote hooks when Discover is invoked.
	s.Source = h.db
	profile, err := api.LoadExecutionProfile(s.Config.ProfileFile)
	if err != nil {
		t.Fatal(err)
	}
	_, profileSHA, err := profile.CanonicalIdentity()
	if err != nil || profileSHA != s.Forward.DeploymentBinding().ProfileSHA256 || profileSHA != s.Recovery.DeploymentBinding().ProfileSHA256 {
		t.Fatal("original profile binding", err)
	}
	s.profile, s.profileHash = profile, profileSHA
	stage, err := s.composeCaptureRuntime(h.db, h.owner)
	if err != nil {
		t.Fatal("actual startup component composition", stage, err)
	}
	if s.Runtime == nil || s.Runtime.Owner != h.owner || s.RuntimeControl == nil || h.owner.productionSource == nil || h.owner.productionSource.service != s || !h.owner.RelayEnabled {
		t.Fatal("original Runtime/source/relay owner not retained")
	}
	input, _, _, _, _ := productionModuleFixture(t)
	input.Authority = f.base.in.Authority
	if err := h.owner.supportsCapture(input); err != nil {
		t.Fatal("bound original six-part spec", err)
	}
	input.Authority.TaskType = "preflight"
	input.Backup = nil
	if err := h.owner.supportsCapture(input); err != nil {
		t.Fatal("bound original preflight", err)
	}
	input.Authority.InstallationID = "foreign"
	if h.owner.supportsCapture(input) == nil {
		t.Fatal("foreign installation accepted")
	}
	// The exact same constructor must fail closed when original formal mount
	// identity pins are missing, before a fresh runtime can be exposed.
	operation := s.captureMaterials.Operations["capture-database"]
	operation.MountIdentities = nil
	s.captureMaterials.Operations["capture-database"] = operation
	f.writeGrant(t)
	if _, err := s.composeCaptureRuntime(h.db, h.owner); err == nil {
		t.Fatal("missing original formal mount identities accepted")
	}
}
