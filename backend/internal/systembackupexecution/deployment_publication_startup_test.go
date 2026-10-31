package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
	api "clawreef/internal/systembackupdeployment"
	s "clawreef/internal/systembackupsecurity"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

type publicationStartupFixture struct {
	service       *DeploymentService
	inputs        DeploymentStartupInputs
	client        *fake.Clientset
	grant         c.ExecutionGrant
	materials     PublicationSignerMaterials
	logins, signs atomic.Int64
}

// The real production file-binding + attach stages are callable on Windows.
// Native Kube and issuer records are local fixtures; no success state is made.
func newPublicationStartupFixture(t *testing.T, account, server, database string, mutations ...func(*s.InstallationSigningRecord)) *publicationStartupFixture {
	t.Helper()
	x := &publicationStartupFixture{}
	cfg := testDeploymentConfiguration(t)
	cfg.InstallationID = "installation_publication_bootstrap"
	dir := t.TempDir()
	cfg.KeyDirectory = dir
	materialPath := filepath.Join(dir, "publication-materials.json")
	cfg.PublicationSigners = &PublicationSignerReference{Protocol: PublicationSignerMaterialsVersion, Path: materialPath}
	cfg.ProfileFile = filepath.Join(dir, "profile.json")
	profile := api.ExecutionProfile{InstallationID: cfg.InstallationID, Revision: "r1", Orchestrator: "kubernetes", Profile: "cluster", TargetClass: "dr-ready-external", TargetRisks: []string{}, FailureDomain: "local-test", RestoreTargetRef: "isolated-target", RestoreTargetHash: strings.Repeat("f", 64)}
	profileRaw, profileSHA, err := profile.CanonicalIdentity()
	if err != nil {
		t.Fatal(err)
	}
	write := func(path string, raw []byte) {
		t.Helper()
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(cfg.ProfileFile, profileRaw)
	root, key, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(key)
	cfg.ForwardGrant = GrantReference{Path: filepath.Join(dir, "forward.json"), PublicKey: base64.StdEncoding.EncodeToString(root)}
	cfg.RecoveryGrant = GrantReference{Path: filepath.Join(dir, "recovery.json"), PublicKey: base64.StdEncoding.EncodeToString(root)}
	core, _ := json.Marshal(cfg)
	coreFile := filepath.Join(dir, "deployment.json")
	write(coreFile, core)
	recordKey := make([]byte, 32)
	if _, err = rand.Read(recordKey); err != nil {
		t.Fatal(err)
	}
	defer clear(recordKey)
	write(filepath.Join(dir, "record-v1"), recordKey)
	now := time.Now().UTC()
	g := c.ExecutionGrant{Version: "system-backup-execution-grant.v1", InstallationID: cfg.InstallationID, ControllerOwner: cfg.ControllerOwner, DatabaseAccount: account, ServerUUID: server, Database: database, ConfigVersion: 1, ConfigSHA256: strings.Repeat("a", 64), ProfileSHA256: profileSHA, DeploymentConfigSHA256: hash(core), WorkerIssuerSHA256: strings.Repeat("e", 64), NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(5 * time.Minute), Actions: []string{"prepare", "capture", "issue_worker"}, RecordKeys: []c.ExecutionRecordKey{{Ref: "record-v1", SHA256: hash(recordKey)}}}
	loadGrant := func(grant c.ExecutionGrant, path string) *c.PinnedExecutionIdentity {
		t.Helper()
		body, _ := json.Marshal(grant)
		env, _ := json.Marshal(map[string]string{"payload_base64": base64.StdEncoding.EncodeToString(body), "signature_base64": base64.StdEncoding.EncodeToString(ed25519.Sign(key, body))})
		write(path, env)
		p, e := c.NewPinnedExecutionIdentity(path, hash(env), dir, root)
		if e != nil {
			t.Fatal(e)
		}
		return p
	}
	forward := loadGrant(g, cfg.ForwardGrant.Path)
	recovery := g
	recovery.Actions = []string{"recover"}
	recovery.WorkerIssuerSHA256 = ""
	recoveryIdentity := loadGrant(recovery, cfg.RecoveryGrant.Path)
	privateKeys := map[string]ed25519.PrivateKey{}
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/auth/publisher/login" {
			x.logins.Add(1)
			var body struct{ Role, JWT string }
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Error("login body")
				w.WriteHeader(400)
				return
			}
			purpose := strings.TrimSuffix(body.Role, "-role")
			if privateKeys[purpose] == nil || body.JWT != "projected-jwt-for-"+purpose {
				t.Error("wrong purpose workload token")
				w.WriteHeader(403)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "opaque-token-for-" + purpose, "token_type": "batch", "renewable": false, "lease_duration": 10, "policies": []string{purpose + "-policy"}, "metadata": map[string]string{"role": body.Role, "namespace": cfg.Namespace, "pod_uid": "controller-pod-uid", "service_account_uid": "controller-sa-uid"}}})
			return
		}
		purpose := strings.TrimPrefix(r.URL.Path, "/v1/transit/sign/")
		private := privateKeys[purpose]
		var body struct {
			Input   string `json:"input"`
			Version string `json:"key_version"`
		}
		if private == nil || r.Header.Get("X-Vault-Token") != "opaque-token-for-"+purpose || json.NewDecoder(r.Body).Decode(&body) != nil || body.Version != "7" {
			t.Error("wrong purpose sign request")
			w.WriteHeader(403)
			return
		}
		input, e := base64.StdEncoding.Strict().DecodeString(body.Input)
		if e != nil {
			t.Error(e)
			w.WriteHeader(400)
			return
		}
		x.signs.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"signature": "vault:v7:" + base64.StdEncoding.EncodeToString(ed25519.Sign(private, input))}})
	}))
	t.Cleanup(tls.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tls.Certificate().Raw})
	caPath := filepath.Join(dir, "publisher-ca.pem")
	write(caPath, ca)
	issuer, issuerKey, _ := ed25519.GenerateKey(rand.Reader)
	defer clear(issuerKey)
	original := s.InstallationSigningRecord{InstallationID: cfg.InstallationID, Revision: 1, NotBefore: now.Add(-time.Minute), Until: now.Add(5 * time.Minute)}
	materials := PublicationSignerMaterials{Version: PublicationSignerMaterialsVersion, Record: s.FileSigningRecordReader{RecordFile: filepath.Join(dir, "installation-signing.json"), SignatureFile: filepath.Join(dir, "installation-signing.sig")}}
	for _, purpose := range []string{"capture_certificate", "acceptance_record", "catalog_record"} {
		public, private, _ := ed25519.GenerateKey(rand.Reader)
		privateKeys[purpose] = private
		t.Cleanup(func() { clear(private) })
		binding := s.TransitSigningBinding{InstallationID: cfg.InstallationID, Purpose: purpose, KeyID: purpose + "-key", KeyVersion: "registry-v1", Endpoint: tls.URL, KeyName: purpose, ProviderVersion: "7"}
		jwtPath := filepath.Join(dir, purpose+".jwt")
		write(jwtPath, []byte("projected-jwt-for-"+purpose))
		mount := PublicationSigningMount{Binding: binding, AuthMount: "publisher", Role: purpose + "-role", Policy: purpose + "-policy", JWTFile: jwtPath, CAFile: caPath, CASHA256: hash(ca)}
		materials.Mounts = append(materials.Mounts, mount)
		original.Keys = append(original.Keys, s.ArtifactSigningPublicKey{InstallationID: cfg.InstallationID, Purpose: purpose, KeyID: binding.KeyID, KeyVersion: binding.KeyVersion, PublicKey: public, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)})
		original.Permissions = append(original.Permissions, s.InstallationSigningPermission{Binding: binding, AuthMount: mount.AuthMount, Role: mount.Role, Policy: mount.Policy, CASHA256: mount.CASHA256, SQLOwner: &s.SQLSigningOwnerGrant{ServerUUID: server, Database: database, DatabaseAccount: account, ControllerOwner: "public:controller-pod-uid", ConfigVersion: g.ConfigVersion, ConfigSHA256: g.ConfigSHA256, Workload: s.SigningWorkloadIdentity{Namespace: cfg.Namespace, PodUID: "controller-pod-uid", ServiceAccountUID: "controller-sa-uid"}}})
	}
	for _, mutate := range mutations {
		mutate(&original)
	}
	record, _ := json.Marshal(original)
	write(materials.Record.RecordFile, record)
	write(materials.Record.SignatureFile, ed25519.Sign(issuerKey, append([]byte(s.InstallationSigningDomain), record...)))
	materials.Pin = s.InstallationSigningPin{InstallationID: original.InstallationID, Revision: original.Revision, RecordSHA256: hash(record), Issuer: issuer}
	materialRaw, _ := json.Marshal(materials)
	write(materialPath, materialRaw)
	x.client = fake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: cfg.Namespace, UID: types.UID(cfg.NamespaceUID)}}, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "controller", Namespace: cfg.Namespace, UID: "controller-pod-uid"}, Spec: corev1.PodSpec{ServiceAccountName: "controller"}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "controller", Namespace: cfg.Namespace, UID: "controller-sa-uid"}})
	x.service = &DeploymentService{ConfigPath: coreFile, ConfigDigest: hash(core), Forward: forward, Recovery: recoveryIdentity, ForwardEnabled: true}
	x.inputs = DeploymentStartupInputs{PublicationSigners: []PublicationSignerInput{{File: materialPath, SHA256: hash(materialRaw)}}, ControllerPodName: "controller"}
	x.grant = g
	x.materials = materials
	return x
}

func TestPublicationSignerSharedProductionFileBootstrap(t *testing.T) {
	x := newPublicationStartupFixture(t, "publisher@127.0.0.1", "server", "control")
	if err := x.service.bindDeploymentStartupInputs(x.inputs); err != nil {
		t.Fatal("actual shared startup file stage", err)
	}
	if x.service.publicationInput == nil || x.service.Forward.DeploymentBinding().DeploymentConfigSHA256 != x.service.ConfigDigest {
		t.Fatal("material binding changed parent core/Forward pin")
	}
	if x.logins.Load() != 0 || x.signs.Load() != 0 {
		t.Fatal("file stage used provider")
	}
	for _, fault := range []string{"missing", "extra", "wrong hash", "wrong path", "changed core"} {
		t.Run(fault, func(t *testing.T) {
			service := *x.service
			service.publicationInput = nil
			in := x.inputs
			in.PublicationSigners = append([]PublicationSignerInput(nil), x.inputs.PublicationSigners...)
			switch fault {
			case "missing":
				in.PublicationSigners = nil
			case "extra":
				in.PublicationSigners = append(in.PublicationSigners, in.PublicationSigners[0])
			case "wrong hash":
				in.PublicationSigners[0].SHA256 = strings.Repeat("0", 64)
			case "wrong path":
				in.PublicationSigners[0].File = filepath.Join(t.TempDir(), "other.json")
			case "changed core":
				service.ConfigDigest = strings.Repeat("0", 64)
			}
			if service.bindDeploymentStartupInputs(in) == nil || service.publicationInput != nil {
				t.Fatal("bad forward startup input accepted")
			}
		})
	}
	if runtime.GOOS != "linux" {
		if got, err := NewDeploymentServiceWithInputs(context.Background(), nil, nil, nil, "", "", "", "", true, x.inputs); err == nil || got != nil {
			t.Fatal("production Linux guard bypassed")
		}
	}
}

func TestPublicationSignerRecoveryIgnoresUnavailableMaterials(t *testing.T) {
	x := newPublicationStartupFixture(t, "publisher@127.0.0.1", "server", "control")
	x.service.ForwardEnabled = false
	x.service.Forward = x.service.Recovery
	for _, path := range []string{x.inputs.PublicationSigners[0].File, x.materials.Record.RecordFile, x.materials.Record.SignatureFile, x.materials.Mounts[0].CAFile, x.materials.Mounts[0].JWTFile} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := x.service.bindDeploymentStartupInputs(x.inputs); err != nil {
		t.Fatal("missing signer files blocked recovery", err)
	}
	if err := x.service.attachPublicationSigners(context.Background(), nil, x.client, x.inputs.ControllerPodName); err != nil {
		t.Fatal("recovery attach required signer", err)
	}
	if x.service.publicationFactory != nil || x.service.publicationInput != nil || x.service.PublisherOwner != "public:controller-pod-uid" || x.logins.Load() != 0 {
		t.Fatal("recovery retained forward signer authority")
	}
}

func TestPublicationSignerActualServiceAttachStage(t *testing.T) {
	x := newPublicationStartupFixture(t, "publisher@127.0.0.1", "server", "control")
	if err := x.service.bindDeploymentStartupInputs(x.inputs); err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(providerAdmissionConnector{grant: x.grant})
	defer db.Close()
	if err := x.service.attachPublicationSigners(context.Background(), db, x.client, x.inputs.ControllerPodName); err != nil {
		t.Fatal("actual production attach stage", err)
	}
	if x.service.publicationFactory == nil || x.service.PublisherOwner != "public:controller-pod-uid" || x.logins.Load() != 0 || x.signs.Load() != 0 {
		t.Fatal("production attach did not pin actual workload without provider access")
	}
	if _, err := x.service.PublicationSignersForTask(context.Background(), c.ClaimToken{Target: c.Target{Kind: c.TargetBackup, PublicID: "sbk_11111111-2222-4333-8444-555555555555"}, Owner: "public:other-pod", RowVersion: 11}); err == nil {
		t.Fatal("service substituted current publisher identity")
	}
	x.service.ForwardEnabled = false
	if _, err := x.service.PublicationSignersForTask(context.Background(), c.ClaimToken{}); err == nil {
		t.Fatal("disabled Forward retained publication entry")
	}
}

func TestPublicationSignerSignedScopeAndWorkloadStartupDenials(t *testing.T) {
	for _, fault := range []string{"config version", "config SHA", "SQL account", "SQL database", "SQL server", "installation", "Pod UID", "SA UID", "worker SA", "missing JWT", "core reference replacement", "controller SA RBAC denied"} {
		t.Run(fault, func(t *testing.T) {
			mutate := func(record *s.InstallationSigningRecord) {
				for i := range record.Permissions {
					g := record.Permissions[i].SQLOwner
					switch fault {
					case "config version":
						g.ConfigVersion++
					case "config SHA":
						g.ConfigSHA256 = strings.Repeat("b", 64)
					case "SQL account":
						g.DatabaseAccount = "different@127.0.0.1"
					case "SQL database":
						g.Database = "different"
					case "SQL server":
						g.ServerUUID = "different"
					case "Pod UID":
						g.Workload.PodUID = "different"
					case "SA UID":
						g.Workload.ServiceAccountUID = "different"
					case "worker SA":
						g.Workload.ServiceAccountUID = "sa-uid"
					case "installation":
						record.Permissions[i].Binding.InstallationID = "installation_other"
					}
				}
				if fault == "installation" {
					record.InstallationID = "installation_other"
					for i := range record.Keys {
						record.Keys[i].InstallationID = record.InstallationID
					}
				}
			}
			x := newPublicationStartupFixture(t, "publisher@127.0.0.1", "server", "control", mutate)
			if _, err := s.LoadPublicationSignerHistory(context.Background(), x.inputs.PublicationSigners[0]); err != nil {
				t.Fatal("negative must have a real valid original issuer signature", err)
			}
			if fault == "missing JWT" {
				if err := os.Remove(x.materials.Mounts[0].JWTFile); err != nil {
					t.Fatal(err)
				}
			}
			if fault == "controller SA RBAC denied" {
				x.client.PrependReactor("get", "serviceaccounts", func(ktesting.Action) (bool, kruntime.Object, error) {
					return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "serviceaccounts"}, "controller", errors.New("self SA read denied"))
				})
			}
			if fault == "worker SA" {
				pod, _ := x.client.CoreV1().Pods("backup").Get(context.Background(), "controller", metav1.GetOptions{})
				pod.Spec.ServiceAccountName = "worker"
				x.client.CoreV1().Pods("backup").Update(context.Background(), pod, metav1.UpdateOptions{})
				x.client.CoreV1().ServiceAccounts("backup").Create(context.Background(), &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "worker", Namespace: "backup", UID: "sa-uid"}}, metav1.CreateOptions{})
			}
			if fault == "core reference replacement" {
				cfg, err := LoadDeploymentConfig(x.service.ConfigPath, x.service.ConfigDigest)
				if err != nil {
					t.Fatal(err)
				}
				cfg.PublicationSigners.Path = filepath.Join(t.TempDir(), "replacement-materials.json")
				raw, _ := json.Marshal(cfg)
				x.service.ConfigPath = filepath.Join(t.TempDir(), "replacement-core.json")
				if err = os.WriteFile(x.service.ConfigPath, raw, 0600); err != nil {
					t.Fatal(err)
				}
				x.service.ConfigDigest = hash(raw)
			}
			err := x.service.bindDeploymentStartupInputs(x.inputs)
			if err == nil {
				db := sql.OpenDB(providerAdmissionConnector{grant: x.grant})
				defer db.Close()
				err = x.service.attachPublicationSigners(context.Background(), db, x.client, x.inputs.ControllerPodName)
			}
			if err == nil || x.service.publicationFactory != nil || x.logins.Load() != 0 || x.signs.Load() != 0 {
				t.Fatal("invalid startup binding reached provider or installed signer")
			}
		})
	}
}
