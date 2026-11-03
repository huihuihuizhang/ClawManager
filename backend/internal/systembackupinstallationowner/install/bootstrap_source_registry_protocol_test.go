package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

// This is the actual authenticated issuer plus existing SQL/API transports.
// Source/registry bytes below are deliberately inert synthetic association
// inputs. No native source completeness, registry semantic or slot is claimed.
func bootstrapSourceProtocolFixture(t *testing.T, ctx context.Context) (*authorityFixture, pd.BootstrapConsumptionRequest, []byte, BootstrapSourceRegistryDefinition, BootstrapSourceFilePin) {
	t.Helper()
	f, _, selection, pack := terminalMappingIssueFixture(t, ctx)
	d, pin := bootstrapSourceProtocolDefinition(t, ctx, f)
	return f, selection, pack, d, pin
}

func bootstrapSourceProtocolDefinition(t *testing.T, ctx context.Context, f *authorityFixture) (BootstrapSourceRegistryDefinition, BootstrapSourceFilePin) {
	t.Helper()
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private fixture directory")
	}
	write := func(name string, raw []byte) BootstrapSourceFilePin {
		pin := BootstrapSourceFilePin{filepath.Join(dir, name), hash(raw)}
		if err := os.WriteFile(pin.File, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return pin
	}
	b := f.record.Binding
	controller := BootstrapSourceController{Namespace: b.Namespace, NamespaceUID: b.NamespaceUID, Deployment: "original-source-controller", DeploymentUID: "original-source-controller-uid", ReplicaSet: "original-source-rs", ReplicaSetUID: "original-source-rs-uid", Pod: b.PodName, PodUID: b.PodUID, ServiceAccount: b.ServiceAccountName, ServiceAccountUID: b.ServiceAccountUID}
	api := f.i.kube.(*kubefake.Clientset)
	pod, err := api.CoreV1().Pods(b.Namespace).Get(ctx, b.PodName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	controlled := true
	pod.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: controller.ReplicaSet, UID: types.UID(controller.ReplicaSetUID), Controller: &controlled}}
	if _, err = api.CoreV1().Pods(b.Namespace).Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: controller.ReplicaSet, Namespace: b.Namespace, UID: types.UID(controller.ReplicaSetUID), OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: controller.Deployment, UID: types.UID(controller.DeploymentUID), Controller: &controlled}}}}
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: controller.Deployment, Namespace: b.Namespace, UID: types.UID(controller.DeploymentUID)}}
	dep.Spec.Template.Spec.ServiceAccountName = b.ServiceAccountName
	if _, err = api.AppsV1().ReplicaSets(b.Namespace).Create(ctx, rs, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = api.AppsV1().Deployments(b.Namespace).Create(ctx, dep, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	d := BootstrapSourceRegistryDefinition{SchemaVersion: BootstrapSourceRegistryVersion, Profile: BootstrapSourceRegistryProfile, Controller: controller, Deployment: write("deployment", []byte("original deployment bytes")), Materials: write("materials", []byte("original source materials bytes")), ExecutionProfile: write("profile", []byte("original execution profile bytes")), MetadataIssuerPublic: write("source-public", f.i.public), PartsRegistry: write("parts", []byte("parts")), SourceWritersRegistry: write("writers", []byte("source_writers"))}
	d.RuntimeAgent = &BootstrapSourceRuntimeAgent{Operation: "gateway_state_read", ScopeSHA256: hash([]byte("original-runtime-agent-scope")), CA: write("agent.ca", []byte("original runtime agent CA")), Credential: write("agent.token", []byte("original read-only runtime agent token"))}
	metadata := ControllerSourceMetadataGrant{Version: "system-backup-original-source-metadata-grant.v1", InstallationID: f.record.Target.InstallationID, ControllerOwner: "original-controller-owner", DeploymentConfigSHA256: d.Deployment.SHA256, CaptureGrantSHA256: strings.Repeat("c", 64), ConfigSHA256: f.config.SHA256(), ScopeSHA256: strings.Repeat("d", 64), Namespace: b.Namespace, NamespaceUID: b.NamespaceUID, ControllerDeployment: controller.Deployment, ControllerDeploymentUID: controller.DeploymentUID, ControllerServiceAccount: b.ServiceAccountName, ControllerServiceAccountUID: b.ServiceAccountUID, NotBefore: f.record.NotBefore, Until: f.record.Until}
	metadataRaw, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(struct{ Record, Signature []byte }{metadataRaw, ed25519.Sign(f.key, append([]byte("system-backup-controller-source-metadata.v1\x00"), metadataRaw...))})
	if err != nil {
		t.Fatal(err)
	}
	d.MetadataGrant = write("metadata", envelope)
	for _, purpose := range []string{"source_api", "source_objects", "source_redis", "source_sql"} {
		c := BootstrapSourceConnection{Purpose: purpose, Endpoint: "https://source.example:443", Account: "original-" + purpose, CA: write(purpose+".ca", []byte("original CA "+purpose)), Credential: write(purpose+".credential", []byte("original credential "+purpose)), IdentitySHA256: hash([]byte("identity-" + purpose)), ScopeSHA256: hash([]byte("scope-" + purpose))}
		if purpose == "source_redis" {
			c.Endpoint = "rediss://source.example:6379"
		}
		if purpose == "source_sql" {
			c.Endpoint, c.ServerUUID, c.Database = "mysql+tls://source.example:3306", "original-source-server", "original_source"
		}
		d.Connections = append(d.Connections, c)
	}
	raw, err := canonical(d)
	if err != nil {
		t.Fatal(err)
	}
	return d, write("definition", raw)
}

func TestBootstrapSourceRegistryProtocolActualIssuerAndDistinctDomain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f, selection, pack, definition, file := bootstrapSourceProtocolFixture(t, ctx)
	signed, err := f.i.IssueBootstrapSourceRegistries(ctx, f.password, f.enrollment, pack, hash(pack), file.File, file.SHA256, selection, f.files, f.key)
	if err != nil {
		t.Fatal("actual original issuer", err)
	}
	r, err := verifyBootstrapSourceRegistries(signed.Record, signed.Signature, f.i.public)
	if err != nil || r.CaptureRecordSHA256 != hash(f.draft) || r.Source.MetadataGrant != definition.MetadataGrant || bootstrapSourceSelectionHash(r.Selection) != bootstrapSourceSelectionHash(selection) || !r.NotBefore.Equal(f.record.NotBefore) || !r.Until.Equal(f.record.Until) || f.s.openTx.Load() != 0 {
		t.Fatal("source association lost original selection/window or locks", err)
	}
	for _, domain := range []string{BootstrapOriginalMappingDomain, FunctionalClassificationDomain, "system-backup-controller-source-metadata.v1\x00"} {
		wrong := ed25519.Sign(f.key, append([]byte(domain), signed.Record...))
		if _, err = verifyBootstrapSourceRegistries(signed.Record, wrong, f.i.public); err == nil {
			t.Fatal("cross-domain authority", domain)
		}
	}
	if bytes.Contains(signed.Record, []byte("original credential source_sql")) {
		t.Fatal("private source credential exported")
	}
}

func TestBootstrapSourceRegistryProtocolRejectsSelectionAndSourceKeySubstitution(t *testing.T) {
	for _, scenario := range []string{"selection", "metadata-key", "parts-pin", "window"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			f, selection, pack, definition, file := bootstrapSourceProtocolFixture(t, ctx)
			switch scenario {
			case "selection":
				selection.Candidates[0].MappingHash = pd.Hash(strings.Repeat("f", 64))
			case "metadata-key":
				public, private, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				clear(private)
				if os.WriteFile(definition.MetadataIssuerPublic.File, public, 0600) != nil {
					t.Fatal("source public substitution")
				}
				definition.MetadataIssuerPublic.SHA256 = hash(public)
			case "parts-pin":
				definition.PartsRegistry.SHA256 = strings.Repeat("e", 64)
			case "window":
				raw, err := os.ReadFile(definition.MetadataGrant.File)
				if err != nil {
					t.Fatal(err)
				}
				g, _, err := decodeBootstrapSourceMetadata(raw, f.i.public)
				if err != nil {
					t.Fatal(err)
				}
				g.Until = f.record.Until.Add(-time.Microsecond)
				record, err := json.Marshal(g)
				if err != nil {
					t.Fatal(err)
				}
				raw, err = json.Marshal(struct{ Record, Signature []byte }{record, ed25519.Sign(f.key, append([]byte("system-backup-controller-source-metadata.v1\x00"), record...))})
				if err != nil || os.WriteFile(definition.MetadataGrant.File, raw, 0600) != nil {
					t.Fatal("metadata window", err)
				}
				definition.MetadataGrant.SHA256 = hash(raw)
			}
			if scenario != "selection" {
				raw, err := canonical(definition)
				if err != nil || os.WriteFile(file.File, raw, 0600) != nil {
					t.Fatal("definition mutation", err)
				}
				file.SHA256 = hash(raw)
			}
			signed, err := f.i.IssueBootstrapSourceRegistries(ctx, f.password, f.enrollment, pack, hash(pack), file.File, file.SHA256, selection, f.files, f.key)
			if err == nil || len(signed.Record) != 0 || len(signed.Signature) != 0 {
				t.Fatal("invalid independent source association admitted", scenario, err)
			}
		})
	}
}

func TestBootstrapSourceRegistryProtocolAuthenticatedRereadRejectsTransientBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "original-locator")
	original := []byte("independently selected original bytes")
	if os.WriteFile(path, original, 0600) != nil {
		t.Fatal("original bytes")
	}
	state := &consumerCaptureState{files: []consumerPinnedFile{{path, hash(original), 262144}}}
	if raw, err := readBootstrapSourceAuthenticated(state, path, 262144); err != nil || !bytes.Equal(raw, original) {
		t.Fatal("positive original authenticated read", err)
	}
	if os.WriteFile(path, []byte("transient foreign locator/public/plan"), 0600) != nil {
		t.Fatal("transient bytes")
	}
	if _, err := readBootstrapSourceAuthenticated(state, path, 262144); err == nil {
		t.Fatal("restoring later must not authenticate this transient read")
	}
}
