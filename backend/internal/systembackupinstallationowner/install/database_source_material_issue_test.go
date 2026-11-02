package install

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/worker"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func databaseSourceRequestFixture(t *testing.T, database, uuid string) worker.Request {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("pure/denied database source input reached a server")
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	return worker.Request{Database: &worker.DatabaseSpec{Name: database, ServerUUID: uuid, Address: "10.20.30.40:3306", TLSServerName: "original-mysql.invalid", RootCA: ca, MaxRows: 100000, MaxMemoryBytes: 16 << 20, SourceScope: domain.BusinessTableSourceScope, SchemaCensus: &domain.SchemaCensusSpec{Version: domain.SchemaCensusVersion, Definer: "metadata_owner@localhost", DefinitionSHA256: strings.Repeat("a", 64)}}}
}

func TestDatabaseSourceConnectorKeepsNativeTLSAndClosedDriverOptions(t *testing.T) {
	r := databaseSourceRequestFixture(t, "original", "11111111-2222-3333-4444-555555555555")
	var verified atomic.Bool
	credential := worker.DatabaseCredential{Username: "finite_source", Password: []byte("component-only-secret")}
	cfg, err := databaseSourceConnector(r, credential, &verified)
	if err != nil || cfg.TLS == nil || cfg.TLS.MinVersion != tls.VersionTLS13 || cfg.TLS.InsecureSkipVerify || cfg.TLS.ServerName != r.Database.TLSServerName || cfg.TLS.RootCAs == nil || cfg.MultiStatements || cfg.AllowAllFiles || cfg.AllowCleartextPasswords || cfg.AllowFallbackToPlaintext || cfg.InterpolateParams || len(cfg.Params) != 0 || verified.Load() {
		t.Fatal("native source connector weakened or claimed observation", err)
	}
	credential.Username = "root"
	if _, err := databaseSourceConnector(r, credential, &verified); err == nil {
		t.Fatal("root source account accepted")
	}
	credential.Username = "finite_source"
	r.Database.RootCA = []byte("not a CA")
	if _, err := databaseSourceConnector(r, credential, &verified); err == nil {
		t.Fatal("unpinned TLS source accepted")
	}
}

func TestDatabaseSourceIssuerRejectsOriginalServiceDriftBeforeNativeSigningComponent(t *testing.T) {
	f, ctx, intent := sourceMaterialFixture(t)
	request := databaseSourceRequestFixture(t, intent.Database, intent.ServerUUID)
	// Select one original production definition BEFORE real A preparation.
	original := map[string]any{"Version": "original-six-part-source-material-definition.v1", "ConfigSHA256": intent.ConfigSHA256, "CoreSHA256": intent.DeploymentConfigSHA256, "ForwardGrantSHA256": intent.CaptureGrantSHA256, "Materials": map[string]any{"Operations": map[string]any{"capture-database": map[string]any{"Request": request}}}}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(intent.DefinitionFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	intent.DefinitionSHA256 = hash(raw)
	issuer, err := f.i.PrepareSourceMaterialIssue(ctx, f.password, f.enrollment, intent)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(intent.DefinitionFile)
	credentialRaw, _ := json.Marshal(worker.DatabaseCredential{Username: "finite_source", Password: []byte("component-only-secret")})
	credentialFile := filepath.Join(directory, "original-database-source-credential.json")
	if err = os.WriteFile(credentialFile, credentialRaw, 0600); err != nil {
		t.Fatal(err)
	}
	definition := DatabaseSourceIssueDefinition{Version: DatabaseSourceIssueVersion, OriginalDefinitionSHA256: intent.DefinitionSHA256, Account: "finite_source@%", Service: "original-mysql", ServiceUID: "changed-original-service-uid", Port: 3306, Source: worker.FormalSourceMount{GrantFile: filepath.Join(directory, "original-database-source-grant.json"), Issuer: f.i.public, CredentialFile: credentialFile, CredentialSHA256: hash(credentialRaw)}}
	_, err = f.i.kube.CoreV1().Services(intent.Namespace).Create(ctx, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: definition.Service, Namespace: intent.Namespace, UID: types.UID("actual-original-service-uid")}, Spec: corev1.ServiceSpec{ClusterIP: "10.20.30.40", Ports: []corev1.ServicePort{{Port: 3306, Protocol: corev1.ProtocolTCP}}}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	issueRaw, err := canonical(definition)
	if err != nil {
		t.Fatal(err)
	}
	issueFile := filepath.Join(directory, "original-database-source-issue.json")
	if err = os.WriteFile(issueFile, issueRaw, 0600); err != nil {
		t.Fatal(err)
	}
	selected, err := issuer.originalDatabaseSourceRequest()
	if err != nil || selected.Operation != "capture-database" {
		t.Fatal("original empty operation template was not bound to its fixed map key", err)
	}
	if result, err := issuer.IssueDatabaseSource(ctx, issueFile, hash(issueRaw), f.key); err == nil || result.Source.GrantSHA256 != "" {
		t.Fatal("changed native Service issued database delegation", err)
	}
	if _, err = os.Stat(definition.Source.GrantFile); !os.IsNotExist(err) || f.s.writes != 0 || f.signs.Load() != 0 {
		t.Fatal("refused service issued a grant/SQL mutation/provider probe", err)
	}
	if _, err := issuer.SignWorkerSource(ctx, worker.FormalSourceGrant{Operation: "capture-database"}, f.key); err == nil {
		t.Fatal("old generic source signer bypassed native database checks")
	}
}

func TestDatabaseSourceGrantFileRetainsExactOriginalRetryAndConflicts(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("original issuer uses Linux private directory contract")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "original-database-grant.json")
	original := []byte("component-original-fixed-window-signature")
	if writeDatabaseSourceGrant(file, original) != nil || writeDatabaseSourceGrant(file, original) != nil {
		t.Fatal("exact original retry rejected")
	}
	if writeDatabaseSourceGrant(file, []byte("different-window-or-signature")) == nil {
		t.Fatal("conflicting grant overwritten")
	}
	actual, err := os.ReadFile(file)
	if err != nil || string(actual) != string(original) {
		t.Fatal("original grant bytes changed", err)
	}
}
