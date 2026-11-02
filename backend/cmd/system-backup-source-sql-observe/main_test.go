package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"

	"clawreef/internal/systembackup/domain"
	"github.com/go-sql-driver/mysql"
)

func TestFirstInstallActualProjectionTemplatesWithholdPrivateValues(t *testing.T) {
	python := os.Getenv("SBK_PUBLIC_INPUTS_PYTHON")
	if python == "" {
		t.Skip("set SBK_PUBLIC_INPUTS_PYTHON to the reviewed actual Python3 executable; no Kubernetes needed")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "..", "scripts", "system-backup-d-first-install-inputs.py"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, python, script, "templates")
	command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	raw, err := command.Output()
	if err != nil {
		t.Fatal("actual local template generator", err)
	}
	var templates map[string]string
	if json.Unmarshal(raw, &templates) != nil || len(templates) != 13 {
		t.Fatal("complete public projection list")
	}
	const canary = "PRIVATE_VALUE_MUST_NEVER_REACH_PROJECTED_STDOUT"
	podSpec := map[string]any{"serviceAccountName": "actual-sa", "nodeName": "actual-node", "containers": []any{map[string]any{"name": "actual", "image": "actual@sha256:" + strings.Repeat("a", 64), "command": []string{canary}, "args": []string{canary}, "env": []any{map[string]any{"name": "LITERAL_PASSWORD", "value": canary}, map[string]any{"name": "SOURCE_PASSWORD", "valueFrom": map[string]any{"secretKeyRef": map[string]any{"name": "actual-secret-reference", "key": "password"}}}}, "volumeMounts": []any{map[string]any{"name": "actual-volume", "mountPath": "/actual-mount"}}}}, "volumes": []any{map[string]any{"name": "actual-volume", "secret": map[string]any{"secretName": "actual-secret-reference", "items": []any{map[string]any{"key": "password", "path": "password"}}}}}}
	for resource, source := range templates {
		t.Run(resource, func(t *testing.T) {
			item := map[string]any{"metadata": map[string]any{"name": "actual", "uid": "actual-uid", "namespace": "clawmanager-zhanghui08-system", "resourceVersion": "10", "generation": 1, "annotations": map[string]string{"private": canary}}, "spec": map[string]any{"replicas": 1, "containers": podSpec["containers"], "volumes": podSpec["volumes"], "template": map[string]any{"spec": podSpec}, "jobTemplate": map[string]any{"spec": map[string]any{"template": map[string]any{"spec": podSpec}}}, "ports": []any{map[string]any{"name": "mysql", "port": 3306}}, "selector": map[string]string{"app": "actual"}}, "data": map[string]string{"private": canary}}
			parsed, err := template.New(resource).Option("missingkey=default").Parse(source)
			if err != nil {
				t.Fatal("actual generated Go template syntax", err)
			}
			var out bytes.Buffer
			document := map[string]any{"metadata": map[string]any{"resourceVersion": "100"}, "items": []any{item}}
			if parsed.Execute(&out, document) != nil || bytes.Contains(out.Bytes(), []byte(canary)) {
				t.Fatal("projection failed or selected private bytes")
			}
			if resource == "pods" || resource == "deployments" || resource == "cronjobs" {
				if !bytes.Contains(out.Bytes(), []byte("actual-secret-reference")) {
					t.Fatal("lost the actual public credential reference")
				}
			}
			var result map[string]any
			if json.Unmarshal(out.Bytes(), &result) != nil {
				t.Fatal("projection was not bounded JSON")
			}
		})
	}
}

func originalSQLPlanFixture() (sourcePlan, publicInventory) {
	p := sourcePlan{Version: "original-production-source-sql-plan.v1", Purpose: "functional_test", InventorySHA256: strings.Repeat("a", 64), Namespace: "clawmanager-zhanghui08-system", NamespaceUID: "337cfe30-2c17-4b8e-b32a-760778b8098e", OwnerSubject: "original-owner", OwnerUID: "owner-uid", OwnerGroupsSHA256: strings.Repeat("b", 64), Service: "original-mysql", ServiceUID: "original-mysql-service-uid", Port: 3306, Address: "10.96.0.14:3306", Database: "original_source", ServerUUID: "12345678-1234-1234-1234-123456789abc", Account: "sbk_source@10.%", TLSServerName: "original-mysql.clawmanager-zhanghui08-system.svc", CASHA256: strings.Repeat("c", 64)}
	var inventory publicInventory
	inventory.Version, inventory.Namespace, inventory.NamespaceUID, inventory.ObservedAt = "zhanghui08-original-first-install-public-inputs.v1", p.Namespace, p.NamespaceUID, time.Now().UTC().Add(-time.Second)
	inventory.Owner.Subject, inventory.Owner.UID, inventory.Owner.GroupsSHA256 = p.OwnerSubject, p.OwnerUID, p.OwnerGroupsSHA256
	service := serviceIdentity{Name: p.Service, UID: p.ServiceUID, Namespace: p.Namespace, ClusterIP: "10.96.0.14"}
	service.Ports = append(service.Ports, struct{ Port int }{3306})
	inventory.Objects = map[string]struct{ Items []serviceIdentity }{"services": {Items: []serviceIdentity{service}}}
	return p, inventory
}

func TestProductionSQLPlanRequiresActualOriginalPublicServiceOwnerAndFreshness(t *testing.T) {
	p, inventory := originalSQLPlanFixture()
	if validatePlan(p, inventory, time.Now()) != nil {
		t.Fatal("explicit public selection")
	}
	for _, name := range []string{"namespace", "namespace-uid", "owner", "service-uid", "port", "address", "stale", "root"} {
		t.Run(name, func(t *testing.T) {
			p, inventory := originalSQLPlanFixture()
			switch name {
			case "namespace":
				p.Namespace = "another"
			case "namespace-uid":
				p.NamespaceUID = "another"
			case "owner":
				p.OwnerSubject = "another"
			case "service-uid":
				p.ServiceUID = "another"
			case "port":
				p.Port = 63507
			case "address":
				p.Address = "127.0.0.1:3306"
			case "stale":
				inventory.ObservedAt = time.Now().Add(-16 * time.Minute)
			case "root":
				p.Account = "root@localhost"
			}
			if validatePlan(p, inventory, time.Now()) == nil {
				t.Fatal("accepted a different or stale original source")
			}
		})
	}
}

func TestProductionSourceAccountProposalUsesExactExistingFinitePolicy(t *testing.T) {
	p, _ := originalSQLPlanFixture()
	p.Census = domain.SchemaCensusSpec{Version: domain.SchemaCensusVersion, Definer: "sbk_metadata_owner@localhost"}
	proposal, err := sourceProposal(p)
	if err != nil || proposal.DatabaseMutated || proposal.PermissionsApplied || proposal.Ready {
		t.Fatal("pure original source proposal", err)
	}
	grants := make([]string, len(proposal.SourceGrants))
	for n, grant := range proposal.SourceGrants {
		grants[n] = strings.TrimSuffix(grant, ";")
	}
	if domain.ValidateBusinessSourceGrants(p.Database, grants) != nil || len(grants) != len(domain.BusinessCaptureTables())+2 || !strings.Contains(proposal.CreateLockedDefinerSQL, " ACCOUNT LOCK;") {
		t.Fatal("proposal widened or missed the actual finite source policy")
	}
	p.Census.DefinitionSHA256 = proposal.ExpectedCensus.DefinitionSHA256
	if _, err := sourceProposal(p); err != nil {
		t.Fatal("original same-body pin", err)
	}
	p.Census.DefinitionSHA256 = strings.Repeat("f", 64)
	if _, err := sourceProposal(p); err == nil {
		t.Fatal("replaced original census body")
	}
	p.Census.DefinitionSHA256, p.Census.Definer = "", p.Account
	if _, err := sourceProposal(p); err == nil {
		t.Fatal("combined broad metadata definer and source login")
	}
}

// This uses real TLS with an explicit local CA/leaf component fixture. It is
// not a MySQL handshake, native production account or field certificate proof.
func TestProductionSQLTLSRequiresActualVerifiedSANAndOriginalCA(t *testing.T) {
	p, _ := originalSQLPlanFixture()
	newCA := func(serial int64) ([]byte, *x509.Certificate, ed25519.PrivateKey) {
		public, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		certificate := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "explicit component CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, key)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { clear(key) })
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), parsed, key
	}
	ca, issuer, issuerKey := newCA(1)
	wrongCA, _, _ := newCA(2)
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), DNSNames: []string{p.TLSServerName}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, issuer, public, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	defer server.Close()
	for _, name := range []string{"original", "wrong-san", "wrong-ca"} {
		t.Run(name, func(t *testing.T) {
			selected, roots := p, ca
			if name == "wrong-san" {
				selected.TLSServerName = "different.invalid"
			}
			if name == "wrong-ca" {
				roots = wrongCA
			}
			selected.CASHA256 = hash(roots)
			input := mysql.NewConfig()
			input.User, input.Passwd, input.Net, input.Addr, input.DBName = "sbk_source", "explicit-component-only", "tcp", p.Address, p.Database
			var observed observation
			cfg, err := productionConnector(selected, []byte(input.FormatDSN()), roots, &observed)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := tls.Dial("tcp", server.Listener.Addr().String(), cfg.TLS)
			if conn != nil {
				conn.Close()
			}
			if name == "original" {
				if err != nil || observed.PeerLeafSHA256 != hash(der) || observed.TLSVersion != "TLS 1.3" {
					t.Fatal("verified original SAN/CA", err)
				}
			} else if err == nil || observed.PeerLeafSHA256 != "" {
				t.Fatal("accepted a mismatched original SAN/CA")
			}
		})
	}
}
