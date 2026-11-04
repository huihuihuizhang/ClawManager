//go:build systembackup_minio_september_native

package systembackupexecution

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
)

const cOnceNativeRoot = "/fixture"

type cOnceNativeFixture struct {
	Version, Owner, MinioImage, Endpoint, Region string
	CAFile, CASHA256, SPKISHA256                 string
	NotBefore, Until                             time.Time
}
type cOnceNativeProof struct {
	Owner, MinioImage, ImageID, ContainerID, DataVolume, NetworkID string
	InternalNetwork, NoPublishedPorts                              bool
}

func cOnceNativeOwner(t *testing.T) string {
	t.Helper()
	owner := os.Getenv("C_MINIO_NATIVE_OWNER")
	if os.Getenv("C_MINIO_NATIVE_ROOT") != cOnceNativeRoot || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(owner) {
		t.Fatal("explicit solely owned fixture required")
	}
	return owner
}
func cOnceNativeRandom(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		t.Fatal(e)
	}
	return hex.EncodeToString(b)
}
func cOnceNativeSave(t *testing.T, name string, b []byte) {
	t.Helper()
	f, e := os.OpenFile(filepath.Join(cOnceNativeRoot, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.Write(b)
	se, closeErr := f.Sync(), f.Close()
	if e != nil || se != nil || closeErr != nil {
		t.Fatal("fixture write")
	}
}
func cOnceNativeSaveJSON(t *testing.T, name string, value any) {
	t.Helper()
	raw, e := ce.Canonical(value)
	if e != nil {
		t.Fatal(e)
	}
	cOnceNativeSave(t, name, raw)
}
func cOnceNativeRead(t *testing.T, name string, value any) {
	t.Helper()
	raw, e := cOnceNativeReadFile(filepath.Join(cOnceNativeRoot, name))
	if e != nil || decodePublicationCanonical(raw, value) != nil {
		t.Fatal("private original fixture metadata missing")
	}
	clear(raw)
}

// Local test reader only; never replaces a production authority/material reader.
func cOnceNativeReadFile(path string) ([]byte, error) {
	return pinnedDeploymentFile(path, cOnceNativeFileSHA(path), 262144)
}
func cOnceNativeFileSHA(path string) string {
	b, e := os.ReadFile(path)
	if e != nil {
		return ""
	}
	defer clear(b)
	return hash(b)
}

// No MinIO/MC calls. Produces only a disposable private TLS/root credential
// fixture. The orchestrator must start an independent exact immutable server
// and persist actual Docker inspect proof before the native test can run.
func TestMinIOOnceFixturePrepareAssets(t *testing.T) {
	owner := cOnceNativeOwner(t)
	image := os.Getenv("C_MINIO_NATIVE_IMAGE")
	if !regexp.MustCompile(`^[^\s@]+@sha256:[a-f0-9]{64}$`).MatchString(image) {
		t.Fatal("independently selected immutable image required")
	}
	st, e := os.Lstat(cOnceNativeRoot)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		t.Fatal("new sole-owned empty fixture mount required")
	}
	entries, e := os.ReadDir(cOnceNativeRoot)
	if e != nil || len(entries) != 0 {
		t.Fatal("fixture must be empty")
	}
	if e = os.Chmod(cOnceNativeRoot, 0700); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"certs", "secrets"} {
		if e = os.Mkdir(filepath.Join(cOnceNativeRoot, name), 0700); e != nil {
			t.Fatal(e)
		}
	}
	now := time.Now().UTC()
	until := now.Add(45 * time.Minute)
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	leafKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned native fixture " + owner}, NotBefore: now.Add(-time.Minute), NotAfter: until, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "minio-native"}, NotBefore: now.Add(-time.Minute), NotAfter: until, DNSNames: []string{"minio-native", "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	keyDER, e := x509.MarshalPKCS8PrivateKey(leafKey)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(keyDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	cOnceNativeSave(t, "certs/ca.pem", caPEM)
	cOnceNativeSave(t, "certs/public.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	defer clear(keyPEM)
	cOnceNativeSave(t, "certs/private.key", keyPEM)
	parsed, e := x509.ParseCertificate(leafDER)
	if e != nil {
		t.Fatal(e)
	}
	f := cOnceNativeFixture{Version: "owned-native-single-send-fixture.v1", Owner: owner, MinioImage: image, Endpoint: "https://minio-native:9000", Region: "us-east-1", CAFile: filepath.Join(cOnceNativeRoot, "certs/ca.pem"), CASHA256: hash(caPEM), SPKISHA256: hash(parsed.RawSubjectPublicKeyInfo), NotBefore: now.Add(-time.Minute), Until: until}
	root := nativePublicationCredential{AccessKey: "cnroot" + owner, SecretKey: cOnceNativeRandom(t, 32), NotBefore: f.NotBefore, Until: f.Until}
	cOnceNativeSaveJSON(t, "secrets/root.json", root)
	cOnceNativeSave(t, "secrets/root-user", []byte(root.AccessKey))
	cOnceNativeSave(t, "secrets/root-password", []byte(root.SecretKey))
	cOnceNativeSaveJSON(t, "fixture.json", f)
}
func loadCOnceNativeFixture(t *testing.T) (cOnceNativeFixture, cOnceNativeProof) {
	t.Helper()
	owner := cOnceNativeOwner(t)
	var f cOnceNativeFixture
	var p cOnceNativeProof
	cOnceNativeRead(t, "fixture.json", &f)
	cOnceNativeRead(t, "image-proof.json", &p)
	if f.Version != "owned-native-single-send-fixture.v1" || f.Owner != owner || f.Endpoint != "https://minio-native:9000" || f.Region != "us-east-1" || p.Owner != owner || p.MinioImage != f.MinioImage || p.DataVolume != "c-minio-native-"+owner+"-data" || !p.InternalNetwork || !p.NoPublishedPorts || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(p.ImageID) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(p.ContainerID) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(p.NetworkID) || time.Now().Before(f.NotBefore) || !time.Now().Before(f.Until) {
		t.Fatal("actual immutable solely owned isolated fixture proof missing")
	}
	return f, p
}
func cOnceNativeClient(t *testing.T, f cOnceNativeFixture, root nativePublicationCredential) *minioPermissionHTTP {
	t.Helper()
	n, e := newMinioPermissionHTTP(minioPermissionProvider{Endpoint: f.Endpoint, Region: f.Region, CAFile: f.CAFile, CASHA256: f.CASHA256, SPKISHA256: f.SPKISHA256}, root)
	if e != nil {
		t.Fatal(e)
	}
	return n
}
func cOnceNativeServer(ctx context.Context, n *minioPermissionHTTP) (string, string, error) {
	raw, status, e := n.get(ctx, "/minio/admin/v3/info", url.Values{"metrics": {"false"}})
	if e != nil || status != 200 || minioPermissionUniqueJSON(raw) != nil {
		return "", "", minioPermissionFailure("single-send-real-server")
	}
	var info struct {
		DeploymentID, Region string
		Servers              []struct {
			State, Version string
			CommitID       string `json:"commitID"`
		}
	}
	if json.Unmarshal(raw, &info) != nil || info.DeploymentID == "" || info.Region != n.provider.Region || len(info.Servers) != 1 || info.Servers[0].State != "online" || info.Servers[0].Version != "2025-09-07T16:13:09Z" || info.Servers[0].CommitID != "07c3a429bfed433e49018cb0f78a52145d4bedeb" {
		// Test-only allowlisted diagnostics. Never print raw server info, an
		// endpoint, deployment ID, credentials, disks, pools or configuration.
		diagnostic := struct {
			Region              string                  `json:"region"`
			ServerCount         int                     `json:"server_count"`
			DeploymentIDPresent bool                    `json:"deployment_id_present"`
			Servers             []cOnceSafeServerFields `json:"servers"`
		}{Region: cOnceSafeField(info.Region, 64), ServerCount: len(info.Servers), DeploymentIDPresent: info.DeploymentID != "", Servers: []cOnceSafeServerFields{}}
		for i, server := range info.Servers {
			if i == 4 {
				break
			}
			diagnostic.Servers = append(diagnostic.Servers, cOnceSafeServerFields{cOnceSafeField(server.State, 32), cOnceSafeField(server.Version, 128), cOnceSafeField(server.CommitID, 64)})
		}
		body, _ := json.Marshal(diagnostic)
		return "", "", fmt.Errorf("%w; safe_server_info=%s", minioPermissionFailure("single-send-exact-september"), body)
	}
	return info.DeploymentID, hash(raw), nil
}

type cOnceSafeServerFields struct {
	State   string `json:"state"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

func cOnceSafeField(value string, max int) string {
	if len(value) > max {
		return "<redacted-invalid>"
	}
	for _, ch := range value {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '.' || ch == ':' || ch == '-' || ch == '_') {
			return "<redacted-invalid>"
		}
	}
	return value
}
