package systembackupexecution

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"os"
	"path/filepath"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	installation "clawreef/internal/systembackupinstallationowner"
	"clawreef/internal/systembackupinstallationowner/install"
	ma "clawreef/internal/systembackupminioauthority"
	"golang.org/x/crypto/bcrypt"
	authnv1 "k8s.io/api/authentication/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

type minioSeptemberFirstInstallFixture struct {
	f                                                  *minioTerminalComponent
	model                                              *minioFirstInstallSQL
	owner                                              *install.Installer
	enrollment                                         install.EnrollmentPin
	password                                           []byte
	intentFile, intentSHA, materialsFile, materialsSHA string
}

func septemberFirstInstallPrivateDirectory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	return dir
}
func septemberFirstInstallWrite(t *testing.T, dir, name string, value any) (string, string) {
	t.Helper()
	raw, e := ce.Canonical(value)
	if e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(dir, name)
	if e = os.WriteFile(file, raw, 0600); e != nil {
		t.Fatal(e)
	}
	return file, hash(raw)
}

// Actual original Installer.New -> Enroll -> IssueMinIOSQLInstall, not a
// supplied success result. Only SQL/Kube transports and native API responses
// are controlled models; native TLS and request HMACs execute in real clients.
func newMinioSeptemberFirstInstallFixture(t *testing.T, ctx context.Context, scenario string) *minioSeptemberFirstInstallFixture {
	t.Helper()
	f := newMinioSeptemberTerminalComponent(t, scenario)
	out := &minioSeptemberFirstInstallFixture{f: f, password: []byte("original-first-install-operator-password")}
	t.Cleanup(func() { clear(out.password) })
	stored, e := bcrypt.GenerateFromPassword(out.password, bcrypt.MinCost)
	if e != nil {
		t.Fatal(e)
	}
	auth := &producerComponentSQL{account: f.declaration.Actor.InstallerDatabaseAccount, server: f.grant.ServerUUID, database: f.grant.Database, username: f.grant.Username, stored: string(stored), userID: f.grant.UserID, afterSourceWindow: time.Now().UTC().Add(time.Hour)}
	out.model = &minioFirstInstallSQL{f: f, auth: auth, data: minioFirstInstallData{refs: map[string][]driver.Value{}}}
	db := sql.OpenDB(minioFirstInstallConnector{m: out.model})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	old := f.input.Pin.Enrollment
	target := f.input.Pin.Target
	plan := install.Plan{SchemaVersion: install.PlanVersion, EnrollmentName: old.ConfigMapName, EnrollmentID: old.ID, IssuerID: old.IssuerID, EnrollmentRevision: old.Revision, Target: installation.Target{InstallationID: target.InstallationID, ServerUUID: target.ServerUUID, Database: target.Database, DatabaseAccount: target.ConsumerDatabaseAccount, ClusterID: target.ClusterUID, Namespace: target.Namespace, NamespaceUID: target.NamespaceUID}, InstallerDatabaseAccount: auth.account, LocalAdminUsername: auth.username, OwnerUsername: old.OwnerSubject, OwnerUID: old.OwnerUID, OwnerGroups: []string{"system:authenticated"}, IssuerPublicKeySHA256: hash(f.public), KubernetesAPI: "https://original-kubernetes.invalid", KubernetesCASHA256: hash([]byte("original-kubernetes-ca")), DatabaseCASHA256: hash([]byte("original-database-ca")), DatabaseTLSServerName: "original-database.invalid"}
	f.kube.PrependReactor("create", "selfsubjectreviews", func(ktesting.Action) (bool, kruntime.Object, error) {
		return true, &authnv1.SelfSubjectReview{Status: authnv1.SelfSubjectReviewStatus{UserInfo: authnv1.UserInfo{Username: plan.OwnerUsername, UID: plan.OwnerUID, Groups: append([]string(nil), plan.OwnerGroups...)}}}, nil
	})
	planRaw, e := ce.Canonical(plan)
	if e != nil {
		t.Fatal(e)
	}
	out.owner, e = install.New(db, f.kube, planRaw, hash(planRaw), f.public, hash(f.public))
	if e != nil {
		t.Fatal("actual original Installer.New", e)
	}
	receipt, e := out.owner.Enroll(ctx, out.password)
	if e != nil {
		t.Fatal("actual original Enroll", e)
	}
	out.enrollment = receipt.Pin
	// Replace the helper's synthetic enrollment declarations with ACTUAL
	// original Enroll results. No transport-produced observation is copied into
	// the new SQL records and no fresh deadline is manually constructed.
	enrollment := old
	enrollment.ConfigMapUID = receipt.Pin.ConfigMapUID
	enrollment.DocumentSHA256 = ma.Digest(receipt.Pin.DocumentSHA256)
	enrollment.PlanSHA256 = ma.Digest(hash(planRaw))
	groups, _ := ce.Canonical(plan.OwnerGroups)
	enrollment.OwnerGroupsSHA256 = ma.Digest(hash(groups))
	g := f.declaration
	g.Enrollment = enrollment
	g.References = nil
	for i := range f.refs {
		f.refs[i].Enrollment = enrollment
		raw, e := ma.EncodeSQLReference(f.refs[i])
		if e != nil {
			t.Fatal(e)
		}
		g.References = append(g.References, ma.SQLReferenceHash{Purpose: f.refs[i].Reference.Purpose, SHA256: ma.Digest(hash(raw))})
	}
	set, _ := ce.Canonical(g.References)
	g.ReferenceSetSHA256 = ma.Digest(hash(set))
	grantRaw, e := ma.EncodeSQLGrant(g)
	if e != nil {
		t.Fatal(e)
	}
	f.declaration = g
	f.input.Pin.Enrollment = enrollment
	f.input.Pin.GrantSHA256 = ma.Digest(hash(grantRaw))
	f.input.Pin.ReferenceSetSHA256 = g.ReferenceSetSHA256
	intent := install.MinIOSQLInstallIntent{Version: install.MinIOSQLInstallIntentVersion, Pin: f.input.Pin, Grant: g, References: f.refs}
	dir := septemberFirstInstallPrivateDirectory(t)
	out.intentFile, out.intentSHA = septemberFirstInstallWrite(t, dir, "original-install-intent.json", intent)
	raw, e := out.owner.IssueMinIOSQLInstall(ctx, out.password, out.enrollment, out.intentFile, out.intentSHA, f.key)
	if e != nil {
		t.Fatal("actual original seven-record issuer", e)
	}
	if out.model.execs != 0 || out.model.data.head != nil {
		t.Fatal("original issue inserted SQL metadata")
	}
	bundleDir := septemberFirstInstallPrivateDirectory(t)
	if e = install.SaveMinIOSQLBundle(bundleDir, raw); e != nil {
		t.Fatal(e)
	}
	f.input.BundleFile = filepath.Join(bundleDir, "minio-sql-authority.bundle.json")
	f.input.BundleSHA256 = hash(raw)
	f.bundle, e = ma.DecodeSQLBundle(raw, ma.Digest(hash(raw)))
	if e != nil {
		t.Fatal(e)
	}
	materials := MinIOBootstrapTerminalMaterials{Version: "original-minio-bootstrap-terminal-materials.v1", GrantFile: f.input.GrantFile, GrantSHA256: f.input.GrantSHA256, DefinitionFile: f.input.DefinitionFile, DefinitionSHA256: f.input.DefinitionSHA256, PermissionSource: f.input.PermissionSource, CapabilityIntentFile: f.input.CapabilityIntentFile, CapabilityIntentSHA256: f.input.CapabilityIntentSHA256, ReferenceFiles: f.input.ReferenceFiles, ProvenanceFile: f.input.ProvenanceFile}
	out.materialsFile, out.materialsSHA = septemberFirstInstallWrite(t, dir, "original-terminal-materials.json", materials)
	return out
}

func (f *minioSeptemberFirstInstallFixture) prepare(t *testing.T, ctx context.Context) (MinIOBootstrapTerminalCandidate, error) {
	t.Helper()
	return PrepareOriginalMinIOTerminalInput(ctx, f.owner, f.f.kube, f.password, f.enrollment, f.intentFile, f.intentSHA, f.f.input.BundleFile, f.f.input.BundleSHA256, f.materialsFile, f.materialsSHA, septemberFirstInstallPrivateDirectory(t))
}
