package install

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"database/sql/driver"
	"os"
	"path/filepath"
	"testing"
	"time"

	ma "clawreef/internal/systembackupminioauthority"
	sec "clawreef/internal/systembackupsecurity"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

type minioSQLLifecycleFixture struct {
	base      *authorityFixture
	model     *minioSQLModel
	intent    MinIOSQLInstallIntent
	file, sha string
}

// Actual existing A Installer.New/Enroll/bcrypt/Ed25519 and actual seven-row
// C lifecycle calls, strict SQL/Kubernetes protocol models. The pre-existing
// signed permission source is a scope fixture, NOT native capability evidence.
func newMinioSQLLifecycleFixture(t *testing.T) *minioSQLLifecycleFixture {
	t.Helper()
	base := newAuthorityFixture(t)
	p := base.i.plan
	f := &minioSQLLifecycleFixture{base: base}
	f.model = &minioSQLModel{auth: base.s.auth, data: minioSQLData{refs: map[string][]driver.Value{}}, installation: p.Target.InstallationID, enrollment: p.EnrollmentID, authority: "original-minio-authority", grantID: "original-minio-grant"}
	db := sql.OpenDB(minioSQLConnector{f.model})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	base.i.db = db
	base.i.kube.(*fake.Clientset).PrependReactor("*", "*", func(ktesting.Action) (bool, runtime.Object, error) {
		if f.model.open.Load() != 0 {
			t.Error("Kubernetes I/O inside MinIO SQL transaction")
		}
		return false, nil, nil
	})
	d := func(s string) ma.Digest { return ma.Digest(hash([]byte(s))) }
	groups, _ := canonical(p.OwnerGroups)
	target := ma.Target{InstallationID: p.Target.InstallationID, ServerUUID: p.Target.ServerUUID, Database: p.Target.Database, ConsumerDatabaseAccount: p.Target.DatabaseAccount, ClusterUID: p.Target.ClusterID, Namespace: p.Target.Namespace, NamespaceUID: p.Target.NamespaceUID}
	enrollment := ma.Enrollment{ID: p.EnrollmentID, Revision: p.EnrollmentRevision, ConfigMapName: p.EnrollmentName, ConfigMapUID: base.enrollment.ConfigMapUID, DocumentSHA256: ma.Digest(base.enrollment.DocumentSHA256), PlanSHA256: ma.Digest(base.i.planHash), IssuerID: p.IssuerID, IssuerPublicSHA256: ma.Digest(p.IssuerPublicKeySHA256), OwnerSubject: p.OwnerUsername, OwnerUID: p.OwnerUID, OwnerGroupsSHA256: ma.Digest(hash(groups))}
	obj := func(name string) ma.ObjectIdentity { return ma.ObjectIdentity{Name: name, UID: name + "-uid"} }
	now := time.Now().UTC().Truncate(time.Microsecond)
	g := ma.SQLGrant{Version: ma.SQLGrantVersion, AuthorityID: f.model.authority, GrantID: f.model.grantID, RecordRevision: 1, PermissionEpoch: 1, Target: target, Enrollment: enrollment, Actor: ma.Actor{LocalAdminUserID: 7, LocalAdminUsername: p.LocalAdminUsername, InstallerDatabaseAccount: p.InstallerDatabaseAccount}, ConfigSHA256: ma.Digest(base.config.SHA256()), BootstrapGrantSHA256: ma.Digest(base.files.GrantFileSHA256), Provider: ma.Provider{IdentityHash: d("provider"), IdentityProfile: "original-provider.v1", Endpoint: "https://minio.original.invalid", Region: "us-east-1", DeploymentID: "original-deployment", CASHA256: d("ca"), SPKISHA256: d("spki"), ServerVersion: "2025-04-22T22:12:26Z", ServerCommit: "0d7408fc9969caf07de6a8c3a84f9fbb10a6739e", ImageProvenanceSHA256: d("image-provenance"), Deployment: obj("minio"), ReplicaSet: obj("minio-rs"), Pod: obj("minio-pod"), Service: obj("minio-service"), ServiceAccount: obj("minio-sa"), Container: "minio", ImageID: "sha256:original-image", Node: "original-node", NodeUID: "original-node-uid"}, PermissionSource: ma.PermissionSource{Profile: ma.PermissionProfile, Grant: obj("original-permission-grant"), Head: obj("original-permission-head"), ObserverAccountSHA256: d("observer-account"), ObserverCredentialFileSHA256: d("observer-credential-file"), ObserverLocatorSHA256: d("observer-locator"), ObserverPolicyName: "original-observer", ObserverNormalizedPolicySHA256: d("observer-policy")}, Observation: ma.ObservationBinding{Profile: ma.NativeObservationProfile, DefinitionSHA256: d("native-definition"), CapabilityIntentSHA256: d("original-capability-intent"), MaximumAgeMicroseconds: ma.MaximumObservationAgeMicroseconds}, NotBefore: now.Add(-time.Minute), Until: now.Add(time.Minute)}
	originalRefs := map[string]sec.BootstrapSecretRef{}
	for _, r := range base.config.References() {
		originalRefs[r.Purpose] = r
	}
	var refs []ma.SQLReferenceRecord
	for _, purpose := range minioSQLPurposes() {
		original := originalRefs[string(purpose)]
		r := ma.Reference{Purpose: purpose, IdentityHash: ma.Digest(original.IdentityHash), IdentityVersion: original.Version, DescriptorSHA256: d("descriptor-" + string(purpose)), IdentityProfile: "original-reference.v1", ProviderIdentityHash: g.Provider.IdentityHash, ScopeSHA256: d("scope-" + string(purpose)), ScopeProfile: "original-scope.v1", AccountSHA256: d("account-" + string(purpose)), CredentialFileSHA256: d("credential-" + string(purpose)), CredentialLocatorSHA256: d("locator-" + string(purpose)), PolicyName: string(purpose), NormalizedPolicySHA256: d("policy-" + string(purpose)), Bucket: "original-artifacts", Root: target.InstallationID + "/", StagingRoot: target.InstallationID + "_staging/", CapabilityProfile: "original-protocol.v1", CapabilityIntentSHA256: g.Observation.CapabilityIntentSHA256, NotBefore: now.Add(-2 * time.Minute), Until: now.Add(5 * time.Minute), ProtectedUntil: now.Add(10 * time.Minute)}
		switch purpose {
		case ma.ArtifactRead:
			r.Capability = "exact_read"
		case ma.ArtifactWrite:
			r.Capability = "conditional_create"
		case ma.ArtifactDelete:
			r.Capability = "exact_delete"
		case ma.CatalogRead:
			r.Capability = "exact_read"
		case ma.CatalogAppend:
			r.Capability = "append_record"
		}
		if purpose == ma.CatalogRead || purpose == ma.CatalogAppend {
			r.Bucket = "original-catalog"
			r.Root = target.InstallationID + "/catalog/"
			r.StagingRoot = ""
		}
		record := ma.SQLReferenceRecord{Version: ma.SQLReferenceVersion, AuthorityID: g.AuthorityID, GrantID: g.GrantID, RecordRevision: 1, PermissionEpoch: 1, Target: target, Enrollment: enrollment, ConfigSHA256: g.ConfigSHA256, Reference: r}
		raw, e := ma.EncodeSQLReference(record)
		if e != nil {
			t.Fatal(e)
		}
		refs = append(refs, record)
		g.References = append(g.References, ma.SQLReferenceHash{Purpose: purpose, SHA256: ma.Digest(hash(raw))})
	}
	set, _ := canonical(g.References)
	g.ReferenceSetSHA256 = ma.Digest(hash(set))
	provider := g.Provider
	convert := func(o ma.ObjectIdentity) MinIOPermissionObject {
		return MinIOPermissionObject{Name: o.Name, UID: o.UID}
	}
	permission := MinIOPermissionGrant{Version: "minio-permission-grant.v1", Installation: target.InstallationID, Namespace: target.Namespace, NamespaceUID: target.NamespaceUID, ConfigSHA256: string(g.ConfigSHA256), Profile: MinIOPermissionProfileV2, Epoch: 1, NotBefore: now.Add(-2 * time.Minute), Until: now.Add(2 * time.Minute), Provider: MinIOPermissionProvider{Endpoint: provider.Endpoint, Region: provider.Region, CASHA256: string(provider.CASHA256), SPKISHA256: string(provider.SPKISHA256), DeploymentID: provider.DeploymentID, Deployment: convert(provider.Deployment), ReplicaSet: convert(provider.ReplicaSet), Pod: convert(provider.Pod), Service: convert(provider.Service), ServiceAccount: convert(provider.ServiceAccount), Container: provider.Container, ImageID: provider.ImageID, Node: provider.Node, NodeUID: provider.NodeUID}}
	for _, v := range refs {
		r := v.Reference
		permission.Principals = append(permission.Principals, MinIOPermissionPrincipal{Purpose: string(r.Purpose), IdentityHash: string(r.IdentityHash), RefVersion: r.IdentityVersion, AccountSHA256: string(r.AccountSHA256), PolicyName: r.PolicyName, PolicySHA256: string(r.NormalizedPolicySHA256)})
	}
	permissionRaw, _ := canonical(permission)
	g.PermissionSource.GrantSHA256 = ma.Digest(hash(permissionRaw))
	head := MinIOPermissionHead{Version: "minio-permission-head.v1", Installation: target.InstallationID, State: "active", GrantSHA256: hash(permissionRaw), Epoch: 1, NotBefore: permission.NotBefore, Until: permission.Until}
	headRaw, _ := canonical(head)
	g.PermissionSource.InitialHeadSHA256 = ma.Digest(hash(headRaw))
	client := base.i.kube.(*fake.Clientset)
	for _, v := range []struct {
		ref    ma.ObjectIdentity
		raw    []byte
		domain string
	}{{g.PermissionSource.Grant, permissionRaw, minioGrantDomain}, {g.PermissionSource.Head, headRaw, minioHeadDomain}} {
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: v.ref.Name, Namespace: target.Namespace, UID: types.UID(v.ref.UID), ResourceVersion: "original-1"}, Data: map[string]string{"record.json": string(v.raw)}, BinaryData: map[string][]byte{"signature": ed25519.Sign(base.key, append([]byte(v.domain), v.raw...))}}
		if e := client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("configmaps"), cm, target.Namespace); e != nil {
			t.Fatal(e)
		}
	}
	grantRaw, e := ma.EncodeSQLGrant(g)
	if e != nil {
		t.Fatal(e)
	}
	pin := ma.SQLTrustPin{Target: target, Enrollment: enrollment, AuthorityID: g.AuthorityID, GrantID: g.GrantID, GrantRevision: 1, MinimumHeadRevision: 1, MinimumPermissionEpoch: 1, GrantSHA256: ma.Digest(hash(grantRaw)), ReferenceSetSHA256: g.ReferenceSetSHA256, IssuerPublic: append([]byte(nil), base.i.public...)}
	f.intent = MinIOSQLInstallIntent{Version: MinIOSQLInstallIntentVersion, Pin: pin, Grant: g, References: refs}
	raw, e := canonical(f.intent)
	if e != nil {
		t.Fatal(e)
	}
	f.file = filepath.Join(t.TempDir(), "original-minio-intent.json")
	f.sha = hash(raw)
	if e = os.WriteFile(f.file, raw, 0600); e != nil {
		t.Fatal(e)
	}
	return f
}

func (f *minioSQLLifecycleFixture) issue(t *testing.T, ctx context.Context) []byte {
	t.Helper()
	raw, e := f.base.i.IssueMinIOSQLInstall(ctx, f.base.password, f.base.enrollment, f.file, f.sha, f.base.key)
	if e != nil {
		t.Fatal("actual original operator issue", e)
	}
	return raw
}
