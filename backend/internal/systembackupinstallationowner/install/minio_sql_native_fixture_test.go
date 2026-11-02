//go:build systembackup_mysql

package install

import (
	owner "clawreef/internal/systembackupinstallationowner"
	ma "clawreef/internal/systembackupminioauthority"
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"crypto/ed25519"
	"database/sql"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type nativeMinioSQLFixture struct {
	n                *nativeAuthorityFixture
	f                *minioSQLLifecycleFixture
	captureDirectory string
}

// Reuses actual independent-UUID SAN/TLS random-owned schema/limited accounts.
// No strict SQL model is constructed. Real migration134/users remain intact.
func newNativeMinioSQLFixture(t *testing.T, ctx context.Context) *nativeMinioSQLFixture {
	t.Helper()
	n := newNativeAuthorityFixture(t, ctx)
	applyNativeMinio135(t, ctx, n.root)
	for _, entry := range []struct{ account, rights string }{{n.f.i.plan.InstallerDatabaseAccount, "SELECT,INSERT,UPDATE"}, {n.f.i.plan.Target.DatabaseAccount, "SELECT"}} {
		parts := strings.Split(entry.account, "@")
		if len(parts) != 2 || parts[1] != "127.0.0.1" || !strings.HasPrefix(parts[0], "a_oi_") && !strings.HasPrefix(parts[0], "a_oc_") {
			t.Fatal("actual owned limited account scope")
		}
		for _, c := range parts[0] {
			if c != '_' && !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') {
				t.Fatal("owned account identifier")
			}
		}
		for _, table := range []string{"system_backup_minio_owner_heads", "system_backup_minio_owner_grants", "system_backup_minio_owner_refs"} {
			if _, e := n.root.ExecContext(ctx, "GRANT "+entry.rights+" ON `"+n.database+"`."+table+" TO '"+parts[0]+"'@'127.0.0.1'"); e != nil {
				t.Fatal("exact owned MinIO control-table grants", e)
			}
		}
	}
	requireNativeAuthorityTLS(t, ctx, n.installer)
	requireNativeAuthorityTLS(t, ctx, n.consumer)
	capture := nativeAuthorityIssue(t, ctx, n, "native-minio-prefix")
	if _, e := n.f.i.ImportCapture(ctx, n.f.password, n.f.enrollment, capture, hash(capture), n.f.files); e != nil {
		t.Fatal("real migration134 original capture source", e)
	}
	directory := t.TempDir()
	if e := os.Chmod(directory, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e := n.f.i.ExportCommitted(ctx, n.f.password, n.f.enrollment, capture, hash(capture), directory); e != nil {
		t.Fatal("actual original capture prefix export", e)
	}
	f := newNativeMinioSQLIntent(t, n.f)
	if f.model != nil || f.base.i.db != n.installer {
		t.Fatal("native lifecycle replaced by model")
	}
	return &nativeMinioSQLFixture{n: n, f: f, captureDirectory: directory}
}
func applyNativeMinio135(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	raw, e := os.ReadFile("../../db/migrations/135_backup_v2_minio_owner_authority.sql")
	if e != nil || hash(raw) != "b37bc2d94a2b508b36173b09cc00345200d6b0a5a787abb5ef7d0ee6f50d5583" {
		t.Fatal("actual frozen migration135 bytes", e)
	}
	var lines []string
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			lines = append(lines, line)
		}
	}
	count := 0
	for _, statement := range strings.Split(strings.Join(lines, "\n"), ";") {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}
		if !strings.HasPrefix(statement, "CREATE TABLE system_backup_minio_owner_") {
			t.Fatal("unexpected migration135 operation")
		}
		if _, e := db.ExecContext(ctx, statement); e != nil {
			t.Fatal("actual migration135", e)
		}
		count++
	}
	if count != 3 {
		t.Fatal("migration135 must contain exactly three original tables")
	}
}

// Original public metadata declaration only; all authority/lifecycle SQL is
// exclusively the actual limited SAN/TLS installer, never a strict model.
func newNativeMinioSQLIntent(t *testing.T, base *authorityFixture) *minioSQLLifecycleFixture {
	t.Helper()
	f := &minioSQLLifecycleFixture{base: base}
	p := base.i.plan
	d := func(s string) ma.Digest { return ma.Digest(hash([]byte(s))) }
	groups, _ := canonical(p.OwnerGroups)
	target := ma.Target{InstallationID: p.Target.InstallationID, ServerUUID: p.Target.ServerUUID, Database: p.Target.Database, ConsumerDatabaseAccount: p.Target.DatabaseAccount, ClusterUID: p.Target.ClusterID, Namespace: p.Target.Namespace, NamespaceUID: p.Target.NamespaceUID}
	enrollment := ma.Enrollment{ID: p.EnrollmentID, Revision: p.EnrollmentRevision, ConfigMapName: p.EnrollmentName, ConfigMapUID: base.enrollment.ConfigMapUID, DocumentSHA256: ma.Digest(base.enrollment.DocumentSHA256), PlanSHA256: ma.Digest(base.i.planHash), IssuerID: p.IssuerID, IssuerPublicSHA256: ma.Digest(p.IssuerPublicKeySHA256), OwnerSubject: p.OwnerUsername, OwnerUID: p.OwnerUID, OwnerGroupsSHA256: ma.Digest(hash(groups))}
	obj := func(name string) ma.ObjectIdentity { return ma.ObjectIdentity{Name: name, UID: name + "-uid"} }
	now := time.Now().UTC().Truncate(time.Microsecond)
	g := ma.SQLGrant{Version: ma.SQLGrantVersion, AuthorityID: "native-minio-authority", GrantID: "native-minio-grant", RecordRevision: 1, PermissionEpoch: 1, Target: target, Enrollment: enrollment, Actor: ma.Actor{LocalAdminUserID: 7, LocalAdminUsername: p.LocalAdminUsername, InstallerDatabaseAccount: p.InstallerDatabaseAccount}, ConfigSHA256: ma.Digest(base.config.SHA256()), BootstrapGrantSHA256: ma.Digest(base.files.GrantFileSHA256), Provider: ma.Provider{IdentityHash: d("provider"), IdentityProfile: "original-provider.v1", Endpoint: "https://minio.original.invalid", Region: "us-east-1", DeploymentID: "original-deployment", CASHA256: d("ca"), SPKISHA256: d("spki"), ServerVersion: "2025-04-22T22:12:26Z", ServerCommit: "0d7408fc9969caf07de6a8c3a84f9fbb10a6739e", ImageProvenanceSHA256: d("image-provenance"), Deployment: obj("minio"), ReplicaSet: obj("minio-rs"), Pod: obj("minio-pod"), Service: obj("minio-service"), ServiceAccount: obj("minio-sa"), Container: "minio", ImageID: "sha256:original-image", Node: "original-node", NodeUID: "original-node-uid"}, PermissionSource: ma.PermissionSource{Profile: ma.PermissionProfile, Grant: obj("original-permission-grant"), Head: obj("original-permission-head"), ObserverAccountSHA256: d("observer-account"), ObserverCredentialFileSHA256: d("observer-credential-file"), ObserverLocatorSHA256: d("observer-locator"), ObserverPolicyName: "original-observer", ObserverNormalizedPolicySHA256: d("observer-policy")}, Observation: ma.ObservationBinding{Profile: ma.NativeObservationProfile, DefinitionSHA256: d("native-definition"), CapabilityIntentSHA256: d("original-capability-intent"), MaximumAgeMicroseconds: ma.MaximumObservationAgeMicroseconds}, NotBefore: now.Add(-time.Minute), Until: now.Add(5 * time.Minute)}
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
	permission := MinIOPermissionGrant{Version: "minio-permission-grant.v1", Installation: target.InstallationID, Namespace: target.Namespace, NamespaceUID: target.NamespaceUID, ConfigSHA256: string(g.ConfigSHA256), Profile: MinIOPermissionProfileV2, Epoch: 1, NotBefore: now.Add(-2 * time.Minute), Until: now.Add(10 * time.Minute), Provider: MinIOPermissionProvider{Endpoint: provider.Endpoint, Region: provider.Region, CASHA256: string(provider.CASHA256), SPKISHA256: string(provider.SPKISHA256), DeploymentID: provider.DeploymentID, Deployment: convert(provider.Deployment), ReplicaSet: convert(provider.ReplicaSet), Pod: convert(provider.Pod), Service: convert(provider.Service), ServiceAccount: convert(provider.ServiceAccount), Container: provider.Container, ImageID: provider.ImageID, Node: provider.Node, NodeUID: provider.NodeUID}}
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

func nativeMinioConsumer(t *testing.T, ctx context.Context, f *nativeMinioSQLFixture, readMinio bool) *sql.Tx {
	t.Helper()
	raw, e := ReadPrivateFile(filepath.Join(f.captureDirectory, "owner.pin.json"), 262144)
	var pin owner.TrustPin
	if e != nil || decodeExact(raw, &pin) != nil {
		t.Fatal("real original capture pin", e)
	}
	validator, e := owner.NewCaptureSigningIdentityOnlyValidator(pin, RecordFilesAt(f.captureDirectory))
	if e != nil {
		t.Fatal(e)
	}
	check, e := validator.Prepare(ctx, f.n.f.grant, f.n.f.config)
	if e != nil {
		t.Fatal(e)
	}
	original, ok := check.(*owner.PreparedCaptureSigning)
	if !ok {
		t.Fatal("actual concrete original capture identity")
	}
	tx, e := f.n.consumer.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	var username, role, provider string
	var active bool
	if tx.QueryRowContext(ctx, "SELECT username,role,is_active,auth_provider FROM users WHERE id=7 FOR SHARE").Scan(&username, &role, &active, &provider) != nil || username != f.n.f.i.plan.LocalAdminUsername || role != "admin" || !active || provider != "local" {
		t.Fatal("real current admin prefix")
	}
	guard, e := original.AuthorizeOriginal(ctx, tx, f.n.f.grant, f.n.f.config)
	if e != nil || guard.RecheckOriginalIdentity(ctx, tx) != nil {
		t.Fatal("real migration134 capture owner prefix", e)
	}
	if readMinio {
		snapshot, e := ma.ReadSQLCurrent(ctx, tx, f.f.intent.Pin)
		if e != nil {
			t.Fatal("real SELECT-only seven-row shared source", e)
		}
		_, now, e := snapshot.Comparison()
		if e != nil || snapshot.RequireCurrent(now) != nil {
			t.Fatal("real original SQL identity window", e)
		}
	}
	return tx
}
func nativeMinioCounts(t *testing.T, ctx context.Context, f *nativeMinioSQLFixture, wantHead, wantGrant, wantRefs int) {
	t.Helper()
	for _, entry := range []struct {
		table string
		want  int
	}{{"system_backup_minio_owner_heads", wantHead}, {"system_backup_minio_owner_grants", wantGrant}, {"system_backup_minio_owner_refs", wantRefs}} {
		var count int
		if f.n.root.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+entry.table).Scan(&count) != nil || count != entry.want {
			t.Fatal("actual original row count", entry.table, count)
		}
	}
	var capture, users int
	if f.n.root.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_backup_installation_owner_heads").Scan(&capture) != nil || capture != 1 || f.n.root.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE id=7").Scan(&users) != nil || users != 1 {
		t.Fatal("real migration134/users prefix was replaced or lost")
	}
}
