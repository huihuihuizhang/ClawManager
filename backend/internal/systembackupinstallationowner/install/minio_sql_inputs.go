package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"reflect"
	"time"

	ma "clawreef/internal/systembackupminioauthority"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const MinIOSQLInstallIntentVersion = "original-minio-sql-install-intent.v1"

// This is original scope authorization, not caller permission evidence. Real
// native permission/protocol Prepare remains mandatory before fresh use.
type MinIOSQLInstallIntent struct {
	Version    string
	Pin        ma.SQLTrustPin
	Grant      ma.SQLGrant
	References []ma.SQLReferenceRecord
}

func (s *authenticatedOperator) minioSQLPin(ctx context.Context, enrollment EnrollmentPin, p ma.SQLTrustPin) error {
	if s == nil || !s.live(ctx) || s.authority(ctx, enrollment) != nil {
		return ErrInstall
	}
	i := s.installer
	plan := i.plan
	t := ma.Target{InstallationID: plan.Target.InstallationID, ServerUUID: plan.Target.ServerUUID, Database: plan.Target.Database, ConsumerDatabaseAccount: plan.Target.DatabaseAccount, ClusterUID: plan.Target.ClusterID, Namespace: plan.Target.Namespace, NamespaceUID: plan.Target.NamespaceUID}
	groups, e := canonical(plan.OwnerGroups)
	if e != nil {
		return ErrInstall
	}
	want := ma.Enrollment{ID: plan.EnrollmentID, Revision: plan.EnrollmentRevision, ConfigMapName: plan.EnrollmentName, ConfigMapUID: enrollment.ConfigMapUID, DocumentSHA256: ma.Digest(enrollment.DocumentSHA256), PlanSHA256: ma.Digest(i.planHash), IssuerID: plan.IssuerID, IssuerPublicSHA256: ma.Digest(plan.IssuerPublicKeySHA256), OwnerSubject: plan.OwnerUsername, OwnerUID: plan.OwnerUID, OwnerGroupsSHA256: ma.Digest(hash(groups))}
	if p.Target != t || p.Enrollment != want || !bytes.Equal(p.IssuerPublic, i.public) {
		return ErrInstall
	}
	return nil
}

func minioSQLActor(s *authenticatedOperator, g ma.SQLGrant) bool {
	return s != nil && g.Actor.LocalAdminUserID == s.userID && g.Actor.LocalAdminUsername == s.installer.plan.LocalAdminUsername && g.Actor.InstallerDatabaseAccount == s.installer.plan.InstallerDatabaseAccount
}

func minioSQLPurposes() []ma.Purpose {
	return []ma.Purpose{ma.ArtifactDelete, ma.ArtifactRead, ma.ArtifactWrite, ma.CatalogAppend, ma.CatalogRead}
}

// Read the actual original Kubernetes permission source outside SQL locks.
// This authenticates the bound source declaration, not native operation
// capability. SQL authority installation never substitutes for native Prepare.
func (s *authenticatedOperator) minioSQLKubernetes(ctx context.Context, g ma.SQLGrant, refs []ma.SQLReferenceRecord, now time.Time) error {
	if !s.live(ctx) || len(refs) != 5 {
		return ErrInstall
	}
	p := g.PermissionSource
	k := s.installer.kube
	namespace := g.Target.Namespace
	read := func(ref ma.ObjectIdentity, domain string, out any, expected ma.Digest) error {
		cm, e := k.CoreV1().ConfigMaps(namespace).Get(ctx, ref.Name, metav1.GetOptions{})
		if e != nil || cm == nil || string(cm.UID) != ref.UID || cm.Namespace != namespace || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil || len(cm.Data) != 1 || len(cm.BinaryData) != 1 {
			return ErrInstall
		}
		raw := []byte(cm.Data["record.json"])
		if len(raw) > 32768 || ma.Digest(hash(raw)) != expected || decodeExact(raw, out) != nil || !ed25519.Verify(s.installer.public, append([]byte(domain), raw...), cm.BinaryData["signature"]) {
			return ErrInstall
		}
		return nil
	}
	var original MinIOPermissionGrant
	var head MinIOPermissionHead
	if read(p.Grant, minioGrantDomain, &original, p.GrantSHA256) != nil || read(p.Head, minioHeadDomain, &head, p.InitialHeadSHA256) != nil {
		return ErrInstall
	}
	if original.Version != "minio-permission-grant.v1" || original.Installation != g.Target.InstallationID || original.Namespace != namespace || original.NamespaceUID != g.Target.NamespaceUID || original.ConfigSHA256 != string(g.ConfigSHA256) || original.Profile != MinIOPermissionProfileV2 || original.Epoch != g.PermissionEpoch || head.Version != "minio-permission-head.v1" || head.Installation != g.Target.InstallationID || head.State != "active" || head.Epoch != original.Epoch || head.GrantSHA256 != string(p.GrantSHA256) || head.EngineSHA256 != "" || len(original.Principals) != 5 {
		return ErrInstall
	}
	for _, w := range [][2]time.Time{{original.NotBefore, original.Until}, {head.NotBefore, head.Until}} {
		if now.Before(w[0]) || !now.Before(w[1]) || g.NotBefore.Before(w[0]) || g.Until.After(w[1]) {
			return ErrInstall
		}
	}
	provider := original.Provider
	want := g.Provider
	if provider.Endpoint != want.Endpoint || provider.Region != want.Region || provider.DeploymentID != want.DeploymentID || provider.CASHA256 != string(want.CASHA256) || provider.SPKISHA256 != string(want.SPKISHA256) || provider.Container != want.Container || provider.ImageID != want.ImageID || provider.Node != want.Node || provider.NodeUID != want.NodeUID {
		return ErrInstall
	}
	for _, v := range []struct {
		original MinIOPermissionObject
		want     ma.ObjectIdentity
	}{{provider.Deployment, want.Deployment}, {provider.ReplicaSet, want.ReplicaSet}, {provider.Pod, want.Pod}, {provider.Service, want.Service}, {provider.ServiceAccount, want.ServiceAccount}} {
		if v.original.Name != v.want.Name || v.original.UID != v.want.UID {
			return ErrInstall
		}
	}
	byPurpose := map[string]MinIOPermissionPrincipal{}
	for _, v := range original.Principals {
		if byPurpose[v.Purpose].Purpose != "" {
			return ErrInstall
		}
		byPurpose[v.Purpose] = v
	}
	for _, r := range refs {
		v := r.Reference
		original := byPurpose[string(v.Purpose)]
		if original.Purpose != string(v.Purpose) || original.IdentityHash != string(v.IdentityHash) || original.RefVersion != v.IdentityVersion || original.AccountSHA256 != string(v.AccountSHA256) || original.PolicyName != v.PolicyName || original.PolicySHA256 != string(v.NormalizedPolicySHA256) {
			return ErrInstall
		}
	}
	return nil
}

func minioSQLRead(ctx context.Context, s *authenticatedOperator, p ma.SQLTrustPin) (*ma.SQLCurrentSnapshot, bool, error) {
	tx, e := s.installer.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return nil, false, ErrInstall
	}
	defer tx.Rollback()
	if _, e = s.lockAdmin(ctx, tx); e != nil {
		return nil, false, ErrInstall
	}
	absent, e := minioSQLLock(ctx, tx, p, false)
	if e != nil {
		return nil, false, e
	}
	if absent {
		return nil, true, nil
	}
	snapshot, e := ma.ReadSQLCurrentForInstaller(ctx, tx, p)
	if e != nil {
		return nil, false, ErrInstall
	}
	return snapshot, false, nil
}

// Private owner-store lock selector; no consumer route uses the write branch.
// All five exact ref keys are acquired in fixed purpose order, not optimizer
// multi-row/ENUM ordering. Admin prefix is already held by lockAdmin.
func minioSQLLock(ctx context.Context, tx *sql.Tx, p ma.SQLTrustPin, write bool) (bool, error) {
	var query string
	if write {
		query = `SELECT current_grant_id,current_grant_revision,permission_epoch,row_version FROM system_backup_minio_owner_heads WHERE installation_id=? AND enrollment_id=? AND authority_id=? FOR UPDATE`
	} else {
		query = `SELECT current_grant_id,current_grant_revision,permission_epoch,row_version FROM system_backup_minio_owner_heads WHERE installation_id=? AND enrollment_id=? AND authority_id=? FOR SHARE`
	}
	var id string
	var revision, epoch, row uint64
	e := tx.QueryRowContext(ctx, query, p.Target.InstallationID, p.Enrollment.ID, p.AuthorityID).Scan(&id, &revision, &epoch, &row)
	if errors.Is(e, sql.ErrNoRows) {
		return true, nil
	}
	if e != nil || id != p.GrantID || revision != p.GrantRevision || epoch != 1 || row == 0 {
		return false, ErrInstall
	}
	if write {
		query = `SELECT row_version FROM system_backup_minio_owner_grants WHERE installation_id=? AND enrollment_id=? AND authority_id=? AND grant_id=? AND record_revision=? FOR UPDATE`
	} else {
		query = `SELECT row_version FROM system_backup_minio_owner_grants WHERE installation_id=? AND enrollment_id=? AND authority_id=? AND grant_id=? AND record_revision=? FOR SHARE`
	}
	if tx.QueryRowContext(ctx, query, p.Target.InstallationID, p.Enrollment.ID, p.AuthorityID, id, revision).Scan(&row) != nil || row == 0 {
		return false, ErrInstall
	}
	if write {
		query = `SELECT row_version FROM system_backup_minio_owner_refs WHERE installation_id=? AND enrollment_id=? AND authority_id=? AND grant_id=? AND record_revision=? AND purpose=? FOR UPDATE`
	} else {
		query = `SELECT row_version FROM system_backup_minio_owner_refs WHERE installation_id=? AND enrollment_id=? AND authority_id=? AND grant_id=? AND record_revision=? AND purpose=? FOR SHARE`
	}
	for _, purpose := range minioSQLPurposes() {
		if tx.QueryRowContext(ctx, query, p.Target.InstallationID, p.Enrollment.ID, p.AuthorityID, id, revision, string(purpose)).Scan(&row) != nil || row == 0 {
			return false, ErrInstall
		}
	}
	return false, nil
}

func minioSQLBundle(ctx context.Context, s *authenticatedOperator, enrollment EnrollmentPin, p ma.SQLTrustPin, raw []byte, sha string) (ma.SQLBundle, ma.SQLGrant, ma.SQLHead, []ma.SQLReferenceRecord, error) {
	var zero ma.SQLBundle
	if s.minioSQLPin(ctx, enrollment, p) != nil {
		return zero, ma.SQLGrant{}, ma.SQLHead{}, nil, ErrInstall
	}
	b, e := ma.DecodeSQLBundle(raw, ma.Digest(sha))
	if e != nil || b.PlanSHA256 != ma.Digest(s.installer.planHash) || b.EnrollmentDocumentSHA256 != ma.Digest(enrollment.DocumentSHA256) {
		return zero, ma.SQLGrant{}, ma.SQLHead{}, nil, ErrInstall
	}
	set, e := ma.VerifySQLRecordSet(p, b.Grant, b.GrantSignature, b.Head, b.HeadSignature, b.References)
	if e != nil {
		return zero, ma.SQLGrant{}, ma.SQLHead{}, nil, ErrInstall
	}
	g, h, refs, e := set.Detached()
	if e != nil || !minioSQLActor(s, g) {
		return zero, ma.SQLGrant{}, ma.SQLHead{}, nil, ErrInstall
	}
	if b.Action == ma.SQLActionInstall && (h.State != ma.StateActive || h.HeadRevision != 1) || b.Action == ma.SQLActionRevoke && (h.State != ma.StateRevoked || h.HeadRevision != 2 || b.Expected.GrantSHA256 != p.GrantSHA256 || b.Expected.ReferenceSetSHA256 != p.ReferenceSetSHA256 || b.Expected.CurrentGrantID != g.GrantID || b.Expected.CurrentGrantRevision != g.RecordRevision) {
		return zero, ma.SQLGrant{}, ma.SQLHead{}, nil, ErrInstall
	}
	return b, g, h, refs, nil
}

func minioSQLResultExpected(b ma.SQLBundle, h ma.SQLHead) ma.SQLExpected {
	e := b.Expected
	if b.Action == ma.SQLActionInstall {
		e = ma.SQLExpected{HeadRowVersion: 1, GrantRowVersion: 1, ReferenceRows: []ma.SQLReferenceCAS{}}
		for _, v := range b.References {
			e.ReferenceRows = append(e.ReferenceRows, ma.SQLReferenceCAS{Purpose: v.Purpose, SHA256: ma.Digest(hash(v.Record)), RowVersion: 1})
		}
	} else {
		e.HeadRowVersion++
		e.GrantRowVersion++
		e.ReferenceRows = append([]ma.SQLReferenceCAS(nil), e.ReferenceRows...)
		for n := range e.ReferenceRows {
			e.ReferenceRows[n].RowVersion++
		}
	}
	e.HeadRevision = h.HeadRevision
	e.PermissionEpoch = h.PermissionEpoch
	e.CurrentGrantID = h.CurrentGrantID
	e.CurrentGrantRevision = h.CurrentGrantRevision
	e.HeadSHA256 = ma.Digest(hash(b.Head))
	e.GrantSHA256 = h.GrantSHA256
	e.ReferenceSetSHA256 = h.ReferenceSetSHA256
	e.State = h.State
	return e
}

func minioSQLExact(snapshot *ma.SQLCurrentSnapshot, b ma.SQLBundle, h ma.SQLHead) bool {
	e, _, err := snapshot.Comparison()
	if err != nil || !reflect.DeepEqual(e, minioSQLResultExpected(b, h)) {
		return false
	}
	g, gs, head, hs, refs, err := snapshot.SignedRecords()
	return err == nil && bytes.Equal(g, b.Grant) && bytes.Equal(gs, b.GrantSignature) && bytes.Equal(head, b.Head) && bytes.Equal(hs, b.HeadSignature) && reflect.DeepEqual(refs, b.References)
}
