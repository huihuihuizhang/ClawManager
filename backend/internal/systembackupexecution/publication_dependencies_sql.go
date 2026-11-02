package systembackupexecution

import (
	"context"
	"database/sql"
	"reflect"
	"time"

	a "clawreef/internal/systembackupkekadapter"
	kms "clawreef/internal/systembackupkms"
	security "clawreef/internal/systembackupsecurity"
)

type publicationDependencyIdentity struct {
	account, server, database, configSHA string
	version                              uint64
}

type publicationDependencySQL struct {
	now      time.Time
	identity publicationDependencyIdentity
	window   publicationDependencyWindow
}

func (s *DeploymentService) dependencyPublisherGrant(ctx context.Context) (security.PublisherCaptureGrant, error) {
	g, p := s.Forward.DeploymentBinding(), s.publisherVerifier
	if p == nil {
		return security.PublisherCaptureGrant{}, publicationDependencyFailure("publisher-grant-source", nil)
	}
	w := p.Workload
	return security.CheckPublisherCaptureDeploymentGrant(ctx, security.PublisherCaptureAuthorityConfig{
		DB:         s.publisherVerifierDB,
		Deployment: security.PublisherCaptureDeployment{InstallationID: g.InstallationID, ServerUUID: g.ServerUUID, Database: g.Database, DatabaseAccount: g.DatabaseAccount, ControllerOwner: g.ControllerOwner, ConfigVersion: g.ConfigVersion, ConfigSHA256: g.ConfigSHA256, ProfileSHA256: g.ProfileSHA256, DeploymentConfigSHA256: g.DeploymentConfigSHA256, CaptureGrantSHA256: s.Forward.GrantSHA256(), NotBefore: g.NotBefore, Until: g.ExpiresAt},
		Workload:   security.PublisherCaptureWorkload{Namespace: w.Namespace, NamespaceUID: p.KubernetesReads.NamespaceUID, PodName: w.PodName, PodUID: w.PodUID, ServiceAccountName: w.ServiceAccountName, ServiceAccountUID: w.ServiceAccountUID, PublisherOwner: w.ControllerOwner, GrantSHA256: w.GrantSHA256}, GrantMount: p.Grant,
	})
}

// No task table or task-shaped comparison facts are used by this read. Expected
// identities come only from the independently authenticated deployment/config.
func (s *DeploymentService) readPublicationDependencySQL(ctx context.Context, target *PublicationTargetMaterials, catalog *PublicationCatalogMaterials) (publicationDependencySQL, error) {
	var out publicationDependencySQL
	fail := func(stage string, err error) (publicationDependencySQL, error) {
		return publicationDependencySQL{}, publicationDependencyFailure(stage, err)
	}
	g := s.Forward.DeploymentBinding()
	tx, err := s.publisherVerifierDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return fail("current-sql-view", err)
	}
	defer tx.Rollback()
	i := &out.identity
	if tx.QueryRowContext(ctx, `SELECT CURRENT_USER(),@@server_uuid,DATABASE(),UTC_TIMESTAMP(6)`).Scan(&i.account, &i.server, &i.database, &out.now) != nil || i.account != g.DatabaseAccount || i.server != g.ServerUUID || i.database != g.Database {
		return fail("current-sql-identity", nil)
	}
	if err = out.window.include(out.now, g.NotBefore, g.ExpiresAt); err != nil {
		return fail("original-forward-window", err)
	}
	var raw []byte
	var size int64
	if tx.QueryRowContext(ctx, `SELECT cfg.version,cfg.config_sha256,cfg.canonical_config_json,cfg.config_size_bytes FROM system_backup_v2_configs cfg JOIN system_backup_v2_installation_state st ON st.origin_installation_id=cfg.origin_installation_id AND st.active_config_version=cfg.version WHERE cfg.origin_installation_id=? AND cfg.version=? AND cfg.config_sha256=? AND cfg.enabled=TRUE AND st.last_effective_enabled=TRUE FOR SHARE`, g.InstallationID, g.ConfigVersion, g.ConfigSHA256).Scan(&i.version, &i.configSHA, &raw, &size) != nil || i.version != g.ConfigVersion || i.configSHA != g.ConfigSHA256 || int64(len(raw)) != size || hash(raw) != g.ConfigSHA256 {
		return fail("original-current-config", nil)
	}
	defer clear(raw)
	refs, err := publicationSnapshotReferences(raw, i.configSHA)
	if err != nil {
		return fail("original-config-references", err)
	}
	if target != nil && catalog != nil {
		expected := []publicationConfigReference{
			{"artifact_read", target.ReadIdentityHash, target.ReadRefVersion}, {"artifact_write", target.WriteIdentityHash, target.WriteRefVersion},
			{"artifact_delete", target.DeleteIdentityHash, target.DeleteRefVersion}, {"artifact_ca", target.CAIdentityHash, target.CARefVersion},
			{"catalog_read", catalog.ReadIdentityHash, catalog.ReadRefVersion}, {"catalog_append", catalog.AppendIdentityHash, catalog.AppendRefVersion},
		}
		if err = publicationDependencyReferencesTx(ctx, tx, g.InstallationID, i.version, i.configSHA, refs, expected); err != nil {
			return fail("current-artifact-catalog-config-references", err)
		}
	}
	var epoch uint64
	if tx.QueryRowContext(ctx, `SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=? FOR SHARE`, g.InstallationID).Scan(&epoch) != nil || s.publisherVerifier == nil {
		return fail("original-kek-fence", nil)
	}
	p := s.publisherVerifier
	if acceptanceCurrentKEKBindingTx(ctx, tx, p.Binding) != nil {
		return fail("current-kek-binding", nil)
	}
	owner, err := a.ReadCurrentOriginalUnwrapTx(ctx, tx, p.Binding, p.InstallationIssuer, out.now)
	if err != nil || owner.GenerateRevoked {
		return fail("current-original-kek-owner", err)
	}
	if err = out.window.include(out.now, owner.NotBefore, owner.Until); err != nil {
		return fail("original-kek-owner-window", err)
	}
	var capability []byte
	var checksum string
	var contentSize uint64
	var expires time.Time
	if tx.QueryRowContext(ctx, `SELECT inline_payload,content_checksum,content_size_bytes,expires_at FROM system_backup_v2_evidence WHERE public_id=? AND owner_target_type='system' AND owner_target_public_id=? AND evidence_type='capability_snapshot' AND storage_state='inline' AND observed_health='healthy' AND encryption='none' FOR SHARE`, p.UnwrapCapability.Source.RecordID, g.InstallationID).Scan(&capability, &checksum, &contentSize, &expires) != nil || len(capability) == 0 || len(capability) > 8192 || uint64(len(capability)) != contentSize || hash(capability) != checksum {
		return fail("original-unwrap-capability-row", nil)
	}
	cap, err := a.InspectProviderCapabilityMaterial(capability, p.UnwrapCapability, p.Binding, kms.Unwrap, expires, out.now)
	if err != nil || cap.Facts.Permission.ControllerVerifier == nil || !reflect.DeepEqual(*cap.Facts.Permission.ControllerVerifier, p.Workload) {
		return fail("current-original-unwrap-capability", err)
	}
	if err = out.window.include(out.now, cap.NotBefore, cap.Until); err == nil {
		err = out.window.include(out.now, cap.NotBefore, expires)
	}
	if err != nil {
		return fail("original-unwrap-capability-window", err)
	}
	grant, err := s.dependencyPublisherGrant(ctx)
	if err != nil {
		return fail("current-original-publisher-grant", err)
	}
	if err = out.window.include(out.now, grant.NotBefore, grant.Until); err != nil {
		return fail("original-publisher-grant-window", err)
	}
	if tx.Rollback() != nil {
		return fail("current-sql-view-close", nil)
	}
	return out, nil
}

func publicationDependencyReferencesTx(ctx context.Context, tx *sql.Tx, installation string, version uint64, sha string, original map[string]publicationConfigReference, expected []publicationConfigReference) error {
	// The identifier set is fixed; no input or DTO becomes a SQL identifier.
	var values [12]string
	args := make([]any, len(values))
	for i := range values {
		args[i] = &values[i]
	}
	if len(expected) != 6 || tx.QueryRowContext(ctx, `SELECT artifact_read_identity_hash,artifact_read_ref_version,artifact_write_identity_hash,artifact_write_ref_version,artifact_delete_identity_hash,artifact_delete_ref_version,artifact_ca_identity_hash,artifact_ca_ref_version,catalog_read_identity_hash,catalog_read_ref_version,catalog_append_identity_hash,catalog_append_ref_version FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=? FOR SHARE`, installation, version, sha).Scan(args...) != nil {
		return publicationDependencyFailure("current-config-reference-columns", nil)
	}
	for i, ref := range expected {
		if original[ref.Purpose] != ref || values[2*i] != ref.Identity || values[2*i+1] != ref.Version {
			return publicationDependencyFailure("original-config-reference-mismatch", nil)
		}
	}
	return nil
}
