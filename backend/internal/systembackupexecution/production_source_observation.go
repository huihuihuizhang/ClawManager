package systembackupexecution

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"time"

	"clawreef/internal/systembackup/domain"
	b "clawreef/internal/systembackup/publicadapter"
	api "clawreef/internal/systembackupdeployment"
	d "clawreef/internal/systembackupdispatch"
)

// Only the real service's pinned source-owner delegation can construct this
// observer. It has no task, passed flag, public parts, or executable callback.
type sourceSQLObservation struct {
	delegation      *sourceMetadataDelegation
	control, source *sql.DB
	profileSHA256   string
}

// Facts only, never a readiness/admission receipt or physical stopped proof.
type observedSourceSQL struct {
	metadata                                                        productionSQLSourceMetadata
	instances                                                       []b.InstanceIdentity
	server, database, account                                       string
	configVersion                                                   uint64
	configSHA256, profileSHA256, sourceScopeSHA256, inventorySHA256 string
	observedAt, until                                               time.Time
}

func (s *DeploymentService) newSourceSQLObservation(ctx context.Context) (*sourceSQLObservation, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !s.ForwardEnabled || s.Forward == nil || s.Source == nil || s.Runtime == nil || s.Runtime.Owner == nil || s.Runtime.Owner.Gate.Authority.DB == nil || s.profileHash == "" || s.checkProductionCaptureMaterials() != nil || s.captureMaterials.Discovery == nil {
		return nil, d.ErrNotReady
	}
	deadline, bounded := ctx.Deadline()
	grant := s.Forward.DeploymentBinding()
	if !bounded || !forwardCaptureActions(grant) || grant.ProfileSHA256 != s.profileHash {
		return nil, d.ErrNotReady
	}
	p := s.captureMaterials.Discovery
	raw, err := pinnedDeploymentFile(p.GrantFile, p.GrantSHA256, 65536)
	var envelope signedSourceMetadataGrant
	var original originalSourceMetadataGrant
	if err != nil || decodeMetadataCanonical(raw, &envelope) != nil || len(envelope.Record) < 2 || len(envelope.Record) > 32768 || len(envelope.Signature) != ed25519.SignatureSize || decodeMetadataCanonical(envelope.Record, &original) != nil {
		return nil, d.ErrNotReady
	}
	scope, err := sourceMetadataScope(*s.captureMaterials)
	if err != nil {
		return nil, d.ErrNotReady
	}
	until := deadline
	for _, limit := range []time.Time{original.Until, grant.ExpiresAt} {
		if limit.Before(until) {
			until = limit
		}
	}
	x := &sourceSQLObservation{delegation: &sourceMetadataDelegation{service: s, owner: s.Runtime.Owner, grant: original, scope: scope, configSHA256: grant.ConfigSHA256, until: until}, control: s.Runtime.Owner.Gate.Authority.DB, source: s.Source, profileSHA256: s.profileHash}
	if x.recheck(ctx) != nil {
		return nil, d.ErrNotReady
	}
	return x, nil
}

func (x *sourceSQLObservation) checkDeployment(ctx context.Context) error {
	if x == nil || x.delegation == nil || ctx == nil || ctx.Err() != nil {
		return d.ErrNotReady
	}
	y, s := x.delegation, x.delegation.service
	if s == nil || !s.ForwardEnabled || s.Forward == nil || s.Runtime == nil || s.Runtime.Owner == nil || s.Runtime.Owner != y.owner || s.Source != x.source || x.source == nil || x.control == nil || s.Runtime.Owner.Gate.Authority.DB != x.control || y.checkLocal(ctx) != nil || s.Forward.CheckDeployment(ctx, x.control) != nil {
		return d.ErrNotReady
	}
	g := s.Forward.DeploymentBinding()
	profile, err := api.LoadExecutionProfile(s.Config.ProfileFile)
	if err != nil {
		return d.ErrNotReady
	}
	_, profileSHA, err := profile.CanonicalIdentity()
	if err != nil || profile.InstallationID != s.Config.InstallationID || profileSHA != x.profileSHA256 || profileSHA != g.ProfileSHA256 || s.profileHash != x.profileSHA256 || !forwardCaptureActions(g) {
		return d.ErrNotReady
	}
	tx, err := x.control.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return d.ErrNotReady
	}
	defer tx.Rollback()
	var version uint64
	var effective, enabled bool
	var sum string
	var size int64
	var raw []byte
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT s.active_config_version,s.last_effective_enabled,c.enabled,c.config_sha256,c.config_size_bytes,c.canonical_config_json,UTC_TIMESTAMP(6)
FROM system_backup_v2_installation_state s JOIN system_backup_v2_configs c ON c.origin_installation_id=s.origin_installation_id AND c.version=s.active_config_version
WHERE s.origin_installation_id=?`, s.Config.InstallationID).Scan(&version, &effective, &enabled, &sum, &size, &raw, &now) != nil || !effective || !enabled || version != g.ConfigVersion || sum != g.ConfigSHA256 || sum != y.configSHA256 || size != int64(len(raw)) || len(raw) < 2 || len(raw) > 262144 || hash(raw) != sum || now.Before(y.grant.NotBefore) || now.Before(g.NotBefore) || !now.Before(y.until) {
		return d.ErrNotReady
	}
	var canonical struct {
		Enabled bool `json:"enabled"`
	}
	if json.Unmarshal(raw, &canonical) != nil || !canonical.Enabled {
		return d.ErrNotReady
	}
	if tx.Commit() != nil {
		return d.ErrNotReady
	}
	return nil
}

func (x *sourceSQLObservation) recheck(ctx context.Context) error {
	if x.checkDeployment(ctx) != nil || x.delegation.checkWorkload(ctx) != nil || x.delegation.service.checkStagingLocation(ctx, x.delegation.owner.Client) != nil {
		return d.ErrNotReady
	}
	// A config, pin or grant replacement during the last GET closes the object.
	return x.checkDeployment(ctx)
}

func (x *sourceSQLObservation) observe(ctx context.Context) (*observedSourceSQL, error) {
	if x == nil || x.delegation == nil || ctx == nil {
		return nil, d.ErrNotReady
	}
	ctx, cancel := context.WithDeadline(ctx, x.delegation.until)
	defer cancel()
	if x.recheck(ctx) != nil {
		return nil, d.ErrNotReady
	}
	s := x.delegation.service
	// Actual least-privilege source grants/census are required, not control SQL.
	if s.checkSource(ctx) != nil {
		return nil, d.ErrNotReady
	}
	tx, err := x.source.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, d.ErrNotReady
	}
	defer tx.Rollback()
	if s.checkSourceIdentity(ctx, tx) != nil {
		return nil, d.ErrNotReady
	}
	instances, err := domain.ReadSourceInstances(ctx, tx)
	if err != nil {
		return nil, d.ErrNotReady
	}
	for index, instance := range instances {
		if instance.ID <= 0 || instance.UserID <= 0 || instance.Generation <= 0 || (index > 0 && instances[index-1].ID >= instance.ID) || (instance.Status != "running" && instance.Status != "stopped") {
			return nil, d.ErrNotReady
		}
	}
	metadata, err := readProductionSQLMetadata(ctx, s, tx, instances)
	if err != nil {
		return nil, d.ErrNotReady
	}
	// Preserve an explicit empty collection only after complete successful EOF.
	if instances == nil {
		instances = []b.InstanceIdentity{}
	}
	out := &observedSourceSQL{metadata: metadata, instances: instances, configVersion: s.Forward.DeploymentBinding().ConfigVersion, configSHA256: x.delegation.configSHA256, profileSHA256: x.profileSHA256, sourceScopeSHA256: x.delegation.scope, until: x.delegation.until}
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),CURRENT_USER(),UTC_TIMESTAMP(6)").Scan(&out.server, &out.database, &out.account, &out.observedAt) != nil || out.server != s.Config.SourceServerUUID || out.database != s.Config.SourceDatabase || out.observedAt.Before(x.delegation.grant.NotBefore) || !out.observedAt.Before(out.until) {
		return nil, d.ErrNotReady
	}
	raw, err := json.Marshal(instances)
	if err != nil {
		return nil, d.ErrNotReady
	}
	out.inventorySHA256 = hash(raw)
	if tx.Commit() != nil || x.recheck(ctx) != nil || !time.Now().Before(out.until) {
		return nil, d.ErrNotReady
	}
	return out, nil
}
