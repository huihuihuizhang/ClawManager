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
		return nil, sourceObservationRejected(sourceObserverBindings)
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
		return nil, sourceObservationRejected(sourceObserverGrant)
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
	x := &sourceSQLObservation{delegation: &sourceMetadataDelegation{service: s, owner: s.Runtime.Owner, grant: original, scope: scope, configSHA256: grant.ConfigSHA256, configVersion: grant.ConfigVersion, until: until}, control: s.Runtime.Owner.Gate.Authority.DB, source: s.Source, profileSHA256: s.profileHash}
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
		return sourceObservationRejected(sourceObserverBindings)
	}
	g := s.Forward.DeploymentBinding()
	profile, err := api.LoadExecutionProfile(s.Config.ProfileFile)
	if err != nil {
		return d.ErrNotReady
	}
	_, profileSHA, err := profile.CanonicalIdentity()
	if err != nil || profile.InstallationID != s.Config.InstallationID || profileSHA != x.profileSHA256 || profileSHA != g.ProfileSHA256 || s.profileHash != x.profileSHA256 || !forwardCaptureActions(g) {
		return sourceObservationRejected(sourceObserverProfile)
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
WHERE s.origin_installation_id=?`, s.Config.InstallationID).Scan(&version, &effective, &enabled, &sum, &size, &raw, &now) != nil || !effective || !enabled || size != int64(len(raw)) || len(raw) < 2 || len(raw) > 262144 || hash(raw) != sum || now.Before(y.grant.NotBefore) || now.Before(g.NotBefore) || !now.Before(y.until) {
		return sourceObservationRejected(sourceObserverConfigState)
	}
	if version != g.ConfigVersion || sum != g.ConfigSHA256 || sum != y.configSHA256 {
		// These are actual CURRENT SQL vs original signed-owner bindings,
		// unlike two original v1 material files. Only A's real first-enable
		// lineage can admit this single immutable v1 -> enabled v2 change.
		if g.ConfigVersion != 1 || (y.configSHA256 != g.ConfigSHA256 && y.configSHA256 != sum) {
			return sourceObservationRejected(sourceObserverConfigState)
		}
		if _, err := readOriginalEnabledConfiguration(ctx, tx, s.Config.InstallationID, g.ConfigSHA256, version, sum, raw); err != nil {
			return sourceObservationRejected(sourceObserverConfigState)
		}
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
	if x.checkDeployment(ctx) != nil {
		return d.ErrNotReady
	}
	if x.delegation.checkWorkload(ctx) != nil {
		return sourceObservationRejected(sourceObserverController)
	}
	if x.delegation.service.checkStagingLocation(ctx, x.delegation.owner.Client) != nil {
		return sourceObservationRejected(sourceObserverStaging)
	}
	// A config, pin or grant replacement during the last GET closes the object.
	return x.checkDeployment(ctx)
}

func (x *sourceSQLObservation) observe(ctx context.Context) (*observedSourceSQL, error) {
	if x == nil || x.delegation == nil || ctx == nil {
		return nil, sourceObservationDetailRejected(sourceSQLInput)
	}
	ctx, cancel := context.WithDeadline(ctx, x.delegation.until)
	defer cancel()
	if x.recheck(ctx) != nil {
		return nil, sourceObservationDetailRejected(sourceSQLOriginal)
	}
	s := x.delegation.service
	// Actual least-privilege source grants/census are required, not control SQL.
	if s.checkSource(ctx) != nil {
		return nil, sourceObservationRejected(sourceObserverSQLIdentity)
	}
	tx, err := x.source.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, sourceObservationDetailRejected(sourceSQLBegin)
	}
	defer tx.Rollback()
	if s.checkSourceIdentity(ctx, tx) != nil {
		return nil, sourceObservationDetailRejected(sourceSQLSnapshotIdentity)
	}
	instances, err := domain.ReadSourceInstances(ctx, tx)
	if err != nil {
		return nil, sourceObservationDetailRejected(sourceSQLInstancesRead)
	}
	if bindRuntimeTestScope(s.Config, &b.SourceInventory{Database: s.Config.SourceDatabase, ServerUUID: s.Config.SourceServerUUID, Instances: instances}) != nil {
		return nil, sourceObservationDetailRejected(sourceSQLInstancesShape)
	}
	for index, instance := range instances {
		if deferredRuntimeTestInstance(s.Config, instance) {
			continue
		}
		if instance.ID <= 0 || instance.UserID <= 0 || !instance.ValidRuntimeGeneration() || (index > 0 && instances[index-1].ID >= instance.ID) || (instance.Status != "running" && instance.Status != "stopped") {
			return nil, sourceObservationDetailRejected(sourceSQLInstancesShape)
		}
	}
	metadata, err := readProductionSQLMetadata(ctx, s, tx, instances)
	if err != nil {
		return nil, sourceObservationRejected(sourceObserverSQLMetadata)
	}
	// Preserve an explicit empty collection only after complete successful EOF.
	if instances == nil {
		instances = []b.InstanceIdentity{}
	}
	// These fields retain the original source-grant provenance. The active
	// enabled configuration is independently rechecked in each SQL view above;
	// neither this metadata nor a remembered lineage acts as current authority.
	out := &observedSourceSQL{metadata: metadata, instances: instances, configVersion: s.Forward.DeploymentBinding().ConfigVersion, configSHA256: x.delegation.configSHA256, profileSHA256: x.profileSHA256, sourceScopeSHA256: x.delegation.scope, until: x.delegation.until}
	var sqlClock any
	if tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),CURRENT_USER(),UTC_TIMESTAMP(6)").Scan(&out.server, &out.database, &out.account, &sqlClock) != nil {
		return nil, sourceObservationDetailRejected(sourceSQLClockRead)
	}
	out.observedAt, err = decodeSourceObservationSQLTime(sqlClock)
	if err != nil {
		return nil, sourceObservationDetailRejected(sourceSQLClockRead)
	}
	if out.server != s.Config.SourceServerUUID || out.database != s.Config.SourceDatabase {
		return nil, sourceObservationDetailRejected(sourceSQLClockIdentity)
	}
	if out.observedAt.Before(x.delegation.grant.NotBefore) || !out.observedAt.Before(out.until) {
		return nil, sourceObservationDetailRejected(sourceSQLClockWindow)
	}
	raw, err := json.Marshal(instances)
	if err != nil {
		return nil, sourceObservationDetailRejected(sourceSQLProjection)
	}
	out.inventorySHA256 = hash(raw)
	if tx.Commit() != nil {
		return nil, sourceObservationDetailRejected(sourceSQLCommit)
	}
	if x.recheck(ctx) != nil {
		return nil, sourceObservationDetailRejected(sourceSQLOriginalTail)
	}
	if !time.Now().Before(out.until) {
		return nil, sourceObservationDetailRejected(sourceSQLDeadline)
	}
	return out, nil
}
