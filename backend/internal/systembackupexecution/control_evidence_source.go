package systembackupexecution

import (
	"context"
	"database/sql"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	security "clawreef/internal/systembackupsecurity"
)

// PrepareControlEvidenceSource is the actual service's ORIGINAL live capture
// producer, called by D's source freeze after its real writer/source selection.
// sourceExclusion is a locator for D's registered original source-selection
// proof, not a success flag. There is no publisher/old-claim/Unwrap entry here.
func (s *DeploymentService) PrepareControlEvidenceSource(ctx context.Context, in d.Input, sourceExclusion ce.EvidenceRef) (ce.PreparedSource, error) {
	var zero ce.PreparedSource
	if s == nil || ctx == nil || ctx.Err() != nil || !s.ForwardEnabled || s.Runtime == nil || s.Runtime.Owner == nil || s.captureMaterials == nil || s.captureMaterials.ControlEvidence == nil || s.checkProductionCaptureMaterials() != nil || in.Authority.InstallationID != s.Config.InstallationID || in.Authority.TaskType != "backup" || in.Authority.Phase != "capture" {
		return zero, c.ErrExecutionAuthority
	}
	input := *s.captureMaterials.ControlEvidence
	if input.Validate() != nil {
		return zero, c.ErrExecutionAuthority
	}
	schemaRaw, err := pinnedDeploymentFile(input.SchemaRegistryFile, input.SchemaRegistrySHA256, 8<<20)
	if err != nil {
		return zero, err
	}
	redactionRaw, err := pinnedDeploymentFile(input.RedactionRegistryFile, input.RedactionRegistrySHA256, 65536)
	if err != nil {
		return zero, err
	}
	schemaPin, redactionPin, names, err := ce.ReadPolicies(schemaRaw, redactionRaw, input)
	if err != nil {
		return zero, err
	}
	gate := s.Runtime.Owner.Gate.Authority
	// Only this actual service's original production wrapper is admitted. A raw
	// signing key, pinned identity alone, DTO or callback cannot stand in for it.
	wrapper, ok := gate.Authorization.(deploymentAuthorization)
	if !ok || wrapper.Service != s || gate.DB == nil || gate.InstallationID != s.Config.InstallationID || s.Forward.CheckDeployment(ctx, gate.DB) != nil {
		return zero, c.ErrExecutionAuthority
	}
	sourceIdentity, err := ce.SourceIdentity(s.Config.SourceServerUUID, s.Config.SourceDatabase)
	if err != nil {
		return zero, err
	}
	expected := ce.Expected{Scope: ce.Scope{Installation: in.Authority.InstallationID, Backup: in.Authority.TaskPublicID, Attempt: in.Authority.AttemptNo}, ConfigSHA256: in.Authority.ConfigSHA256, SourceIdentitySHA256: sourceIdentity, SchemaRegistry: schemaPin, RedactionRegistry: redactionPin}
	tx, err := gate.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return zero, c.ErrExecutionAuthority
	}
	defer tx.Rollback()
	guard, err := gate.Bind(ctx, tx, in.Authority)
	if err != nil {
		return zero, err
	}
	source, err := ce.LoadRegisteredSQL(ctx, tx, expected.Scope, sourceExclusion)
	if err != nil {
		return zero, err
	}
	snapshot, err := ce.CollectSQL(ctx, tx, expected, input.CoverageWindowSeconds, names, source)
	if err != nil {
		return zero, err
	}
	proposed, err := ce.Assemble(ctx, snapshot)
	if err != nil {
		return zero, err
	}
	returned := false
	defer func() {
		for _, entry := range proposed.Evidence {
			clear(entry.Payload)
		}
		if !returned {
			clear(proposed.Prepared.SidecarJSON)
			clear(proposed.Prepared.ProofsJSON)
		}
	}()
	var capacity, retentionSeconds int64
	var retainedAt time.Time
	if tx.QueryRowContext(ctx, "SELECT control_metadata_capacity_bytes,evidence_retention_seconds,UTC_TIMESTAMP(6) FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR SHARE", expected.Installation, in.Authority.ConfigVersion).Scan(&capacity, &retentionSeconds, &retainedAt) != nil || retentionSeconds < 60 || retentionSeconds > 10*365*86400 {
		return zero, c.ErrExecutionAuthority
	}
	size := 0
	for _, entry := range proposed.Evidence {
		size += len(entry.Payload)
	}
	if (security.RegistrationCapacity{ReportFile: s.Config.CapacityFile}).ReserveExecutionPayload(ctx, tx, capacity, size) != nil {
		return zero, c.ErrExecutionAuthority
	}
	// These are retained DATA, not a lease or a new execution permission. Keep
	// the original configured evidence retention independent of task heartbeats;
	// every worker pull still requires its live exact original Job/key-use.
	retainedUntil := retainedAt.Add(time.Duration(retentionSeconds) * time.Second).UTC().Truncate(time.Microsecond)
	if !retainedUntil.After(in.Authority.DeadlineAt) {
		return zero, c.ErrExecutionAuthority
	}
	if err = ce.RegisterSQL(ctx, tx, expected.Scope, proposed.Evidence, retainedUntil); err != nil {
		return zero, err
	}
	// Re-read every registered body from the original SQL, before returning any
	// plaintext to the original encrypted plan. No SQL fallback exists offline.
	for _, entry := range proposed.Evidence {
		actual, e := ce.LoadRegisteredSQL(ctx, tx, expected.Scope, ce.EvidenceRef{PublicID: entry.PublicID, SHA256: entry.SHA256})
		if e != nil || ce.SHA256(actual.Payload) != entry.SHA256 {
			return zero, c.ErrExecutionAuthority
		}
	}
	if s.checkProductionCaptureMaterials() != nil || guard.Recheck(ctx, tx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	if _, err = pinnedDeploymentFile(input.SchemaRegistryFile, input.SchemaRegistrySHA256, 8<<20); err != nil {
		return zero, err
	}
	if _, err = pinnedDeploymentFile(input.RedactionRegistryFile, input.RedactionRegistrySHA256, 65536); err != nil {
		return zero, err
	}
	var now time.Time
	if tx.QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&now) != nil || !now.Before(guard.ValidUntil()) || guard.Recheck(ctx, tx) != nil {
		return zero, c.ErrExecutionAuthority
	}
	if tx.Commit() != nil || ctx.Err() != nil {
		return zero, c.ErrExecutionCommitUnknown
	}
	returned = true
	return proposed.Prepared, nil
}

// Job/config serialization uses this locator-only production entry. Bodies are
// registered in original SQL and kept out of Kube specs/env/ordinary staging.
func (s *DeploymentService) PrepareControlEvidenceLocator(ctx context.Context, in d.Input, source ce.EvidenceRef) (ce.CaptureLocator, error) {
	prepared, err := s.PrepareControlEvidenceSource(ctx, in, source)
	if err != nil {
		return ce.CaptureLocator{}, err
	}
	defer clear(prepared.SidecarJSON)
	defer clear(prepared.ProofsJSON)
	return prepared.Locator, nil
}
