package systembackupexecution

import (
	security "clawreef/internal/systembackupsecurity"
	"context"
	"database/sql"
)

// Exact v12 resource-capacity ceilings (097 CHECKs and the public schema).
// A transport ceiling never replaces the original task's configured budget.
const (
	MaxPublicationArtifactBytes int64 = 900 << 30
	MaxPublicationIndexBytes    int64 = 8 << 30
	MinPublicationBudgetBytes   int64 = 1 << 20
)

// Independently supplied authenticated original config budgets; no guessed
// SQL, environment or default value supplies recovery authority.
type ArtifactReadLimits struct{ MaxArtifactBytes, MaxIndexBytes int64 }

func (l ArtifactReadLimits) validate() error {
	if l.MaxArtifactBytes < MinPublicationBudgetBytes || l.MaxArtifactBytes > MaxPublicationArtifactBytes || l.MaxIndexBytes < MinPublicationBudgetBytes || l.MaxIndexBytes > MaxPublicationIndexBytes {
		return errPublicationUnavailable
	}
	return nil
}

// Read the actual materialized budgets under the caller's ORIGINAL current
// publisher guard and same transaction. No nested SQL connection or Kube I/O.
func readPublicationLimitsTx(ctx context.Context, tx *sql.Tx, guard *security.SQLPublisherCaptureGuard) (ArtifactReadLimits, error) {
	var limits ArtifactReadLimits
	if tx == nil || guard == nil {
		return limits, errPublicationUnavailable
	}
	facts := guard.Facts()
	if err := tx.QueryRowContext(ctx, `SELECT max_artifact_bytes,max_index_bytes FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? AND config_sha256=? FOR SHARE`, facts.InstallationID, facts.ConfigVersion, facts.ConfigSHA256).Scan(&limits.MaxArtifactBytes, &limits.MaxIndexBytes); err != nil {
		return ArtifactReadLimits{}, err
	}
	if err := limits.validate(); err != nil {
		return ArtifactReadLimits{}, err
	}
	if err := guard.RecheckTx(ctx, tx); err != nil {
		return ArtifactReadLimits{}, err
	}
	return limits, nil
}

// Callers that read the ORIGINAL config may only tighten a transport. The
// clone shares identity/client, never a mutable process-wide capacity budget.
func (s *nativePublicationS3) withObjectLimit(maxBytes int64) (*nativePublicationS3, error) {
	if s == nil || s.client == nil || s.maxObjectBytes < 1 || s.maxObjectBytes > MaxPublicationArtifactBytes || maxBytes < MinPublicationBudgetBytes || maxBytes > MaxPublicationArtifactBytes {
		return nil, errPublicationUnavailable
	}
	clone := *s
	if maxBytes < clone.maxObjectBytes {
		clone.maxObjectBytes = maxBytes
	}
	return &clone, nil
}
