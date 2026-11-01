package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"

	security "clawreef/internal/systembackupsecurity"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

var ErrPublicationConfigBudgetMismatch = errors.New("original publication configuration budget mismatch")

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
	var snapshot []byte
	var taskBytes, configBytes int64
	if err := tx.QueryRowContext(ctx, `SELECT cfg.max_artifact_bytes,cfg.max_index_bytes,b.config_snapshot_json,b.config_snapshot_size_bytes,cfg.config_size_bytes
FROM system_backup_v2_configs cfg JOIN system_backup_v2_backups b ON b.origin_installation_id=cfg.origin_installation_id AND b.config_version=cfg.version AND b.config_snapshot_sha256=cfg.config_sha256
WHERE cfg.origin_installation_id=? AND cfg.version=? AND cfg.config_sha256=? AND b.public_id=? FOR SHARE`, facts.InstallationID, facts.ConfigVersion, facts.ConfigSHA256, facts.BackupPublicID).Scan(&limits.MaxArtifactBytes, &limits.MaxIndexBytes, &snapshot, &taskBytes, &configBytes); err != nil {
		return ArtifactReadLimits{}, err
	}
	defer clear(snapshot)
	if taskBytes != int64(len(snapshot)) || configBytes != taskBytes {
		return ArtifactReadLimits{}, ErrPublicationConfigBudgetMismatch
	}
	original, err := artifactLimitsFromConfigSnapshot(snapshot, facts.ConfigSHA256)
	if err != nil || original != limits {
		return ArtifactReadLimits{}, ErrPublicationConfigBudgetMismatch
	}
	if err := guard.RecheckTx(ctx, tx); err != nil {
		return ArtifactReadLimits{}, err
	}
	return limits, nil
}

func artifactLimitsFromConfigSnapshot(raw []byte, sha string) (ArtifactReadLimits, error) {
	var zero ArtifactReadLimits
	values, err := publicationConfigValuesFromSnapshot(raw, sha)
	if err != nil {
		return zero, ErrPublicationConfigBudgetMismatch
	}
	capacity, ok := values["capacity"].(map[string]any)
	if !ok {
		return zero, ErrPublicationConfigBudgetMismatch
	}
	artifact, ok := capacity["max_artifact_bytes"].(json.Number)
	if !ok {
		return zero, ErrPublicationConfigBudgetMismatch
	}
	index, ok := capacity["max_index_bytes"].(json.Number)
	if !ok {
		return zero, ErrPublicationConfigBudgetMismatch
	}
	a, err := artifact.Int64()
	if err != nil {
		return zero, ErrPublicationConfigBudgetMismatch
	}
	i, err := index.Int64()
	if err != nil {
		return zero, ErrPublicationConfigBudgetMismatch
	}
	limits := ArtifactReadLimits{MaxArtifactBytes: a, MaxIndexBytes: i}
	if limits.validate() != nil {
		return zero, ErrPublicationConfigBudgetMismatch
	}
	return limits, nil
}

// Shared immutable original-body check for capacities and purpose references.
// Complete ConfigValues business admission remains with the source API owner.
func publicationConfigValuesFromSnapshot(raw []byte, sha string) (map[string]any, error) {
	if len(raw) < 2 || len(raw) > 262144 || !formalCandidateDigest(sha) || hash(raw) != sha {
		return nil, ErrPublicationConfigBudgetMismatch
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, ErrPublicationConfigBudgetMismatch
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var values map[string]any
	if decoder.Decode(&values) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, ErrPublicationConfigBudgetMismatch
	}
	return values, nil
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
