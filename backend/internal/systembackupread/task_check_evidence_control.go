package systembackupread

import "context"

// TaskCheckEvidenceControlSnapshot binds the check references to their stored
// evidence owner and content checksum in the original authorized task snapshot.
// It does not prove provider availability, content integrity or download access.
type TaskCheckEvidenceControlSnapshot struct {
	checks TaskCheckControlSnapshot
	bound  []DetailEvidenceControl
}

func (TaskCheckEvidenceControlSnapshot) MarshalJSON() ([]byte, error)       { return nil, ErrInvalid }
func (s TaskCheckEvidenceControlSnapshot) Checks() TaskCheckControlSnapshot { return s.checks }
func (s TaskCheckEvidenceControlSnapshot) BoundReferences() []DetailEvidenceControl {
	return append([]DetailEvidenceControl{}, s.bound...)
}

// Only the task/check builder can supply this contribution before the final
// authority recheck and Commit. A later full-detail builder must remain inside
// this transaction rather than compose independently committed snapshots.
func readTaskCheckEvidenceControlInTransaction[T any](ctx context.Context, r *Reader, kind TaskKind, publicID string,
	build func(context.Context, detailReadSQL, TaskCheckEvidenceControlSnapshot) (T, error)) (T, error) {
	if build == nil {
		var zero T
		return zero, ErrUnavailable
	}
	return readTaskCheckControlInTransaction(ctx, r, kind, publicID,
		func(ctx context.Context, q detailReadSQL, checks TaskCheckControlSnapshot) (T, error) {
			var zero T
			s, err := readTaskCheckEvidenceControl(ctx, q, checks)
			if err != nil {
				return zero, err
			}
			return build(ctx, q, s)
		})
}

func (r *Reader) ReadTaskCheckEvidenceControl(ctx context.Context, kind TaskKind, publicID string) (TaskCheckEvidenceControlSnapshot, error) {
	return readTaskCheckEvidenceControlInTransaction(ctx, r, kind, publicID,
		func(_ context.Context, _ detailReadSQL, s TaskCheckEvidenceControlSnapshot) (TaskCheckEvidenceControlSnapshot, error) {
			return s, nil
		})
}

// The evidence public ID is globally unique. The owner must be the very task
// whose installation and immutable public ID were read and authorized above.
// No installation inferred from caller input or evidence state is trusted.
const taskCheckEvidenceControlSQL = "SELECT c.id,c.evidence_public_id,c.evidence_sha256,e.schema_version,e.public_id,e.owner_target_type,e.owner_target_public_id,e.content_checksum FROM system_backup_v2_check_results AS c LEFT JOIN system_backup_v2_evidence AS e ON e.public_id=c.evidence_public_id WHERE c.origin_installation_id=? AND c.target_type=? AND c.target_public_id=? AND c.evidence_public_id IS NOT NULL ORDER BY c.checked_at,c.id LIMIT 10001"

func readTaskCheckEvidenceControl(ctx context.Context, q detailReadSQL, checks TaskCheckControlSnapshot) (TaskCheckEvidenceControlSnapshot, error) {
	var zero TaskCheckEvidenceControlSnapshot
	task := checks.detail.execution.task
	// Collect and cross-check repeated bindings before reading any evidence.
	// The existing check reader caps this set at 10,000 rows.
	wanted := make(map[string]string)
	refs := make([]DetailEvidenceControl, 0)
	checksWithEvidence := make([]TaskCheckControl, 0)
	for _, c := range checks.checks {
		if !validDetailEvidence(c.Evidence) {
			return zero, ErrUnavailable
		}
		if !c.Evidence.PublicID.Valid {
			continue
		}
		checksWithEvidence = append(checksWithEvidence, c)
		id, digest := c.Evidence.PublicID.String, c.Evidence.SHA256.String
		if previous, exists := wanted[id]; exists {
			if previous != digest {
				return zero, ErrUnavailable
			}
			continue
		}
		wanted[id] = digest
		refs = append(refs, c.Evidence)
	}
	if len(checksWithEvidence) == 0 {
		return TaskCheckEvidenceControlSnapshot{checks: checks, bound: refs}, nil
	}
	// A bounded left join preserves missing evidence as a failure, rather than
	// hiding it with an inner join or issuing one round trip per reference.
	rows, err := q.QueryContext(ctx, taskCheckEvidenceControlSQL, task.InstallationID, string(task.Kind), task.PublicID)
	if err != nil {
		return zero, ErrUnavailable
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		if count == len(checksWithEvidence) {
			return zero, ErrUnavailable
		}
		c := checksWithEvidence[count]
		var checkID uint64
		var referenceID, referenceHash, schema, id, kind, owner, digest string
		err := rows.Scan(&checkID, &referenceID, &referenceHash, &schema, &id, &kind, &owner, &digest)
		if err != nil || ctx.Err() != nil || checkID != c.ID || referenceID != c.Evidence.PublicID.String || referenceHash != c.Evidence.SHA256.String ||
			schema != "system-backup-evidence.v1" || id != referenceID || kind != string(task.Kind) || owner != task.PublicID || digest != referenceHash {
			return zero, ErrUnavailable
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return zero, ErrUnavailable
	}
	if err := rows.Close(); err != nil {
		return zero, ErrUnavailable
	}
	if count != len(checksWithEvidence) || ctx.Err() != nil {
		return zero, ErrUnavailable
	}
	return TaskCheckEvidenceControlSnapshot{checks: checks, bound: refs}, nil
}
