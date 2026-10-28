package systembackupevidence

import (
	"context"
	"errors"
	"strings"
	"time"
)

// A cursor describes a scan range, never authorization or a durable checkpoint.
// ThroughID=0 starts a new range at the current maximum candidate PK. An ended
// range does not mean all retained groups are eligible or have been collected.
type DownloadRetentionGCBatchCursor struct{ AfterID, ThroughID int64 }

type DownloadRetentionGCBatchResult struct {
	Cursor                                     DownloadRetentionGCBatchCursor
	Examined, Collected, Rejected              int
	EndOfRange, CommitUnknown, RollbackUnknown bool
	ReleaseUnknown                             bool
}

func (DownloadRetentionGCBatchResult) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

const downloadGCBatchMax = 128
const downloadGCBatchIDMax int64 = 9007199254740991

// These are nonlocking hints. Scan the candidate download Operation type in PK
// order without hiding a changed status, missing result or incomplete group.
// Collect independently authenticates and locks/rechecks every original fact.
// LIMIT bounds returned hints and memory, not the optimizer's scan work; actual
// query plans and deployment-scale latency still require MySQL evidence.
const downloadGCBatchUpperSQL = `SELECT COALESCE(MAX(id),0) FROM system_backup_v2_operations WHERE origin_installation_id=? AND operation_type='evidence_download_admission'`
const downloadGCBatchCandidatesSQL = `SELECT id,IF(OCTET_LENGTH(public_id)=40,public_id,NULL) FROM system_backup_v2_operations WHERE origin_installation_id=? AND operation_type='evidence_download_admission' AND id>? AND id<=? ORDER BY id LIMIT ?`
const downloadGCBatchSchemaSQL = `SELECT IF(OCTET_LENGTH(COLUMN_TYPE) BETWEEN 1 AND 8192,COLUMN_TYPE,NULL) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='system_backup_v2_operations' AND COLUMN_NAME='operation_type' AND DATA_TYPE='enum'`
const downloadGCBatchWorkerSQL = `SELECT operation_type,target_type,target_public_id,actor_type,actor_id,status,claim_owner,claim_expires_at,row_version,deadline_at,schema_version
FROM system_backup_v2_operations WHERE origin_installation_id=? AND public_id=?`

type downloadGCBatchCandidate struct {
	id        int64
	operation string
}

// CollectBatch performs one bounded page. The hint transaction is rolled back
// and closed BEFORE any Collect; each candidate retains its own fresh complete
// RR transaction, current authority, physical reservation and sole commit.
// No proof/claim/config/retention deadline is renewed and no call is retried.
// Unknown commit or rollback immediately stops: reconcile before resuming.
// There is no production scheduler, route, default policy or provider action.
func (s *SQLDownloadRetentionGC) CollectBatch(ctx context.Context, cursor DownloadRetentionGCBatchCursor, limit int) (DownloadRetentionGCBatchResult, error) {
	result := DownloadRetentionGCBatchResult{Cursor: cursor}
	if s == nil || ctx == nil || ctx.Err() != nil || limit < 1 || limit > downloadGCBatchMax ||
		cursor.AfterID < 0 || cursor.AfterID > downloadGCBatchIDMax || cursor.ThroughID < 0 || cursor.ThroughID > downloadGCBatchIDMax || cursor.ThroughID != 0 && cursor.AfterID > cursor.ThroughID {
		return result, ErrDenied
	}
	peer, err := pinnedPeerExpiry(ctx, s, s.roots, s.c.CertificateSHA256, s.c.ExpiresAt)
	if err != nil {
		return result, ErrDenied
	}
	// This is a maximum batch budget, not a new grant. The original caller's
	// earlier deadline and pinned peer expiry always remain in force.
	batchContext, cancel := context.WithDeadline(ctx, earlier(peer, time.Now().Add(30*time.Second)))
	defer cancel()
	candidates, through, more, err := s.scanDownloadGCBatch(batchContext, cursor, limit, peer)
	if err != nil {
		return result, err
	}
	result.Cursor.ThroughID = through
	return runDownloadGCBatch(batchContext, result, candidates, more, s.Collect)
}

func (s *SQLDownloadRetentionGC) scanDownloadGCBatch(ctx context.Context, cursor DownloadRetentionGCBatchCursor, limit int, peer time.Time) (candidates []downloadGCBatchCandidate, through int64, more bool, scanErr error) {
	tx, now, err := s.c.Registry.begin(ctx)
	if err != nil {
		return nil, 0, false, ErrAudit
	}
	// Every path, including an empty range, must observe transaction completion
	// before releasing hints. ErrTxDone does not establish the driver's earlier
	// rollback result. This scan performs no writes; report an audit failure,
	// discard all hints and let the caller retain its original cursor.
	defer func() {
		if err := tx.Rollback(); err != nil || ctx.Err() != nil {
			candidates, through, more, scanErr = nil, 0, false, ErrAudit
		}
	}()
	// Even an empty range must belong to the exact running, unexpired worker.
	// This nonlocking snapshot grants no mutation authority. Collect still
	// takes the original worker lock in its complete L0/L1/L2/L3 prefix order.
	worker, err := s.readWorker(ctx, tx, downloadGCBatchWorkerSQL)
	if err != nil {
		return nil, 0, false, err
	}
	if _, err = s.clock(ctx, tx, now, earlier(peer, earlier(worker.lease, worker.deadline))); err != nil {
		return nil, 0, false, err
	}
	// A formal schema without the download proposal would otherwise produce
	// MAX(id)=0 and look like an empty page. This prerequisite is not full
	// schema/role approval; each Collect still runs the complete pinned policy.
	var operationTypes string
	if tx.QueryRowContext(ctx, downloadGCBatchSchemaSQL).Scan(&operationTypes) != nil || !strings.Contains(operationTypes, "'evidence_download_admission'") {
		return nil, 0, false, ErrAudit
	}
	through = cursor.ThroughID
	if through == 0 {
		if tx.QueryRowContext(ctx, downloadGCBatchUpperSQL, s.c.Registry.Installation).Scan(&through) != nil || through < cursor.AfterID || through > downloadGCBatchIDMax {
			return nil, 0, false, ErrAudit
		}
	}
	if through == cursor.AfterID {
		return nil, through, false, nil
	}
	rows, err := tx.QueryContext(ctx, downloadGCBatchCandidatesSQL, s.c.Registry.Installation, cursor.AfterID, through, limit+1)
	if err != nil {
		return nil, 0, false, ErrAudit
	}
	defer rows.Close()
	candidates = []downloadGCBatchCandidate{}
	seen := map[string]bool{}
	previous := cursor.AfterID
	for rows.Next() {
		var c downloadGCBatchCandidate
		if len(candidates) >= limit+1 || rows.Scan(&c.id, &c.operation) != nil || c.id <= previous || c.id > through || !downloadAdmissionOperationID.MatchString(c.operation) || c.operation == s.c.OperationID || seen[c.operation] {
			return nil, 0, false, ErrAudit
		}
		previous, seen[c.operation] = c.id, true
		candidates = append(candidates, c)
	}
	if rows.Err() != nil || rows.Close() != nil || ctx.Err() != nil {
		return nil, 0, false, ErrAudit
	}
	more = len(candidates) > limit
	if more {
		candidates = candidates[:limit]
	}
	return candidates, through, more, nil
}

func runDownloadGCBatch(ctx context.Context, result DownloadRetentionGCBatchResult, candidates []downloadGCBatchCandidate, more bool, collect func(context.Context, string) error) (DownloadRetentionGCBatchResult, error) {
	for _, c := range candidates {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		result.Examined++
		err := collect(ctx, c.operation)
		if err == nil {
			result.Collected++
			result.Cursor.AfterID = c.id
			continue
		}
		result.CommitUnknown = errors.Is(err, ErrDownloadRetentionGCCommitUnknown)
		result.RollbackUnknown = errors.Is(err, ErrDownloadRetentionGCRollbackUnknown)
		result.ReleaseUnknown = errors.Is(err, ErrDownloadRetentionGCReleaseUnknown)
		if result.CommitUnknown || result.RollbackUnknown || result.ReleaseUnknown {
			// Preserve every uncertainty, including a known commit whose lock
			// release could not be confirmed. Never advance or retry this hint.
			var uncertain []error
			if result.CommitUnknown {
				uncertain = append(uncertain, ErrDownloadRetentionGCCommitUnknown)
			}
			if result.RollbackUnknown {
				uncertain = append(uncertain, ErrDownloadRetentionGCRollbackUnknown)
			}
			if result.ReleaseUnknown {
				uncertain = append(uncertain, ErrDownloadRetentionGCReleaseUnknown)
			}
			if len(uncertain) == 1 {
				return result, uncertain[0]
			}
			return result, errors.Join(uncertain...)
		}
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if !errors.Is(err, ErrDenied) {
			return result, boundary(err)
		}
		// A hint can be ineligible or authority may have been withdrawn. This
		// count is rejection, never a reason to relax a guard or renew a grant.
		result.Rejected++
		result.Cursor.AfterID = c.id
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	result.EndOfRange = !more
	if result.EndOfRange {
		result.Cursor.AfterID = result.Cursor.ThroughID
	}
	return result, nil
}
