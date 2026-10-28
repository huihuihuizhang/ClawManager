package systembackupevidence

import (
	"context"
	"time"
)

// GCFailureJournalConfig identifies a pre-provisioned, independently reserved,
// single-writer file. Its records describe provider evidence GC, not metadata GC.
type GCFailureJournalConfig DownloadFailureJournalConfig

type gcFailureJournal struct {
	storage              *DownloadFailureJournal
	operation, principal string
}

type gcFailureJournalRecord struct {
	SchemaVersion string    `json:"schema_version"`
	Installation  string    `json:"origin_installation_id"`
	ServerUUID    string    `json:"server_uuid"`
	Database      string    `json:"database"`
	Operation     string    `json:"worker_operation_public_id"`
	Principal     string    `json:"worker_principal_sha256"`
	EvidenceID    string    `json:"evidence_public_id"`
	Code          string    `json:"failure_code"`
	RecordedAt    time.Time `json:"recorded_at"`
}

// NewJournaledGCRuntime owns the existing file until Close. It creates neither
// storage nor worker authorization, provider proof, SQL policy or scheduling.
func NewJournaledGCRuntime(c GCRuntimeConfig, journalConfig GCFailureJournalConfig) (*GCRuntime, error) {
	r := c.Authority.Registry
	if c.Failure != nil || journalConfig.Installation != r.Installation || journalConfig.ServerUUID != r.ServerUUID || journalConfig.Database != r.Database {
		return nil, ErrInvalid
	}
	storage, err := NewDownloadFailureJournal(DownloadFailureJournalConfig(journalConfig))
	if err != nil {
		return nil, err
	}
	j := &gcFailureJournal{storage: storage, operation: c.Authority.OperationID}
	c.Failure = j.report
	runtime, err := NewGCRuntime(c)
	if err != nil {
		storage.Close()
		return nil, err
	}
	j.principal = runtime.authority.principal
	runtime.journal, runtime.authority.journal = j, j
	return runtime, nil
}

func (r *GCRuntime) CheckFailurePersistence() error {
	if r == nil || r.closed.Load() || r.journal == nil {
		return ErrUnavailable
	}
	return r.journal.check()
}

func (j *gcFailureJournal) check() error {
	if j == nil || j.storage == nil {
		return ErrUnavailable
	}
	return j.storage.Check()
}

// The operation and principal come from this runtime's original admission.
// No caller error, claim, token, manifest or provider locator is accepted.
func (j *gcFailureJournal) append(ctx context.Context, id, code string) error {
	if j == nil || j.storage == nil {
		return ErrUnavailable
	}
	if ctx == nil || ctx.Err() != nil || !idPattern.MatchString(id) || code != "evidence_incomplete" || !gcOperationID.MatchString(j.operation) || !digestPattern.MatchString(j.principal) || j.check() != nil {
		j.storage.poison()
		return ErrUnavailable
	}
	c := j.storage.config
	record := &gcFailureJournalRecord{SchemaVersion: "system-backup-evidence-gc-failure.v1", Installation: c.Installation, ServerUUID: c.ServerUUID, Database: c.Database,
		Operation: j.operation, Principal: j.principal, EvidenceID: id, Code: code, RecordedAt: time.Now().UTC()}
	if j.storage.journal.append(ctx, recoveryAuditJournalEntry{Kind: "evidence_gc_failure", GC: record}) != nil {
		j.storage.poison()
		return ErrUnavailable
	}
	return nil
}

func (j *gcFailureJournal) report(ctx context.Context, id, code string) { _ = j.append(ctx, id, code) }

// Persist each failure before the next candidate. A busy journal denies work;
// failed/full persistence remains failed for this runtime's lifetime.
func (r *GCRuntime) journaledGC(ctx context.Context, ids []string) []error {
	results := make([]error, len(ids))
	remaining := 3 * time.Second
	for n, id := range ids {
		if r.journal.check() != nil {
			results[n] = ErrUnavailable
			continue
		}
		results[n] = r.service.collect(ctx, id)
		if err := results[n]; err != nil && err != ErrConflict && err != ErrState && idPattern.MatchString(id) {
			// Provider time must not consume the independent persistence budget.
			started := time.Now()
			failureCtx, cancel := context.WithTimeout(context.Background(), remaining)
			r.journal.report(failureCtx, id, "evidence_incomplete")
			cancel()
			remaining -= time.Since(started)
		}
	}
	return results
}
