package systembackupevidence

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"time"
)

// Deployment must provision one dedicated regular file on independently
// reserved durable storage and enforce a single writer. No storage is created.
type DownloadFailureJournalConfig struct {
	Path, Installation, ServerUUID, Database string
	MaxBytes                                 int64
}

type DownloadFailureJournal struct {
	journal *RecoveryAuditJournal
	config  DownloadFailureJournalConfig
}

type downloadFailureJournalRecord struct {
	SchemaVersion string                    `json:"schema_version"`
	Installation  string                    `json:"origin_installation_id"`
	ServerUUID    string                    `json:"server_uuid"`
	Database      string                    `json:"database"`
	EvidenceID    string                    `json:"evidence_public_id"`
	Code          string                    `json:"failure_code"`
	RecordedAt    time.Time                 `json:"recorded_at"`
	Reference     *DownloadFailureReference `json:"reference,omitempty"`
}

var downloadFailureUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var downloadFailureDatabase = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

func downloadFailurePrivateMode(mode os.FileMode) bool {
	return mode.Perm() == 0600 || mode.Perm() == 0640
}

func NewDownloadFailureJournal(c DownloadFailureJournalConfig) (*DownloadFailureJournal, error) {
	if !filepath.IsAbs(c.Path) || filepath.Clean(c.Path) != c.Path || !installationPattern.MatchString(c.Installation) || !downloadFailureUUID.MatchString(c.ServerUUID) || !downloadFailureDatabase.MatchString(c.Database) || c.MaxBytes < 4096 || c.MaxBytes > 1<<30 {
		return nil, ErrInvalid
	}
	pathInfo, pathErr := os.Lstat(c.Path)
	if pathErr != nil || !pathInfo.Mode().IsRegular() || pathInfo.Size() > c.MaxBytes {
		return nil, ErrUnavailable
	}
	f, err := os.Open(c.Path)
	if err != nil {
		return nil, ErrUnavailable
	}
	info, statErr := f.Stat()
	valid := statErr == nil && info.Mode().IsRegular() && os.SameFile(info, pathInfo) && info.Size() <= c.MaxBytes
	if valid && runtime.GOOS != "windows" {
		valid = downloadFailurePrivateMode(info.Mode())
	}
	// A partial last line from a crash must not swallow the next JSON record.
	if valid && info.Size() != 0 {
		var tail [1]byte
		n, readErr := f.ReadAt(tail[:], info.Size()-1)
		valid = n == 1 && readErr == nil && tail[0] == '\n'
	}
	closeErr := f.Close()
	if !valid || closeErr != nil {
		return nil, ErrUnavailable
	}
	j, err := NewRecoveryAuditJournal(c.Path, c.MaxBytes)
	if err != nil {
		return nil, err
	}
	opened, err := j.file.Stat()
	if err != nil || !os.SameFile(info, opened) || opened.Size() != info.Size() {
		j.Close()
		return nil, ErrUnavailable
	}
	sink := &DownloadFailureJournal{journal: j, config: c}
	if err = sink.Check(); err != nil {
		j.Close()
		return nil, err
	}
	return sink, nil
}

// Busy persistence cannot authorize another provider call. Require room for the maximum
// bounded entry (2048 bytes plus newline), not a healthy sample line.
func (j *DownloadFailureJournal) Check() error {
	if j == nil || j.journal == nil || !j.journal.mu.TryLock() {
		return ErrUnavailable
	}
	s := j.journal
	defer s.mu.Unlock()
	if s.file == nil || s.poisoned.Load() {
		return ErrUnavailable
	}
	info, err := s.file.Stat()
	pathInfo, pathErr := os.Lstat(s.path)
	if err != nil || pathErr != nil || !info.Mode().IsRegular() || !pathInfo.Mode().IsRegular() || !os.SameFile(info, pathInfo) || info.Size() != s.size || s.size > s.maxBytes-2049 || runtime.GOOS != "windows" && !downloadFailurePrivateMode(info.Mode()) {
		s.poisoned.Store(true)
		return ErrUnavailable
	}
	if s.poisoned.Load() {
		return ErrUnavailable
	}
	return nil
}

func downloadFailureCode(code string) bool {
	for _, err := range []error{ErrInvalid, ErrIntegrity, ErrRedaction, ErrUnavailable, ErrKey, ErrDenied, ErrAuth, ErrState, ErrNotFound, ErrRange, ErrCapacity, ErrAudit, ErrConflict, ErrDownloadAdmissionNotReady} {
		if code == err.Error() {
			return true
		}
	}
	return oneOf(code, "download_audit_or_release_failed", "download_result_audit_or_release_failed")
}

func (j *DownloadFailureJournal) poison() {
	if j != nil && j.journal != nil {
		j.journal.poisoned.Store(true)
	}
}

// recorded_at is diagnostic host UTC, never SQL audit time or authorization.
// No request/proof/claim/provider locator or raw error is accepted.
func (j *DownloadFailureJournal) Append(ctx context.Context, evidenceID, code string) error {
	if j == nil || j.journal == nil {
		return ErrUnavailable
	}
	ref, hasRef := DownloadFailureReferenceFrom(ctx)
	if ctx == nil || ctx.Err() != nil || !idPattern.MatchString(evidenceID) || !downloadFailureCode(code) ||
		code == "download_result_audit_or_release_failed" && !hasRef ||
		hasRef && (!downloadAdmissionOperationID.MatchString(ref.OperationID) || ref.IntentAuditID < 1 || ref.IntentAuditID > 9007199254740991 || !digestPattern.MatchString(ref.ClaimSHA256)) {
		j.poison()
		return ErrUnavailable
	}
	r := &downloadFailureJournalRecord{SchemaVersion: "system-backup-download-failure.v1", Installation: j.config.Installation, ServerUUID: j.config.ServerUUID,
		Database: j.config.Database, EvidenceID: evidenceID, Code: code, RecordedAt: time.Now().UTC()}
	if hasRef {
		r.Reference = &ref
	}
	if err := j.journal.append(ctx, recoveryAuditJournalEntry{Kind: "evidence_download_failure", Download: r}); err != nil {
		j.poison()
		return ErrUnavailable
	}
	return nil
}

func (j *DownloadFailureJournal) Report(ctx context.Context, evidenceID, code string) {
	_ = j.Append(ctx, evidenceID, code)
}

func (j *DownloadFailureJournal) Close() error {
	if j == nil {
		return nil
	}
	return j.journal.Close()
}
