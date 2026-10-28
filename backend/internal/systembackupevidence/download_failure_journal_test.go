package systembackupevidence

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const journalEvidence = "sev_11111111-2222-4333-8444-555555555555"

func failureJournalConfig(t *testing.T) DownloadFailureJournalConfig {
	t.Helper()
	c := DownloadFailureJournalConfig{Path: filepath.Join(t.TempDir(), "failure.jsonl"), Installation: "installation_test", ServerUUID: "11111111-2222-4333-8444-555555555555", Database: "evidence_test", MaxBytes: 4096}
	if err := os.WriteFile(c.Path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	return c
}

func failureJournalFixture(t *testing.T) *DownloadFailureJournal {
	t.Helper()
	j, err := NewDownloadFailureJournal(failureJournalConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	return j
}

func journalReference() DownloadFailureReference {
	return DownloadFailureReference{OperationID: "sop_11111111-2222-4333-8444-555555555555", IntentAuditID: 42, ClaimSHA256: strings.Repeat("a", 64)}
}

func TestDownloadFailureJournalBoundedRecord(t *testing.T) {
	for _, correlated := range []bool{false, true} {
		t.Run(map[bool]string{false: "public_failure", true: "committed_result_failure"}[correlated], func(t *testing.T) {
			j := failureJournalFixture(t)
			ctx := context.Background()
			code := ErrUnavailable.Error()
			ref := journalReference()
			if correlated {
				ctx = context.WithValue(ctx, downloadFailureReferenceKey{}, ref)
				code = "download_result_audit_or_release_failed"
			}
			if err := j.Append(ctx, journalEvidence, code); err != nil || j.Check() != nil {
				t.Fatal("durable append rejected", err)
			}
			raw, err := os.ReadFile(j.config.Path)
			if err != nil || len(raw) > 2049 || bytes.Count(raw, []byte{'\n'}) != 1 {
				t.Fatal("journal framing", err)
			}
			var entry recoveryAuditJournalEntry
			if json.Unmarshal(raw, &entry) != nil || entry.Kind != "evidence_download_failure" || entry.Download == nil || entry.Bootstrap != nil || entry.Authority != nil || entry.Revocation != nil {
				t.Fatal("wrong record kind")
			}
			r := entry.Download
			if r.SchemaVersion != "system-backup-download-failure.v1" || r.Installation != j.config.Installation || r.ServerUUID != j.config.ServerUUID || r.Database != j.config.Database || r.EvidenceID != journalEvidence || r.Code != code || r.RecordedAt.IsZero() {
				t.Fatal("diagnostic identity/correlation lost")
			}
			if correlated && (r.Reference == nil || *r.Reference != ref) || !correlated && r.Reference != nil {
				t.Fatal("incorrect committed reference")
			}
		})
	}
}

func TestDownloadFailureJournalRequiresProvisionedFile(t *testing.T) {
	for _, mode := range []string{"missing", "relative", "directory", "partial_line", "installation", "server", "database", "small", "large", "no_headroom"} {
		t.Run(mode, func(t *testing.T) {
			c := failureJournalConfig(t)
			switch mode {
			case "missing":
				os.Remove(c.Path)
			case "relative":
				c.Path = "failure.jsonl"
			case "directory":
				c.Path = filepath.Dir(c.Path)
			case "partial_line":
				if err := os.WriteFile(c.Path, []byte(`{"partial":`), 0600); err != nil {
					t.Fatal(err)
				}
			case "installation":
				c.Installation = ""
			case "server":
				c.ServerUUID = "unverified"
			case "database":
				c.Database = ""
			case "small":
				c.MaxBytes = 4095
			case "large":
				c.MaxBytes = 1<<30 + 1
			case "no_headroom":
				if err := os.WriteFile(c.Path, bytes.Repeat([]byte{'\n'}, 2048), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if j, err := NewDownloadFailureJournal(c); err == nil {
				j.Close()
				t.Fatal("unsafe journal accepted")
			}
			if mode == "missing" {
				if _, err := os.Stat(c.Path); !os.IsNotExist(err) {
					t.Fatal("missing journal was created")
				}
			}
		})
	}
}

func TestDownloadFailureJournalStickyDenial(t *testing.T) {
	for _, mode := range []string{"nil_context", "canceled", "evidence", "private_error", "missing_reference", "operation", "audit", "claim_hash", "write_failure"} {
		t.Run(mode, func(t *testing.T) {
			j := failureJournalFixture(t)
			ctx := context.Background()
			ref := journalReference()
			id, code := journalEvidence, ErrUnavailable.Error()
			switch mode {
			case "nil_context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "evidence":
				id = "PRIVATE request"
			case "private_error":
				code = "PRIVATE provider error/token"
			case "missing_reference":
				code = "download_result_audit_or_release_failed"
			case "operation":
				ref.OperationID = "PRIVATE operation"
			case "audit":
				ref.IntentAuditID = 9007199254740992
			case "claim_hash":
				ref.ClaimSHA256 = "PRIVATE claim"
			case "write_failure":
				j.journal.file.Close()
			}
			if mode == "operation" || mode == "audit" || mode == "claim_hash" {
				ctx = context.WithValue(ctx, downloadFailureReferenceKey{}, ref)
			}
			j.Report(ctx, id, code)
			if j.Check() == nil || j.Append(context.Background(), journalEvidence, ErrUnavailable.Error()) == nil {
				t.Fatal("failed sink resumed")
			}
			raw, err := os.ReadFile(j.config.Path)
			if err != nil || len(raw) != 0 {
				t.Fatal("invalid/private facts written", err)
			}
		})
	}
}

// Windows denies renaming an os.OpenFile handle without FILE_SHARE_DELETE.
// Reopen the SAME old file after the rename to construct the relevant observed
// state portably: an append handle to the old identity, and a replacement at
// the original path. Equal bytes/size ensure identity, not size, detects it.
func replaceFailureJournalPath(t *testing.T, j *DownloadFailureJournal) []byte {
	t.Helper()
	original, err := j.journal.file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(j.config.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.journal.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(j.config.Path, j.config.Path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(j.config.Path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	retained, err := os.OpenFile(j.config.Path+".old", os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	j.journal.file = retained // fixture only: do not poison via journal.Close
	oldInfo, oldErr := retained.Stat()
	newInfo, newErr := os.Lstat(j.config.Path)
	if oldErr != nil || newErr != nil || !os.SameFile(original, oldInfo) || os.SameFile(oldInfo, newInfo) || oldInfo.Size() != newInfo.Size() || oldInfo.Size() != j.journal.size || j.journal.poisoned.Load() {
		t.Fatal("replacement fixture did not preserve the old handle identity and equal-size new path")
	}
	return raw
}

func TestDownloadFailureJournalTamperAndCapacity(t *testing.T) {
	for _, mode := range []string{"truncate", "foreign_append", "replace", "replace_append", "capacity", "close"} {
		t.Run(mode, func(t *testing.T) {
			j := failureJournalFixture(t)
			if err := j.Append(context.Background(), journalEvidence, ErrUnavailable.Error()); err != nil {
				t.Fatal(err)
			}
			var replaced []byte
			switch mode {
			case "truncate":
				if err := os.Truncate(j.config.Path, 0); err != nil {
					t.Fatal(err)
				}
			case "foreign_append":
				f, err := os.OpenFile(j.config.Path, os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteString("foreign\n")
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "replace", "replace_append":
				replaced = replaceFailureJournalPath(t, j)
				if mode == "replace_append" && j.Append(context.Background(), journalEvidence, ErrUnavailable.Error()) == nil {
					t.Fatal("append accepted a replaced path without a prior Check")
				}
			case "capacity":
				for n := 0; n < 20 && j.Check() == nil; n++ {
					if err := j.Append(context.Background(), journalEvidence, ErrUnavailable.Error()); err != nil {
						t.Fatal(err)
					}
				}
			case "close":
				if err := j.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if j.Check() == nil || j.Append(context.Background(), journalEvidence, ErrUnavailable.Error()) == nil {
				t.Fatal("unsafe sink remained usable")
			}
			info, err := os.Stat(j.config.Path)
			if err != nil || info.Size() > j.config.MaxBytes {
				t.Fatal("capacity exceeded", err)
			}
			if replaced != nil {
				for _, path := range []string{j.config.Path, j.config.Path + ".old"} {
					raw, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(raw, replaced) {
						t.Fatal("replacement rejection wrote to a journal file", err)
					}
				}
			}
		})
	}
}

func TestDownloadFailureJournalBusyDoesNotBlockAuthority(t *testing.T) {
	j := failureJournalFixture(t)
	j.journal.mu.Lock()
	done := make(chan error, 1)
	go func() { done <- j.Check() }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("busy persistence admitted")
		}
	case <-time.After(2 * time.Second):
		t.Error("readiness waited behind fsync")
	}
	j.journal.mu.Unlock()
	if j.Check() != nil {
		t.Fatal("busy check permanently poisoned healthy journal")
	}
}

func TestDownloadFailureJournalPrivateModes(t *testing.T) {
	for _, mode := range []os.FileMode{0600, 0640, 0660, 0610, 0607, 0750, 0644, 0000} {
		t.Run(mode.String(), func(t *testing.T) {
			if downloadFailurePrivateMode(mode) != (mode == 0600 || mode == 0640) {
				t.Fatal("unsafe journal permission mode", mode)
			}
		})
	}
}

func TestJournaledDownloadRuntimeFailureGuard(t *testing.T) {
	cfg, x, requests := downloadRuntimeFixture(t)
	c := failureJournalConfig(t)
	cfg.Authority.Registry.ServerUUID, cfg.Authority.Registry.Database = c.ServerUUID, c.Database
	// A pre-existing arbitrary callback cannot replace the durable sink.
	if r, err := NewJournaledDownloadRuntime(cfg, c); err == nil {
		r.Close()
		t.Fatal("callback override accepted")
	}
	cfg.Failure = nil
	r, err := NewJournaledDownloadRuntime(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.CheckFailurePersistence() != nil || r.authority.journal != r.journal {
		t.Fatal("journal not bound to provider authority")
	}
	// A failure latched after request creation prevents HTTP, authentication and
	// a later provider authorization; no downstream SQL or network is attempted.
	r.journal.Report(context.Background(), journalEvidence, "PRIVATE error")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, x.f.request)
	if w.Code != 503 || r.CheckFailurePersistence() == nil {
		t.Fatal("unhealthy runtime stayed ready")
	}
	if _, _, err = r.authority.AuthenticateContext(x.f.request); err == nil {
		t.Fatal("unhealthy sink authenticated")
	}
	x.f.a.journal = r.journal
	before := x.f.db.begins
	if _, err = x.f.a.AuthorizeS3(x.f.ctx, S3Scope{Ref: x.f.record.Ref, Operation: S3Stat}); err != ErrDenied || x.f.db.begins != before || requests.Load() != 0 {
		t.Fatal("unhealthy sink reached SQL/provider", err)
	}
	r.Close()
	if r.CheckFailurePersistence() == nil {
		t.Fatal("closed runtime ready")
	}
}
