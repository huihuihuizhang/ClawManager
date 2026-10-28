package db

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"regexp"
	"sort"
	"strings"
)

const reviewedRuntimeMigration = "109_backup_v2_add_system_backup_registration_runtime.sql"

// MigrationHistoryReview is constructed only by ParseMigrationHistoryReview.
// It records operator-reviewed source provenance, not SQL equivalence or backup
// admission. Neither the historical SQL nor historical ledger rows are written.
type MigrationHistoryReview struct {
	document migrationHistoryDocument
}

type migrationHistoryDocument struct {
	Version         int                      `json:"version"`
	ServerUUID      string                   `json:"server_uuid"`
	Database        string                   `json:"database"`
	CatalogSHA256   string                   `json:"catalog_sha256"`
	ReviewedBy      string                   `json:"reviewed_by"`
	ReviewReference string                   `json:"review_reference"`
	Decision        string                   `json:"decision"`
	ExpectedApplied []string                 `json:"expected_applied"`
	Pending         []string                 `json:"pending"`
	Historical      []migrationHistorySource `json:"historical"`
}

type migrationHistorySource struct {
	Filename            string `json:"filename"`
	SQLSHA256           string `json:"sql_sha256"`
	ProvenanceReference string `json:"provenance_reference"`
}

// ParseMigrationHistoryReview validates a digest-pinned, deployment-owned
// review and the exact original SQL bytes mounted alongside it. A review is an
// operator trust input like MigrationTarget, never a client/HTTP parameter.
// Its scope is deliberately limited to retaining reviewed historical entries
// while adding 080 to an otherwise fully applied current catalog.
func ParseMigrationHistoryReview(raw []byte, digest string, sources fs.FS) (*MigrationHistoryReview, error) {
	reject := errors.New("historical migration review or source evidence invalid")
	if len(raw) == 0 || len(raw) > 128*1024 || sources == nil || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(digest) {
		return nil, reject
	}
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != digest {
		return nil, reject
	}
	var doc migrationHistoryDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&doc) != nil || decoder.Decode(new(any)) != io.EOF || doc.Version != 1 || doc.Decision != "retain_history_without_replay" || !reviewText(doc.ReviewedBy) || !reviewText(doc.ReviewReference) {
		return nil, reject
	}
	catalog, err := EmbeddedMigrationCatalog()
	if err != nil || doc.CatalogSHA256 != catalog.Hash || len(doc.Pending) != 1 || doc.Pending[0] != reviewedRuntimeMigration || len(doc.Historical) == 0 || len(doc.Historical) > 64 {
		return nil, reject
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(doc.ServerUUID) || !regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`).MatchString(doc.Database) {
		return nil, reject
	}
	want := make(map[string]bool)
	known := make(map[string]bool)
	for _, name := range catalog.Filenames {
		known[name] = true
		if name != reviewedRuntimeMigration {
			want[name] = true
		}
	}
	if !known[reviewedRuntimeMigration] {
		return nil, reject
	}
	for _, source := range doc.Historical {
		if !regexp.MustCompile(`^[0-9]{3}_[A-Za-z0-9_]+\.sql$`).MatchString(source.Filename) || known[source.Filename] || want[source.Filename] || !reviewText(source.ProvenanceReference) {
			return nil, reject
		}
		f, err := sources.Open(source.Filename)
		if err != nil {
			return nil, reject
		}
		data, readErr := io.ReadAll(io.LimitReader(f, 1024*1024+1))
		closeErr := f.Close()
		h := sha256.Sum256(data)
		if readErr != nil || closeErr != nil || len(data) == 0 || len(data) > 1024*1024 || hex.EncodeToString(h[:]) != source.SQLSHA256 {
			return nil, reject
		}
		want[source.Filename] = true
	}
	if len(doc.ExpectedApplied) != len(want) {
		return nil, reject
	}
	for _, name := range doc.ExpectedApplied {
		if !want[name] {
			return nil, reject
		}
		delete(want, name)
	}
	return &MigrationHistoryReview{document: doc}, nil
}

func reviewText(s string) bool {
	return len(s) > 0 && len(s) <= 512 && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\r\n\x00")
}

func (r *MigrationHistoryReview) matchesTarget(target MigrationTarget) bool {
	return r != nil && r.document.Version == 1 && r.document.ServerUUID == target.ServerUUID && r.document.Database == target.Database && r.document.CatalogSHA256 == target.CatalogSHA256
}

func (r *MigrationHistoryReview) verifyLedger(applied map[string]struct{}) error {
	want := append([]string(nil), r.document.ExpectedApplied...)
	// A successful retry may contain 080, but no other extra or missing entry.
	if _, done := applied[reviewedRuntimeMigration]; done {
		want = append(want, reviewedRuntimeMigration)
	}
	got := make([]string, 0, len(applied))
	for name := range applied {
		got = append(got, name)
	}
	sort.Strings(want)
	sort.Strings(got)
	if len(want) != len(got) {
		return errors.New("reviewed migration ledger drift")
	}
	for i := range want {
		if want[i] != got[i] {
			return errors.New("reviewed migration ledger drift")
		}
	}
	return nil
}
