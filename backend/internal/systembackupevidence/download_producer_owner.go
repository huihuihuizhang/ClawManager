package systembackupevidence

import (
	"bytes"
	"context"
	"database/sql"
	"reflect"
	"strconv"
	"strings"

	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

// SQLDownloadOwners adds historical producer capability evidence to the four
// task owners. It never derives a write deadline for other system evidence,
// staging/resources, promotion or catalog from a read lease or parent task.
type SQLDownloadOwnersConfig struct {
	Registry                SQLRegistry
	Sessions                *sec.SQLLoginSessions
	RegistryDirectory, Root string
}
type SQLDownloadOwners struct{ *SQLTaskDownloadOwners }

func NewSQLDownloadOwners(c SQLDownloadOwnersConfig) (*SQLDownloadOwners, error) {
	if !safeKey(c.Root) {
		return nil, ErrDownloadAdmissionNotReady
	}
	s, err := NewSQLTaskDownloadOwners(SQLTaskDownloadOwnersConfig{Registry: c.Registry, Sessions: c.Sessions, RegistryDirectory: c.RegistryDirectory})
	if err != nil {
		return nil, err
	}
	s.producer = true
	s.producerRoot = c.Root
	return &SQLDownloadOwners{s}, nil
}

type producerDownloadDefinition struct {
	table, fields, order string
	stage, limit         int
}

// The projections match producer-authority-persistence.json and D's strict
// StoredRecord decoder. The canonical bytes alone never authorize a read.
func producerDownloadDefinitions() []producerDownloadDefinition {
	return []producerDownloadDefinition{
		{"system_backup_producer_result_receipts", "scope_key scope_bytes receipt_key_hash request_hash run_id evidence_id target_hash result_version committed_at retention_expires_at charged_bytes record_bytes record_sha256", "scope_key,receipt_key_hash", 3, 98304},
		{"system_backup_producer_runs", "scope_key run_id grant_id grant_generation target_hash target_generation evidence_id owner_write_expires_at observed_at observation_expires_at state row_version record_bytes record_sha256", "scope_key,run_id", 4, 16384},
		{"system_backup_producer_evidence_bindings", "scope_key scope_bytes run_id evidence_id grant_id grant_generation owner_write_expires_at observation_expires_at retention_expires_at record_bytes record_sha256", "scope_key,evidence_id", 4, 32768},
		{"system_backup_producer_evidence_refs", "scope_key evidence_id reference_kind reference_key_hash protected_until record_bytes record_sha256", "scope_key,reference_kind,reference_key_hash", 5, 8192},
	}
}

func producerDownloadSQL(d producerDownloadDefinition, locking bool) string {
	columns := strings.Fields(d.fields)
	for n, c := range columns {
		if c == "record_bytes" {
			columns[n] = "IF(OCTET_LENGTH(record_bytes) BETWEEN 1 AND " + strconv.Itoa(d.limit) + ",record_bytes,NULL)"
		}
	}
	q := "SELECT " + strings.Join(columns, ",") + " FROM " + d.table + " WHERE evidence_id=? ORDER BY " + d.order + " LIMIT 10001"
	if locking {
		q += " FOR UPDATE"
	}
	return q
}

func (s *SQLTaskDownloadOwners) producerRows(ctx context.Context, tx *sql.Tx, d producerDownloadDefinition, i Identity, locking bool, count *int) ([]any, error) {
	return s.producerRowsVisit(ctx, tx, d, i, locking, count, nil)
}

// Receipt/ref scans validate one bounded record at a time. Only the unique
// run/history owner rows are retained; a 10,000-row prefix must not retain
// 10,000 complete canonical result bodies in memory.
func (s *SQLTaskDownloadOwners) producerRowsVisit(ctx context.Context, tx *sql.Tx, d producerDownloadDefinition, i Identity, locking bool, count *int, visit func(any) error) ([]any, error) {
	if !s.producer || !s.downloadIdentity(i) || i.OwnerType != "system" {
		return nil, ErrDownloadAdmissionNotReady
	}
	rows, err := tx.QueryContext(ctx, producerDownloadSQL(d, locking), i.ID)
	if err != nil {
		return nil, ErrDownloadAdmissionNotReady
	}
	defer rows.Close()
	fields := strings.Fields(d.fields)
	scope := pd.Scope{ServerUUID: pd.ServerUUID(s.c.Registry.ServerUUID), Database: pd.Database(s.c.Registry.Database), Installation: pd.Installation(i.Installation)}
	var result []any
	var previous []byte
	for rows.Next() {
		if *count >= maxTaskDownloadReferences {
			return nil, ErrIntegrity
		}
		values, args := make([]any, len(fields)), make([]any, len(fields))
		for n := range values {
			args[n] = &values[n]
		}
		if rows.Scan(args...) != nil {
			return nil, ErrIntegrity
		}
		stored := pd.StoredRecord{Table: d.table, Columns: map[string]any{}}
		for n, field := range fields {
			stored.Columns[field] = values[n]
		}
		var record any
		switch d.stage {
		case 3:
			record = new(pd.ReceiptRecord)
		case 4:
			if strings.HasSuffix(d.table, "_runs") {
				record = new(pd.RunRecord)
			} else {
				record = new(pd.HistoricalBindingRecord)
			}
		case 5:
			record = new(pd.ReferenceRecord)
		}
		if pd.DecodeStoredRecord(stored, scope, record) != nil {
			return nil, ErrIntegrity
		}
		key, ok := stored.Columns["scope_key"].([]byte)
		if !ok || len(key) != 32 {
			return nil, ErrIntegrity
		}
		key = append([]byte{}, key...)
		var id pd.EvidenceID
		switch r := record.(type) {
		case *pd.ReceiptRecord:
			id = r.Request.Evidence.EvidenceID
			key = append(key, []byte(r.ReceiptKeyHash)...)
		case *pd.RunRecord:
			id = r.EvidenceID
			key = append(key, []byte(r.RunID)...)
		case *pd.HistoricalBindingRecord:
			id = r.Evidence.EvidenceID
			key = append(key, []byte(id)...)
		case *pd.ReferenceRecord:
			id = r.EvidenceID
			// MySQL sorts this ENUM by its declared ordinal, not lexical text.
			rank := map[string]byte{"producer_result": 1, "producer_receipt": 2, "bootstrap_candidate": 3, "hold": 4}[r.ReferenceKind]
			if rank == 0 {
				return nil, ErrIntegrity
			}
			key = append(append(key, rank), []byte(r.ReferenceKeyHash)...)
		}
		if string(id) != i.ID || previous != nil && bytes.Compare(key, previous) <= 0 {
			return nil, ErrIntegrity
		}
		previous = key
		*count++
		if visit != nil {
			if err := visit(record); err != nil {
				return nil, err
			}
		}
		if d.stage == 4 {
			if len(result) != 0 {
				return nil, ErrIntegrity
			}
			result = append(result, record)
		}
	}
	if rows.Err() != nil || rows.Close() != nil {
		return nil, ErrDownloadAdmissionNotReady
	}
	return result, nil
}

func (s *SQLTaskDownloadOwners) producerOwner(ctx context.Context, tx *sql.Tx, i Identity, locking bool, count *int) (pd.HistoricalBindingRecord, error) {
	if !s.producer || !s.downloadIdentity(i) || i.OwnerType != "system" || i.Type != "" && i.Type != "capability_snapshot" {
		return pd.HistoricalBindingRecord{}, ErrDownloadAdmissionNotReady
	}
	var run *pd.RunRecord
	var history *pd.HistoricalBindingRecord
	for _, d := range producerDownloadDefinitions() {
		if d.stage != 4 {
			continue
		}
		r, err := s.producerRows(ctx, tx, d, i, locking, count)
		if err != nil || len(r) != 1 {
			return pd.HistoricalBindingRecord{}, ErrIntegrity
		}
		if v, ok := r[0].(*pd.RunRecord); ok {
			run = v
		} else {
			history = r[0].(*pd.HistoricalBindingRecord)
		}
	}
	if run == nil || history == nil || run.RunID != history.RunID || run.GrantID != history.GrantID || run.GrantGeneration != history.GrantGeneration || run.TargetHash != history.TargetHash || run.InputHash != history.InputHash || run.OwnerWriteExpiresAt != history.OwnerWriteExpiresAt || run.ObservedAt == nil || run.ObservationExpiresAt == nil || *run.ObservedAt != history.ObservedAt || *run.ObservationExpiresAt != history.ObservationExpiresAt || history.Evidence.OwnerType != "system" || string(history.Evidence.OwnerID) != i.Installation || history.Evidence.EvidenceType != "capability_snapshot" || history.Evidence.ImmutableVersion != nil || i.Classification != "" && history.Evidence.Classification != i.Classification {
		return pd.HistoricalBindingRecord{}, ErrIntegrity
	}
	created, _ := history.CreatedAt.Time()
	deadline, _ := history.OwnerWriteExpiresAt.Time()
	if !downloadAdmissionContentTime(created) || !downloadAdmissionContentTime(deadline) || !created.Before(deadline) {
		return pd.HistoricalBindingRecord{}, ErrIntegrity
	}
	return *history, nil
}

func (s *SQLTaskDownloadOwners) matchProducer(ctx context.Context, tx *sql.Tx, r Record) error {
	h, err := s.producerOwner(ctx, tx, r.Manifest.Identity, false, new(int))
	if err != nil {
		return err
	}
	created, _ := h.CreatedAt.Time()
	retention, _ := h.RetentionExpiresAt.Time()
	deadline, _ := h.OwnerWriteExpiresAt.Time()
	if !r.CreatedAt.Equal(created) || !r.OwnerDeadline.Equal(deadline) || r.ExpiresAt.Before(retention) {
		return ErrIntegrity
	}
	channel := ProducerEvidenceChannel{Root: s.producerRoot, Store: KeyRef{string(h.Evidence.StoreIdentityHash), string(h.Evidence.StoreRefVersion)}, Write: KeyRef{string(h.Evidence.WriteIdentityHash), string(h.Evidence.WriteRefVersion)}, RecoveryProfileHash: string(h.Evidence.RecoveryProfileHash)}
	// Historical binding is the immutable pending record. Only compare using a
	// detached copy; never erase the actual ready object's immutable version.
	pending := r
	pending.State, pending.Ref.ImmutableVersion = "pending", ""
	if pending.Ref.RelativeKey != string(h.RelativeKey) || MatchProducerBinding(pending, channel, h.Evidence) != nil {
		return ErrIntegrity
	}
	for _, d := range producerDownloadDefinitions() {
		if d.stage != 3 {
			continue
		}
		_, err := s.producerRowsVisit(ctx, tx, d, r.Manifest.Identity, false, new(int), func(record any) error {
			receipt := record.(*pd.ReceiptRecord)
			evidence := receipt.Request.Evidence
			if evidence.ImmutableVersion != nil && string(*evidence.ImmutableVersion) != r.Ref.ImmutableVersion {
				return ErrIntegrity
			}
			evidence.ImmutableVersion = nil
			digests, err := pd.ResultHashes(receipt.Request)
			if err != nil || digests.Target != h.TargetHash || !reflect.DeepEqual(receipt.Request.Admission, h.Admission) || receipt.Request.GrantID != h.GrantID || receipt.Request.GrantGeneration != h.GrantGeneration || receipt.Request.DomainEpoch != h.DomainEpoch || evidence != h.Evidence || receipt.Request.RunID != h.RunID || receipt.Request.InputHash != h.InputHash || receipt.Request.ObservedAt != h.ObservedAt || receipt.Request.ObservationExpiresAt != h.ObservationExpiresAt {
				return ErrIntegrity
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLTaskDownloadOwners) producerReferenceStage(ctx context.Context, tx *sql.Tx, installed map[string]bool, i Identity, stage int, locking bool, count *int) error {
	if i.OwnerType != "system" {
		return checkTaskDownloadProducerStage(ctx, tx, installed, i.ID, stage, locking)
	}
	if !s.producer || len(installed) != len(taskDownloadSystemProducerTables) {
		return ErrDownloadAdmissionNotReady
	}
	for _, d := range producerDownloadDefinitions() {
		if d.stage != stage {
			continue
		}
		if _, err := s.producerRows(ctx, tx, d, i, locking, count); err != nil {
			return err
		}
	}
	return nil
}
