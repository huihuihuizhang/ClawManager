package systembackupevidence

import (
	"context"
	"database/sql"
	"reflect"
	"strconv"
	"sync"
	"time"

	pd "clawreef/internal/systembackupproducer"
	sec "clawreef/internal/systembackupsecurity"
)

// One necessary Policy.Lock component, not a complete GC policy or grant. It
// retains all C1 rows and verifies the original capability binding and expired
// C1 protections. Current GC authority, complete metadata/DDL freeze, other
// evidence/logical/catalog/import dependencies and physical capacity are still
// required. No current producer write grant is manufactured or renewed.
type DownloadGCProducerEligibilityConfig struct {
	Database           sec.DatabaseIdentity
	Installation, Root string
}

type SQLDownloadGCProducerEligibility struct {
	c DownloadGCProducerEligibilityConfig
}

func NewSQLDownloadGCProducerEligibility(c DownloadGCProducerEligibilityConfig) (*SQLDownloadGCProducerEligibility, error) {
	if c.Database.ServerUUID == "" || !gcSQLName.MatchString(c.Database.Database) || !installationPattern.MatchString(c.Installation) || !safeKey(c.Root) {
		return nil, ErrDenied
	}
	return &SQLDownloadGCProducerEligibility{c: c}, nil
}

const downloadGCProducerTablesSQL = `SELECT TABLE_NAME,TABLE_TYPE,COALESCE(ENGINE,'') FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('system_backup_producer_evidence_bindings','system_backup_producer_evidence_refs','system_backup_producer_result_receipts','system_backup_producer_runs') ORDER BY BINARY TABLE_NAME`

func gcProducerTables(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, downloadGCProducerTablesSQL)
	if err != nil {
		return ErrDenied
	}
	defer rows.Close()
	want := map[string]bool{}
	for _, table := range taskDownloadSystemProducerTables {
		want[table] = true
	}
	for rows.Next() {
		var table, kind, engine string
		if rows.Scan(&table, &kind, &engine) != nil || !want[table] || kind != "BASE TABLE" || engine != "InnoDB" {
			return ErrDenied
		}
		delete(want, table)
	}
	if len(want) != 0 || rows.Err() != nil || rows.Close() != nil {
		return ErrDenied
	}
	return nil
}

type gcProducerFacts struct {
	receipts, references   string
	run, history           string
	version                string
	receiptCount, refCount int
}

func gcProducerFold(prior, table string, n int, record any) string {
	return hash(canonical(struct {
		Prior, Table, Body string
		Count              int
	}{prior, table, hash(canonical(record)), n}))
}

// The reader uses only the shared closed SQL projections and strict C1 record
// codec. It has no sessions, user RBAC, admission, provider or grant methods in
// this component; authentication remains the collector's mandatory GC policy.
func (s *SQLDownloadGCProducerEligibility) reader() *SQLTaskDownloadOwners {
	return &SQLTaskDownloadOwners{c: SQLTaskDownloadOwnersConfig{Registry: SQLRegistry{Installation: s.c.Installation, ServerUUID: s.c.Database.ServerUUID, Database: s.c.Database.Database}}, producer: true, producerRoot: s.c.Root}
}

func gcProducerHistory(h pd.HistoricalBindingRecord, scope DownloadRetentionGCScope, root string, now time.Time) error {
	i, b := scope.Evidence, h.Evidence
	created, _ := h.CreatedAt.Time()
	deadline, _ := h.OwnerWriteExpiresAt.Time()
	retention, _ := h.RetentionExpiresAt.Time()
	observation, _ := h.ObservationExpiresAt.Time()
	key, err := keyFor(root, i)
	if err != nil || string(h.RelativeKey) != key || string(b.RelativeKeyHash) != hash([]byte(key)) ||
		b.OwnerType != "system" || string(b.OwnerID) != scope.Installation || string(b.EvidenceID) != i.ID || b.EvidenceType != "capability_snapshot" || b.ImmutableVersion != nil ||
		b.Classification != i.Classification || string(b.ContentHash) != i.ContentHash || string(b.ContentBytes) != strconv.FormatInt(i.ContentSize, 10) || string(b.ManifestHash) != scope.ManifestSHA256 ||
		!downloadAdmissionContentTime(created) || !created.Equal(scope.EvidenceCreatedAt) || created.After(scope.AdmittedAt) ||
		!downloadAdmissionContentTime(deadline) || !created.Before(deadline) || deadline.After(now) ||
		!downloadAdmissionContentTime(retention) || retention.Before(deadline) || retention.After(now) || !downloadAdmissionContentTime(observation) || observation.After(now) {
		return ErrDenied
	}
	return nil
}

func gcProducerPair(run pd.RunRecord, h pd.HistoricalBindingRecord) error {
	if !oneOf(run.State, "committed", "superseded") || run.ObservedAt == nil || run.ObservationExpiresAt == nil ||
		run.RunID != h.RunID || run.GrantID != h.GrantID || run.GrantGeneration != h.GrantGeneration || run.TargetHash != h.TargetHash || run.InputHash != h.InputHash || run.EvidenceID != h.Evidence.EvidenceID ||
		run.OwnerWriteExpiresAt != h.OwnerWriteExpiresAt || *run.ObservedAt != h.ObservedAt || *run.ObservationExpiresAt != h.ObservationExpiresAt {
		return ErrDenied
	}
	return nil
}

func (s *SQLDownloadGCProducerEligibility) read(ctx context.Context, tx *sql.Tx, scope DownloadRetentionGCScope, now time.Time, original *gcProducerFacts) (gcProducerFacts, error) {
	var out gcProducerFacts
	var server, database string
	if tx.QueryRowContext(ctx, downloadGCTaskDatabaseSQL).Scan(&server, &database) != nil || server != s.c.Database.ServerUUID || database != s.c.Database.Database || gcProducerTables(ctx, tx) != nil {
		return out, ErrDenied
	}
	r := s.reader()
	definitions := producerDownloadDefinitions()
	var hint pd.HistoricalBindingRecord
	if original == nil {
		// A nonlocking hint avoids acquiring L4 before L3. Every hint fact is
		// independently compared with the later locked historical binding.
		rows, err := r.producerRows(ctx, tx, definitions[2], scope.Evidence, false, new(int))
		if err != nil || len(rows) != 1 {
			return out, ErrDenied
		}
		hint = *rows[0].(*pd.HistoricalBindingRecord)
	} else {
		// No new hint/snapshot on recheck. The original digest selects no keys.
		// Receipt matching is deferred until the existing L4 keys are reread.
	}
	count := 0
	var pendingReceipts string
	receiptCount := 0
	readReceipts := func(h *pd.HistoricalBindingRecord, run *pd.RunRecord, budget *int) (string, int, string, error) {
		root, n, version := "", 0, ""
		_, err := r.producerRowsVisit(ctx, tx, definitions[0], scope.Evidence, true, budget, func(record any) error {
			v := record.(*pd.ReceiptRecord)
			retention, _ := v.RetentionExpiresAt.Time()
			committed, _ := v.CommittedAt.Time()
			if !downloadAdmissionContentTime(retention) || retention.After(now) || !downloadAdmissionContentTime(committed) || committed.After(now) {
				return ErrDenied
			}
			if h != nil {
				b := v.Request.Evidence
				expectedVersion, versionErr := v.Request.ExpectedEvidenceVersion.Uint64()
				if versionErr != nil || expectedVersion > uint64(scope.EvidenceRowVersion) {
					return ErrDenied
				}
				if b.ImmutableVersion != nil {
					if string(*b.ImmutableVersion) == "null" || !s3Token([]byte(*b.ImmutableVersion), 1, 256) {
						return ErrDenied
					}
					if version != "" && version != string(*b.ImmutableVersion) {
						return ErrDenied
					}
					version = string(*b.ImmutableVersion)
				}
				b.ImmutableVersion = nil
				digests, err := pd.ResultHashes(v.Request)
				if err != nil || digests.Target != h.TargetHash || b != h.Evidence || v.Request.RunID != h.RunID || v.Request.GrantID != h.GrantID || v.Request.GrantGeneration != h.GrantGeneration || v.Request.DomainEpoch != h.DomainEpoch ||
					!reflect.DeepEqual(v.Request.Admission, h.Admission) || v.Request.InputHash != h.InputHash || v.Request.ObservedAt != h.ObservedAt || v.Request.ObservationExpiresAt != h.ObservationExpiresAt || v.CommittedAt < h.CreatedAt || run != nil && v.Request.TargetGeneration != run.TargetGeneration {
					return ErrDenied
				}
			}
			n++
			root = gcProducerFold(root, definitions[0].table, n, v)
			return nil
		})
		return root, n, version, err
	}
	var err error
	if original == nil {
		if gcProducerHistory(hint, scope, s.c.Root, now) != nil {
			return out, ErrDenied
		}
		pendingReceipts, receiptCount, _, err = readReceipts(&hint, nil, &count)
	} else {
		pendingReceipts, receiptCount, _, err = readReceipts(nil, nil, &count)
	}
	if err != nil || receiptCount == 0 {
		return out, ErrDenied
	}
	var run *pd.RunRecord
	var history *pd.HistoricalBindingRecord
	for _, d := range definitions {
		if d.stage != 4 {
			continue
		}
		rows, err := r.producerRows(ctx, tx, d, scope.Evidence, true, &count)
		if err != nil || len(rows) != 1 {
			return out, ErrDenied
		}
		if v, ok := rows[0].(*pd.RunRecord); ok {
			run = v
		} else {
			history = rows[0].(*pd.HistoricalBindingRecord)
		}
	}
	if run == nil || history == nil || gcProducerHistory(*history, scope, s.c.Root, now) != nil || gcProducerPair(*run, *history) != nil || original == nil && !reflect.DeepEqual(hint, *history) {
		return out, ErrDenied
	}
	out.run, out.history = hash(canonical(run)), hash(canonical(history))
	// The same L3 predicate/range was already locked. Re-read CURRENT receipts
	// after the independently locked owner, never an RR consistent snapshot.
	out.receipts, out.receiptCount, out.version, err = readReceipts(history, run, new(int))
	if err != nil || out.receipts != pendingReceipts || out.receiptCount != receiptCount || out.version == "" {
		return out, ErrDenied
	}
	_, err = r.producerRowsVisit(ctx, tx, definitions[3], scope.Evidence, true, &count, func(record any) error {
		v := record.(*pd.ReferenceRecord)
		created, _ := v.CreatedAt.Time()
		until, _ := v.ProtectedUntil.Time()
		if !downloadAdmissionContentTime(created) || created.Before(scope.EvidenceCreatedAt) || created.After(now) || !downloadAdmissionContentTime(until) || until.Before(created) || until.After(now) {
			return ErrDenied
		}
		out.refCount++
		out.references = gcProducerFold(out.references, definitions[3].table, out.refCount, v)
		return nil
	})
	if err != nil {
		return out, ErrDenied
	}
	return out, nil
}

type gcProducerGuardState struct {
	sync.Mutex
	failed bool
	lastAt time.Time
}
type DownloadGCProducerEligibilityGuard struct {
	source   *SQLDownloadGCProducerEligibility
	tx       *sql.Tx
	scope    DownloadRetentionGCScope
	original gcProducerFacts
	state    *gcProducerGuardState
}

func (DownloadGCProducerEligibilityGuard) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (DownloadGCProducerEligibilityGuard) String() string {
	return "DownloadGCProducerEligibilityGuard"
}
func (DownloadGCProducerEligibilityGuard) GoString() string {
	return "DownloadGCProducerEligibilityGuard"
}

func (s *SQLDownloadGCProducerEligibility) Lock(ctx context.Context, tx *sql.Tx, scope DownloadRetentionGCScope, now time.Time) (*DownloadGCProducerEligibilityGuard, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || tx == nil || scope.Database != s.c.Database || scope.Installation != s.c.Installation ||
		!scope.Evidence.validExternal() || scope.Evidence.Installation != s.c.Installation || scope.Evidence.OwnerID != s.c.Installation || scope.Evidence.OwnerType != "system" || scope.Evidence.Type != "capability_snapshot" || scope.Evidence.Media != "application/json" || !oneOf(scope.Evidence.Classification, "confidential", "sensitive") || scope.Evidence.ContentSize > MaxCapabilityContent ||
		!digestPattern.MatchString(scope.PrincipalSHA256) || !digestPattern.MatchString(scope.RequestHash) || !digestPattern.MatchString(scope.ManifestSHA256) || !downloadAdmissionOperationID.MatchString(scope.Operation) || !downloadAdmissionOperationID.MatchString(scope.WorkerOperation) || scope.Operation == scope.WorkerOperation ||
		scope.OperationID < 1 || scope.EvidenceID < 1 || scope.EvidenceRowVersion < 1 || scope.EvidenceRowVersion > 9007199254740991 || scope.ActorID < 1 || scope.IntentAuditID < 1 || scope.ResultAuditID < 1 || scope.IntentAuditID == scope.ResultAuditID ||
		!downloadAdmissionContentTime(now) || !downloadAdmissionContentTime(scope.EvidenceCreatedAt) || !downloadAdmissionContentTime(scope.AdmittedAt) || scope.EvidenceCreatedAt.After(scope.AdmittedAt) || scope.AdmittedAt.After(now) ||
		!downloadAdmissionContentTime(scope.RetainUntil) || !downloadAdmissionContentTime(scope.MinimumRetainUntil) || scope.RetainUntil.Before(scope.AdmittedAt) || scope.MinimumRetainUntil.Before(scope.AdmittedAt) || scope.RetainUntil.After(now) || scope.MinimumRetainUntil.After(now) {
		return nil, ErrDenied
	}
	facts, err := s.read(ctx, tx, scope, now, nil)
	if err != nil {
		return nil, ErrDenied
	}
	return &DownloadGCProducerEligibilityGuard{source: s, tx: tx, scope: scope, original: facts, state: &gcProducerGuardState{lastAt: now}}, nil
}

func (g *DownloadGCProducerEligibilityGuard) Recheck(ctx context.Context, tx *sql.Tx, scope DownloadRetentionGCScope, now time.Time) error {
	if g == nil || g.state == nil {
		return ErrDenied
	}
	g.state.Lock()
	defer g.state.Unlock()
	fail := func() error { g.state.failed = true; return ErrDenied }
	if g.state.failed || g.source == nil || ctx == nil || ctx.Err() != nil || tx != g.tx || scope != g.scope || !downloadAdmissionContentTime(now) || now.Before(g.state.lastAt) {
		return fail()
	}
	facts, err := g.source.read(ctx, tx, scope, now, &g.original)
	if err != nil || facts != g.original {
		return fail()
	}
	g.state.lastAt = now
	return nil
}

var _ DownloadRetentionGCGuard = (*DownloadGCProducerEligibilityGuard)(nil)
