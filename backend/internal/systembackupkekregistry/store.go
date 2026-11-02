package systembackupkekregistry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

var ErrKEKFacts = errors.New("backup KEK facts unavailable")
var ErrKEKCoverage = errors.New("backup KEK source coverage incomplete")

var kekHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Bind never opens or commits a transaction. The original owner must acquire
// its domain, authorization, operation and existing-reference locks first.
// ReadSnapshot uses a short preparatory read transaction and grants nothing.
type SQLStore struct{}

type Bound struct {
	tx             SQLWriteView
	installationID string
	epoch          uint64
	original       Snapshot
}

func hashJSON(v any) ([]byte, string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, "", ErrKEKFacts
	}
	h := sha256.Sum256(raw)
	return raw, hex.EncodeToString(h[:]), nil
}

// semanticCoreHash excludes only the two redacted descriptions and their raw
// byte hashes. The original typed-reference bytes remain in core_json for the
// first admission and in each later admission observation. A change to a
// security-bearing reference field still changes this digest.
func semanticCoreHash(b Binding) (string, error) {
	if !validTypedReference(b.GenerateRef) || !validTypedReference(b.UnwrapRef) {
		return "", ErrKEKFacts
	}
	var err error
	b.GenerateRef.RawJSON, err = semanticReference(b.GenerateRef.RawJSON)
	if err != nil {
		return "", err
	}
	b.UnwrapRef.RawJSON, err = semanticReference(b.UnwrapRef.RawJSON)
	if err != nil {
		return "", err
	}
	b.GenerateRef.SHA256, b.UnwrapRef.SHA256 = "", ""
	_, digest, err := hashJSON(b)
	return digest, err
}

func validTypedReference(ref TypedReference) bool {
	if len(ref.RawJSON) == 0 || len(ref.RawJSON) > 16384 || !kekHash.MatchString(ref.SHA256) {
		return false
	}
	h := sha256.Sum256(ref.RawJSON)
	return hex.EncodeToString(h[:]) == ref.SHA256
}

// SameSecurityBinding compares two authenticated mappings for one immutable
// logical key. Only the redacted descriptions and their raw-byte digests may
// differ. The first mapping's exact bytes remain stored as provenance; a new
// admission stores its own exact bytes separately.
func SameSecurityBinding(a, b Binding) bool {
	x, err := semanticCoreHash(a)
	if err != nil {
		return false
	}
	y, err := semanticCoreHash(b)
	return err == nil && x == y
}

func semanticReference(raw []byte) ([]byte, error) {
	var ref map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &ref) != nil || ref == nil {
		return nil, ErrKEKFacts
	}
	delete(ref, "description_redacted")
	canonical, err := json.Marshal(ref)
	if err != nil {
		return nil, ErrKEKFacts
	}
	return canonical, nil
}

// BindingFingerprint matches C/A's JCS hash of the complete KeyBinding.
// The immutable core has a separate digest because it includes provider and
// source provenance beyond the key identity.
func BindingFingerprint(b Binding) (string, error) {
	raw, err := json.Marshal(map[string]string{
		"provider": b.Key.Provider, "identity_hash": b.Key.IdentityHash,
		"registry_version": b.Key.RegistryVersion, "provider_key_id": b.Key.ProviderKeyID,
		"provider_version": b.Key.ProviderVersion,
	})
	if err != nil {
		return "", ErrKEKFacts
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return "", ErrKEKFacts
	}
	h := sha256.Sum256(canonical)
	return hex.EncodeToString(h[:]), nil
}

func validPartition(p Partition) bool {
	switch p {
	case RetainedArtifacts, InflightAndUnknownWrites, HoldsAndCatalog, RestoreAndPrune:
		return true
	}
	return false
}

func present(v any) bool {
	if v == nil {
		return false
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !r.IsNil()
	}
	return true
}

// ReadSnapshot obtains comparison facts before A prepares independent source
// observations. The later Bind must compare every fact and the fence epoch in
// the original owner's transaction; this read never authorizes a write.
func (SQLStore) ReadSnapshot(ctx context.Context, db *sql.DB, installationID string) (Snapshot, error) {
	if ctx == nil || ctx.Err() != nil || db == nil || installationID == "" || len(installationID) > 128 {
		return Snapshot{}, ErrKEKFacts
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return Snapshot{}, err
	}
	defer tx.Rollback()
	s := Snapshot{InstallationID: installationID, Bindings: []BindingFacts{}, Coverage: []CoverageSource{}, References: []Reference{}}
	// A never-before-admitted installation has no fence yet. Keep its epoch at
	// zero and its coverage empty; Bind creates the fence in the original write
	// transaction and checks the same zero-epoch facts before any admission.
	if err = tx.QueryRowContext(ctx, `SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=? FOR SHARE`, installationID).Scan(&s.Epoch); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, ErrKEKFacts
	}
	if err = tx.QueryRowContext(ctx, `SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)`).Scan(&s.Database.ServerUUID, &s.Database.Database, &s.ObservedAt); err != nil || s.Database.ServerUUID == "" || s.Database.Database == "" || s.ObservedAt.IsZero() {
		return Snapshot{}, ErrKEKFacts
	}
	if err = readBindings(ctx, tx, &s, true); err != nil {
		return Snapshot{}, err
	}
	if err = readReferences(ctx, tx, &s, true); err != nil {
		return Snapshot{}, err
	}
	if err = readCoverage(ctx, tx, &s, true); err != nil {
		return Snapshot{}, err
	}
	if err = tx.Commit(); err != nil {
		return Snapshot{}, err
	}
	return cloneSnapshot(s), nil
}

// SameSnapshotFacts compares the fixed SQL facts while treating ObservedAt as
// the preparation sample time, not a persisted row. Bind samples a later SQL
// time and must not reject an otherwise unchanged source for that reason.
func SameSnapshotFacts(a, b Snapshot) bool {
	a.ObservedAt, b.ObservedAt = time.Time{}, time.Time{}
	return reflect.DeepEqual(a, b)
}

func (SQLStore) Bind(ctx context.Context, tx SQLWriteView, installationID string) (*Bound, LockedSnapshot, error) {
	if ctx == nil || ctx.Err() != nil || !present(tx) || installationID == "" || len(installationID) > 128 {
		return nil, LockedSnapshot{}, ErrKEKFacts
	}
	// The stable fence also protects an empty index against concurrent inserts.
	if _, err := tx.ExecContext(ctx, `INSERT IGNORE INTO system_backup_v2_kek_fences(installation_id,epoch) VALUES (?,0)`, installationID); err != nil {
		return nil, LockedSnapshot{}, err
	}
	b := &Bound{tx: tx, installationID: installationID}
	if err := tx.QueryRowContext(ctx, `SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=? FOR UPDATE`, installationID).Scan(&b.epoch); err != nil {
		return nil, LockedSnapshot{}, err
	}
	s := Snapshot{InstallationID: installationID, Epoch: b.epoch, Bindings: []BindingFacts{}, Coverage: []CoverageSource{}, References: []Reference{}}
	if err := tx.QueryRowContext(ctx, `SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)`).Scan(&s.Database.ServerUUID, &s.Database.Database, &s.ObservedAt); err != nil || s.Database.ServerUUID == "" || s.Database.Database == "" {
		return nil, LockedSnapshot{}, ErrKEKFacts
	}
	if err := readBindings(ctx, tx, &s, true); err != nil {
		return nil, LockedSnapshot{}, err
	}
	if err := readReferences(ctx, tx, &s, true); err != nil {
		return nil, LockedSnapshot{}, err
	}
	if err := readCoverage(ctx, tx, &s, true); err != nil {
		return nil, LockedSnapshot{}, err
	}
	b.original = cloneSnapshot(s)
	return b, LockedSnapshot{facts: cloneSnapshot(s)}, nil
}

func readBindings(ctx context.Context, tx SQLReadView, s *Snapshot, locked bool) error {
	query := `SELECT ` + bindingReadColumns + ` FROM system_backup_v2_kek_bindings WHERE installation_id=? ORDER BY identity_hash,registry_version`
	if locked {
		query += ` FOR SHARE`
	}
	rows, err := tx.QueryContext(ctx, query, s.InstallationID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		facts, err := scanBindingRow(rows, s.InstallationID)
		if err != nil {
			return err
		}
		s.Bindings = append(s.Bindings, facts)
	}
	return rows.Err()
}

func readCoverage(ctx context.Context, tx SQLReadView, s *Snapshot, locked bool) error {
	query := `SELECT partition_name,source_id,source_sha256,source_json FROM system_backup_v2_kek_coverage WHERE installation_id=? ORDER BY partition_name,source_id`
	if locked {
		query += ` FOR SHARE`
	}
	rows, err := tx.QueryContext(ctx, query, s.InstallationID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var partition, sourceID, digest string
		var raw []byte
		if rows.Scan(&partition, &sourceID, &digest, &raw) != nil {
			return ErrKEKFacts
		}
		var item CoverageSource
		if json.Unmarshal(raw, &item) != nil || item.Partition != Partition(partition) || item.SourceID != sourceID || !validPartition(item.Partition) {
			return ErrKEKFacts
		}
		canonical, actual, err := hashJSON(item)
		if err != nil || actual != digest || !bytes.Equal(canonical, raw) {
			return ErrKEKFacts
		}
		s.Coverage = append(s.Coverage, item)
	}
	return rows.Err()
}

func readReferences(ctx context.Context, tx SQLReadView, s *Snapshot, locked bool) error {
	query := `SELECT partition_name,source_record_id,source_record_version,identity_hash,registry_version,reference_state,reference_sha256,reference_json FROM system_backup_v2_kek_references WHERE installation_id=? ORDER BY partition_name,source_record_id,source_record_version`
	if locked {
		query += ` FOR SHARE`
	}
	rows, err := tx.QueryContext(ctx, query, s.InstallationID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var partition, sourceID, sourceVersion, identity, version, state, digest string
		var raw []byte
		if rows.Scan(&partition, &sourceID, &sourceVersion, &identity, &version, &state, &digest, &raw) != nil {
			return ErrKEKFacts
		}
		var item Reference
		if json.Unmarshal(raw, &item) != nil || item.Partition != Partition(partition) || item.SourceRecordID != sourceID || item.SourceRecordVersion != sourceVersion || item.Key.IdentityHash != identity || item.Key.RegistryVersion != version || item.State != ReferenceState(state) || !validPartition(item.Partition) {
			return ErrKEKFacts
		}
		canonical, actual, err := hashJSON(item)
		if err != nil || actual != digest || !bytes.Equal(canonical, raw) {
			return ErrKEKFacts
		}
		s.References = append(s.References, item)
	}
	return rows.Err()
}

func (b *Bound) Snapshot() LockedSnapshot {
	if b == nil {
		return LockedSnapshot{}
	}
	return LockedSnapshot{facts: cloneSnapshot(b.original)}
}

func (b *Bound) sqlNow(ctx context.Context) (time.Time, error) {
	var now time.Time
	if b == nil || b.tx == nil || b.tx.QueryRowContext(ctx, `SELECT UTC_TIMESTAMP(6)`).Scan(&now) != nil || now.IsZero() {
		return time.Time{}, ErrKEKFacts
	}
	return now, nil
}

func (b *Bound) advance(ctx context.Context) error {
	result, err := b.tx.ExecContext(ctx, `UPDATE system_backup_v2_kek_fences SET epoch=epoch+1 WHERE installation_id=? AND epoch=?`, b.installationID, b.epoch)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return ErrKEKFacts
	}
	b.epoch++
	return nil
}

// Recheck is called before the original owner's commit. It does not reacquire
// earlier domain locks, perform provider I/O, or turn a prepared candidate into
// an execution grant.
func (b *Bound) Recheck(ctx context.Context, prepared PreparedAdmission) error {
	if b == nil {
		return ErrKEKFacts
	}
	return b.RecheckWithReadView(ctx, b.tx, prepared)
}

// RecheckWithReadView accepts the original transaction's sealed read callback
// after its write capability has closed. It never reopens that capability or
// starts another transaction; bootstrap candidate final checks use this form.
func (b *Bound) RecheckWithReadView(ctx context.Context, read SQLReadView, prepared PreparedAdmission) error {
	if ctx == nil || ctx.Err() != nil || b == nil || !present(read) || !present(prepared) || !present(prepared.OriginalMapping()) {
		return ErrKEKFacts
	}
	var epoch uint64
	if err := read.QueryRowContext(ctx, `SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=? FOR UPDATE`, b.installationID).Scan(&epoch); err != nil || epoch != b.epoch {
		return ErrKEKFacts
	}
	var now time.Time
	err := read.QueryRowContext(ctx, `SELECT UTC_TIMESTAMP(6)`).Scan(&now)
	expected := prepared.ExpectedSnapshot()
	if err != nil || !SameSnapshotFacts(expected, b.original) || expected.ObservedAt.IsZero() || expected.ObservedAt.After(now) || !now.Before(prepared.ValidUntil()) {
		return ErrKEKFacts
	}
	// A's frozen preparation includes its original SQL sample timestamp. The
	// rows and epoch above were checked against current locking reads.
	locked := cloneSnapshot(b.original)
	locked.ObservedAt = expected.ObservedAt
	if prepared.Recheck(ctx, read, LockedSnapshot{facts: locked}, now) != nil {
		return ErrKEKFacts
	}
	return nil
}

// CompleteScan deliberately has no success path until every original source
// adapter, historical adoption receipt and writer mutation hook is installed.
func (b *Bound) CompleteScan(context.Context) (LockedSnapshot, error) {
	return LockedSnapshot{}, ErrKEKCoverage
}
