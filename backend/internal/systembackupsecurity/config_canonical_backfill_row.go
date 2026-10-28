package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The exact 137 published 066 columns plus the separate nullable 081
// candidate. Hash of sorted column names joined with LF, without final LF.
// Evolution requires a new explicit schema/profile review, not SELECT omission.
// This column-set check is not an installed schema/catalog or write approval.
const configBackfillLockedColumnsSHA256 = "652956166534da92c7545d04b057310cc0f62029baa4b6d15ea41c39b69c4356"
const configBackfillLockedColumnCount = 138
const configBackfillLockedSelect = "SELECT * FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR UPDATE"

type configBackfillCanonicalState uint8

const (
	configBackfillCanonicalNull configBackfillCanonicalState = iota + 1
	configBackfillCanonicalOriginal
)

// A private, transaction-bound observation, never a maintenance grant, source
// attestation, read capability or permission to execute a write. No caller may
// use this in place of independently authenticated maintenance/source authority.
// It contains no exportable legacy metadata or row-identity JSON.
type lockedConfigBackfillRow struct {
	tx                             *sql.Tx
	database                       DatabaseIdentity
	installation, rowID, rowSHA256 string
	version                        int64
	original                       []byte
	canonical                      configBackfillCanonicalState
	observedAt                     time.Time
}

func (lockedConfigBackfillRow) MarshalJSON() ([]byte, error) { return nil, ErrConfigMutation }

func backfillLockedText(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case []byte:
		return string(v), true
	case int64:
		return strconv.FormatInt(v, 10), true
	case uint64:
		return strconv.FormatUint(v, 10), true
	case bool:
		if v {
			return "1", true
		}
		return "0", true
	default:
		return "", false
	}
}
func backfillLockedInt(value any) (int64, bool) {
	if _, boolean := value.(bool); boolean {
		return 0, false
	}
	text, ok := backfillLockedText(value)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(text, 10, 64)
	return n, err == nil && strconv.FormatInt(n, 10) == text
}

// The caller owns its already-authorized transaction, its lock order and all
// commit/rollback decisions. Read the ENTIRE real row so new or missing columns
// cannot disappear from the fingerprint. Decode actual driver scalars without
// float64, trimming, decimal normalization or reconstructing a row from source.
// Both NULL and original bytes remain observations requiring write authority.
func readLockedConfigBackfillRow(ctx context.Context, tx *sql.Tx, database DatabaseIdentity, installation string, version int64, source []byte) (lockedConfigBackfillRow, error) {
	zero := lockedConfigBackfillRow{}
	if ctx == nil || ctx.Err() != nil || tx == nil || !database.valid() || !configMutationInstallation.MatchString(installation) || version < 1 || version > 9007199254740991 || len(source) < 2 || len(source) > 262144 {
		return zero, ErrConfigMutation
	}
	// Freeze before the first SQL callback can mutate caller-owned storage.
	original := append([]byte(nil), source...)
	values, err := DecodeConfigValues(original)
	if err != nil || !bytes.Equal(values.CanonicalJSON(), original) {
		return zero, ErrConfigMutation
	}
	if database.check(ctx, tx) != nil {
		return zero, ErrRegistrationUnavailable
	}
	rows, err := tx.QueryContext(ctx, configBackfillLockedSelect, installation, version)
	if err != nil {
		return zero, ErrRegistrationUnavailable
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil || len(columns) != configBackfillLockedColumnCount {
		return zero, ErrRegistrationUnavailable
	}
	// database/sql returns the driver's name slice directly. Keep the mapping
	// stable even if Next/Close reuses it after Scan has copied the cell bytes.
	columns = append([]string(nil), columns...)
	sorted := append([]string(nil), columns...)
	sort.Strings(sorted)
	if registrationHash(strings.Join(sorted, "\n")) != configBackfillLockedColumnsSHA256 {
		return zero, ErrRegistrationUnavailable
	}
	if !rows.Next() {
		return zero, ErrRegistrationUnavailable
	}
	stored := make([]any, len(columns))
	dest := make([]any, len(columns))
	for i := range stored {
		dest[i] = &stored[i]
	}
	if rows.Scan(dest...) != nil {
		return zero, ErrRegistrationUnavailable
	}
	if rows.Next() || rows.Err() != nil || rows.Close() != nil || ctx.Err() != nil {
		return zero, ErrRegistrationUnavailable
	}
	cell := make(map[string]any, len(columns))
	for i, name := range columns {
		cell[name] = stored[i]
	}
	facts := ConfigBackfillRowFacts{TargetServerUUID: database.ServerUUID, TargetDatabase: database.Database, Materialized: map[string]string{}}
	if _, boolean := cell["id"].(bool); boolean {
		return zero, ErrRegistrationUnavailable
	}
	facts.RowID, _ = backfillLockedText(cell["id"])
	for name, target := range map[string]*string{"schema_version": &facts.SchemaVersion, "origin_installation_id": &facts.InstallationID, "config_sha256": &facts.ConfigSHA256, "created_by": &facts.CreatedBy} {
		switch value := cell[name].(type) {
		case string:
			*target = value
		case []byte:
			*target = string(value)
		default:
			return zero, ErrRegistrationUnavailable
		}
	}
	var ok bool
	if facts.Version, ok = backfillLockedInt(cell["version"]); !ok || facts.Version != version || facts.InstallationID != installation {
		return zero, ErrRegistrationUnavailable
	}
	if facts.RowVersion, ok = backfillLockedInt(cell["row_version"]); !ok {
		return zero, ErrRegistrationUnavailable
	}
	if facts.ConfigSizeBytes, ok = backfillLockedInt(cell["config_size_bytes"]); !ok {
		return zero, ErrRegistrationUnavailable
	}
	if copied := cell["copied_from_version"]; copied != nil {
		n, valid := backfillLockedInt(copied)
		if !valid {
			return zero, ErrRegistrationUnavailable
		}
		facts.CopiedFromVersion = &n
	}
	if reason := cell["change_reason"]; reason != nil {
		var s string
		switch value := reason.(type) {
		case string:
			s = value
		case []byte:
			s = string(value)
		default:
			return zero, ErrRegistrationUnavailable
		}
		facts.ChangeReason = &s
	}
	if facts.CreatedAt, ok = cell["created_at"].(time.Time); !ok {
		return zero, ErrRegistrationUnavailable
	}
	for name, value := range cell {
		switch name {
		case "id", "schema_version", "origin_installation_id", "version", "copied_from_version", "config_sha256", "config_size_bytes", "created_by", "change_reason", "row_version", "created_at", "canonical_config_json":
			continue
		}
		actual, valid := backfillLockedText(value)
		if !valid {
			return zero, ErrRegistrationUnavailable
		}
		facts.Materialized[name] = actual
	}
	_, rowSHA, err := CanonicalConfigBackfillRowIdentity(facts, original)
	if err != nil {
		return zero, ErrRegistrationUnavailable
	}
	state := configBackfillCanonicalNull
	if raw := cell["canonical_config_json"]; raw != nil {
		var canonical []byte
		switch value := raw.(type) {
		case string:
			canonical = []byte(value)
		case []byte:
			canonical = value
		default:
			return zero, ErrRegistrationConflict
		}
		if !bytes.Equal(canonical, original) {
			return zero, ErrRegistrationConflict
		}
		state = configBackfillCanonicalOriginal
	}
	var server, databaseName string
	var now time.Time
	var offset int64
	err = tx.QueryRowContext(ctx, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))").Scan(&server, &databaseName, &now, &offset)
	if err != nil || server != database.ServerUUID || databaseName != database.Database || now.IsZero() || offset != 0 || ctx.Err() != nil {
		return zero, ErrRegistrationUnavailable
	}
	return lockedConfigBackfillRow{tx: tx, database: database, installation: installation, rowID: facts.RowID, rowSHA256: rowSHA, version: version, original: original, canonical: state, observedAt: now}, nil
}

// Repeat the complete locked scan after arbitrary caller work. This exact-state
// guard does not permit even NULL->source; a later authorized writer must make
// that one transition explicitly and atomically with its audit/receipt.
func recheckLockedConfigBackfillRow(ctx context.Context, tx *sql.Tx, previous lockedConfigBackfillRow) error {
	if tx == nil || tx != previous.tx || previous.rowSHA256 == "" || previous.observedAt.IsZero() {
		return ErrRegistrationUnavailable
	}
	current, err := readLockedConfigBackfillRow(ctx, tx, previous.database, previous.installation, previous.version, previous.original)
	if err != nil {
		return err
	}
	if current.rowID != previous.rowID || current.rowSHA256 != previous.rowSHA256 || current.canonical != previous.canonical || current.observedAt.Before(previous.observedAt) {
		return ErrRegistrationUnavailable
	}
	return nil
}
