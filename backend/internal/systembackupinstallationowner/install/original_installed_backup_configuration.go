package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"time"
	"unicode/utf8"
)

var errOriginalInstalledBackupConfiguration = errors.New("original installed backup configuration rejected")

// This is private SOURCE DATA, not admin/enrollment/coverage authorization.
// Only the original authenticated Installer caller supplies its actual DB and
// unchanged context/deadline. There is no caller-selected installation ID,
// config document, reference list, digest, default config or Passed parameter.
type originalInstalledBackupConfiguration struct {
	origin                                      *originalInstalledBackupConfiguration
	ctx                                         context.Context
	db                                          *sql.DB
	until, checkedAt                            time.Time
	serverUUID, database, account, installation string
	version                                     uint64
	versions                                    []originalInstalledBackupConfigVersion
	failed                                      bool
}

type originalInstalledBackupConfigVersion struct {
	version    uint64
	raw        []byte
	sha256     string
	references []originalInstalledBackupSecretReference
}

// Public reference identities only. The real fixed provider/name/version/purpose
// comes from each original immutable SQL version, including retired versions.
type originalInstalledBackupSecretReference struct {
	Provider string `json:"provider"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Purpose  string `json:"purpose"`
}

func (*originalInstalledBackupConfiguration) MarshalJSON() ([]byte, error) {
	return nil, errOriginalInstalledBackupConfiguration
}
func (*originalInstalledBackupConfiguration) String() string {
	return "OriginalInstalledBackupConfiguration"
}
func (*originalInstalledBackupConfiguration) GoString() string {
	return "OriginalInstalledBackupConfiguration"
}

// Never call Store.Config here: its sql.ErrNoRows -> DefaultConfig path cannot
// establish either original installation identity or an empty history universe.
func readOriginalInstalledBackupConfiguration(ctx context.Context, db *sql.DB, until time.Time) (*originalInstalledBackupConfiguration, error) {
	if ctx == nil || db == nil || ctx.Err() != nil || !time.Now().Before(until) {
		return nil, errOriginalInstalledBackupConfiguration
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || until.After(deadline) {
		return nil, errOriginalInstalledBackupConfiguration
	}
	r := &originalInstalledBackupConfiguration{ctx: ctx, db: db, until: until}
	r.origin = r
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, errOriginalInstalledBackupConfiguration
	}
	defer tx.Rollback()
	if r.readLocked(ctx, tx) != nil || tx.Rollback() != nil {
		r.close()
		return nil, errOriginalInstalledBackupConfiguration
	}
	return r, nil
}

func (r *originalInstalledBackupConfiguration) local(ctx context.Context) bool {
	return r != nil && r.origin == r && !r.failed && r.db != nil && ctx != nil && reflect.ValueOf(ctx).Comparable() &&
		ctx == r.ctx && ctx.Err() == nil && time.Now().Before(r.until)
}

func (r *originalInstalledBackupConfiguration) readLocked(ctx context.Context, tx *sql.Tx) error {
	if !r.local(ctx) || tx == nil {
		return errOriginalInstalledBackupConfiguration
	}
	var before time.Time
	if tx.QueryRowContext(ctx, `SELECT CURRENT_USER(),@@server_uuid,DATABASE(),UTC_TIMESTAMP(6)`).Scan(&r.account, &r.serverUUID, &r.database, &before) != nil ||
		r.account == "" || r.database == "" || !regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`).MatchString(r.serverUUID) ||
		before.IsZero() || before.Nanosecond()%1000 != 0 || !before.Before(r.until) {
		return errOriginalInstalledBackupConfiguration
	}
	if tx.QueryRowContext(ctx, `SELECT origin_installation_id,config_version FROM system_backup_installation_state WHERE singleton_id=1 FOR SHARE`).Scan(&r.installation, &r.version) != nil ||
		!regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`).MatchString(r.installation) || r.version > 4096 {
		return errOriginalInstalledBackupConfiguration
	}
	rows, err := tx.QueryContext(ctx, `SELECT version,config_json FROM system_backup_config_versions ORDER BY version FOR SHARE`)
	if err != nil {
		return errOriginalInstalledBackupConfiguration
	}
	defer rows.Close()
	total := 0
	for rows.Next() {
		var v originalInstalledBackupConfigVersion
		if rows.Scan(&v.version, &v.raw) != nil {
			clear(v.raw)
			return errOriginalInstalledBackupConfiguration
		}
		total += len(v.raw)
		if len(r.versions) >= 4096 || v.version != uint64(len(r.versions)+1) || v.version > r.version ||
			len(v.raw) == 0 || len(v.raw) > 4<<20 || total > 16<<20 {
			clear(v.raw)
			return errOriginalInstalledBackupConfiguration
		}
		refs, err := originalInstalledBackupReferences(v.raw)
		if err != nil {
			clear(v.raw)
			return err
		}
		v.references = refs
		sum := sha256.Sum256(v.raw)
		v.sha256 = hex.EncodeToString(sum[:])
		r.versions = append(r.versions, v)
	}
	if rows.Err() != nil || rows.Close() != nil || uint64(len(r.versions)) != r.version {
		return errOriginalInstalledBackupConfiguration
	}
	var account, server, database string
	var after time.Time
	if tx.QueryRowContext(ctx, `SELECT CURRENT_USER(),@@server_uuid,DATABASE(),UTC_TIMESTAMP(6)`).Scan(&account, &server, &database, &after) != nil ||
		account != r.account || server != r.serverUUID || database != r.database || after.Before(before) || !after.Before(r.until) || !r.local(ctx) {
		return errOriginalInstalledBackupConfiguration
	}
	r.checkedAt = after
	return nil
}

// No new lifetime or source scope is introduced. This is an independent read
// before native I/O/final SQL; not a replacement for D's actual source guard.
func (r *originalInstalledBackupConfiguration) recheck(ctx context.Context) error {
	if !r.local(ctx) {
		return errOriginalInstalledBackupConfiguration
	}
	fresh, err := readOriginalInstalledBackupConfiguration(ctx, r.db, r.until)
	if err != nil {
		r.close()
		return err
	}
	defer fresh.close()
	if !r.same(fresh) || fresh.checkedAt.Before(r.checkedAt) {
		r.close()
		return errOriginalInstalledBackupConfiguration
	}
	return nil
}

// SQL-only source equality inside D's original transaction. The D caller owns
// real tx binding, lock order, current admin/enrollment/head and coverage guard;
// this DATA comparison alone never authenticates or admits the transaction.
func (r *originalInstalledBackupConfiguration) recheckLocked(ctx context.Context, original *sql.Tx) error {
	if !r.local(ctx) || original == nil {
		return errOriginalInstalledBackupConfiguration
	}
	fresh := &originalInstalledBackupConfiguration{ctx: r.ctx, db: r.db, until: r.until}
	fresh.origin = fresh
	defer fresh.close()
	if fresh.readLocked(ctx, original) != nil || !r.same(fresh) || fresh.checkedAt.Before(r.checkedAt) {
		r.close()
		return errOriginalInstalledBackupConfiguration
	}
	return nil
}

func (r *originalInstalledBackupConfiguration) same(other *originalInstalledBackupConfiguration) bool {
	if r.serverUUID != other.serverUUID || r.database != other.database || r.account != other.account || r.installation != other.installation ||
		r.version != other.version || len(r.versions) != len(other.versions) {
		return false
	}
	for n, v := range r.versions {
		if v.version != other.versions[n].version || v.sha256 != other.versions[n].sha256 || !bytes.Equal(v.raw, other.versions[n].raw) {
			return false
		}
	}
	return true
}

func (r *originalInstalledBackupConfiguration) close() {
	if r == nil {
		return
	}
	r.failed = true
	for _, v := range r.versions {
		clear(v.raw)
	}
	r.versions = nil
}

func originalInstalledBackupReferences(raw []byte) ([]originalInstalledBackupSecretReference, error) {
	if !utf8.Valid(raw) {
		return nil, errOriginalInstalledBackupConfiguration
	}
	// Scan EVERY object, including otherwise unmodelled original config fields,
	// for duplicate keys before extracting the fixed legacy SecretRef fields.
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var scan func(int) error
	scan = func(depth int) error {
		if depth > 64 {
			return errOriginalInstalledBackupConfiguration
		}
		token, err := d.Token()
		if err != nil {
			return errOriginalInstalledBackupConfiguration
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					name, ok := key.(string)
					if err != nil || !ok || seen[name] {
						return errOriginalInstalledBackupConfiguration
					}
					seen[name] = true
					if scan(depth+1) != nil {
						return errOriginalInstalledBackupConfiguration
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim('}') {
					return errOriginalInstalledBackupConfiguration
				}
			case '[':
				for d.More() {
					if scan(depth+1) != nil {
						return errOriginalInstalledBackupConfiguration
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim(']') {
					return errOriginalInstalledBackupConfiguration
				}
			default:
				return errOriginalInstalledBackupConfiguration
			}
		}
		return nil
	}
	if scan(0) != nil {
		return nil, errOriginalInstalledBackupConfiguration
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errOriginalInstalledBackupConfiguration
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, errOriginalInstalledBackupConfiguration
	}
	var enabled bool
	value, exists := fields["enabled"]
	if !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) || json.Unmarshal(value, &enabled) != nil {
		return nil, errOriginalInstalledBackupConfiguration
	}
	var result []originalInstalledBackupSecretReference
	pattern := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	for _, selected := range []struct{ field, purpose string }{{"artifact_target", "artifact"}, {"encryption_key", "encryption"}, {"signing_key", "signing"}, {"catalog", "catalog"}} {
		value, exists := fields[selected.field]
		if !exists || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			if enabled {
				return nil, errOriginalInstalledBackupConfiguration
			}
			continue
		}
		var keys map[string]json.RawMessage
		if json.Unmarshal(value, &keys) != nil || len(keys) != 4 {
			return nil, errOriginalInstalledBackupConfiguration
		}
		var ref originalInstalledBackupSecretReference
		decoder := json.NewDecoder(bytes.NewReader(value))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&ref) != nil || ref.Purpose != selected.purpose || (ref.Provider != "kubernetes" && ref.Provider != "vault") ||
			!pattern.MatchString(ref.Name) || !pattern.MatchString(ref.Version) || ref.Version == "latest" {
			return nil, errOriginalInstalledBackupConfiguration
		}
		result = append(result, ref)
	}
	return result, nil
}
