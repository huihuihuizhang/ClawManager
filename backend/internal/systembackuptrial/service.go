// Package systembackuptrial owns the opt-in trial workflow. It does not use
// formal backup admission, task storage or recovery point registration.
package systembackuptrial

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/staging"

	"github.com/go-sql-driver/mysql"
)

const maxEncoded = 64 << 20

var limits = domain.Limits{MaxRows: 100000, MaxBytes: maxEncoded}
var taskID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var errConfig = errors.New("trial configuration unavailable")
var errReadback = errors.New("trial readback mismatch")

type Task struct {
	ID       string         `json:"id"`
	BackupID string         `json:"backup_id,omitempty"`
	Status   string         `json:"status"`
	Stage    string         `json:"stage"`
	Error    string         `json:"error,omitempty"`
	Readback bool           `json:"readback_verified"`
	Counts   map[string]int `json:"counts,omitempty"`
}

type Readiness struct {
	Missing        []string `json:"missing"`
	RestoreMissing []string `json:"restore_missing"`
}

type Service struct {
	env  func(string) string
	mu   sync.Mutex
	task *Task
}

func New(env func(string) string) *Service { return &Service{env: env} }

func (s *Service) value(name string) string {
	return strings.TrimSpace(s.env("SYSTEM_BACKUP_TRIAL_" + name))
}

func readSetting(file string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(file) {
		return nil, errConfig
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, errConfig
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errConfig
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errConfig
	}
	return data, nil
}

func (s *Service) database(credential string) (*sql.DB, string, error) {
	raw, err := readSetting(s.value(credential+"_DSN_FILE"), 8192)
	if err != nil {
		return nil, "", err
	}
	defer clear(raw)
	cfg, err := mysql.ParseDSN(string(bytes.TrimSpace(raw)))
	if err != nil || cfg.DBName == "" || cfg.User == "" || cfg.Passwd == "" {
		return nil, "", errConfig
	}
	// Use verified TLS on remote TCP. Local development can use loopback
	// and a Unix socket with filesystem permissions.
	if cfg.Net == "tcp" {
		host, _, addrErr := net.SplitHostPort(cfg.Addr)
		if addrErr != nil {
			return nil, "", errConfig
		}
		local := net.ParseIP(host).IsLoopback()
		if !local && cfg.TLSConfig != "true" {
			return nil, "", errConfig
		}
	} else if cfg.Net != "unix" {
		return nil, "", errConfig
	}
	cfg.MultiStatements = false
	cfg.AllowAllFiles = false
	cfg.ParseTime = credential == "RUNTIME"
	if cfg.Params == nil {
		cfg.Params = make(map[string]string)
	}
	cfg.Params["time_zone"] = "'+00:00'"
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 30 * time.Second
	cfg.WriteTimeout = 30 * time.Second
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, "", errConfig
	}
	db := sql.OpenDB(connector)
	if credential != "RUNTIME" {
		db.SetMaxOpenConns(2)
	}
	return db, cfg.DBName, nil
}

func (s *Service) key() ([]byte, error) {
	raw, err := readSetting(s.value("KEY_FILE"), 128)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	key, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil || len(key) != 32 {
		clear(key)
		return nil, errConfig
	}
	return key, nil
}

type storage struct{ writer, reader *os.Root }

func (s *Service) storage() (storage, error) {
	w, r := s.value("WRITE_DIR"), s.value("READ_DIR")
	if !filepath.IsAbs(w) || !filepath.IsAbs(r) || filepath.Clean(w) == filepath.Clean(r) {
		return storage{}, errConfig
	}
	writer, err := os.OpenRoot(w)
	if err != nil {
		return storage{}, errConfig
	}
	reader, err := os.OpenRoot(r)
	if err != nil {
		writer.Close()
		return storage{}, errConfig
	}
	return storage{writer, reader}, nil
}

func (s storage) close() {
	s.reader.Close()
	s.writer.Close()
}

func newID() string {
	var raw [16]byte
	rand.Read(raw[:])
	return hex.EncodeToString(raw[:])
}

func removeOwned(root *os.Root, name string) error {
	// Windows requires clearing the read-only attribute before deleting a
	// file sealed by staging.
	if err := root.Chmod(name, 0600); err != nil {
		return err
	}
	return root.Remove(name)
}

func binding(id string) staging.Binding {
	scope := sha256.Sum256([]byte("clawmanager.system-backup.trial.v1"))
	return staging.Binding{BackupID: id, Attempt: "1", Path: id + ".trial", EnvelopeID: id, CaptureContextHash: hex.EncodeToString(scope[:])}
}

func taskKey(key []byte, id string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("clawmanager.system-backup.trial.v1:" + id))
	return mac.Sum(nil)
}

func (s storage) probe(ctx context.Context, master []byte) (err error) {
	id := newID()
	key := taskKey(master, id)
	defer clear(key)
	b := binding(id)
	challenge := []byte(newID())
	receipt, err := staging.SealFile(ctx, s.writer, b.Path, key, b, func(w io.Writer) error {
		_, err := w.Write(challenge)
		return err
	})
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, removeOwned(s.writer, receipt.Name))
	}()
	// Verify the configured reader can only read this mount by trying to
	// create a unique directory. Clean it up immediately if writable.
	marker := id + ".write-probe"
	if err := s.reader.Mkdir(marker, 0700); err == nil {
		return errors.Join(errConfig, s.reader.Remove(marker))
	} else if !errors.Is(err, os.ErrPermission) && !errors.Is(err, syscall.EROFS) {
		return errConfig
	}
	var got bytes.Buffer
	if err := s.open(ctx, receipt, key, b, &got, 128); err != nil || !bytes.Equal(got.Bytes(), challenge) {
		return errReadback
	}
	return nil
}

func (s storage) open(ctx context.Context, receipt staging.Receipt, key []byte, b staging.Binding, dst io.Writer, limit int64) error {
	if receipt.Name != b.Path || receipt.Size < 1 || receipt.Size > maxEncoded+(1<<20) {
		return errReadback
	}
	f, err := staging.OpenFile(ctx, s.reader, receipt)
	if err != nil {
		return err
	}
	defer f.Close()
	return staging.Open(ctx, f, dst, key, b, limit)
}

type artifact struct {
	Receipt staging.Receipt `json:"receipt"`
}

type manifest struct {
	SourceUUID string         `json:"source_uuid"`
	SHA256     string         `json:"snapshot_sha256"`
	Counts     map[string]int `json:"counts"`
}

func (s storage) metadata(id string) (artifact, error) {
	var out artifact
	f, err := s.reader.Open(id + ".receipt")
	if err != nil {
		return out, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 2048 {
		return out, errReadback
	}
	raw, err := io.ReadAll(io.LimitReader(f, 2049))
	if err != nil || len(raw) > 2048 {
		return out, errReadback
	}
	return out, json.Unmarshal(raw, &out)
}

func (s storage) snapshot(ctx context.Context, id string, a artifact, master []byte) (domain.Snapshot, manifest, error) {
	key := taskKey(master, id)
	defer clear(key)
	var plain bytes.Buffer
	defer func() { clear(plain.Bytes()) }()
	if err := s.open(ctx, a.Receipt, key, binding(id), &plain, maxEncoded); err != nil {
		return domain.Snapshot{}, manifest{}, err
	}
	reader := bufio.NewReader(&plain)
	line, err := reader.ReadSlice('\n')
	var m manifest
	if err != nil || json.Unmarshal(line, &m) != nil || m.SourceUUID == "" {
		return domain.Snapshot{}, manifest{}, errReadback
	}
	snapshot, err := domain.Decode(reader, limits)
	if err != nil {
		return domain.Snapshot{}, manifest{}, err
	}
	digest, err := domain.Digest(snapshot)
	if err != nil || digest != m.SHA256 || !maps.Equal(counts(snapshot), m.Counts) {
		return domain.Snapshot{}, manifest{}, errReadback
	}
	return snapshot, m, domain.ValidateTrial(snapshot)
}

func (s *Service) restoreSettings() []string {
	var missing []string
	if s.value("RESTORE_ISOLATED") != "true" ||
		s.value("RESTORE_UUID") == "" || s.value("RESTORE_UUID") == s.value("SOURCE_UUID") {
		missing = append(missing, "restore_isolation")
	}
	for _, name := range []string{"RESTORE", "RESTORE_READ"} {
		db, database, err := s.database(name)
		if err != nil {
			missing = append(missing, strings.ToLower(name)+"_credential")
			continue
		}
		db.Close()
		if !strings.HasPrefix(database, "cm_drill_") {
			missing = append(missing, "restore_database_name")
		}
	}
	if !strings.HasPrefix(s.value("RESTORE_NAMESPACE"), "cm-drill-") ||
		s.value("RESTORE_STORAGE_CLASS") == "" {
		missing = append(missing, "restore_placement")
	}
	return missing
}

func (s *Service) readiness(ctx context.Context) Readiness {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var out Readiness
	source, database, err := s.database("SOURCE")
	if err != nil {
		out.Missing = append(out.Missing, "source_credential")
	} else {
		defer source.Close()
		if err := domain.CheckTrialSource(ctx, source, database, s.value("SOURCE_UUID")); err != nil {
			out.Missing = append(out.Missing, "source_"+category(err))
		}
	}
	key, err := s.key()
	if err != nil {
		out.Missing = append(out.Missing, "encryption_key")
	}
	defer clear(key)
	store, err := s.storage()
	if err != nil {
		out.Missing = append(out.Missing, "storage_mounts")
	} else {
		defer store.close()
		if len(key) == 32 && store.probe(ctx, key) != nil {
			out.Missing = append(out.Missing, "storage_write_readback")
		}
	}
	out.RestoreMissing = s.restoreSettings()
	return out
}

func category(err error) string {
	switch {
	case errors.Is(err, domain.ErrSchema):
		return "schema"
	case errors.Is(err, domain.ErrIsolation):
		return "isolation"
	case errors.Is(err, domain.ErrNotEmpty):
		return "target_not_empty"
	case errors.Is(err, domain.ErrData):
		return "data"
	case errors.Is(err, domain.ErrCapacity):
		return "capacity"
	case errors.Is(err, domain.ErrDatabase):
		return "database"
	case errors.Is(err, domain.ErrNormalization):
		return "placement"
	default:
		return "failed"
	}
}
