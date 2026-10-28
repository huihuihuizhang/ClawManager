package systembackupnoncebootstrap

import (
	"bytes"
	sec "clawreef/internal/systembackupsecurity"
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func hash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

type fixture struct {
	v      *Validator
	g      sec.OfflineBootstrapGrant
	c      sec.BootstrapConfig
	clock  *time.Time
	active sec.BootstrapSecretRef
}

func setup(t *testing.T) fixture {
	t.Helper()
	raw, e := os.ReadFile("../systembackupevidence/testdata/download_mfa_probe_inputs.json")
	if e != nil {
		t.Fatal(e)
	}
	var capsule struct {
		Effective json.RawMessage `json:"effective_config"`
	}
	if e = json.Unmarshal(raw, &capsule); e != nil {
		t.Fatal(e)
	}
	cfg, e := sec.DecodeBootstrapConfig(capsule.Effective)
	if e != nil {
		t.Fatal(e)
	}
	var active sec.BootstrapSecretRef
	for _, r := range cfg.References() {
		if r.Purpose == "nonce_hmac" {
			active = r
		}
	}
	now := time.Now().UTC()
	dir := t.TempDir()
	b := Binding{InstallationID: "installation_test", ServerUUID: "00000000-0000-0000-0000-000000000001", Database: "synthetic_test", ConfigSHA256: cfg.SHA256(), NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	for i, p := range []sec.BootstrapSecretRef{active, {Purpose: "nonce_hmac", IdentityHash: strings.Repeat("d", 64), Version: "retained-v0"}} {
		desc, _ := json.Marshal(map[string]string{"ref_kind": "external_secret", "purpose": "strong_auth_nonce_hmac", "identity_hash": p.IdentityHash, "identity_version": p.Version, "provider_identity_hash": strings.Repeat("b", 64), "scope_hash": strings.Repeat("c", 64), "description_redacted": "synthetic nonce reference", "read_mode": "exact_version_only"})
		material := bytes.Repeat([]byte{byte(i + 1)}, 32)
		d := filepath.Join(dir, fmt.Sprint(i)+".json")
		m := filepath.Join(dir, fmt.Sprint(i)+".key")
		if os.WriteFile(d, desc, 0600) != nil || os.WriteFile(m, material, 0600) != nil {
			t.Fatal("fixture write failed")
		}
		b.Keys = append(b.Keys, Key{IdentityHash: p.IdentityHash, Version: p.Version, ProviderIdentityHash: strings.Repeat("b", 64), ScopeHash: strings.Repeat("c", 64), DescriptorFile: d, DescriptorSHA256: hash(desc), MaterialFile: m, MaterialSHA256: hash(material), ProtectedUntil: now.Add(time.Hour)})
	}
	v, e := New(b)
	if e != nil {
		t.Fatal(e)
	}
	v.now = func() time.Time { return now }
	return fixture{v, sec.OfflineBootstrapGrant{InstallationID: b.InstallationID, ServerUUID: b.ServerUUID, Database: b.Database, ConfigSHA256: b.ConfigSHA256}, cfg, &now, active}
}

type state struct {
	server, db                  string
	rows                        [][]driver.Value
	queries, commits, rollbacks int
	fail                        bool
	after                       func()
}
type drv struct{ s *state }
type conn struct{ s *state }
type txn struct{ s *state }
type rows struct {
	values  [][]driver.Value
	columns []string
}

func (d drv) Open(string) (driver.Conn, error)      { return &conn{d.s}, nil }
func (c *conn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unexpected prepare") }
func (c *conn) Close() error                        { return nil }
func (c *conn) Begin() (driver.Tx, error)           { return &txn{c.s}, nil }
func (c *conn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	c.s.queries++
	if c.s.fail {
		return nil, errors.New("synthetic SQL failure")
	}
	if q == "SELECT @@server_uuid,DATABASE()" && len(args) == 0 {
		return &rows{[][]driver.Value{{c.s.server, c.s.db}}, []string{"server", "database"}}, nil
	}
	if q == `SELECT nonce_hmac_ref_version,nonce_hmac_identity_hash,NULL FROM system_backup_v2_configs
UNION SELECT nonce_hmac_key_version,NULL,MAX(retain_until) FROM system_backup_v2_strong_auth_nonces WHERE retain_until>? GROUP BY nonce_hmac_key_version` && len(args) == 1 {
		if c.s.after != nil {
			c.s.after()
		}
		return &rows{c.s.rows, []string{"version", "identity", "retain_until"}}, nil
	}
	return nil, errors.New("unexpected SQL")
}
func (t *txn) Commit() error      { t.s.commits++; return nil }
func (t *txn) Rollback() error    { t.s.rollbacks++; return nil }
func (r *rows) Columns() []string { return r.columns }
func (r *rows) Close() error      { return nil }
func (r *rows) Next(out []driver.Value) error {
	if len(r.values) == 0 {
		return io.EOF
	}
	copy(out, r.values[0])
	r.values = r.values[1:]
	return nil
}

var driverID atomic.Int64

func transaction(t *testing.T, f fixture) (*sql.Tx, *state) {
	t.Helper()
	s := &state{server: f.g.ServerUUID, db: f.g.Database, rows: [][]driver.Value{{f.active.Version, f.active.IdentityHash, nil}, {"retained-v0", nil, f.clock.Add(30 * time.Minute)}}}
	name := fmt.Sprintf("nonce-bootstrap-%d", driverID.Add(1))
	sql.Register(name, drv{s})
	db, e := sql.Open(name, "")
	if e != nil {
		t.Fatal(e)
	}
	tx, e := db.BeginTx(context.Background(), nil)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = tx.Rollback(); _ = db.Close() })
	return tx, s
}

func TestNoncePrepareAndTransactionRetention(t *testing.T) {
	f := setup(t)
	check, e := f.v.Prepare(context.Background(), f.g, f.c)
	if e != nil {
		t.Fatal(e)
	}
	tx, s := transaction(t, f)
	if check.Recheck(context.Background(), tx, *f.clock) != nil || s.queries != 2 || s.commits != 0 || s.rollbacks != 0 {
		t.Fatal("same transaction read-only recheck failed")
	}
	material, e := f.v.Material(f.active.IdentityHash, f.active.Version)
	if e != nil || len(material) != 32 {
		t.Fatal("exact material missing")
	}
	material[0] = 9
	wipe(material)
	again, e := f.v.Material(f.active.IdentityHash, f.active.Version)
	defer wipe(again)
	if e != nil || again[0] != 1 {
		t.Fatal("material ownership violated")
	}
	// Initial bootstrap has no stored config/nonce rows yet; the active original
	// mapping still has to pass Prepare, not a made-up persisted config.
	s.rows = nil
	if check.Recheck(context.Background(), tx, *f.clock) != nil {
		t.Fatal("initial installation rejected")
	}
}
func TestNonceRejectsIncompleteOrChangedHistory(t *testing.T) {
	for _, name := range []string{"missing-version", "conflicting-identity", "retention-too-short", "null-facts", "wrong-db", "wrong-server", "sql-failure", "changed-active", "changed-history", "changed-descriptor", "deleted-history", "expired", "sql-clock-backwards", "wall-clock-backwards", "late-read", "cancel"} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			prepared, e := f.v.Prepare(context.Background(), f.g, f.c)
			if e != nil {
				t.Fatal(e)
			}
			tx, s := transaction(t, f)
			now := *f.clock
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "missing-version":
				s.rows = append(s.rows, []driver.Value{"absent-v1", nil, now.Add(time.Minute)})
			case "conflicting-identity":
				s.rows = append(s.rows, []driver.Value{f.active.Version, strings.Repeat("e", 64), nil})
			case "retention-too-short":
				s.rows[1][2] = now.Add(2 * time.Hour)
			case "null-facts":
				s.rows[1][2] = nil
			case "wrong-db":
				s.db = "other"
			case "wrong-server":
				s.server = "other"
			case "sql-failure":
				s.fail = true
			case "changed-active":
				_ = os.WriteFile(f.v.binding.Keys[0].MaterialFile, bytes.Repeat([]byte{9}, 32), 0600)
			case "changed-history":
				_ = os.WriteFile(f.v.binding.Keys[1].MaterialFile, bytes.Repeat([]byte{9}, 32), 0600)
			case "changed-descriptor":
				_ = os.WriteFile(f.v.binding.Keys[0].DescriptorFile, []byte("{}"), 0600)
			case "deleted-history":
				_ = os.Remove(f.v.binding.Keys[1].MaterialFile)
			case "expired":
				now = now.Add(30 * time.Second)
			case "sql-clock-backwards":
				now = now.Add(-time.Microsecond)
			case "wall-clock-backwards":
				*f.clock = now.Add(-time.Microsecond)
			case "late-read":
				s.after = func() { *f.clock = now.Add(30 * time.Second) }
			case "cancel":
				cancel()
			}
			if prepared.Recheck(ctx, tx, now) != sec.ErrRegistrationUnavailable {
				t.Fatal("unsafe recheck accepted")
			}
			if s.commits != 0 || s.rollbacks != 0 {
				t.Fatal("adapter ended caller transaction")
			}
		})
	}
}
func TestNoncePrepareRejectsBadMaterialAndBinding(t *testing.T) {
	for _, name := range []string{"short-key", "long-key", "bad-descriptor", "wrong-grant", "expired", "cancel", "no-active", "alias", "relative-file", "duplicate-version", "short-retention", "kubernetes-ref"} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			k := &f.v.binding.Keys[0]
			switch name {
			case "short-key":
				_ = os.WriteFile(k.MaterialFile, bytes.Repeat([]byte{1}, 31), 0600)
			case "long-key":
				_ = os.WriteFile(k.MaterialFile, bytes.Repeat([]byte{1}, 33), 0600)
			case "bad-descriptor":
				_ = os.WriteFile(k.DescriptorFile, []byte("{}"), 0600)
			case "wrong-grant":
				f.g.InstallationID = "installation_other"
			case "expired":
				*f.clock = f.clock.Add(time.Hour)
			case "cancel":
				cancel()
			case "no-active":
				f.v.binding.Keys = f.v.binding.Keys[1:]
			case "alias":
				k.Version = "latest"
			case "relative-file":
				k.MaterialFile = "relative"
			case "duplicate-version":
				f.v.binding.Keys = append(f.v.binding.Keys, *k)
			case "short-retention":
				k.ProtectedUntil = *f.clock
			case "kubernetes-ref":
				raw, _ := os.ReadFile(k.DescriptorFile)
				raw = bytes.Replace(raw, []byte("external_secret"), []byte("kubernetes_secret"), 1)
				_ = os.WriteFile(k.DescriptorFile, raw, 0600)
				k.DescriptorSHA256 = hash(raw)
			}
			if name == "alias" || name == "relative-file" || name == "duplicate-version" || name == "short-retention" {
				if _, e := New(f.v.binding); e == nil {
					t.Fatal("invalid composition accepted")
				}
				return
			}
			if _, e := f.v.Prepare(ctx, f.g, f.c); e != sec.ErrRegistrationUnavailable {
				t.Fatal("bad preparation accepted")
			}
		})
	}
}
func TestNonceMappingCopyAndOutputIsolation(t *testing.T) {
	f := setup(t)
	b := f.v.binding
	v, e := New(b)
	if e != nil {
		t.Fatal(e)
	}
	b.Keys[0].MaterialFile = "mutated"
	if v.binding.Keys[0].MaterialFile == "mutated" {
		t.Fatal("caller mutated validator")
	}
	for _, value := range []any{v.binding, v.binding.Keys[0], v} {
		s := fmt.Sprintf("%v %#v", value, value)
		if strings.Contains(s, v.binding.Keys[0].MaterialSHA256) || strings.Contains(s, v.binding.Keys[0].MaterialFile) {
			t.Fatal("mapping leaked")
		}
		if _, e := json.Marshal(value); e == nil {
			t.Fatal("mapping serialized")
		}
	}
	if _, e := v.Material("wrong", f.active.Version); e == nil {
		t.Fatal("unmapped material exposed")
	}
	var nilv *Validator
	if _, e := nilv.Material("", ""); e == nil {
		t.Fatal("nil accepted")
	}
}
