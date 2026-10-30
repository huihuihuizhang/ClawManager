package systembackupkekadapter

import (
	c "clawreef/internal/systembackupkekcandidate"
	reg "clawreef/internal/systembackupkekregistry"
	w "clawreef/internal/systembackupwire"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func ownerRecordFixture(t *testing.T) (OriginalRecord, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	raw, e := os.ReadFile("../systembackupkekcandidate/testdata/mapping.json")
	if e != nil {
		t.Fatal(e)
	}
	m, e := c.DecodeMapping(raw)
	if e != nil {
		t.Fatal(e)
	}
	v := m.Input()
	src := func(x c.SourceRecord) reg.SourceRecord {
		return reg.SourceRecord{SourceID: x.SourceID, RecordID: x.RecordID, RecordVersion: x.RecordVersion, ContentSHA256: x.ContentSHA256}
	}
	ref := func(x c.KMSReference) reg.TypedReference {
		raw, _ := json.Marshal(x)
		h := sha256.Sum256(raw)
		return reg.TypedReference{RawJSON: raw, SHA256: hex.EncodeToString(h[:])}
	}
	b := reg.Binding{InstallationID: v.InstallationID, ConfigRef: reg.ReferencePin{IdentityHash: v.ConfigRef.IdentityHash, Version: v.ConfigRef.Version}, Key: w.KeyBinding{Provider: v.KeyBinding.Provider, IdentityHash: v.KeyBinding.IdentityHash, RegistryVersion: v.KeyBinding.RegistryVersion, ProviderKeyID: v.KeyBinding.ProviderKeyID, ProviderVersion: v.KeyBinding.ProviderVersion}, Provider: reg.ProviderBinding{Endpoint: v.Provider.Endpoint, KeyName: v.Provider.KeyName, ProviderIdentityHash: v.Provider.ProviderIdentityHash, ScopeHash: v.Provider.ScopeHash, CAPEMSHA256: v.Provider.CAPEMSHA256, CASource: src(v.Provider.CASource)}, GenerateRef: ref(v.GenerateRef), UnwrapRef: ref(v.UnwrapRef)}
	raw, _ = json.Marshal(b)
	h := sha256.Sum256(raw)
	source := src(v.Provider.CASource)
	source.ContentSHA256 = hex.EncodeToString(h[:])
	now := time.Now().UTC()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return OriginalRecord{Binding: b, Source: source, Revision: "r1", NotBefore: now.Add(-time.Hour), Until: now.Add(time.Hour)}, pub, key
}
func signOwner(r OriginalRecord, key ed25519.PrivateKey) ([]byte, []byte) {
	raw, _ := json.Marshal(r)
	return raw, ed25519.Sign(key, append([]byte("system-backup-original-kek.v1\x00"), raw...))
}

func TestOwnerRecordValidationAndMonotoneRevocation(t *testing.T) {
	r, pub, key := ownerRecordFixture(t)
	raw, sig := signOwner(r, key)
	if _, err := decodeOwnerRecord(raw, sig, pub); err != nil {
		t.Fatal(err)
	}
	old := r
	r.Revision = "r2"
	r.GenerateRevoked = true
	r.Until = time.Now().Add(-time.Minute)
	r.NotBefore = r.Until.Add(-time.Hour)
	raw, sig = signOwner(r, key)
	if _, err := decodeOwnerRecord(raw, sig, pub); err != nil {
		t.Fatal("expired revocation must be importable", err)
	}
	if !ownerTransition(old, r) {
		t.Fatal("revocation denied")
	}
	if ownerTransition(r, old) {
		t.Fatal("revocation resurrected")
	}
	next := r
	next.Revision = "r3"
	next.Binding.Provider.Endpoint = "https://different.invalid"
	if ownerTransition(r, next) {
		t.Fatal("binding changed")
	}
	raw, sig = signOwner(old, key)
	raw[0] = ' '
	if _, err := decodeOwnerRecord(raw, sig, pub); err == nil {
		t.Fatal("tamper accepted")
	}
	bad := old
	bad.Binding.UnwrapRef = bad.Binding.GenerateRef
	b, _ := json.Marshal(bad.Binding)
	h := sha256.Sum256(b)
	bad.Source.ContentSHA256 = hex.EncodeToString(h[:])
	raw, sig = signOwner(bad, key)
	if _, err := decodeOwnerRecord(raw, sig, pub); err == nil {
		t.Fatal("wrong purpose accepted")
	}
}

// This driver models transaction boundaries and captures the actual SQL order;
// authority semantics are exercised separately above with genuine signatures.
type ownerSQL struct {
	wrongDatabase, badReadback bool
	calls                      []string
	now                        time.Time
	raw, sig                   []byte
	version                    uint64
	digest                     string
	failHistory, failCommit    bool
	committed, rolled          bool
}
type ownerConnector struct{ s *ownerSQL }

func (c ownerConnector) Connect(context.Context) (driver.Conn, error) { return c.s, nil }
func (c ownerConnector) Driver() driver.Driver                        { return ownerDriver{} }

type ownerDriver struct{}

func (ownerDriver) Open(string) (driver.Conn, error)    { return nil, errors.New("unused") }
func (s *ownerSQL) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (s *ownerSQL) Close() error                        { return nil }
func (s *ownerSQL) Begin() (driver.Tx, error)           { return s, nil }
func (s *ownerSQL) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	s.calls = append(s.calls, "begin")
	return s, nil
}
func (s *ownerSQL) Commit() error {
	s.calls = append(s.calls, "commit")
	s.committed = true
	if s.failCommit {
		return errors.New("unknown")
	}
	return nil
}
func (s *ownerSQL) Rollback() error { s.rolled = true; return nil }
func (s *ownerSQL) ExecContext(_ context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	s.calls = append(s.calls, q)
	if strings.Contains(q, "authority_history") && s.failHistory {
		return nil, errors.New("duplicate revision")
	}
	if strings.HasPrefix(q, "INSERT INTO system_backup_installation_kek_authority(") {
		s.version = uint64(a[7].Value.(int64))
		s.digest = a[6].Value.(string)
	}
	if strings.HasPrefix(q, "UPDATE system_backup_installation_kek_authority SET") {
		s.version = uint64(a[4].Value.(int64))
		s.digest = a[3].Value.(string)
	}
	return driver.RowsAffected(1), nil
}

type ownerRows struct {
	columns []string
	values  []driver.Value
	done    bool
}

func (r *ownerRows) Columns() []string { return r.columns }
func (r *ownerRows) Close() error      { return nil }
func (r *ownerRows) Next(v []driver.Value) error {
	if r.done || r.values == nil {
		return io.EOF
	}
	copy(v, r.values)
	r.done = true
	return nil
}
func (s *ownerSQL) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	s.calls = append(s.calls, q)
	r := &ownerRows{}
	switch {
	case strings.Contains(q, "@@server_uuid"):
		r.columns = []string{"11111111-1111-1111-1111-111111111111", "db", "now"}
		r.values = []driver.Value{"11111111-1111-1111-1111-111111111111", "database", s.now}
		if s.wrongDatabase {
			r.values[1] = "wrong"
		}
	case strings.Contains(q, "SELECT epoch"):
		r.columns = []string{"epoch"}
		r.values = []driver.Value{int64(0)}
	case strings.Contains(q, "SELECT signed_record"):
		r.columns = []string{"raw", "sig", "version"}
		if s.raw != nil {
			r.values = []driver.Value{s.raw, s.sig, int64(s.version)}
		}
	case strings.Contains(q, "SELECT row_version"):
		r.columns = []string{"version", "hash"}
		r.values = []driver.Value{int64(s.version), s.digest}
		if s.badReadback {
			r.values[1] = "wrong"
		}
	default:
		r.columns = []string{"now"}
		r.values = []driver.Value{s.now}
	}
	return r, nil
}
func TestAuthorityWriterAtomicFenceAndRollback(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		expected                uint64
		historyFail, commitFail bool
		want                    error
	}{{"insert", 0, false, false, nil}, {"stale", 2, false, false, ErrAuthorityWrite}, {"replayed-revision", 0, true, false, ErrAuthorityWrite}, {"unknown-commit", 0, false, true, ErrAuthorityCommitUnknown}} {
		t.Run(tc.name, func(t *testing.T) {
			r, pub, key := ownerRecordFixture(t)
			raw, sig := signOwner(r, key)
			s := &ownerSQL{now: time.Now().UTC(), failHistory: tc.historyFail, failCommit: tc.commitFail}
			db := sql.OpenDB(ownerConnector{s})
			defer db.Close()
			writer, e := NewInstallationAuthorityWriter(db, r.Binding.InstallationID, reg.DatabaseIdentity{ServerUUID: "11111111-1111-1111-1111-111111111111", Database: "database"}, pub)
			if e != nil {
				t.Fatal(e)
			}
			_, e = writer.Put(context.Background(), raw, sig, tc.expected)
			if !errors.Is(e, tc.want) {
				t.Fatalf("got %v want %v", e, tc.want)
			}
			joined := strings.Join(s.calls, "\n")
			if tc.want == nil {
				f := strings.Index(joined, "FOR UPDATE")
				h := strings.Index(joined, "INSERT INTO system_backup_installation_kek_authority_history")
				if f < 0 || h < f || !s.committed {
					t.Fatal("write bypassed fence/commit")
				}
			} else if tc.want != ErrAuthorityCommitUnknown && !s.rolled {
				t.Fatal("rejection did not roll back")
			}
		})
	}
}

func TestAuthorityWriterExpiredRenewalAndRevocation(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		r, pub, key := ownerRecordFixture(t)
		r.Until = time.Now().UTC().Add(-time.Hour)
		r.NotBefore = r.Until.Add(-time.Hour)
		oldRaw, oldSig := signOwner(r, key)
		s := &ownerSQL{now: time.Now().UTC(), raw: oldRaw, sig: oldSig, version: 1}
		db := sql.OpenDB(ownerConnector{s})
		writer, err := NewInstallationAuthorityWriter(db, r.Binding.InstallationID, reg.DatabaseIdentity{ServerUUID: "11111111-1111-1111-1111-111111111111", Database: "database"}, pub)
		if err != nil {
			t.Fatal(err)
		}
		r.Revision = "r2"
		if revoke {
			r.GenerateRevoked = true
		} else {
			r.NotBefore = s.now.Add(-time.Minute)
			r.Until = s.now.Add(time.Hour)
		}
		raw, sig := signOwner(r, key)
		version, err := writer.Put(context.Background(), raw, sig, 1)
		if err != nil || version != 2 {
			t.Fatalf("expired renewal/revocation=%v: version=%d error=%v", revoke, version, err)
		}
		db.Close()
	}
}

func TestAuthorityWriterRejectsInvalidOrUnobservedWrites(t *testing.T) {
	for _, name := range []string{"wrong-database", "bad-readback", "expired-active", "wrong-signature", "zero-writer"} {
		t.Run(name, func(t *testing.T) {
			r, pub, key := ownerRecordFixture(t)
			s := &ownerSQL{now: time.Now().UTC(), wrongDatabase: name == "wrong-database", badReadback: name == "bad-readback"}
			if name == "expired-active" {
				r.Until = s.now.Add(-time.Minute)
				r.NotBefore = r.Until.Add(-time.Hour)
			}
			raw, sig := signOwner(r, key)
			if name == "wrong-signature" {
				sig[0] ^= 1
			}
			db := sql.OpenDB(ownerConnector{s})
			defer db.Close()
			writer, e := NewInstallationAuthorityWriter(db, r.Binding.InstallationID, reg.DatabaseIdentity{ServerUUID: "11111111-1111-1111-1111-111111111111", Database: "database"}, pub)
			if e != nil {
				t.Fatal(e)
			}
			if name == "zero-writer" {
				writer = &InstallationAuthorityWriter{}
			}
			_, e = writer.Put(context.Background(), raw, sig, 0)
			want := ErrAuthorityWrite
			if name == "bad-readback" {
				want = ErrAuthorityCommitUnknown
			}
			if !errors.Is(e, want) {
				t.Fatalf("got %v want %v", e, want)
			}
			if name == "expired-active" || name == "wrong-database" {
				if s.committed || !s.rolled {
					t.Fatal("invalid record committed")
				}
			}
		})
	}
}
