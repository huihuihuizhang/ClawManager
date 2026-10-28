package systembackupsecurity

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// Scripted transport checks SQL, ordering, binding and failures, not InnoDB
// range locks or concurrent replay. Those require the real MySQL gate.
type downloadNonceDB struct {
	t                                  *testing.T
	now                                time.Time
	identity                           DatabaseIdentity
	installations, versions            []string
	active                             string
	configVersion                      int64
	queries                            []string
	lookups                            []NonceHMACCandidate
	consumed                           map[string]int64
	failAt, writes, commits, rollbacks int
	offset                             int64
	afterQuery                         func(string)
}

func (d *downloadNonceDB) Driver() driver.Driver                        { return registrationTestDriver{} }
func (d *downloadNonceDB) Connect(context.Context) (driver.Conn, error) { return d, nil }
func (*downloadNonceDB) Prepare(string) (driver.Stmt, error)            { return nil, errors.New("not used") }
func (*downloadNonceDB) Close() error                                   { return nil }
func (*downloadNonceDB) Begin() (driver.Tx, error) {
	return nil, errors.New("explicit isolation required")
}
func (d *downloadNonceDB) BeginTx(_ context.Context, o driver.TxOptions) (driver.Tx, error) {
	if o.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || o.ReadOnly {
		return nil, errors.New("wrong isolation")
	}
	return d, nil
}
func (d *downloadNonceDB) Commit() error   { d.commits++; return nil }
func (d *downloadNonceDB) Rollback() error { d.rollbacks++; return nil }
func (d *downloadNonceDB) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	d.writes++
	return nil, errors.New("scope must never write")
}
func (d *downloadNonceDB) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	d.queries = append(d.queries, q)
	if d.failAt == len(d.queries) {
		return nil, errors.New("PRIVATE SQL failure")
	}
	if strings.Count(q, "?") != len(args) {
		d.t.Fatal("placeholder mismatch")
	}
	if d.afterQuery != nil {
		d.afterQuery(q)
	}
	list := func(values []string) driver.Rows {
		rows := &registrationTestRows{width: 1}
		for _, value := range values {
			rows.data = append(rows.data, []driver.Value{value})
		}
		return rows
	}
	switch q {
	case "SELECT @@server_uuid,DATABASE()":
		return registrationRow(d.identity.ServerUUID, d.identity.Database), nil
	case sensitiveDownloadInstallationsSQL:
		return list(d.installations), nil
	case "SELECT active_config_version FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE":
		if args[0].Value != "installation_test" {
			d.t.Fatal("wrong installation")
		}
		return registrationRow(d.configVersion), nil
	case "SELECT nonce_hmac_ref_version FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR UPDATE":
		if args[0].Value != "installation_test" || args[1].Value != d.configVersion {
			d.t.Fatal("wrong config binding")
		}
		return registrationRow(d.active), nil
	case "SELECT UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))":
		return registrationRow(d.now, d.offset), nil
	case sensitiveDownloadNonceVersionsSQL:
		if !args[0].Value.(time.Time).Equal(d.now) {
			d.t.Fatal("history must use SQL clock")
		}
		return list(d.versions), nil
	case sensitiveDownloadNonceLookupSQL:
		c := NonceHMACCandidate{HMAC: args[0].Value.(string), KeyVersion: args[1].Value.(string)}
		d.lookups = append(d.lookups, c)
		if id, ok := d.consumed[c.KeyVersion]; ok {
			return registrationRow(id), nil
		}
		return &registrationTestRows{width: 1}, nil
	}
	d.t.Fatal("unexpected SQL", q)
	return nil, errors.New("unexpected SQL")
}

func downloadNonceFixture(t *testing.T) (*downloadNonceDB, *sql.Tx, SensitiveDownloadProofVerification) {
	t.Helper()
	r, p, cfg := sensitiveDownloadSignedFixture(t)
	v, err := r.VerifyProof(p, p.Payload.Issuer, cfg)
	if err != nil {
		t.Fatal(err)
	}
	d := &downloadNonceDB{t: t, now: cfg.Now, identity: DatabaseIdentity{"11111111-2222-3333-4444-555555555555", "synthetic"},
		installations: []string{"installation_other", "installation_test"}, versions: []string{"v1", "v2"}, active: "v2", configVersion: 4, consumed: map[string]int64{}}
	db := sql.OpenDB(d)
	t.Cleanup(func() { db.Close() })
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback() })
	return d, tx, v
}

func TestSensitiveDownloadNonceScopeGlobalHistoryAndExactLookups(t *testing.T) {
	d, tx, v := downloadNonceFixture(t)
	s, err := LockSensitiveDownloadNonceScope(context.Background(), tx, d.identity, "installation_test")
	if err != nil || s == nil {
		t.Fatal(err)
	}
	want := []string{"SELECT @@server_uuid,DATABASE()", sensitiveDownloadInstallationsSQL,
		"SELECT active_config_version FROM system_backup_v2_installation_state WHERE origin_installation_id=? FOR UPDATE",
		"SELECT nonce_hmac_ref_version FROM system_backup_v2_configs WHERE origin_installation_id=? AND version=? FOR UPDATE",
		"SELECT UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))", sensitiveDownloadNonceVersionsSQL,
		"SELECT UTC_TIMESTAMP(6),TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),CURRENT_TIMESTAMP(6))"}
	if strings.Join(d.queries, "\n") != strings.Join(want, "\n") {
		t.Fatal("wrong lock sequence", d.queries)
	}
	versions := s.RequiredVersions()
	versions[0] = "changed"
	if s.RequiredVersions()[0] != "v1" || s.ActiveVersion() != "v2" {
		t.Fatal("mutable history")
	}
	if _, err = json.Marshal(s); err == nil || fmt.Sprintf("%v %#v", s, s) != "SensitiveDownloadNonceScope SensitiveDownloadNonceScope" {
		t.Fatal("scope leaked")
	}
	if err = s.LockCandidates(context.Background(), tx, v); err != nil {
		t.Fatal(err)
	}
	expected := v.NonceCandidates()
	sort.Slice(expected, func(i, j int) bool {
		return expected[i].HMAC < expected[j].HMAC || expected[i].HMAC == expected[j].HMAC && expected[i].KeyVersion < expected[j].KeyVersion
	})
	if fmt.Sprint(d.lookups) != fmt.Sprint(expected) || d.writes != 0 || d.commits != 0 || d.rollbacks != 0 {
		t.Fatal("wrong key or transaction ownership")
	}
	before := len(d.queries)
	clone := *s
	if clone.LockCandidates(context.Background(), tx, v) == nil || len(d.queries) != before {
		t.Fatal("copy bypassed one-attempt state")
	}
	if s.LockCandidates(context.Background(), tx, v) == nil || len(d.queries) != before {
		t.Fatal("scope reused")
	}
}

func TestSensitiveDownloadNonceScopeRejectsIncompletePersistentHistory(t *testing.T) {
	for name, change := range map[string]func(*downloadNonceDB){
		"foreign_database":        func(d *downloadNonceDB) { d.identity.Database = "other" },
		"installation_missing":    func(d *downloadNonceDB) { d.installations = []string{"installation_other"} },
		"empty_installations":     func(d *downloadNonceDB) { d.installations = nil },
		"duplicate_installations": func(d *downloadNonceDB) { d.installations = []string{"installation_test", "installation_test"} },
		"invalid_installation":    func(d *downloadNonceDB) { d.installations = []string{"bad", "installation_test"} },
		"unordered_installations": func(d *downloadNonceDB) { d.installations = []string{"installation_test", "installation_other"} },
		"zero_config":             func(d *downloadNonceDB) { d.configVersion = 0 },
		"unsafe_config":           func(d *downloadNonceDB) { d.configVersion = 9007199254740992 },
		"active_missing":          func(d *downloadNonceDB) { d.versions = []string{"v1"} },
		"history_empty":           func(d *downloadNonceDB) { d.versions = nil },
		"history_duplicate":       func(d *downloadNonceDB) { d.versions = []string{"v1", "v1", "v2"} },
		"history_unordered":       func(d *downloadNonceDB) { d.versions = []string{"v2", "v1"} },
		"history_path":            func(d *downloadNonceDB) { d.versions = []string{"../key", "v2"} },
		"active_path":             func(d *downloadNonceDB) { d.active = "../key" },
		"history_bound": func(d *downloadNonceDB) {
			d.versions = make([]string, 10001)
			for i := range d.versions {
				d.versions[i] = fmt.Sprintf("v%05d", i)
			}
			d.active = "v00000"
		},
		"installation_bound": func(d *downloadNonceDB) {
			d.installations = make([]string, 10001)
			for i := range d.installations {
				d.installations[i] = fmt.Sprintf("installation_%05d", i)
			}
			d.installations[10000] = "installation_test"
		},
		"non_utc_session": func(d *downloadNonceDB) { d.offset = 1 },
		"non_utc_driver":  func(d *downloadNonceDB) { d.now = d.now.In(time.FixedZone("offset", 3600)) },
		"submicrosecond":  func(d *downloadNonceDB) { d.now = d.now.Add(time.Nanosecond) },
		"clock_backwards": func(d *downloadNonceDB) {
			clocks := 0
			d.afterQuery = func(q string) {
				if strings.HasPrefix(q, "SELECT UTC_TIMESTAMP") {
					clocks++
					if clocks == 2 {
						d.now = d.now.Add(-time.Microsecond)
					}
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			d, tx, _ := downloadNonceFixture(t)
			database := d.identity
			change(d)
			if s, err := LockSensitiveDownloadNonceScope(context.Background(), tx, database, "installation_test"); err != ErrRegistrationUnavailable || s != nil {
				t.Fatal("bad scope accepted", err)
			}
			if d.writes != 0 || d.commits != 0 {
				t.Fatal("wrote during failed prefix")
			}
		})
	}
	for i := 1; i <= 7; i++ {
		t.Run(fmt.Sprintf("sql_failure_%d", i), func(t *testing.T) {
			d, tx, _ := downloadNonceFixture(t)
			d.failAt = i
			if s, err := LockSensitiveDownloadNonceScope(context.Background(), tx, d.identity, "installation_test"); err != ErrRegistrationUnavailable || s != nil {
				t.Fatal("SQL failure accepted", err)
			}
		})
	}
}

func TestSensitiveDownloadNonceScopeRejectsReplayAndProofSubstitution(t *testing.T) {
	for _, name := range []string{"old_replay", "active_replay", "bad_ledger_id", "lookup_failure", "post_lookup_expiry", "post_lookup_clock_backwards", "foreign_tx", "ended_tx", "zero_proof", "missing_candidate", "extra_candidate", "duplicate_candidate", "changed_active", "bad_hmac", "foreign_installation", "canceled"} {
		t.Run(name, func(t *testing.T) {
			d, tx, v := downloadNonceFixture(t)
			s, err := LockSensitiveDownloadNonceScope(context.Background(), tx, d.identity, "installation_test")
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			borrowed := tx
			switch name {
			case "old_replay":
				d.consumed["v1"] = 51
			case "active_replay":
				d.consumed["v2"] = 52
			case "bad_ledger_id":
				d.consumed["v1"] = 0
			case "lookup_failure":
				d.failAt = len(d.queries) + 2
			case "post_lookup_expiry":
				d.afterQuery = func(q string) {
					if q == sensitiveDownloadNonceLookupSQL {
						d.now = d.now.Add(time.Hour)
					}
				}
			case "post_lookup_clock_backwards":
				d.afterQuery = func(q string) {
					if q == sensitiveDownloadNonceLookupSQL {
						d.now = d.now.Add(-time.Microsecond)
					}
				}
			case "foreign_tx":
				_, borrowed, _ = downloadNonceFixture(t)
			case "ended_tx":
				tx.Rollback()
			case "zero_proof":
				v = SensitiveDownloadProofVerification{}
			case "missing_candidate":
				v.candidates = v.candidates[:1]
			case "extra_candidate":
				v.candidates = append(v.candidates, NonceHMACCandidate{KeyVersion: "v3", HMAC: strings.Repeat("f", 64)})
			case "duplicate_candidate":
				v.candidates[1] = v.candidates[0]
			case "changed_active":
				v.active.HMAC = strings.Repeat("f", 64)
			case "bad_hmac":
				v.candidates[0].HMAC = "not-a-digest"
			case "foreign_installation":
				v.request.installation = "installation_other"
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			err = s.LockCandidates(ctx, borrowed, v)
			if err == nil {
				t.Fatal("invalid proof/ledger accepted")
			}
			if name == "old_replay" || name == "active_replay" {
				var ve *VerificationError
				if !errors.As(err, &ve) || ve.Code != FailureReplayed {
					t.Fatal("wrong replay error", err)
				}
			}
			before := len(d.queries)
			if s.LockCandidates(context.Background(), tx, v) == nil || len(d.queries) != before {
				t.Fatal("failed scope recovered")
			}
			if d.writes != 0 || d.commits != 0 {
				t.Fatal("failed lookup wrote")
			}
		})
	}
}
