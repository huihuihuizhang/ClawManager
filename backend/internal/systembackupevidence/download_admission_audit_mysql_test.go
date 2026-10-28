//go:build systembackup_mysql

package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

type downloadAuditProbeInputs struct {
	Kind       string   `json:"kind"`
	Catalog    string   `json:"catalog_sha256"`
	Migrations []string `json:"migration_files"`
}

func decodeDownloadAuditProbeInputs(raw []byte) (downloadAuditProbeInputs, error) {
	var zero downloadAuditProbeInputs
	if len(raw) > 65536 {
		return zero, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return zero, ErrInvalid
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return zero, ErrInvalid
		}
		name, ok := key.(string)
		if !ok || seen[name] || name != "kind" && name != "catalog_sha256" && name != "migration_files" {
			return zero, ErrInvalid
		}
		seen[name] = true
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return zero, ErrInvalid
		}
	}
	if _, err = d.Token(); err != nil {
		return zero, ErrInvalid
	}
	var extra any
	if len(seen) != 3 || d.Decode(&extra) != io.EOF || json.Unmarshal(raw, &zero) != nil || zero.Kind != "d_download_audit_probe_inputs.v1" || !digestPattern.MatchString(zero.Catalog) || len(zero.Migrations) != 96 {
		return downloadAuditProbeInputs{}, ErrInvalid
	}
	for i, name := range zero.Migrations {
		if !regexp.MustCompile(`^[0-9]{3}_[A-Za-z0-9_]+\.sql$`).MatchString(name) || i > 0 && zero.Migrations[i-1] >= name {
			return downloadAuditProbeInputs{}, ErrInvalid
		}
	}
	return zero, nil
}

func downloadAuditProbeCapsule(t *testing.T) downloadAuditProbeInputs {
	t.Helper()
	f, err := os.Open(os.Getenv("D_DOWNLOAD_AUDIT_INPUTS"))
	mustSQL(t, err)
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	mustSQL(t, err)
	if hash(raw) != os.Getenv("D_DOWNLOAD_AUDIT_INPUTS_SHA256") {
		t.Fatal("download audit capsule hash differs")
	}
	input, err := decodeDownloadAuditProbeInputs(raw)
	mustSQL(t, err)
	return input
}

func TestDDownloadAdmissionAuditMySQLSeed(t *testing.T) {
	input := downloadAuditProbeCapsule(t)
	raw, err := json.Marshal(input)
	mustSQL(t, err)
	for _, tc := range []struct {
		name   string
		change func([]byte) []byte
	}{
		{"duplicate", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"kind":`), []byte(`"kind":"duplicate","kind":`), 1)
		}},
		{"unknown", func(b []byte) []byte { return append([]byte(`{"extra":1,`), b[1:]...) }},
		{"trailing", func(b []byte) []byte { return append(b, []byte(`{}`)...) }},
		{"catalog", func(b []byte) []byte { return bytes.Replace(b, []byte(input.Catalog), []byte("bad"), 1) }},
		{"budget", func([]byte) []byte { return make([]byte, 65537) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeDownloadAuditProbeInputs(tc.change(bytes.Clone(raw))); err == nil {
				t.Fatal("invalid capsule accepted")
			}
		})
	}
	t.Log("PASS download admission audit seed only; real_mysql=not_run")
}

func downloadAuditProbeDatabase(t *testing.T, ctx context.Context) *sql.DB {
	t.Helper()
	run, uid := os.Getenv("D_INVARIANT_RUN"), os.Getenv("D_INVARIANT_NAMESPACE_UID")
	if !regexp.MustCompile(`^sbk-mig-[0-9]{12}-[0-9a-f]{4}$`).MatchString(run) || !regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`).MatchString(uid) {
		t.Fatal("owned namespace UID required")
	}
	host := os.Getenv("D_INVARIANT_MYSQL_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	if net.ParseIP(host) == nil || strings.Contains(host, ":") || os.Getenv("MYSQL_ROOT_PASSWORD") == "" {
		t.Fatal("isolated IPv4 credentials required")
	}
	cfg := mysql.NewConfig()
	cfg.User = "root"
	cfg.Passwd = os.Getenv("MYSQL_ROOT_PASSWORD")
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(host, "3306")
	cfg.DBName = "clawmanager"
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 15 * time.Second
	cfg.WriteTimeout = 15 * time.Second
	db, err := sql.Open("mysql", cfg.FormatDSN())
	mustSQL(t, err)
	t.Cleanup(func() { db.Close() })
	var gotRun, gotUID, pin, server string
	mustSQL(t, db.QueryRowContext(ctx, "SELECT run_namespace,namespace_uid,server_uuid FROM d_invariant_run_marker WHERE id=1").Scan(&gotRun, &gotUID, &pin))
	mustSQL(t, db.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&server))
	if gotRun != run || gotUID != uid || pin != server {
		t.Fatal("database outside exact owned run")
	}
	return db
}

func downloadAuditOwnedUser(t *testing.T, ctx context.Context, db *sql.DB) int64 {
	t.Helper()
	var entropy [10]byte
	_, err := rand.Read(entropy[:])
	mustSQL(t, err)
	name := "d_audit_" + hex.EncodeToString(entropy[:])
	email := name + "@example.invalid"
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		var id int64
		err := db.QueryRowContext(cleanup, "SELECT id FROM users WHERE username=? AND email=?", name, email).Scan(&id)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("CLEANUP_PENDING download audit user=%s", name)
			return
		}
		if err == nil {
			if _, err = db.ExecContext(cleanup, "DELETE FROM audit_logs WHERE user_id=? AND action='system_backup.evidence_download.intent'", id); err != nil {
				t.Errorf("CLEANUP_PENDING download audit user=%s audit rows", name)
				return
			}
			var n int
			if db.QueryRowContext(cleanup, "SELECT COUNT(*) FROM audit_logs WHERE user_id=?", id).Scan(&n) != nil || n != 0 {
				t.Errorf("CLEANUP_PENDING download audit user=%s remaining audit", name)
				return
			}
			if _, err = db.ExecContext(cleanup, "DELETE FROM users WHERE id=? AND username=? AND email=?", id, name, email); err != nil {
				t.Errorf("CLEANUP_PENDING download audit user=%s", name)
				return
			}
		}
		var n int
		if db.QueryRowContext(cleanup, "SELECT COUNT(*) FROM users WHERE username=? AND email=?", name, email).Scan(&n) != nil || n != 0 {
			t.Errorf("CLEANUP_PENDING download audit user=%s absence", name)
			return
		}
		t.Log("CLEANED download admission audit owned user/audit", name)
	})
	r, err := db.ExecContext(ctx, "INSERT INTO users(username,email,password_hash,role,is_active) VALUES (?,?,?,'admin',TRUE)", name, email, "isolated-download-audit-fixture-not-login")
	mustSQL(t, err)
	id, err := r.LastInsertId()
	mustSQL(t, err)
	return id
}

// This root tests the audit component only against the fresh actual catalog.
// It does not authorize a download or consume a nonce/create claim/operation.
func TestDDownloadAdmissionAuditMySQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	input := downloadAuditProbeCapsule(t)
	db := downloadAuditProbeDatabase(t, ctx)
	rows, err := db.QueryContext(ctx, "SELECT filename FROM schema_migrations ORDER BY filename")
	mustSQL(t, err)
	var names []string
	for rows.Next() {
		var name string
		mustSQL(t, rows.Scan(&name))
		names = append(names, name)
	}
	mustSQL(t, rows.Err())
	mustSQL(t, rows.Close())
	if !slices.Equal(names, input.Migrations) {
		t.Fatal("actual catalog filenames differ")
	}
	store := SQLDownloadAdmissionAudits{}
	for _, scenario := range []string{"actual_insert_id_and_timestamp", "rollback_visibility", "same_transaction_mutation", "cross_transaction_anchor"} {
		t.Run(scenario, func(t *testing.T) {
			user := downloadAuditOwnedUser(t, ctx, db)
			var entropy [16]byte
			_, err := rand.Read(entropy[:])
			mustSQL(t, err)
			h := hex.EncodeToString(entropy[:])
			uuid := h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
			f := DownloadAdmissionIntent{Installation: "installation_audit_probe", OperationID: "sop_" + uuid, EvidenceID: "sev_" + uuid, RequestHash: strings.Repeat("a", 64), ManifestSHA256: strings.Repeat("b", 64), Claim: "aev_" + h, ActorID: user, EvidenceRowVersion: 7, Start: 1, End: 9, RangePresent: true}
			tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
			mustSQL(t, err)
			defer tx.Rollback()
			a, err := store.StageIntent(ctx, tx, f)
			mustSQL(t, err)
			var pending int
			mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_logs WHERE id=?", a.id).Scan(&pending))
			if pending != 0 {
				t.Fatal("audit committed outside caller transaction")
			}
			switch scenario {
			case "actual_insert_id_and_timestamp":
				id, err := store.RecheckIntent(ctx, tx, a)
				mustSQL(t, err)
				if id != a.id || id < 1 {
					t.Fatal("actual ID changed")
				}
				mustSQL(t, tx.Commit())
				var actor int64
				var created time.Time
				var raw []byte
				mustSQL(t, db.QueryRowContext(ctx, "SELECT user_id,details,created_at FROM audit_logs WHERE id=?", id).Scan(&actor, &raw, &created))
				var body map[string]any
				mustSQL(t, json.Unmarshal(raw, &body))
				if actor != user || !created.Equal(a.recordedAt) || created.Nanosecond() != 0 || body["claim_sha256"] != hash([]byte(f.Claim)) || body["operation_public_id"] != f.OperationID || strings.Contains(string(raw), f.Claim) {
					t.Fatal("stored audit facts or precision differ")
				}
			case "rollback_visibility":
				mustSQL(t, tx.Rollback())
				mustSQL(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_logs WHERE id=?", a.id).Scan(&pending))
				if pending != 0 {
					t.Fatal("rolled back intent remained")
				}
			case "same_transaction_mutation":
				_, err := tx.ExecContext(ctx, "UPDATE audit_logs SET details=JSON_SET(details,'$.evidence_row_version',99) WHERE id=?", a.id)
				mustSQL(t, err)
				if id, err := store.RecheckIntent(ctx, tx, a); !errors.Is(err, ErrAudit) || id != 0 {
					t.Fatal("rewritten audit accepted")
				}
			case "cross_transaction_anchor":
				other, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
				mustSQL(t, err)
				defer other.Rollback()
				if id, err := store.RecheckIntent(ctx, other, a); !errors.Is(err, ErrAudit) || id != 0 {
					t.Fatal("anchor crossed tx")
				}
			}
		})
	}
	t.Logf("PASS D download admission audit actual SQL; cases=4 catalog=%s migrations=%d fixture_root_grants=yes nonce_consumed=no production_approval=no", input.Catalog, len(input.Migrations))
}
