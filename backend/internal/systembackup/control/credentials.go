package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/worker"
)

type DatabaseGrant struct{ Database, ServerUUID, Host, Mode string }
type storedCredential struct {
	Spec     DatabaseGrant
	Username string
	Password []byte
	Owner    string
}
type DatabaseCredentials struct {
	Vault Vault
	Admin *sql.DB
}

var sqlName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func (g DatabaseGrant) valid() bool {
	return sqlName.MatchString(g.Database) && g.ServerUUID != "" && (g.Host == "%" || g.Host == "localhost" || net.ParseIP(g.Host) != nil) && (g.Mode == "capture" || g.Mode == "verify" || (g.Mode == "restore" && strings.HasPrefix(g.Database, "cm_drill_"))) && (g.Mode != "verify" || strings.HasPrefix(g.Database, "cm_drill_"))
}
func credentialOwner(t Task, ref string, g DatabaseGrant) string {
	b, _ := json.Marshal([]any{t.ID, t.ProfileRevision, ref, g})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func (p DatabaseCredentials) record(ctx context.Context, t Task, ref string, spec *DatabaseGrant) (storedCredential, error) {
	if !identifier.MatchString(ref) {
		return storedCredential{}, ErrInvalid
	}
	raw, e := p.Vault.Get(ctx, t, ref, "database-credential")
	if errors.Is(e, ErrNotFound) && spec != nil {
		if !spec.valid() {
			return storedCredential{}, ErrInvalid
		}
		random := make([]byte, 32)
		if _, e = rand.Read(random); e != nil {
			return storedCredential{}, ErrNotReady
		}
		owner := credentialOwner(t, ref, *spec)
		value := storedCredential{Spec: *spec, Username: "cm_bk_" + owner[:24], Owner: owner, Password: []byte("Cm9!" + hex.EncodeToString(random))}
		clear(random)
		raw, e = json.Marshal(value)
		clear(value.Password)
		if e != nil {
			return value, ErrInvalid
		}
		if e = p.Vault.Put(ctx, t, ref, "database-credential", raw); e != nil {
			clear(raw)
			return storedCredential{}, e
		}
	} else if e != nil {
		return storedCredential{}, e
	}
	defer clear(raw)
	var out storedCredential
	if json.Unmarshal(raw, &out) != nil || !out.Spec.valid() || out.Owner != credentialOwner(t, ref, out.Spec) || out.Username != "cm_bk_"+out.Owner[:24] || len(out.Password) != 68 || !strings.HasPrefix(string(out.Password), "Cm9!") {
		clear(out.Password)
		return storedCredential{}, ErrConflict
	}
	if _, e = hex.DecodeString(string(out.Password[4:])); e != nil || (spec != nil && out.Spec != *spec) {
		clear(out.Password)
		return storedCredential{}, ErrConflict
	}
	return out, nil
}
func (p DatabaseCredentials) state(ctx context.Context, t Task, ref, operation string) error {
	s := p.Vault.Store
	tx, e := s.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if s.Fence(ctx, tx, t) != nil {
		return ErrFence
	}
	var active, revoked bool
	e = tx.QueryRowContext(ctx, "SELECT active,revoked FROM system_backup_credentials WHERE task_id=? AND credential_ref=? FOR UPDATE", t.ID, ref).Scan(&active, &revoked)
	if errors.Is(e, sql.ErrNoRows) && (operation == "prepare" || operation == "revoke") {
		revoked = operation == "revoke"
		_, e = tx.ExecContext(ctx, "INSERT INTO system_backup_credentials(task_id,credential_ref,active,revoked) VALUES(?,?,FALSE,?)", t.ID, ref, revoked)
	}
	if e != nil {
		return ErrNotReady
	}
	if operation != "revoke" && operation != "removed" {
		current, e := load(ctx, tx, t.ID)
		n, ne := now(ctx, tx)
		if e != nil || ne != nil || !current.CanCancel || current.Deadline <= n || revoked {
			return ErrFence
		}
	}
	switch operation {
	case "prepare", "check":
	case "load":
		if !active {
			return ErrNotReady
		}
	case "activate":
		_, e = tx.ExecContext(ctx, "UPDATE system_backup_credentials SET active=TRUE WHERE task_id=? AND credential_ref=? AND revoked=FALSE", t.ID, ref)
	case "revoke":
		_, e = tx.ExecContext(ctx, "UPDATE system_backup_credentials SET revoked=TRUE,active=FALSE WHERE task_id=? AND credential_ref=?", t.ID, ref)
	case "removed":
		if !revoked || active {
			return ErrConflict
		}
		_, e = tx.ExecContext(ctx, "UPDATE system_backup_credentials SET removed=TRUE WHERE task_id=? AND credential_ref=? AND revoked=TRUE AND active=FALSE", t.ID, ref)
	default:
		return ErrInvalid
	}
	if e != nil || s.Fence(ctx, tx, t) != nil || tx.Commit() != nil {
		return ErrNotReady
	}
	return nil
}

// account serializes all account DDL on the REMOTE server, not merely the
// controller DB. A timed-out prior DDL must finish/release this session lock
// before cleanup can prove the account locked and all sessions terminated.
func (p DatabaseCredentials) account(ctx context.Context, r storedCredential, fn func(*sql.Conn) error) error {
	if p.Admin == nil {
		return ErrNotReady
	}
	conn, e := p.Admin.Conn(ctx)
	if e != nil {
		return ErrNotReady
	}
	defer func() { // Never return a connection with a lingering named lock to the pool.
		conn.Raw(func(any) error { return driver.ErrBadConn })
		conn.Close()
	}()
	var database, uuid string
	if conn.QueryRowContext(ctx, "SELECT DATABASE(), @@server_uuid").Scan(&database, &uuid) != nil || database != r.Spec.Database || uuid != r.Spec.ServerUUID {
		return ErrConflict
	}
	var sslName, sslCipher string
	if conn.QueryRowContext(ctx, "SHOW SESSION STATUS LIKE 'Ssl_cipher'").Scan(&sslName, &sslCipher) != nil || sslCipher == "" {
		return ErrNotReady
	}
	var locked int
	if conn.QueryRowContext(ctx, "SELECT GET_LOCK(?,0)", "cm-backup-"+r.Owner[:40]).Scan(&locked) != nil || locked != 1 {
		return ErrNotReady
	}
	return fn(conn)
}
func remoteOwner(ctx context.Context, c *sql.Conn, r storedCredential) (bool, error) {
	var owner sql.NullString
	e := c.QueryRowContext(ctx, "SELECT ATTRIBUTE->>'$.clawmanager_backup' FROM information_schema.USER_ATTRIBUTES WHERE USER=? AND HOST=?", r.Username, r.Spec.Host).Scan(&owner)
	if errors.Is(e, sql.ErrNoRows) {
		return false, nil
	}
	if e != nil {
		return false, ErrNotReady
	}
	if !owner.Valid || owner.String != r.Owner {
		return false, ErrConflict
	}
	return true, nil
}
func accountSQL(r storedCredential) string { return "'" + r.Username + "'@'" + r.Spec.Host + "'" }
func (p DatabaseCredentials) Ensure(ctx context.Context, t Task, ref string, g DatabaseGrant) error {
	r, e := p.record(ctx, t, ref, &g)
	if e != nil {
		return e
	}
	defer clear(r.Password)
	if e = p.state(ctx, t, ref, "prepare"); e != nil {
		return e
	}
	return p.account(ctx, r, func(c *sql.Conn) error {
		exists, e := remoteOwner(ctx, c, r)
		if e != nil {
			return e
		}
		execute := func(statement string) error {
			if e := p.state(ctx, t, ref, "check"); e != nil {
				return e
			}
			if _, e := c.ExecContext(ctx, statement); e != nil {
				return ErrNotReady
			}
			return nil
		}
		if !exists {
			if e = execute("CREATE USER " + accountSQL(r) + " IDENTIFIED BY '" + string(r.Password) + "' REQUIRE SSL WITH MAX_USER_CONNECTIONS 2 ACCOUNT LOCK ATTRIBUTE '{\"clawmanager_backup\":\"" + r.Owner + "\"}'"); e != nil {
				return e
			}
		}
		exists, e = remoteOwner(ctx, c, r)
		if e != nil || !exists {
			return ErrConflict
		}
		grants := "SELECT"
		if g.Mode == "restore" {
			grants = "SELECT, INSERT, UPDATE, DELETE"
		}
		grantDatabase, e := domain.QuotedGrantDatabase(ctx, c, g.Database)
		if e != nil {
			return ErrNotReady
		}
		if e = execute("GRANT " + grants + " ON " + grantDatabase + ".* TO " + accountSQL(r)); e != nil {
			return e
		}
		if e = verifyAccountGrants(ctx, c, r); e != nil {
			return e
		}
		if e = execute("ALTER USER " + accountSQL(r) + " ACCOUNT UNLOCK"); e != nil {
			return e
		}
		return p.state(ctx, t, ref, "activate")
	})
}
func verifyAccountGrants(ctx context.Context, c *sql.Conn, r storedCredential) error {
	grantDatabase, e := domain.QuotedGrantDatabase(ctx, c, r.Spec.Database)
	if e != nil {
		return ErrNotReady
	}
	rows, e := c.QueryContext(ctx, "SHOW GRANTS FOR "+accountSQL(r))
	if e != nil {
		return ErrNotReady
	}
	defer rows.Close()
	seen := map[string]bool{}
	expected := map[string]bool{"SELECT": true}
	if r.Spec.Mode == "restore" {
		expected["INSERT"] = true
		expected["UPDATE"] = true
		expected["DELETE"] = true
	}
	for rows.Next() {
		var grant string
		if rows.Scan(&grant) != nil {
			return ErrNotReady
		}
		if strings.Contains(grant, "WITH GRANT OPTION") {
			return ErrConflict
		}
		if strings.HasPrefix(grant, "GRANT USAGE ON *.* TO ") {
			continue
		}
		parts := strings.SplitN(grant, " ON "+grantDatabase+".* TO ", 2)
		if len(parts) != 2 || !strings.HasPrefix(parts[0], "GRANT ") {
			return ErrConflict
		}
		for _, privilege := range strings.Split(strings.TrimPrefix(parts[0], "GRANT "), ",") {
			privilege = strings.TrimSpace(privilege)
			if !expected[privilege] || seen[privilege] {
				return ErrConflict
			}
			seen[privilege] = true
		}
	}
	if rows.Err() != nil || len(seen) != len(expected) {
		return ErrConflict
	}
	return nil
}
func (p DatabaseCredentials) Load(ctx context.Context, t Task, ref string) (*worker.DatabaseCredential, error) {
	r, e := p.record(ctx, t, ref, nil)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			clear(r.Password)
		}
	}()
	if e = p.state(ctx, t, ref, "load"); e != nil {
		return nil, e
	}
	e = p.account(ctx, r, func(c *sql.Conn) error {
		exists, e := remoteOwner(ctx, c, r)
		if e != nil || !exists {
			return ErrConflict
		}
		var locked string
		if c.QueryRowContext(ctx, "SELECT account_locked FROM mysql.user WHERE User=? AND Host=?", r.Username, r.Spec.Host).Scan(&locked) != nil || locked != "N" {
			return ErrNotReady
		}
		return verifyAccountGrants(ctx, c, r)
	})
	if e != nil {
		return nil, e
	}
	ok = true
	return &worker.DatabaseCredential{Username: r.Username, Password: r.Password}, nil
}
func (p DatabaseCredentials) Revoke(ctx context.Context, t Task, ref string) error {
	r, e := p.record(ctx, t, ref, nil)
	if e != nil {
		return e
	}
	defer clear(r.Password)
	if e = p.state(ctx, t, ref, "revoke"); e != nil {
		return e
	}
	return p.account(ctx, r, func(c *sql.Conn) error {
		exists, e := remoteOwner(ctx, c, r)
		if e != nil {
			return e
		}
		fence := func() error {
			tx, e := p.Vault.Store.begin(ctx)
			if e != nil {
				return e
			}
			defer tx.Rollback()
			return p.Vault.Store.Fence(ctx, tx, t)
		}
		exec := func(q string) error {
			if e := fence(); e != nil {
				return e
			}
			if _, e := c.ExecContext(ctx, q); e != nil {
				return ErrNotReady
			}
			return nil
		}
		if exists {
			if e = exec("ALTER USER " + accountSQL(r) + " ACCOUNT LOCK"); e != nil {
				return e
			}
		}
		var foreign int
		if c.QueryRowContext(ctx, "SELECT COUNT(*) FROM mysql.user WHERE User=? AND Host<>?", r.Username, r.Spec.Host).Scan(&foreign) != nil || foreign != 0 {
			return ErrConflict
		}
		for {
			if e = fence(); e != nil {
				return e
			}
			rows, e := c.QueryContext(ctx, "SELECT ID FROM information_schema.PROCESSLIST WHERE USER=?", r.Username)
			if e != nil {
				return ErrNotReady
			}
			var ids []uint64
			for rows.Next() {
				var id uint64
				if rows.Scan(&id) != nil || id == 0 {
					rows.Close()
					return ErrNotReady
				}
				ids = append(ids, id)
				if len(ids) > 64 {
					rows.Close()
					return ErrConflict
				}
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return ErrNotReady
			}
			if len(ids) == 0 {
				break
			}
			for _, id := range ids {
				if e = exec("KILL CONNECTION " + strconv.FormatUint(id, 10)); e != nil {
					return e
				}
			}
			if !waitPoll(ctx, 100*time.Millisecond) {
				return ctx.Err()
			}
		}
		if exists {
			if e = exec("DROP USER " + accountSQL(r)); e != nil {
				return e
			}
		}
		exists, e = remoteOwner(ctx, c, r)
		if e != nil || exists {
			return ErrNotReady
		}
		var sessions int
		if c.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE USER=?", r.Username).Scan(&sessions) != nil || sessions != 0 {
			return ErrNotReady
		}
		return p.state(ctx, t, ref, "removed")
	})
}
