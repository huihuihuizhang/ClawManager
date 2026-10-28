package systembackupsecurity

import (
	"context"
	"crypto/tls"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type maintenanceHolderSessionConnector struct{ state *mutationSessionDB }

func (c maintenanceHolderSessionConnector) Driver() driver.Driver { return registrationTestDriver{} }
func (c maintenanceHolderSessionConnector) Connect(context.Context) (driver.Conn, error) {
	return &maintenanceHolderSessionConn{loginSessionConn{&c.state.loginSessionDB}, c.state}, nil
}

type maintenanceHolderSessionConn struct {
	loginSessionConn
	state *mutationSessionDB
}

func (c *maintenanceHolderSessionConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.state.queries = append(c.state.queries, query)
	if strings.HasPrefix(query, "SELECT UTC_TIMESTAMP(6),TIMESTAMPDIFF") {
		return registrationRow(c.state.finalNow, c.state.offset), nil
	}
	return c.loginSessionConn.QueryContext(ctx, query, args)
}

func (c *maintenanceHolderSessionConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.state.writes++
	return nil, errors.New("holder check must not write")
}

// Real JWT verification and the actual SQL session adapter; the SQL transport
// and grant remain models. No real grant or directory event is attested here.
func maintenanceSessionHolderFixture(t *testing.T) (*mutationSessionFixture, *configMaintenanceSessionHolder, configMaintenanceScope, *http.Request) {
	t.Helper()
	f := newMutationSessionFixture(t)
	if err := f.tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(maintenanceHolderSessionConnector{f.model})
	f.s.db = db
	var err error
	f.tx, err = db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.tx.Rollback(); db.Close() })
	now := time.Now().UTC().Truncate(time.Second)
	f.notBefore, f.model.now, f.model.finalNow = now, now, now
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": 42, "token_type": "access", "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix()})
	raw, err := token.SignedString(f.s.secret)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "https://maintenance.invalid/private", nil)
	req.TLS.Version = tls.VersionTLS13
	req.Header.Set("Authorization", "Bearer "+raw)
	h, err := newConfigMaintenanceSessionHolder(f.s, "deployment-stable-issuer", req)
	if err != nil {
		t.Fatal(err)
	}
	// Re-signing a token does not create a SQL session: install its independently
	// recorded credential-bound row explicitly in this synthetic SQL model.
	f.actor, f.ctx = h.actor, h.bound
	row := loginSessionRow{user: h.actor.UserID, subject: h.actor.Subject, credential: registrationHash(f.model.password), expires: h.actor.SessionExpiresAt}
	f.model.pending = map[string]loginSessionRow{h.actor.Session: row}
	_, _, _, old, _ := maintenanceServiceFixture(t)
	var body map[string]any
	if json.Unmarshal(old.canonical, &body) != nil {
		t.Fatal("maintenance request fixture")
	}
	body["target_server_uuid"], body["target_database"] = f.s.identity.ServerUUID, f.s.identity.Database
	body["origin_installation_id"], body["maintenance_actor_sha256"] = f.installation, h.digest
	rawBody, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := newConfigMaintenanceScope(f.s.identity, f.installation, h.digest, old.key, rawBody)
	if err != nil {
		t.Fatal(err)
	}
	return f, h, scope, req
}

func TestConfigMaintenanceSessionHolderAuthenticatesTransport(t *testing.T) {
	f, h, _, req := maintenanceSessionHolderFixture(t)
	for _, tc := range []struct {
		name string
		edit func(*http.Request)
	}{
		{"no-tls", func(r *http.Request) { r.TLS = nil }},
		{"old-tls", func(r *http.Request) { r.TLS = &tls.ConnectionState{Version: tls.VersionTLS11} }},
		{"forwarded-tls", func(r *http.Request) { r.TLS = nil; r.Header.Set("X-Forwarded-Proto", "https") }},
		{"missing-bearer", func(r *http.Request) { r.Header.Del("Authorization") }},
		{"forged-bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer forged") }},
		{"duplicate-bearer", func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) }},
		{"cancelled", func(r *http.Request) {
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			*r = *r.WithContext(ctx)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := req.Clone(req.Context())
			tc.edit(r)
			got, err := newConfigMaintenanceSessionHolder(f.s, h.issuer, r)
			if got != nil || !errors.Is(err, ErrRegistrationPermission) {
				t.Fatal("invalid transport released holder", err)
			}
		})
	}
	if got, err := newConfigMaintenanceSessionHolder(f.s, h.issuer, nil); got != nil || err == nil {
		t.Fatal("nil request accepted")
	}
	if got, err := newConfigMaintenanceSessionHolder(f.s, " ", req); got != nil || err == nil {
		t.Fatal("invalid logical issuer accepted")
	}
	if _, err := json.Marshal(h); err == nil {
		t.Fatal("holder serialized")
	}
}

func TestConfigMaintenanceSessionHolderChecksCurrentSessionAndGrant(t *testing.T) {
	for _, name := range []string{"active", "different-context", "different-holder", "different-installation", "different-target", "different-actor", "revoked-before", "changed-password", "grant-wrong-principal", "grant-wrong-issuer", "grant-private-error", "revoked-during-grant", "shortened-during-grant", "expired-during-grant", "cancelled-during-grant"} {
		t.Run(name, func(t *testing.T) {
			f, h, scope, req := maintenanceSessionHolderFixture(t)
			calls := 0
			ctx, cancel := context.WithCancel(h.bound)
			defer cancel()
			switch name {
			case "different-context":
				ctx = context.Background()
			case "different-holder":
				other, err := newConfigMaintenanceSessionHolder(f.s, h.issuer, req)
				if err != nil {
					t.Fatal(err)
				}
				ctx = other.bound
			case "different-installation":
				scope.identity.Installation = "installation_other"
			case "different-target":
				scope.database.Database = "another_database"
			case "different-actor":
				scope.identity.Actor = strings.Repeat("f", 64)
			case "revoked-before":
				f.session(func(r *loginSessionRow) { r.revoked = true })
			case "changed-password":
				f.model.password = "new-password"
			}
			verify, err := h.withGrantVerifier(func(context.Context, *sql.Tx, configMaintenanceScope, time.Time) (configMaintenanceGrantFacts, error) {
				calls++
				facts := configMaintenanceGrantFacts{actorIssuer: h.issuer, principal: h.principal, issuer: "independent-grant-issuer", grantID: "grant-01"}
				switch name {
				case "grant-wrong-principal":
					facts.principal = "user:7"
				case "grant-wrong-issuer":
					facts.actorIssuer = "different-issuer"
				case "grant-private-error":
					return facts, errors.New("PRIVATE grant file detail")
				case "revoked-during-grant":
					f.session(func(r *loginSessionRow) { r.revoked = true })
				case "shortened-during-grant":
					f.session(func(r *loginSessionRow) { r.expires = r.expires.Add(-time.Second) })
				case "expired-during-grant":
					f.model.finalNow = h.actor.SessionExpiresAt
				case "cancelled-during-grant":
					cancel()
				}
				return facts, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			got, err := verify(ctx, f.tx, scope, f.notBefore)
			if name == "active" {
				if err != nil || got.principal != h.principal || got.issuer != "independent-grant-issuer" || calls != 1 {
					t.Fatal("valid independent holder/grant rejected", err)
				}
			} else if err == nil || got != (configMaintenanceGrantFacts{}) || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("invalid holder released grant facts", err)
			}
			if (strings.HasPrefix(name, "different-") || name == "revoked-before" || name == "changed-password") && calls != 0 {
				t.Fatal("grant verifier ran before holder admission")
			}
			if f.model.writes != 0 || f.model.commits != 0 {
				t.Fatal("holder wrote or committed caller transaction")
			}
		})
	}
}
