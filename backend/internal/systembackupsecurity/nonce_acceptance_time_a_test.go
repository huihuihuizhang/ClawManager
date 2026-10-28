package systembackupsecurity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// Wrap the existing transaction models. Only SQL transport/UTC_TIMESTAMP are
// modeled: real Ed25519 verification still runs. Evaluate the actual INSERT's
// WHERE times and published ledger ordering rather than assuming an INSERT
// succeeds. This does not establish real MySQL locks or CHECK enforcement.
type aNonceTimeConnector struct {
	base driver.Connector
	tap  *aNonceTimeTap
}

func (c aNonceTimeConnector) Driver() driver.Driver { return c.base.Driver() }
func (c aNonceTimeConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &aNonceTimeConn{Conn: conn, tap: c.tap}, nil
}

type aNonceTimeTap struct {
	t                                        *testing.T
	now                                      *time.Time
	advance                                  func()
	providerSkew                             int64
	called                                   bool
	authenticated, earliest, latest, expires time.Time
	inserted                                 bool
}

type aNonceTimeConn struct {
	driver.Conn
	tap *aNonceTimeTap
}

func (c *aNonceTimeConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
}
func (c *aNonceTimeConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	rows, err := c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
	if err != nil || !strings.Contains(query, "SELECT provider_proof_issuers_registry_version") {
		return rows, err
	}
	defer rows.Close()
	values := make([]driver.Value, len(rows.Columns()))
	if err := rows.Next(values); err != nil {
		return nil, err
	}
	values[9] = c.tap.providerSkew
	return registrationRow(values...), nil
}
func (c *aNonceTimeConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if !strings.Contains(query, "INSERT INTO system_backup_v2_strong_auth_nonces") {
		return c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
	}
	p := c.tap
	p.called = true
	if len(args) != 17 || !strings.Contains(query, "WHERE UTC_TIMESTAMP(6)>=? AND UTC_TIMESTAMP(6)<? AND UTC_TIMESTAMP(6)<=?") {
		p.t.Fatal("nonce SQL must preserve the three original time guards")
	}
	p.authenticated, p.expires = args[9].Value.(time.Time), args[10].Value.(time.Time)
	p.earliest, p.latest = args[14].Value.(time.Time), args[16].Value.(time.Time)
	if p.advance != nil {
		p.advance()
	}
	now := *p.now
	if now.Before(p.earliest) || !now.Before(args[15].Value.(time.Time)) || now.After(p.latest) {
		return driver.RowsAffected(0), nil
	}
	if p.authenticated.After(now) || now.After(p.expires) || !args[13].Value.(time.Time).After(p.expires) {
		p.t.Fatal("nonce INSERT would violate published ledger time ordering")
	}
	p.inserted = true
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
}

func aNonceTimeDB(t *testing.T, base driver.Connector, tap *aNonceTimeTap) *sql.DB {
	t.Helper()
	db := sql.OpenDB(aNonceTimeConnector{base: base, tap: tap})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}

func aResignNonceTimeProof(t *testing.T, p *Proof, auth, expiry time.Time) {
	t.Helper()
	p.Payload.AuthTime, p.Payload.ExpiresAt = auth.Format(time.RFC3339Nano), expiry.Format(time.RFC3339Nano)
	payload, err := CanonicalPayload(p.Payload)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("s", 32)))
	p.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key,
		[]byte(p.Signature.ProtectedHeader+"."+base64.RawURLEncoding.EncodeToString(payload))))
}

func TestASensitiveDownloadNonceAcceptanceTime(t *testing.T) {
	for _, offset := range []time.Duration{-time.Minute, 3 * time.Second} {
		t.Run(offset.String(), func(t *testing.T) {
			r, proof, cfg := sensitiveDownloadSignedFixture(t)
			cfg.ClockSkew = 5 * time.Second
			proof.Payload.AuthTime = cfg.Now.Add(offset).Format(time.RFC3339Nano)
			payload, err := CanonicalPayload(proof.Payload)
			if err != nil {
				t.Fatal(err)
			}
			key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
			proof.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key,
				[]byte(proof.Signature.ProtectedHeader+"."+base64.RawURLEncoding.EncodeToString(payload))))
			v, err := r.VerifyProof(proof, proof.Payload.Issuer, cfg)
			if err != nil || !v.ProofAcceptedAt().Equal(cfg.Now) {
				t.Fatal("server verification sample not preserved", err)
			}
			if v.ProofAcceptedAt().Equal(cfg.Now.Add(offset)) {
				t.Fatal("issuer time used as server acceptance")
			}
			cfg.Now = cfg.Now.Add(time.Hour)
			if !v.ProofAcceptedAt().Equal(cfg.Now.Add(-time.Hour)) {
				t.Fatal("acceptance time refreshed")
			}
		})
	}
	if !(SensitiveDownloadProofVerification{}).ProofAcceptedAt().IsZero() {
		t.Fatal("zero proof has acceptance time")
	}
}

func TestAProviderNonceUsesSQLAcceptanceTime(t *testing.T) {
	for _, name := range []string{"past_auth", "future_within_skew", "future_outside_skew", "clock_regression", "expiry_during_insert", "age_during_insert"} {
		t.Run(name, func(t *testing.T) {
			svc, actor, raw, proof, state := registrationFixture(t)
			accepted := state.now
			auth, expiry := accepted.Add(-time.Minute), accepted.Add(time.Minute)
			if name == "future_within_skew" {
				auth = accepted.Add(3 * time.Second)
			}
			if name == "future_outside_skew" {
				auth = accepted.Add(31 * time.Second)
			}
			if name == "age_during_insert" {
				expiry = accepted.Add(20 * time.Minute)
			}
			aResignNonceTimeProof(t, &proof, auth, expiry)
			tap := &aNonceTimeTap{t: t, now: &state.now, providerSkew: 30}
			switch name {
			case "clock_regression":
				tap.advance = func() { state.now = accepted.Add(-time.Microsecond) }
			case "expiry_during_insert":
				tap.advance = func() { state.now = expiry }
			case "age_during_insert":
				tap.advance = func() { state.now = auth.Add(330*time.Second + time.Microsecond) }
			}
			svc.DB = aNonceTimeDB(t, registrationTestConnector{state}, tap)
			result, err := svc.Register(context.Background(), actor, raw, proof)
			if name == "past_auth" || name == "future_within_skew" {
				if err != nil || result.HTTPStatus != 201 || state.commits != 1 || !tap.inserted || !tap.authenticated.Equal(accepted) || !tap.earliest.Equal(accepted) {
					t.Fatalf("server acceptance time lost: err=%v authenticated=%s accepted=%s", err, tap.authenticated, accepted)
				}
			} else if err == nil || result.HTTPStatus != 0 || state.commits != 0 || len(state.committed) != 0 || tap.inserted {
				t.Fatal("invalid final clock/proof committed effects", err)
			}
			if name == "future_outside_skew" && tap.called {
				t.Fatal("invalid proof reached nonce INSERT")
			}
		})
	}
}

func TestAConfigNonceUsesSQLAcceptanceTime(t *testing.T) {
	for _, name := range []string{"past_auth", "future_within_skew", "future_outside_skew", "clock_regression", "expiry_during_insert", "age_during_insert"} {
		t.Run(name, func(t *testing.T) {
			svc, actor, raw, state, cfg := mutationTransactionFixture(t)
			raw = bytes.Replace(raw, []byte(`"retention_seconds":2592000`), []byte(`"retention_seconds":86400`), 1)
			raw = bytes.Replace(raw, []byte(`"change_reason":null`), []byte(`"change_reason":"nonce acceptance time regression"`), 1)
			request, err := DecodeConfigMutationRequest(ConfigUpdateEndpoint, raw)
			if err != nil {
				t.Fatal(err)
			}
			accepted := state.now
			proof := mutationTransactionProof(t, request, actor, accepted, &cfg)
			svc.Authority = mutationTestAuthority{state, cfg}
			numbers := state.data.rows[1].snapshot.numbers
			skew := time.Duration(numbers["strong_auth_clock_skew_seconds"]) * time.Second
			auth, expiry := accepted.Add(-time.Minute), accepted.Add(3*time.Minute)
			if name == "future_within_skew" {
				auth = accepted.Add(skew)
			}
			if name == "future_outside_skew" {
				auth = accepted.Add(skew + time.Microsecond)
			}
			if name == "age_during_insert" {
				expiry = accepted.Add(20 * time.Minute)
			}
			aResignNonceTimeProof(t, &proof, auth, expiry)
			tap := &aNonceTimeTap{t: t, now: &state.now}
			switch name {
			case "clock_regression":
				tap.advance = func() { state.now = accepted.Add(-time.Microsecond) }
			case "expiry_during_insert":
				tap.advance = func() { state.now = expiry }
			case "age_during_insert":
				tap.advance = func() {
					state.now = auth.Add(time.Duration(numbers["strong_auth_max_age_seconds"])*time.Second + skew + time.Microsecond)
				}
			}
			svc.DB = aNonceTimeDB(t, mutationTestConnector{state}, tap)
			result, err := svc.Mutate(context.Background(), actor, ConfigUpdateEndpoint, "mutation_key_0123456789", "a-nonce-time", raw, &proof)
			if name == "past_auth" || name == "future_within_skew" {
				if err != nil || result.HTTPStatus != 200 || state.data.active != 2 || !tap.inserted || !tap.authenticated.Equal(accepted) || !tap.earliest.Equal(accepted) {
					t.Fatalf("server acceptance time lost: err=%v authenticated=%s accepted=%s", err, tap.authenticated, accepted)
				}
			} else {
				mutationARequireRollback(t, state, result, err)
				if tap.inserted {
					t.Fatal("nonce time guard accepted invalid clock")
				}
			}
			if name == "future_outside_skew" && tap.called {
				t.Fatal("invalid proof reached nonce INSERT")
			}
		})
	}
}
