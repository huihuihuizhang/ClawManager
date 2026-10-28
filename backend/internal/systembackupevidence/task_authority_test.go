package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Scripted database transport exercises the real authority's SQL, scan and
// decision paths. It is not a MySQL lock/concurrency integration test.
type authorityQuery struct {
	match        string
	args, values []driver.Value
}
type authorityDB struct {
	t                      *testing.T
	plan                   []authorityQuery
	index, commits, begins int
	onBegin                func(int)
	onCommit               func()
	commitErr              bool
}
type authorityDriver struct{}

func (authorityDriver) Open(string) (driver.Conn, error)            { return nil, errors.New("use connector") }
func (d *authorityDB) Driver() driver.Driver                        { return authorityDriver{} }
func (d *authorityDB) Connect(context.Context) (driver.Conn, error) { return d, nil }
func (d *authorityDB) Prepare(string) (driver.Stmt, error)          { return nil, errors.New("no statements") }
func (d *authorityDB) Close() error                                 { return nil }
func (d *authorityDB) Begin() (driver.Tx, error) {
	return nil, errors.New("explicit transaction required")
}
func (d *authorityDB) BeginTx(_ context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if opts.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) || opts.ReadOnly {
		d.t.Fatal("wrong transaction options")
	}
	d.index = 0
	d.begins++
	if d.onBegin != nil {
		d.onBegin(d.begins)
	}
	return d, nil
}
func (d *authorityDB) Commit() error {
	if d.index != len(d.plan) {
		d.t.Fatalf("commit before all checks: %d/%d", d.index, len(d.plan))
	}
	if d.commitErr {
		return errors.New("private db failure")
	}
	if d.onCommit != nil {
		d.onCommit()
	}
	d.commits++
	return nil
}
func (d *authorityDB) Rollback() error { return nil }
func (d *authorityDB) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if d.index >= len(d.plan) {
		d.t.Fatalf("unexpected SQL: %s", q)
	}
	p := d.plan[d.index]
	d.index++
	if !strings.Contains(q, p.match) || len(args) != len(p.args) {
		d.t.Fatalf("wrong SQL/args: %s", q)
	}
	for i, a := range args {
		if !reflect.DeepEqual(a.Value, p.args[i]) {
			d.t.Fatalf("wrong SQL argument %d", i)
		}
	}
	return &authorityRows{values: p.values}, nil
}

type authorityRows struct {
	values []driver.Value
	done   bool
}

func (r *authorityRows) Columns() []string { return make([]string, len(r.values)) }
func (r *authorityRows) Close() error      { return nil }
func (r *authorityRows) Next(dst []driver.Value) error {
	if r.done || r.values == nil {
		return io.EOF
	}
	r.done = true
	copy(dst, r.values)
	return nil
}

type taskFixture struct {
	a        *SQLTaskAuthority
	c        TaskAuthorityConfig
	db       *authorityDB
	ctx      context.Context
	request  *http.Request
	client   tls.Certificate
	identity Identity
	scope    S3Scope
	record   Record
	body     []byte
}

func newTaskFixture(t *testing.T, s3 bool) *taskFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "local task CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ = x509.ParseCertificate(caDER)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "task producer"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ = x509.ParseCertificate(der)
	d := &authorityDB{t: t}
	db := sql.OpenDB(d)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	c := TaskAuthorityConfig{DB: db, Installation: "installation_test", ServerUUID: "test-server", Database: "test-db", ConfigVersion: 3, ConfigSHA256: hash([]byte(`{}`)),
		Root: "evidence", Store: KeyRef{strings.Repeat("a", 64), "store-v1"}, Write: KeyRef{strings.Repeat("b", 64), "write-v1"}, ClientCAPEM: caPEM, ClientCASHA256: hash(caPEM), CertificateSHA256: hash(der),
		OwnerType: "backup", OwnerID: "sbk_11111111-2222-4333-8444-555555555555", ControllerOwner: "controller-one", Attempt: 2, Phase: "capture", JobUnit: "capture", JobUID: "11111111-2222-4333-8444-555555555555", JobGeneration: 1,
		RelayIdentity: "relay-current", RelayVersion: "relay-v2", Issuer: "https://issuer.example", Audience: "evidence-sts", Subject: "system:serviceaccount:backup:producer", TokenFile: filepath.Join(t.TempDir(), "token"), ExpiresAt: now.Add(10 * time.Minute), Classification: "sensitive", LogPolicy: logTestPolicy()}
	f := &taskFixture{c: c, db: d, client: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, body: bytes.Repeat([]byte(logGood+"\n"), 70)}
	line, err := logLine([]byte(logGood), c.LogPolicy, false)
	if err != nil {
		t.Fatal(err)
	}
	f.body = bytes.Repeat(line, 70)
	f.identity = Identity{Installation: c.Installation, ID: "sev_11111111-2222-4333-8444-555555555555", OwnerType: c.OwnerType, OwnerID: c.OwnerID, Type: "job_log_chunk", Media: "text/plain", Classification: c.Classification, ContentHash: hash(f.body), ContentSize: int64(len(f.body))}
	objectKey, _ := keyFor(c.Root, f.identity)
	f.record = Record{Manifest: Manifest{Identity: f.identity}, Claim: "aev_0123456789abcdef0123456789abcdef", RowVersion: 2}
	f.scope = S3Scope{Ref: Ref{Identity: c.Store.Identity, Version: c.Store.Version, RelativeKey: objectKey}, Operation: S3Stat}
	d.plan = []authorityQuery{
		{"SELECT @@server_uuid", nil, []driver.Value{c.ServerUUID, c.Database, now, int64(0)}},
		{"ORDER BY origin_installation_id FOR UPDATE", nil, []driver.Value{c.Installation}},
		{"SELECT active_config_version,last_effective_enabled", []driver.Value{c.Installation}, []driver.Value{c.ConfigVersion, true}},
		{"FROM system_backup_v2_configs", []driver.Value{c.Installation, c.ConfigVersion}, []driver.Value{c.ConfigSHA256, int64(2), true, c.Store.Identity, c.Store.Version, c.Write.Identity, c.Write.Version}},
		{"FROM system_backup_v2_backups", []driver.Value{c.Installation, c.OwnerID}, []driver.Value{c.ConfigVersion, c.ConfigSHA256, int64(2), []byte(`{}`), "capturing", c.ControllerOwner, now.Add(2 * time.Minute), now.Add(5 * time.Minute)}},
		{"ORDER BY attempt_no DESC LIMIT 1 FOR UPDATE", []driver.Value{c.OwnerType, c.OwnerID, c.Phase}, []driver.Value{c.Attempt, "running"}},
		{"FROM system_backup_v2_job_observations", []driver.Value{c.Installation, c.OwnerType, c.OwnerID, c.Attempt, c.Phase, c.JobUnit}, []driver.Value{c.JobUID, c.JobGeneration, c.RelayIdentity, c.RelayVersion, now.Add(-time.Minute), now.Add(3 * time.Minute)}},
	}
	if s3 {
		d.plan = append(d.plan, authorityQuery{"FROM system_backup_v2_evidence WHERE public_id=? FOR UPDATE", []driver.Value{f.identity.ID}, []driver.Value{
			c.OwnerType, c.OwnerID, f.identity.Type, f.identity.Media, c.Classification, f.identity.ContentHash, f.identity.ContentSize, "pending", "evidence", c.Store.Identity, c.Store.Version, objectKey, hash([]byte(objectKey)), nil,
			strings.Repeat("c", 64), int64(20000), "envelope_v1", Framing, f.record.Claim, now.Add(25 * time.Second), now.Add(time.Hour), int64(2),
		}})
	}
	d.plan = append(d.plan, authorityQuery{"SELECT UTC_TIMESTAMP(6)", nil, []driver.Value{now}})
	f.a, err = NewSQLTaskAuthority(c)
	if err != nil {
		t.Fatal(err)
	}
	f.request = httptest.NewRequest("POST", "https://local/evidence", nil)
	f.request.TLS = &tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, ca}}}
	f.ctx, err = f.a.AuthenticateRequest(f.request)
	if err != nil {
		t.Fatal(err)
	}
	if s3 {
		f.ctx = withEvidenceAccess(f.ctx, "task", f.record)
	}
	f.writeToken(t, map[string]any{"iss": c.Issuer, "sub": c.Subject, "aud": c.Audience, "exp": now.Add(8 * time.Minute).Unix()})
	return f
}

func (f *taskFixture) writeToken(t *testing.T, claims map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(claims)
	token := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + base64.RawURLEncoding.EncodeToString(raw) + ".signature"
	if err := os.WriteFile(f.c.TokenFile, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestTaskAuthorityContentAndTLS(t *testing.T) {
	f := newTaskFixture(t, false)
	dispatcher, _ := NewContentDispatcher(f.a)
	if err := dispatcher.Validate(f.ctx, f.identity, bytes.NewReader(f.body)); err != nil || f.db.commits != 2 {
		t.Fatalf("content denied: %v", err)
	}
	// The constructor freezes the caller's policy, and returned policy is owned.
	delete(f.c.LogPolicy.Events, "progress")
	grant, err := f.a.AuthorizeContent(f.ctx, f.identity)
	if err != nil {
		t.Fatal(err)
	}
	delete(grant.JobLog.Events, "progress")
	if err := dispatcher.Validate(f.ctx, f.identity, bytes.NewReader(f.body)); err != nil {
		t.Fatal("policy alias", err)
	}
	// Real TLS transport verifies proof of possession, not just certificate bytes.
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, err := f.a.AuthenticateRequest(r)
		if err != nil || dispatcher.Validate(ctx, f.identity, bytes.NewReader(f.body)) != nil {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(204)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: f.a.roots, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{f.client}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal("mTLS request rejected")
	}
}

func TestTaskAuthorityRejectsIdentityAndState(t *testing.T) {
	for _, test := range []struct {
		name          string
		query, column int
		value         driver.Value
	}{
		{"database", 0, 1, "other"}, {"server", 0, 0, "other"}, {"non_UTC", 0, 3, int64(1)},
		{"installation", 1, 0, "installation_other"}, {"config_version", 2, 0, int64(4)}, {"disabled", 2, 1, false},
		{"config_hash", 3, 0, strings.Repeat("e", 64)}, {"config_disabled", 3, 2, false}, {"store_ref", 3, 4, "other"}, {"write_identity", 3, 5, strings.Repeat("e", 64)},
		{"snapshot_bytes", 4, 3, []byte(`[]`)}, {"task_config", 4, 0, int64(4)}, {"terminal", 4, 4, "succeeded"}, {"canceling", 4, 4, "canceling"},
		{"controller_takeover", 4, 5, "other"}, {"lease_expired", 4, 6, -time.Minute}, {"deadline", 4, 7, -time.Minute},
		{"stale_attempt", 5, 0, int64(3)}, {"failed_attempt", 5, 1, "failed"}, {"job_replaced", 6, 0, "other"}, {"job_generation", 6, 1, int64(2)},
		{"relay_revoked", 6, 5, -time.Second}, {"relay_replaced", 6, 2, "other"}, {"relay_version", 6, 3, "other"},
		{"relay_future", 6, 4, time.Minute}, {"clock_drift", 7, 0, 10 * time.Second}, {"clock_drift_backward", 7, 0, -10 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newTaskFixture(t, false)
			value := test.value
			if offset, ok := value.(time.Duration); ok {
				// Resolve time mutations after this fixture is ready. Earlier
				// subtests must not consume the intended clock-drift offset.
				value = time.Now().UTC().Truncate(time.Microsecond).Add(offset)
			}
			f.db.plan[test.query].values[test.column] = value
			if _, err := f.a.AuthorizeContent(f.ctx, f.identity); err != ErrDenied || f.db.commits != 0 {
				t.Fatal("state admitted", err)
			}
			if strings.HasPrefix(test.name, "clock_drift") && f.db.index != len(f.db.plan) {
				t.Fatal("clock drift did not reach the final SQL clock check")
			}
		})
	}
	t.Run("unbound_context", func(t *testing.T) {
		f := newTaskFixture(t, false)
		if _, err := f.a.AuthorizeContent(context.Background(), f.identity); err != ErrDenied || f.db.begins != 0 {
			t.Fatal(err)
		}
	})
	t.Run("different_authority", func(t *testing.T) {
		f := newTaskFixture(t, false)
		other, err := NewSQLTaskAuthority(f.c)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = other.AuthorizeContent(f.ctx, f.identity); err != ErrDenied {
			t.Fatal(err)
		}
	})
	t.Run("scope", func(t *testing.T) {
		f := newTaskFixture(t, false)
		i := f.identity
		i.OwnerID = "sbk_aaaaaaaa-2222-4333-8444-555555555555"
		if _, err := f.a.AuthorizeContent(f.ctx, i); err != ErrDenied || f.db.begins != 0 {
			t.Fatal(err)
		}
	})
	t.Run("commit", func(t *testing.T) {
		f := newTaskFixture(t, false)
		f.db.commitErr = true
		if _, err := f.a.AuthorizeContent(f.ctx, f.identity); err != ErrDenied {
			t.Fatal(err)
		}
	})
	t.Run("revoked_during_read", func(t *testing.T) {
		f := newTaskFixture(t, false)
		f.db.onBegin = func(n int) {
			if n == 2 {
				f.db.plan[6].values[3] = "revoked"
			}
		}
		d, _ := NewContentDispatcher(f.a)
		if err := d.Validate(f.ctx, f.identity, bytes.NewReader(f.body)); err != ErrRedaction {
			t.Fatal(err)
		}
	})
	for _, name := range []string{"no_tls", "unverified", "handshake", "certificate_pin", "expired_admission"} {
		t.Run(name, func(t *testing.T) {
			f := newTaskFixture(t, false)
			switch name {
			case "no_tls":
				f.request.TLS = nil
			case "unverified":
				f.request.TLS.VerifiedChains = nil
			case "handshake":
				f.request.TLS.HandshakeComplete = false
			case "certificate_pin":
				f.a.c.CertificateSHA256 = strings.Repeat("f", 64)
			case "expired_admission":
				f.a.c.ExpiresAt = time.Now().Add(-time.Second)
			}
			if _, err := f.a.AuthenticateRequest(f.request); err != ErrAuth {
				t.Fatal(err)
			}
		})
	}
}

func TestTaskAuthorityS3ClaimAndObject(t *testing.T) {
	f := newTaskFixture(t, true)
	grant, err := f.a.AuthorizeS3(f.ctx, f.scope)
	if err != nil || grant.Authorization.Evidence != f.identity || grant.Authorization.AttemptNumber != 2 || grant.Authorization.ExpiresAt.After(time.Now().Add(30*time.Second)) {
		t.Fatal("S3 grant", err)
	}
	wipe(grant.Token)
	f.scope.Operation = S3Put
	f.scope.Object = ObjectInfo{SHA256: strings.Repeat("c", 64), Size: 20000}
	f.scope.Deadline = f.db.plan[4].values[7].(time.Time)
	grant, err = f.a.AuthorizeS3(f.ctx, f.scope)
	wipe(grant.Token)
	if err != nil {
		t.Fatal("PUT grant", err)
	}
	for _, test := range []struct {
		name   string
		column int
		value  driver.Value
	}{
		{"owner", 1, "sbk_aaaaaaaa-2222-4333-8444-555555555555"}, {"classification", 4, "internal"}, {"body_hash", 5, strings.Repeat("f", 64)},
		{"ready", 7, "ready"}, {"store", 9, strings.Repeat("f", 64)}, {"key", 11, "evidence/wrong"}, {"key_hash", 12, strings.Repeat("f", 64)},
		{"immutable", 13, "version"}, {"object_hash", 14, strings.Repeat("f", 64)}, {"object_size", 15, int64(1)},
		{"encryption", 16, "none"}, {"claim_taken", 18, "other"}, {"claim_expired", 19, time.Now().Add(-time.Minute)}, {"evidence_expired", 20, time.Now().Add(-time.Minute)}, {"row_version", 21, int64(3)},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newTaskFixture(t, true)
			f.scope.Operation = S3Put
			f.scope.Object = ObjectInfo{SHA256: strings.Repeat("c", 64), Size: 20000}
			f.scope.Deadline = f.db.plan[4].values[7].(time.Time)
			f.db.plan[7].values[test.column] = test.value
			g, err := f.a.AuthorizeS3(f.ctx, f.scope)
			if err != ErrDenied || len(g.Token) != 0 || f.db.commits != 0 {
				t.Fatal("object admitted", err)
			}
		})
	}
	for _, kind := range []string{"missing", "download", "gc", "wrong_id", "wrong_claim", "wrong_version", "range", "delete"} {
		t.Run(kind, func(t *testing.T) {
			f := newTaskFixture(t, true)
			switch kind {
			case "missing":
				f.ctx, _ = f.a.AuthenticateRequest(f.request)
			case "download", "gc":
				f.ctx = withEvidenceAccess(f.ctx, kind, f.record)
			case "wrong_id":
				f.record.Manifest.Identity.ID = "sev_aaaaaaaa-2222-4333-8444-555555555555"
				f.ctx = withEvidenceAccess(f.ctx, "task", f.record)
				f.db.plan[7].args[0] = f.record.Manifest.Identity.ID
			case "wrong_claim":
				f.record.Claim = "other"
				f.ctx = withEvidenceAccess(f.ctx, "task", f.record)
			case "wrong_version":
				f.record.RowVersion++
				f.ctx = withEvidenceAccess(f.ctx, "task", f.record)
			case "range":
				f.scope.Operation = S3Range
			case "delete":
				f.scope.Operation = S3Delete
			}
			g, err := f.a.AuthorizeS3(f.ctx, f.scope)
			if err != ErrDenied || len(g.Token) != 0 {
				t.Fatal(err)
			}
		})
	}
}

func TestTaskAuthorityTokenPrecheck(t *testing.T) {
	for _, name := range []string{"issuer", "subject", "audience", "multi_audience", "expired", "future", "null_exp", "fractional_exp", "missing", "oversize", "duplicate"} {
		t.Run(name, func(t *testing.T) {
			f := newTaskFixture(t, true)
			claims := map[string]any{"iss": f.c.Issuer, "sub": f.c.Subject, "aud": f.c.Audience, "exp": time.Now().Add(time.Minute).Unix()}
			switch name {
			case "issuer":
				claims["iss"] = "https://other.example"
			case "subject":
				claims["sub"] = "other"
			case "audience":
				claims["aud"] = "other"
			case "multi_audience":
				claims["aud"] = []string{f.c.Audience, "other"}
			case "expired":
				claims["exp"] = int64(1)
			case "future":
				claims["nbf"] = time.Now().Add(time.Hour).Unix()
			case "null_exp":
				claims["exp"] = nil
			case "fractional_exp":
				claims["exp"] = 123.5
			}
			f.writeToken(t, claims)
			switch name {
			case "missing":
				os.Remove(f.c.TokenFile)
			case "oversize":
				os.WriteFile(f.c.TokenFile, bytes.Repeat([]byte("a"), 20001), 0600)
			case "duplicate":
				os.WriteFile(f.c.TokenFile, []byte("header."+base64.RawURLEncoding.EncodeToString([]byte(`{"exp":1,"exp":99999999999}`))+".sig"), 0600)
			}
			g, err := f.a.AuthorizeS3(f.ctx, f.scope)
			if err != ErrDenied || len(g.Token) != 0 {
				t.Fatal("token admitted", err)
			}
		})
	}
}

func TestTaskAuthoritySTSRechecksSQL(t *testing.T) {
	for _, mode := range []string{"success", "revoked_during_exchange", "provider_rejects_signature"} {
		t.Run(mode, func(t *testing.T) {
			f := newTaskFixture(t, true)
			token, err := os.ReadFile(f.c.TokenFile)
			if err != nil {
				t.Fatal(err)
			}
			defer wipe(token)
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.ParseForm() != nil || r.Form.Get("WebIdentityToken") != string(token) {
					t.Error("wrong projected token")
					w.WriteHeader(403)
					return
				}
				if mode == "provider_rejects_signature" {
					w.WriteHeader(403)
					return
				}
				if mode == "revoked_during_exchange" {
					f.db.plan[6].values[3] = "revoked"
				}
				session := r.Form.Get("RoleSessionName")
				fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse xmlns="%s"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>%s</SecretAccessKey><SessionToken>%s</SessionToken><Expiration>%s</Expiration></Credentials><Audience>%s</Audience><Provider>%s</Provider><SubjectFromWebIdentityToken>%s</SubjectFromWebIdentityToken><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/evidence/%s</Arn><AssumedRoleId>ROLEID:%s</AssumedRoleId></AssumedRoleUser><PackedPolicySize>10</PackedPolicySize></AssumeRoleWithWebIdentityResult><ResponseMetadata><RequestId>local</RequestId></ResponseMetadata></AssumeRoleWithWebIdentityResponse>`, stsNamespace, s3TestAccess, s3TestSecret, s3TestSession, time.Now().UTC().Add(899*time.Second).Format(time.RFC3339), f.c.Audience, f.c.Issuer, f.c.Subject, session, session)
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			config := S3STSConfig{Store: S3Config{Endpoint: server.URL, Region: "us-east-1", Bucket: "test-bucket", Root: f.c.Root, Installation: f.c.Installation, Identity: f.c.Store.Identity, Version: f.c.Store.Version, CAPEM: ca, CASHA256: hash(ca)}, Endpoint: server.URL, RoleARN: "arn:aws:iam::123456789012:role/evidence", Issuer: f.c.Issuer, Audience: f.c.Audience, CAPEM: ca, CASHA256: hash(ca)}
			resolver, err := NewS3STSCredentials(config, f.a)
			if err != nil {
				t.Fatal(err)
			}
			defer resolver.Close()
			credential, err := resolver.Resolve(f.ctx, f.scope)
			defer wipe(credential.AccessKey)
			defer wipe(credential.SecretKey)
			defer wipe(credential.SessionToken)
			if mode == "success" {
				if err != nil || f.db.commits != 2 || calls != 1 {
					t.Fatal("exchange failed", err)
				}
			} else if err != ErrDenied || len(credential.AccessKey) != 0 || calls != 1 {
				t.Fatal("unsafe exchange", err)
			}
		})
	}
}

type claimCheckingStore struct {
	*testStore
	t        *testing.T
	registry *memoryRegistry
	kind     string
	calls    int
}

func (s *claimCheckingStore) check(ctx context.Context) {
	s.t.Helper()
	r := s.registry.r
	a, ok := evidenceAccessFrom(ctx, s.kind, r.Manifest.Identity.ID)
	if !ok || a.Claim != r.Claim || a.RowVersion != r.RowVersion {
		s.t.Fatal("provider did not receive committed claim")
	}
	s.calls++
}
func (s *claimCheckingStore) Stat(ctx context.Context, r Ref) (ObjectInfo, error) {
	s.check(ctx)
	return s.testStore.Stat(ctx, r)
}
func (s *claimCheckingStore) Put(ctx context.Context, r Ref, body io.Reader, o ObjectInfo, d time.Time) error {
	s.check(ctx)
	return s.testStore.Put(ctx, r, body, o, d)
}
func (s *claimCheckingStore) Delete(ctx context.Context, r Ref, o ObjectInfo) error {
	s.check(ctx)
	return s.testStore.Delete(ctx, r, o)
}
func (s *claimCheckingStore) Absent(ctx context.Context, r Ref) (Absence, error) {
	s.check(ctx)
	return s.testStore.Absent(ctx, r)
}
func (s *claimCheckingStore) Range(ctx context.Context, r Ref, start, length int64) (io.ReadCloser, error) {
	s.check(ctx)
	return s.testStore.Range(ctx, r, start, length)
}

func TestLifecycleCarriesCommittedClaim(t *testing.T) {
	s, m, store, _, object := serviceFixture(t)
	m.r.State = "pending"
	m.r.Ref.ImmutableVersion = ""
	store.present = false
	checked := &claimCheckingStore{testStore: store, t: t, registry: m, kind: "task"}
	s.Store = checked
	if err := s.Publish(context.Background(), m.r.Manifest.Identity.ID, source(object)); err != nil || checked.calls < 3 {
		t.Fatal("publish claim", err)
	}
	checked.kind = "download"
	checked.calls = 0
	r := httptest.NewRequest("GET", "https://local"+Path+m.r.Manifest.Identity.ID, nil)
	r.Header.Set("Range", "bytes=0-20")
	r.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()
	Handler{Service: s, Auth: testAuth{}}.ServeHTTP(w, r)
	if w.Code != 206 || checked.calls < 2 {
		t.Fatal("download claim", w.Code)
	}
	checked.kind = "gc"
	checked.calls = 0
	m.now = m.r.ProtectedUntil.Add(time.Minute)
	if result := s.GC(context.Background(), []string{m.r.Manifest.Identity.ID}); result[0] != nil || checked.calls < 3 {
		t.Fatal("GC claim", result)
	}
}
