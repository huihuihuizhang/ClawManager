package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Adds the conditional KEK locking read to the existing scripted transport.
// Content validation intentionally uses the original query sequence.
type taskPrepareDB struct {
	*authorityDB
	key      KeyRef
	keyReads int
}

func (d *taskPrepareDB) Connect(context.Context) (driver.Conn, error) { return d, nil }
func (d *taskPrepareDB) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.HasPrefix(q, "SELECT evidence_kek_identity_hash,evidence_kek_ref_version") {
		if d.index != 4 || !strings.Contains(q, "FOR UPDATE") || len(args) != 2 || args[0].Value != "installation_test" || args[1].Value != int64(3) {
			d.t.Fatal("KEK not checked under config lock")
		}
		d.keyReads++
		return &authorityRows{values: []driver.Value{d.key.Identity, d.key.Version}}, nil
	}
	return d.authorityDB.QueryContext(ctx, q, args)
}

type taskPrepareFixture struct {
	f                *taskFixture
	p                *TaskPreparer
	c                TransitJWTConfig
	db               *taskPrepareDB
	seed             testKeys
	logins, encrypts atomic.Int32
	mode             string
}

func newTaskPrepareFixture(t *testing.T) *taskPrepareFixture {
	t.Helper()
	f := newTaskFixture(t, false)
	x := &taskPrepareFixture{f: f, seed: testKeys{key: bytes.Repeat([]byte{5}, 32)}}
	x.db = &taskPrepareDB{authorityDB: f.db, key: KeyRef{strings.Repeat("d", 64), "kek-v1"}}
	db := sql.OpenDB(x.db)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	f.a.c.DB = db
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Error("wrong method")
			w.WriteHeader(400)
			return
		}
		switch r.URL.Path {
		case "/v1/auth/evidence-jwt/login":
			x.logins.Add(1)
			var body map[string]string
			want, _ := os.ReadFile(x.c.TokenFile)
			if r.Header.Get("X-Vault-Token") != "" || json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 2 || body["role"] != x.c.Role || body["jwt"] != string(want) {
				t.Error("unbound writer login")
				w.WriteHeader(400)
				return
			}
			policy, ttl := x.c.Policy, 5
			if x.mode == "extra policy" {
				policy = "default"
			}
			if x.mode == "long ttl" {
				ttl = 21
			}
			json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "writer-batch-token-0123456789", "token_type": "batch", "renewable": false, "lease_duration": ttl, "policies": []string{policy}, "metadata": map[string]any{"role": x.c.Role}}})
		case "/v1/transit/encrypt/evidence-key":
			x.encrypts.Add(1)
			var body struct {
				Plaintext []byte `json:"plaintext"`
				Context   string `json:"context"`
				Version   uint32 `json:"key_version"`
			}
			wantContext, _ := EvidenceTransitContext(f.c.Installation, x.c.Transit.Key)
			if r.Header.Get("X-Vault-Token") != "writer-batch-token-0123456789" || json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Plaintext) != 32 || body.Context != wantContext || body.Version != 1 {
				t.Error("unbound writer encrypt")
				w.WriteHeader(400)
				return
			}
			defer wipe(body.Plaintext)
			wrapped, err := (transitSeedKeys{x.seed}).Wrap(r.Context(), x.c.Transit.Key, body.Plaintext)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ciphertext": string(wrapped), "key_version": 1}})
		default:
			t.Error("unexpected writer endpoint")
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	x.c = TransitJWTConfig{Transit: TransitConfig{Endpoint: srv.URL, Installation: f.c.Installation, Key: x.db.key, KeyName: "evidence-key", KeyVersion: 1, CAPEM: ca, CASHA256: hash(ca)}, Mount: "evidence-jwt", Role: "evidence-writer", Policy: "evidence-encrypt-v1", Issuer: f.c.Issuer, Audience: "evidence-transit-write", Subject: f.c.Subject, TokenFile: filepath.Join(t.TempDir(), "writer-jwt")}
	x.writeJWT(t, "signature")
	var err error
	x.p, err = NewTaskPreparer(f.a, x.c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(x.p.Close)
	return x
}

func (x *taskPrepareFixture) writeJWT(t *testing.T, signature string) {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"iss": x.c.Issuer, "aud": x.c.Audience, "sub": x.c.Subject, "exp": time.Now().Add(time.Minute).Unix()})
	if err := os.WriteFile(x.c.TokenFile, []byte("header."+base64.RawURLEncoding.EncodeToString(raw)+"."+signature), 0600); err != nil {
		t.Fatal(err)
	}
}

type taskPreparedReadKeys struct{ testKeys }

func (k taskPreparedReadKeys) Unwrap(ctx context.Context, key KeyRef, wrapped []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(string(wrapped), "vault:v1:"))
	if err != nil {
		return nil, err
	}
	return k.testKeys.Unwrap(ctx, key, raw)
}

func TestTaskPreparerMTLSJWTAndEncryptedStaging(t *testing.T) {
	x := newTaskPrepareFixture(t)
	f := x.f
	type result struct {
		prepared Prepared
		data     []byte
		err      error
	}
	results := make(chan result, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, err := f.a.AuthenticateRequest(r)
		var data bytes.Buffer
		var p Prepared
		if err == nil {
			p, err = x.p.Prepare(ctx, f.identity, source(f.body), &data)
		}
		results <- result{p, data.Bytes(), err}
		if err != nil {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(204)
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: f.a.roots, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	client := srv.Client()
	client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{f.client}
	for _, signature := range []string{"first-signature", "rotated-signature"} {
		x.writeJWT(t, signature)
		res, err := client.Post(srv.URL, "application/octet-stream", nil)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		got := <-results
		if res.StatusCode != 204 || got.err != nil || validateManifest(got.prepared.manifest) != nil || bytes.Contains(got.data, f.body[:40]) {
			t.Fatal("preparation failed or plaintext staged", got.err)
		}
		m := got.prepared.Manifest()
		ref := f.scope.Ref
		ref.ImmutableVersion = "object-v1"
		store := &testStore{present: true, data: got.data, info: ObjectInfo{ref.ImmutableVersion, m.ObjectHash, m.ObjectSize}}
		plain, err := OpenRange(context.Background(), m, ref, store, taskPreparedReadKeys{x.seed}, 0, f.identity.ContentSize-1)
		if err != nil || !bytes.Equal(plain, f.body) {
			t.Fatal("prepared object cannot round-trip", err)
		}
		wipe(plain)
	}
	if x.logins.Load() != 2 || x.encrypts.Load() != 2 || x.db.keyReads != 10 || f.db.commits != 14 {
		t.Fatal("missing live checks or cached token", x.db.keyReads, f.db.commits)
	}
	if _, err := (taskPrepareKeys{x.p}).Unwrap(f.ctx, x.c.Transit.Key, nil); err != ErrKey {
		t.Fatal("writer can unwrap")
	}
	if _, err := x.p.keys.Wrap(f.ctx, x.c.Transit.Key, bytes.Repeat([]byte{1}, 32)); err != ErrKey || x.logins.Load() != 2 {
		t.Fatal("unbound wrap bypassed preparer")
	}
	x.p.Close()
	x.p.Close()
	if _, err := x.p.Prepare(f.ctx, f.identity, source(f.body), io.Discard); err != ErrDenied {
		t.Fatal("closed preparer accepted")
	}
}

func TestTaskPreparerRejectsRevocationAndDrift(t *testing.T) {
	for _, mode := range []string{"context", "owner", "type", "key", "disabled", "attempt", "job", "after login", "key during login", "after encrypt", "after staging", "database clock ahead", "long ttl", "extra policy", "JWT audience", "bad content", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			x := newTaskPrepareFixture(t)
			f := x.f
			ctx, identity, src := f.ctx, f.identity, source(f.body)
			switch mode {
			case "context":
				ctx = context.Background()
			case "owner":
				identity.OwnerID = "sbk_aaaaaaaa-2222-4333-8444-555555555555"
			case "type":
				identity.Type = "capability_snapshot"
			case "key":
				x.db.key.Version = "other"
			case "disabled":
				f.db.plan[2].values[1] = false
			case "attempt":
				f.db.plan[5].values[0] = int64(3)
			case "job":
				f.db.plan[6].values[0] = "other"
			case "after login", "key during login", "after encrypt":
				f.db.onBegin = func(int) {
					if mode == "after encrypt" && x.encrypts.Load() > 0 || mode == "after login" && x.logins.Load() > 0 {
						f.db.plan[4].values[4] = "canceling"
					}
					if mode == "key during login" && x.logins.Load() > 0 {
						x.db.key.Version = "rotated"
					}
				}
			case "after staging":
				opens := 0
				src = func() (io.ReadCloser, error) {
					opens++
					if opens == 2 {
						f.db.plan[4].values[4] = "canceling"
					}
					return io.NopCloser(bytes.NewReader(f.body)), nil
				}
			case "database clock ahead":
				f.db.plan[7].values[0] = time.Now().Add(4 * time.Second)
				f.db.plan[4].values[6] = time.Now().Add(6 * time.Second)
			case "long ttl", "extra policy":
				x.mode = mode
			case "JWT audience":
				x.c.Audience = "wrong"
				x.writeJWT(t, "signature")
			case "bad content":
				body := bytes.Repeat([]byte("PRIVATE unsupported log\n"), 500)
				identity.ContentSize, identity.ContentHash = int64(len(body)), hash(body)
				src = source(body)
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			var dst bytes.Buffer
			p, err := x.p.Prepare(ctx, identity, src, &dst)
			if err == nil || p.manifest.Identity.ID != "" {
				t.Fatal("unauthorized usable preparation", err)
			}
			wantEncrypt := int32(0)
			if mode == "after encrypt" || mode == "after staging" {
				wantEncrypt = 1
			}
			if x.encrypts.Load() != wantEncrypt {
				t.Fatal("unexpected encrypt", x.encrypts.Load())
			}
			if mode == "after staging" && dst.Len() == 0 {
				t.Fatal("staging revocation was not exercised")
			}
		})
	}
}

func TestTaskPreparerRequiresDedicatedReviewedMapping(t *testing.T) {
	x := newTaskPrepareFixture(t)
	for _, mode := range []string{"authority", "installation", "subject", "issuer", "S3 audience", "S3 file", "role path", "root policy", "HTTP", "CA", "key"} {
		t.Run(mode, func(t *testing.T) {
			c, a := x.c, x.f.a
			switch mode {
			case "authority":
				a = nil
			case "installation":
				c.Transit.Installation = "installation_other"
			case "subject":
				c.Subject = "other"
			case "issuer":
				c.Issuer = "https://other.example"
			case "S3 audience":
				c.Audience = x.f.c.Audience
			case "S3 file":
				c.TokenFile = x.f.c.TokenFile
			case "role path":
				c.Role = "../role"
			case "root policy":
				c.Policy = "root"
			case "HTTP":
				c.Transit.Endpoint = "http://localhost"
			case "CA":
				c.Transit.CASHA256 = strings.Repeat("0", 64)
			case "key":
				c.Transit.KeyVersion = 0
			}
			p, err := NewTaskPreparer(a, c)
			if p != nil {
				p.Close()
			}
			if err == nil || p != nil || x.logins.Load() != 0 {
				t.Fatal("unreviewed mapping accepted")
			}
		})
	}
}
