package systembackupevidence

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type taskRuntimeDB struct {
	*taskPrepareDB
	registry *memoryRegistry
}

func (d *taskRuntimeDB) Connect(context.Context) (driver.Conn, error) { return d, nil }
func (d *taskRuntimeDB) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.HasPrefix(q, "SELECT owner_target_type,owner_target_public_id,evidence_type,media_type,redaction_classification") {
		d.registry.mu.Lock()
		r := d.registry.r
		d.registry.mu.Unlock()
		i, m := r.Manifest.Identity, r.Manifest
		if d.index != 7 || !strings.Contains(q, "FOR UPDATE") || len(args) != 1 || args[0].Value != i.ID {
			d.t.Fatal("unbound evidence query")
		}
		return &authorityRows{values: []driver.Value{i.OwnerType, i.OwnerID, i.Type, i.Media, i.Classification, i.ContentHash, i.ContentSize,
			r.State, "evidence", r.Ref.Identity, r.Ref.Version, r.Ref.RelativeKey, hash([]byte(r.Ref.RelativeKey)), nil,
			m.ObjectHash, m.ObjectSize, "envelope_v1", Framing, r.Claim, r.ClaimUntil, r.ExpiresAt, r.RowVersion}}, nil
	}
	return d.taskPrepareDB.QueryContext(ctx, q, args)
}

type taskRuntimeFixture struct {
	x                                *taskPrepareFixture
	c                                TaskRuntimeConfig
	r                                *TaskRuntime
	m                                *memoryRegistry
	puts, proofs, requests, failures atomic.Int32
	revoked, obscure, failResult     atomic.Bool
	mu                               sync.Mutex
	stored                           []byte
	mode                             string
}

func newTaskRuntimeFixture(t *testing.T, mode string) *taskRuntimeFixture {
	t.Helper()
	x := newTaskPrepareFixture(t)
	f := x.f
	y := &taskRuntimeFixture{x: x, mode: mode, m: &memoryRegistry{now: time.Now().UTC()}}
	db := sql.OpenDB(&taskRuntimeDB{taskPrepareDB: x.db, registry: y.m})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	f.db.onBegin = func(int) {
		if y.revoked.Load() {
			f.db.plan[4].values[4] = "canceling"
		}
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		y.requests.Add(1)
		if r.Method == "POST" && r.URL.Path == "/" {
			if r.ParseForm() != nil || r.Form.Get("Action") != "AssumeRoleWithWebIdentity" {
				t.Error("bad STS exchange")
				w.WriteHeader(400)
				return
			}
			session := r.Form.Get("RoleSessionName")
			fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse xmlns="%s"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>%s</SecretAccessKey><SessionToken>%s</SessionToken><Expiration>%s</Expiration></Credentials><Audience>%s</Audience><Provider>%s</Provider><SubjectFromWebIdentityToken>%s</SubjectFromWebIdentityToken><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/evidence/%s</Arn><AssumedRoleId>ROLEID:%s</AssumedRoleId></AssumedRoleUser><PackedPolicySize>10</PackedPolicySize></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`, stsNamespace, s3TestAccess, s3TestSecret, s3TestSession, time.Now().UTC().Add(899*time.Second).Format(time.RFC3339), f.c.Audience, f.c.Issuer, f.c.Subject, session, session)
			return
		}
		y.m.mu.Lock()
		record := y.m.r
		y.m.mu.Unlock()
		if !verifyS3Wire(r) || r.URL.Path != "/evidence-bucket/"+record.Ref.RelativeKey || r.URL.Query().Get("versionId") != "" {
			t.Error("unbound write object")
			w.WriteHeader(403)
			return
		}
		y.mu.Lock()
		defer y.mu.Unlock()
		switch r.Method {
		case "HEAD":
			if len(y.stored) == 0 {
				w.WriteHeader(404)
				return
			}
			if y.obscure.Load() {
				w.WriteHeader(503)
				return
			}
			checksum, _ := hex.DecodeString(hash(y.stored))
			w.Header().Set("X-Amz-Version-Id", "object-v1")
			w.Header().Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(checksum))
			w.Header().Set("Content-Length", fmt.Sprint(len(y.stored)))
		case "PUT":
			y.puts.Add(1)
			if len(y.stored) != 0 || r.Header.Get("If-None-Match") != "*" {
				t.Error("nonconditional or repeated PUT")
				w.WriteHeader(412)
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, record.Manifest.ObjectSize+1))
			if err != nil || int64(len(body)) != record.Manifest.ObjectSize || hash(body) != record.Manifest.ObjectHash {
				t.Error("ciphertext changed")
				w.WriteHeader(400)
				return
			}
			y.stored = body
			if mode == "lost result" {
				y.obscure.Store(true)
				w.WriteHeader(503)
				return
			}
			if mode == "result audit" {
				y.failResult.Store(true)
			}
			checksum, _ := hex.DecodeString(hash(body))
			w.Header().Set("X-Amz-Version-Id", "object-v1")
			w.Header().Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(checksum))
		default:
			t.Error("task attempted read/delete")
			w.WriteHeader(403)
		}
	}))
	t.Cleanup(srv.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	store := S3Config{Endpoint: srv.URL, Region: "us-east-1", Bucket: "evidence-bucket", Root: f.c.Root, Installation: f.c.Installation, Identity: f.c.Store.Identity, Version: f.c.Store.Version, CAPEM: ca, CASHA256: hash(ca)}
	y.c = TaskRuntimeConfig{Authority: f.c, Registry: SQLRegistry{DB: db, Installation: f.c.Installation, ServerUUID: f.c.ServerUUID, Database: f.c.Database, Policy: &downloadTestPolicy{deadline: time.Now().Add(time.Minute)}},
		S3: S3STSConfig{Store: store, Endpoint: srv.URL, RoleARN: "arn:aws:iam::123456789012:role/evidence", Issuer: f.c.Issuer, Audience: f.c.Audience, CAPEM: ca, CASHA256: hash(ca)}, Transit: x.c,
		Failure: func(context.Context, string, string) { y.failures.Add(1) },
		Absence: s3AbsenceFunc(func(_ context.Context, request S3AbsenceRequest) (S3AbsenceProof, error) {
			y.proofs.Add(1)
			if mode == "untrusted proof" {
				return S3AbsenceProof{}, ErrUnavailable
			}
			if mode == "revoked proof" {
				y.revoked.Store(true)
			}
			return S3AbsenceProof{Request: request, ObservedAt: time.Now(), ExpiresAt: time.Now().Add(5 * time.Second)}, nil
		})}
	y.c.Authority.DB = db
	var err error
	y.r, err = NewTaskRuntime(y.c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(y.r.Close)
	// The D owner policy/registry is deliberately synthetic; actual task SQL,
	// mTLS-context checks, JWT/STS clients and S3/Transit protocol paths run.
	y.r.service.Registry = taskRuntimeRegistry{memoryRegistry: y.m, failResult: &y.failResult}
	return y
}

type taskRuntimeRegistry struct {
	*memoryRegistry
	failResult *atomic.Bool
}

func (r taskRuntimeRegistry) WithLocked(ctx context.Context, id string, fn func(Locked) error) error {
	if r.failResult.Load() {
		r.memoryRegistry.failAudit = true
	}
	return r.memoryRegistry.WithLocked(ctx, id, fn)
}

func TestTaskRuntimePrepareRegisterPublishAndRecovery(t *testing.T) {
	for _, mode := range []string{"ready", "lost result", "revoked proof", "untrusted proof", "intent audit", "result audit", "foreign owner"} {
		t.Run(mode, func(t *testing.T) {
			y := newTaskRuntimeFixture(t, mode)
			f := y.x.f
			ctx, err := y.r.AuthenticateRequest(f.request)
			if err != nil {
				t.Fatal(err)
			}
			var staging bytes.Buffer
			prepared, err := y.r.Prepare(ctx, f.identity, source(f.body), &staging)
			if err != nil {
				t.Fatal("prepare", err)
			}
			times := TaskRegistrationTimes{Created: y.m.now, Expires: y.m.now.Add(time.Hour), Protected: y.m.now.Add(2 * time.Hour), Deadline: f.db.plan[4].values[7].(time.Time)}
			if err = y.r.Register(ctx, prepared, times); err != nil {
				t.Fatal("register", err)
			}
			if err = y.r.Register(ctx, prepared, times); err != ErrConflict {
				t.Fatal("duplicate registration replaced bytes", err)
			}
			if y.requests.Load() != 0 || y.m.r.State != "pending" {
				t.Fatal("registration wrote remote bytes")
			}
			if mode == "intent audit" {
				y.m.failAudit = true
			}
			if mode == "foreign owner" {
				y.m.r.Manifest.Identity.OwnerID = "sbk_aaaaaaaa-2222-4333-8444-555555555555"
			}
			err = y.r.Publish(ctx, f.identity.ID, source(staging.Bytes()))
			switch mode {
			case "ready":
				if err != nil || y.m.r.State != "ready" || y.puts.Load() != 1 || y.proofs.Load() != 1 || y.m.r.Ref.ImmutableVersion != "object-v1" {
					t.Fatal("publication not ready", err, y.m.r.State, y.puts.Load())
				}
			case "lost result":
				if err != ErrUnavailable || y.m.r.State != "write_unknown" || y.m.r.Claim != "" || y.puts.Load() != 1 || y.failures.Load() != 1 {
					t.Fatal("lost result not retained", err)
				}
				y.obscure.Store(false)
				// Exact Stat resolves the original object without reading staging,
				// obtaining another Transit token, or issuing another PUT.
				if err = y.r.Publish(ctx, f.identity.ID, func() (io.ReadCloser, error) { t.Error("recovery reopened staging"); return nil, ErrUnavailable }); err != nil || y.m.r.State != "ready" || y.puts.Load() != 1 || y.proofs.Load() != 1 || y.x.logins.Load() != 1 {
					t.Fatal("recovery replayed write", err)
				}
			case "revoked proof", "untrusted proof":
				if err != ErrUnavailable || y.puts.Load() != 0 || y.m.r.State != "write_unknown" || y.failures.Load() != 1 {
					t.Fatal("untrusted absence permitted PUT", err)
				}
			case "intent audit":
				if err != ErrAudit || y.requests.Load() != 0 || y.m.r.Claim != "" || y.m.r.State != "pending" || y.failures.Load() != 1 {
					t.Fatal("failed intent reached provider", err)
				}
			case "result audit":
				if err != ErrAudit || y.puts.Load() != 1 || y.m.r.State != "pending" || y.m.r.Claim == "" || y.failures.Load() != 1 {
					t.Fatal("failed result audit committed ready", err)
				}
			case "foreign owner":
				if err != ErrDenied || y.requests.Load() != 0 || y.m.r.Claim != "" || y.m.r.RowVersion != 1 {
					t.Fatal("foreign evidence was claimed", err)
				}
			}
			if mode == "ready" || mode == "lost result" {
				want := 2
				if mode == "lost result" {
					want = 4
				}
				if len(y.m.audits) != want {
					t.Fatal("missing atomic publish audit", len(y.m.audits))
				}
				for n := 0; n < len(y.m.audits); n += 2 {
					a, b := y.m.audits[n], y.m.audits[n+1]
					if a.Action != "evidence.publish.intent" || b.Action != "evidence.publish.result" || a.ID != b.ID || !strings.HasPrefix(a.ActorID, "task:") || a.ActorID != b.ActorID {
						t.Fatal("unbound publish audit")
					}
				}
			}
			before := y.requests.Load()
			if _, err := y.r.service.Store.Range(ctx, y.m.r.Ref, 0, 10); err != ErrDenied {
				t.Fatal("writer can read")
			}
			if y.r.service.Store.Delete(ctx, y.m.r.Ref, ObjectInfo{}) != ErrDenied {
				t.Fatal("writer can delete")
			}
			y.r.Close()
			y.r.Close()
			if _, err := y.r.AuthenticateRequest(f.request); err != ErrAuth {
				t.Fatal("closed runtime authenticated")
			}
			if err := y.r.Publish(ctx, f.identity.ID, nil); err != ErrDenied || y.requests.Load() != before {
				t.Fatal("closed or read-only denied call reached provider")
			}
		})
	}
}

func TestTaskRuntimeRejectsMissingAdmission(t *testing.T) {
	y := newTaskRuntimeFixture(t, "ready")
	for _, mode := range []string{"policy", "absence", "failure", "database handle", "installation", "database name", "store", "root", "issuer", "audience", "Transit"} {
		t.Run(mode, func(t *testing.T) {
			c := y.c
			switch mode {
			case "policy":
				c.Registry.Policy = nil
			case "absence":
				c.Absence = nil
			case "failure":
				c.Failure = nil
			case "database handle":
				c.Authority.DB = nil
			case "installation":
				c.Registry.Installation = "installation_other"
			case "database name":
				c.Registry.Database = "other"
			case "store":
				c.S3.Store.Version = "other"
			case "root":
				c.S3.Store.Root = "other"
			case "issuer":
				c.S3.Issuer = "https://other.example"
			case "audience":
				c.S3.Audience = "other"
			case "Transit":
				c.Transit = TransitJWTConfig{}
			}
			r, err := NewTaskRuntime(c)
			if r != nil {
				r.Close()
			}
			if err == nil || r != nil || y.requests.Load() != 0 || y.x.logins.Load() != 0 {
				t.Fatal("unreviewed runtime constructed")
			}
		})
	}
}

func TestTaskAbsenceVerifierRechecksClaimAndTask(t *testing.T) {
	for _, mode := range []string{"ok", "before revoke", "after revoke", "claim takeover", "challenge", "provider failure", "unbound context"} {
		t.Run(mode, func(t *testing.T) {
			f := newTaskFixture(t, true)
			calls := 0
			v := TaskAbsenceVerifier{Authority: f.a, Verifier: s3AbsenceFunc(func(_ context.Context, r S3AbsenceRequest) (S3AbsenceProof, error) {
				calls++
				if mode == "provider failure" {
					return S3AbsenceProof{}, ErrUnavailable
				}
				if mode == "after revoke" {
					f.db.plan[4].values[4] = "canceling"
				}
				if mode == "claim takeover" {
					f.db.plan[7].values[18] = "other"
				}
				if mode == "challenge" {
					r.Challenge = strings.Repeat("b", 64)
				}
				return S3AbsenceProof{Request: r, ObservedAt: time.Now(), ExpiresAt: time.Now().Add(time.Second)}, nil
			})}
			ctx := f.ctx
			if mode == "before revoke" {
				f.db.plan[4].values[4] = "canceling"
			}
			if mode == "unbound context" {
				ctx = context.Background()
			}
			proof, err := v.VerifyAbsent(ctx, S3AbsenceRequest{Ref: f.scope.Ref, Challenge: strings.Repeat("a", 64)})
			if mode == "ok" {
				if err != nil || calls != 1 || proof.Request.Ref != f.scope.Ref {
					t.Fatal(err)
				}
			} else if err == nil || proof.Request.Ref != (Ref{}) {
				t.Fatal("unauthorized proof returned")
			}
			if (mode == "before revoke" || mode == "unbound context") && calls != 0 {
				t.Fatal("revoked caller reached proof provider")
			}
		})
	}
}
