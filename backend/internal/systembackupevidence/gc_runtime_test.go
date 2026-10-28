package systembackupevidence

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Transactional fixture for the actual SQL adapter, not a MySQL lock proof.
type gcRuntimeDB struct {
	*recoveryDB
	deletedChunks bool
	failChunks    bool
}

func (d *gcRuntimeDB) Connect(context.Context) (driver.Conn, error) { return d, nil }
func (d *gcRuntimeDB) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	d.pending, d.pendingAudits, d.deletedChunks = d.record, nil, false
	d.pendingObservation = d.observation
	r := d.record
	row := d.plan[6].values
	for n, value := range map[int]driver.Value{4: r.State, 5: r.Failure, 6: nullString(r.Ref.Identity), 7: nullString(r.Ref.Version), 8: nullString(r.Ref.RelativeKey), 9: nullString(r.Ref.ImmutableVersion), 23: nullString(r.Claim), 24: nullTime(r.ClaimUntil), 25: r.ExpiresAt, 26: nullTime(r.ProtectedUntil), 27: r.RowVersion, 30: hash([]byte(r.Ref.RelativeKey))} {
		row[n] = value
	}
	if _, err := d.authorityDB.BeginTx(ctx, opts); err != nil {
		return nil, err
	}
	return d, nil
}
func (d *gcRuntimeDB) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.HasPrefix(q, "SELECT next_reconcile_at FROM system_backup_v2_evidence") {
		return d.recoveryDB.QueryContext(ctx, q, args)
	}
	if d.record.State == "deleted" && d.index == 7 {
		d.index++ // Tombstone loading must not query deleted chunks.
	}
	return d.authorityDB.QueryContext(ctx, q, args)
}
func (d *gcRuntimeDB) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if strings.HasPrefix(q, "UPDATE system_backup_v2_evidence SET storage_state=?") {
		return d.recoveryDB.ExecContext(ctx, q, args)
	}
	if (len(args) != 2 && len(args) != 5) || args[len(args)-2].Value != d.pending.Manifest.Identity.ID || args[len(args)-1].Value != d.pending.RowVersion || d.pending.State != "deleting" || !strings.Contains(q, "storage_state='deleting'") {
		d.t.Fatal("GC cleared data without exact deleting row CAS")
	}
	switch {
	case strings.HasPrefix(q, "DELETE c FROM system_backup_v2_evidence_chunks"):
		if d.failChunks {
			return nil, ErrUnavailable
		}
		d.deletedChunks = true
		return driver.RowsAffected(len(d.pending.Manifest.Chunks)), nil
	case strings.HasPrefix(q, "UPDATE system_backup_v2_evidence SET storage_state='deleted'"):
		if !d.deletedChunks {
			d.t.Fatal("tombstone before chunk cleanup")
		}
		if len(args) != 5 || !strings.Contains(q, ",observed_health=?,last_checked_at=?,next_reconcile_at=?") || args[2].Value != nil {
			d.t.Fatal("GC observation did not share tombstone CAS")
		}
		d.pendingObservation = recoveryTestObservation{health: args[0].Value.(string), checked: args[1].Value.(time.Time)}
		d.pending.State, d.pending.Failure = "deleted", "none"
		d.pending.Ref = Ref{}
		d.pending.Manifest.Chunks = nil
		d.pending.Claim, d.pending.ClaimUntil = "", time.Time{}
		d.pending.RowVersion++
		d.writes++
		return driver.RowsAffected(1), nil
	default:
		d.t.Fatal("unexpected GC mutation", q)
		return nil, ErrDenied
	}
}

type gcRuntimePolicy struct {
	*gcTestPolicy
	db         *gcRuntimeDB
	auditCalls int
	afterAudit func(int)
}

func (p *gcRuntimePolicy) Audit(_ context.Context, _ *sql.Tx, a Audit) error {
	p.auditCalls++
	if p.auditCalls == p.db.failAudit {
		return ErrAudit
	}
	p.db.pendingAudits = append(p.db.pendingAudits, a)
	if p.afterAudit != nil {
		p.afterAudit(p.auditCalls)
	}
	return nil
}

type gcRuntimeFixture struct {
	f                                 *gcFixture
	db                                *gcRuntimeDB
	policy                            *gcRuntimePolicy
	c                                 GCRuntimeConfig
	heads, deletes, exchanges, proofs atomic.Int32
	signals                           int
}

func newGCRuntimeFixture(t *testing.T, mode string) *gcRuntimeFixture {
	t.Helper()
	f := newGCFixture(t)
	r := f.record
	r.State, r.Claim, r.ClaimUntil = "ready", "", time.Time{}
	d := &gcRuntimeDB{recoveryDB: &recoveryDB{authorityDB: f.base.db, record: r}}
	db := sql.OpenDB(d)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	p := &gcRuntimePolicy{gcTestPolicy: f.policy, db: d}
	a := f.c
	a.Registry.DB, a.Registry.Policy = db, p
	x := &gcRuntimeFixture{f: f, db: d, policy: p}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == "POST" && req.URL.Path == "/" {
			x.exchanges.Add(1)
			if req.ParseForm() != nil || req.Form.Get("Action") != "AssumeRoleWithWebIdentity" || strings.Contains(req.Form.Get("Policy"), "PutObject") {
				t.Error("wrong GC credential exchange")
				w.WriteHeader(403)
				return
			}
			session := req.Form.Get("RoleSessionName")
			fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse xmlns="%s"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>%s</SecretAccessKey><SessionToken>%s</SessionToken><Expiration>%s</Expiration></Credentials><Audience>%s</Audience><Provider>%s</Provider><SubjectFromWebIdentityToken>%s</SubjectFromWebIdentityToken><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/evidence/%s</Arn><AssumedRoleId>ROLEID:%s</AssumedRoleId></AssumedRoleUser><PackedPolicySize>10</PackedPolicySize></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`, stsNamespace, s3TestAccess, s3TestSecret, s3TestSession, time.Now().UTC().Add(899*time.Second).Format(time.RFC3339), a.Audience, a.Issuer, a.Subject, session, session)
			return
		}
		if !verifyS3Wire(req) || req.URL.Path != "/evidence-bucket/"+r.Ref.RelativeKey || req.URL.Query().Get("versionId") != r.Ref.ImmutableVersion {
			t.Error("GC request not bound to exact signed version")
			w.WriteHeader(403)
			return
		}
		switch req.Method {
		case "HEAD":
			x.heads.Add(1)
			digest, _ := hex.DecodeString(r.Manifest.ObjectHash)
			if mode == "mismatch" {
				digest[0] ^= 1
			}
			w.Header().Set("X-Amz-Version-Id", r.Ref.ImmutableVersion)
			w.Header().Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(digest))
			w.Header().Set("Content-Length", fmt.Sprint(r.Manifest.ObjectSize))
		case "DELETE":
			x.deletes.Add(1)
			w.Header().Set("X-Amz-Version-Id", r.Ref.ImmutableVersion)
			w.WriteHeader(204)
		default:
			t.Error("GC attempted object body read or write")
			w.WriteHeader(403)
		}
	}))
	t.Cleanup(srv.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	s := S3Config{Endpoint: srv.URL, Region: "us-east-1", Bucket: "evidence-bucket", Root: a.Root, Installation: a.Registry.Installation, Identity: a.Store.Identity, Version: a.Store.Version, CAPEM: ca, CASHA256: hash(ca)}
	x.c = GCRuntimeConfig{Authority: a, S3: S3STSConfig{Store: s, Endpoint: srv.URL, RoleARN: "arn:aws:iam::123456789012:role/evidence", Issuer: a.Issuer, Audience: a.Audience, CAPEM: ca, CASHA256: hash(ca)}, Failure: func(ctx context.Context, id, code string) {
		if ctx.Err() != nil || id != r.Manifest.Identity.ID || code != "evidence_incomplete" {
			t.Error("invalid GC failure signal")
		}
		x.signals++
	}}
	x.c.Absence = s3AbsenceFunc(func(_ context.Context, request S3AbsenceRequest) (S3AbsenceProof, error) {
		x.proofs.Add(1)
		if request.Ref != r.Ref || request.Challenge == "" {
			t.Error("unbound absence challenge")
		}
		if mode == "no_proof" {
			return S3AbsenceProof{}, ErrUnavailable
		}
		now := time.Now().UTC()
		return S3AbsenceProof{Request: request, ObservedAt: now, ExpiresAt: now.Add(20 * time.Second)}, nil
	})
	if mode == "revoke_in_proof" || mode == "revoke_before_result" {
		checks := 0
		d.onBegin = func(int) {
			if x.proofs.Load() > 0 {
				checks++
				if mode == "revoke_in_proof" || checks >= 2 {
					d.plan[5].values[6] = "other-worker"
				}
			}
		}
	}
	if mode == "claim_expiry" || mode == "result_expiry" {
		p.afterAudit = func(call int) {
			if mode == "claim_expiry" && call == 1 || mode == "result_expiry" && call == 2 {
				d.plan[9].values[0] = d.plan[5].values[7] // Time reaches operation expiry after audit.
			}
		}
	}
	if mode == "claim_audit" {
		d.failAudit = 1
	}
	if mode == "result_audit" {
		d.failAudit = 2
	}
	if mode == "chunks" {
		d.failChunks = true
	}
	return x
}

func TestGCRuntimeExactDeleteAndTransactionalResults(t *testing.T) {
	for _, mode := range []string{"ok", "no_proof", "mismatch", "revoke_in_proof", "revoke_before_result", "claim_expiry", "result_expiry", "claim_audit", "result_audit", "chunks"} {
		t.Run(mode, func(t *testing.T) {
			x := newGCRuntimeFixture(t, mode)
			r, err := NewGCRuntime(x.c)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			ctx, err := r.AuthenticateRequest(x.f.peer.request)
			if err != nil {
				t.Fatal(err)
			}
			original := x.db.record
			results := r.GC(ctx, []string{original.Manifest.Identity.ID})
			if len(results) != 1 {
				t.Fatal("missing result")
			}
			got := x.db.record
			if mode == "ok" {
				if results[0] != nil || got.State != "deleted" || got.Ref != (Ref{}) || len(got.Manifest.Chunks) != 0 || got.Claim != "" || len(x.db.audits) != 2 || x.signals != 0 || x.heads.Load() != 2 || x.deletes.Load() != 1 || x.proofs.Load() != 1 || x.exchanges.Load() != 3 {
					t.Fatal("GC did not complete", results, got.State, x.exchanges.Load(), x.heads.Load(), x.deletes.Load(), x.proofs.Load())
				}
				for _, audit := range x.db.audits {
					if audit.ActorID != "gc:"+r.authority.principal {
						t.Fatal("audit lost worker identity")
					}
				}
				// Idempotent tombstones still pass the operation/owner transaction.
				again := r.GC(ctx, []string{original.Manifest.Identity.ID})
				if len(again) != 1 || again[0] != nil || x.deletes.Load() != 1 || len(x.db.audits) != 2 {
					t.Fatal("tombstone retry failed", again)
				}
				x.db.plan[5].values[6] = "other-worker"
				if r.GC(ctx, []string{original.Manifest.Identity.ID})[0] == nil {
					t.Fatal("revoked tombstone acknowledged")
				}
				return
			}
			if results[0] == nil || got.Ref != original.Ref || hash(canonical(got.Manifest)) != hash(canonical(original.Manifest)) || x.signals != 1 {
				t.Fatal("failure discarded evidence or failed to signal", results, got.State, x.signals)
			}
			switch mode {
			case "claim_expiry", "claim_audit":
				if got.State != "ready" || got.Claim != "" || len(x.db.audits) != 0 || x.exchanges.Load() != 0 {
					t.Fatal("failed claim escaped rollback")
				}
			case "no_proof", "mismatch":
				if got.State != "delete_failed" || got.Claim != "" || len(x.db.audits) != 2 {
					t.Fatal("failure result not atomic")
				}
				if mode == "mismatch" && x.deletes.Load() != 0 {
					t.Fatal("deleted mismatching object")
				}
			default:
				if got.State != "deleting" || got.Claim == "" || len(x.db.audits) != 1 {
					t.Fatal("failed result escaped rollback", got.State)
				}
			}
		})
	}
}

func TestGCRuntimeRejectsInvalidAdmissionAndClosedWork(t *testing.T) {
	x := newGCRuntimeFixture(t, "ok")
	for _, mode := range []string{"policy", "failure", "proof", "installation", "store", "version", "root", "issuer", "audience", "operation", "tls"} {
		t.Run(mode, func(t *testing.T) {
			c := x.c
			switch mode {
			case "policy":
				c.Authority.Registry.Policy = nil
			case "failure":
				c.Failure = nil
			case "proof":
				c.Absence = nil
			case "installation":
				c.S3.Store.Installation = "installation_other"
			case "store":
				c.S3.Store.Identity = strings.Repeat("e", 64)
			case "version":
				c.S3.Store.Version = "other"
			case "root":
				c.S3.Store.Root = "other"
			case "issuer":
				c.S3.Issuer = "https://other.example"
			case "audience":
				c.S3.Audience = "other"
			case "operation":
				c.Authority.OperationID = ""
			case "tls":
				c.S3.CASHA256 = strings.Repeat("0", 64)
			}
			r, err := NewGCRuntime(c)
			if r != nil {
				r.Close()
			}
			if err == nil || r != nil {
				t.Fatal("invalid admission accepted")
			}
		})
	}
	r, err := NewGCRuntime(x.c)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	id := x.db.record.Manifest.Identity.ID
	if r.GC(x.f.ctx, []string{id})[0] != ErrDenied || x.db.writes != 0 {
		t.Fatal("foreign authority reached claim")
	}
	if _, err := r.AuthenticateRequest(httptest.NewRequest("POST", "https://gc.example/", nil)); err == nil {
		t.Fatal("missing mTLS accepted")
	}
	if r.GC(context.Background(), make([]string, 101))[0] != ErrCapacity {
		t.Fatal("unbounded batch")
	}
	if r.service.Registry.PersistPending(context.Background(), x.db.record) != ErrDenied {
		t.Fatal("GC allowed registration")
	}
	if r.service.Store.Put(context.Background(), x.db.record.Ref, strings.NewReader("x"), ObjectInfo{}, time.Now()) != ErrDenied {
		t.Fatal("GC allowed PUT")
	}
	if _, err := r.service.Store.Range(context.Background(), x.db.record.Ref, 0, 1); err != ErrDenied {
		t.Fatal("GC allowed body read")
	}
	r.Close()
	r.Close()
	if _, err := r.AuthenticateRequest(x.f.peer.request); err != ErrUnavailable {
		t.Fatal("closed authentication")
	}
	if r.GC(context.Background(), []string{id})[0] != ErrUnavailable || x.exchanges.Load() != 0 || x.db.writes != 0 {
		t.Fatal("closed/rejected GC reached provider")
	}
}
