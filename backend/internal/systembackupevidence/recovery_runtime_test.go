package systembackupevidence

import (
	"context"
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

// The actual TLS STS/S3 clients and SQL recovery/CAS code run here. The SQL
// transport, policy and provider are fixtures, not production admission proof.
func recoveryRuntimeFixture(t *testing.T, f *recoveryFixture, mode string) (RecoveryRuntimeConfig, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var exchanges, heads atomic.Int32
	ref, info := f.db.record.Ref, f.info()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == "POST" && req.URL.Path == "/" {
			exchanges.Add(1)
			if req.ParseForm() != nil || req.Form.Get("Action") != "AssumeRoleWithWebIdentity" || strings.Contains(req.Form.Get("Policy"), "PutObject") || strings.Contains(req.Form.Get("Policy"), "DeleteObject") {
				t.Error("invalid recovery credential exchange")
				w.WriteHeader(403)
				return
			}
			session := req.Form.Get("RoleSessionName")
			fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse xmlns="%s"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>%s</SecretAccessKey><SessionToken>%s</SessionToken><Expiration>%s</Expiration></Credentials><Audience>%s</Audience><Provider>%s</Provider><SubjectFromWebIdentityToken>%s</SubjectFromWebIdentityToken><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/evidence/%s</Arn><AssumedRoleId>ROLEID:%s</AssumedRoleId></AssumedRoleUser><PackedPolicySize>10</PackedPolicySize></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`, stsNamespace, s3TestAccess, s3TestSecret, s3TestSession, time.Now().UTC().Add(899*time.Second).Format(time.RFC3339), f.c.Audience, f.c.Issuer, f.c.Subject, session, session)
			return
		}
		if req.Method != "HEAD" || req.URL.Path != "/evidence-bucket/"+ref.RelativeKey || req.URL.Query().Has("versionId") || !verifyS3Wire(req) {
			t.Error("recovery attempted non-HEAD or wrong object request")
			w.WriteHeader(403)
			return
		}
		heads.Add(1)
		if mode == "404" {
			w.WriteHeader(404)
			return
		}
		digest, _ := hex.DecodeString(info.SHA256)
		if mode == "mismatch" {
			digest[0] ^= 1
		}
		w.Header().Set("X-Amz-Version-Id", info.Version)
		w.Header().Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(digest))
		w.Header().Set("Content-Length", fmt.Sprint(info.Size))
	}))
	t.Cleanup(srv.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	c := f.c
	// Batch fixtures replace the SQL connection with their scan-aware driver.
	c.Registry = f.a.c.Registry
	s := S3Config{Endpoint: srv.URL, Region: "us-east-1", Bucket: "evidence-bucket", Root: c.Root, Installation: c.Registry.Installation, Identity: c.Store.Identity, Version: c.Store.Version, CAPEM: ca, CASHA256: hash(ca)}
	if mode == "revoke" {
		f.db.onBegin = func(int) {
			if heads.Load() > 0 {
				f.db.plan[3].values[0] = strings.Repeat("f", 64)
			}
		}
	}
	return RecoveryRuntimeConfig{Authority: c, S3: S3STSConfig{Store: s, Endpoint: srv.URL, RoleARN: "arn:aws:iam::123456789012:role/evidence", Issuer: c.Issuer, Audience: c.Audience, CAPEM: ca, CASHA256: hash(ca)}}, &exchanges, &heads
}

func TestRecoveryRuntimeSTSAndReadOnlyRecovery(t *testing.T) {
	for _, mode := range []string{"ok", "404", "mismatch", "revoke"} {
		t.Run(mode, func(t *testing.T) {
			f := newRecoveryFixture(t)
			c, exchanges, heads := recoveryRuntimeFixture(t, f, mode)
			r, err := NewRecoveryRuntime(c)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			ctx, err := r.AuthenticateRequest(f.peer.request)
			if err != nil {
				t.Fatal(err)
			}
			before := f.db.record
			err = r.Reconcile(ctx, before.Manifest.Identity.ID)
			if exchanges.Load() != 1 || heads.Load() != 1 {
				t.Fatal("did not exercise STS and HEAD", exchanges.Load(), heads.Load(), err)
			}
			got := f.db.record
			if hash(canonical(got.Manifest)) != hash(canonical(before.Manifest)) || got.OwnerDeadline != before.OwnerDeadline || got.Ref.RelativeKey != before.Ref.RelativeKey {
				t.Fatal("recovery altered original evidence or owner")
			}
			if mode == "ok" {
				if err != nil || got.State != "ready" || got.Ref.ImmutableVersion != f.info().Version || got.Claim != "" || len(f.db.audits) != 2 || len(f.signals) != 0 {
					t.Fatal("matching object did not converge", err, got.State)
				}
			} else {
				if err == nil || got.Ref.ImmutableVersion != "" || len(f.signals) != 1 {
					t.Fatal("failed or revoked observation accepted", err, got.State)
				}
				want := "write_unknown"
				if mode == "mismatch" {
					want = "write_failed"
				}
				if got.State != want {
					t.Fatal("wrong failed state", got.State)
				}
				if mode == "404" && (f.db.observation.next.IsZero() || len(f.db.audits) != 2 || got.Claim != "") {
					t.Fatal("404 lost retry or result audit")
				}
				if mode == "revoke" && (len(f.db.audits) != 1 || got.Claim == "") {
					t.Fatal("revoked result committed")
				}
			}
		})
	}
}

func TestRecoveryRuntimeBatchUsesSameAuthority(t *testing.T) {
	f, scan := newRecoveryScanFixture(t)
	c, exchanges, heads := recoveryRuntimeFixture(t, f, "ok")
	r, err := NewRecoveryRuntime(c)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, err := r.AuthenticateRequest(f.peer.request)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := r.ReconcileBatch(ctx, 0, 1)
	if err != nil || !scan.scanCommitted || batch.AfterID != 10 || batch.More || len(batch.Results) != 1 || batch.Results[0].Err != nil || f.db.record.State != "ready" || exchanges.Load() != 1 || heads.Load() != 1 {
		t.Fatal("runtime batch did not converge", err, batch)
	}
}

func TestRecoveryRuntimeAdmissionAndClosure(t *testing.T) {
	f := newRecoveryFixture(t)
	c, exchanges, heads := recoveryRuntimeFixture(t, f, "ok")
	for _, mode := range []string{"policy", "failure", "installation", "store", "version", "root", "issuer", "audience", "tls"} {
		t.Run(mode, func(t *testing.T) {
			bad := c
			switch mode {
			case "policy":
				bad.Authority.Registry.Policy = nil
			case "failure":
				bad.Authority.Failure = nil
			case "installation":
				bad.S3.Store.Installation = "installation_other"
			case "store":
				bad.S3.Store.Identity = strings.Repeat("e", 64)
			case "version":
				bad.S3.Store.Version = "other"
			case "root":
				bad.S3.Store.Root = "other"
			case "issuer":
				bad.S3.Issuer = "https://other.example"
			case "audience":
				bad.S3.Audience = "other"
			case "tls":
				bad.S3.CASHA256 = strings.Repeat("0", 64)
			}
			r, err := NewRecoveryRuntime(bad)
			if r != nil {
				r.Close()
			}
			if err == nil || r != nil {
				t.Fatal("invalid admission accepted")
			}
		})
	}
	r, err := NewRecoveryRuntime(c)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// A context from a different authority, even with identical configuration,
	// cannot be substituted for this runtime's authenticated peer.
	if err := r.Reconcile(f.ctx, f.db.record.Manifest.Identity.ID); err != ErrDenied || f.db.writes != 0 {
		t.Fatal("foreign authority accepted", err)
	}
	if _, err := r.AuthenticateRequest(httptest.NewRequest("POST", "https://worker.example/", nil)); err == nil {
		t.Fatal("missing mTLS accepted")
	}
	if _, ok := any(recoveryStatOnly{r.store}).(Store); ok {
		t.Fatal("recovery exposes full object store")
	}
	r.Close()
	r.Close()
	if _, err := r.AuthenticateRequest(f.peer.request); err != ErrUnavailable {
		t.Fatal("closed authentication accepted")
	}
	if err := r.Reconcile(context.Background(), f.db.record.Manifest.Identity.ID); err != ErrUnavailable {
		t.Fatal("closed recovery accepted")
	}
	if b, err := r.ReconcileBatch(context.Background(), 17, 1); err != ErrUnavailable || b.AfterID != 17 {
		t.Fatal("closed batch accepted or lost cursor")
	}
	if exchanges.Load() != 0 || heads.Load() != 0 || f.db.writes != 0 {
		t.Fatal("rejected work reached provider/database")
	}
}
