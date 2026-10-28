package systembackupevidence

import (
	"bytes"
	"context"
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

func downloadRuntimeFixture(t *testing.T) (DownloadRuntimeConfig, *downloadTransitFixture, *atomic.Int32) {
	return downloadRuntimeFixtureBeforeRead(t, nil)
}

func downloadRuntimeFixtureBeforeRead(t *testing.T, beforeRead func(context.Context)) (DownloadRuntimeConfig, *downloadTransitFixture, *atomic.Int32) {
	t.Helper()
	x := newDownloadTransitFixture(t, "ok")
	f := x.f
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method == "POST" && r.URL.Path == "/" {
			if r.ParseForm() != nil || r.Form.Get("Action") != "AssumeRoleWithWebIdentity" {
				t.Error("wrong STS call")
				w.WriteHeader(400)
				return
			}
			session := r.Form.Get("RoleSessionName")
			fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse xmlns="%s"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>%s</SecretAccessKey><SessionToken>%s</SessionToken><Expiration>%s</Expiration></Credentials><Audience>%s</Audience><Provider>%s</Provider><SubjectFromWebIdentityToken>%s</SubjectFromWebIdentityToken><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/evidence/%s</Arn><AssumedRoleId>ROLEID:%s</AssumedRoleId></AssumedRoleUser><PackedPolicySize>10</PackedPolicySize></AssumeRoleWithWebIdentityResult><ResponseMetadata><RequestId>local-runtime</RequestId></ResponseMetadata></AssumeRoleWithWebIdentityResponse>`, stsNamespace, s3TestAccess, s3TestSecret, s3TestSession, time.Now().UTC().Add(899*time.Second).Format(time.RFC3339), f.c.Audience, f.c.Issuer, f.c.Subject, session, session)
			return
		}
		if !verifyS3Wire(r) || r.URL.Path != "/evidence-bucket/"+f.record.Ref.RelativeKey || r.URL.Query().Get("versionId") != f.record.Ref.ImmutableVersion {
			t.Error("wrong object authorization")
			w.WriteHeader(403)
			return
		}
		w.Header().Set("X-Amz-Version-Id", f.record.Ref.ImmutableVersion)
		switch r.Method {
		case "HEAD":
			digest, _ := hex.DecodeString(f.record.Manifest.ObjectHash)
			w.Header().Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(digest))
			w.Header().Set("Content-Length", fmt.Sprint(len(f.object)))
		case "GET":
			if beforeRead != nil {
				beforeRead(r.Context())
			}
			var start, end int
			if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil || start < 0 || end < start || end >= len(f.object) {
				t.Error("unbounded Range")
				w.WriteHeader(400)
				return
			}
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(f.object)))
			w.Header().Set("Content-Length", fmt.Sprint(end-start+1))
			w.WriteHeader(206)
			w.Write(f.object[start : end+1])
		default:
			t.Error("download attempted mutation")
			w.WriteHeader(403)
		}
	}))
	t.Cleanup(srv.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	store := S3Config{Endpoint: srv.URL, Region: "us-east-1", Bucket: "evidence-bucket", Root: f.c.Root, Installation: f.c.Registry.Installation, Identity: f.c.Store.Identity, Version: f.c.Store.Version, CAPEM: ca, CASHA256: hash(ca)}
	c := DownloadRuntimeConfig{Authority: f.c, S3: S3STSConfig{Store: store, Endpoint: srv.URL, RoleARN: "arn:aws:iam::123456789012:role/evidence", Issuer: f.c.Issuer, Audience: f.c.Audience, CAPEM: ca, CASHA256: hash(ca)}, Transit: []DownloadTransitConfig{x.c}, Failure: func(context.Context, string, string) {}}
	return c, x, &requests
}

func TestDownloadLegacyHTTPWithSTSAndTransit(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		t.Run(fmt.Sprint(revoked), func(t *testing.T) {
			c, x, requests := downloadRuntimeFixture(t)
			f := x.f
			runtime, err := NewDownloadRuntime(c)
			if err != nil {
				t.Fatal(err)
			}
			defer runtime.Close()
			// This isolates HTTP/provider assembly from D's still-missing real
			// owner/reference policy. Session/RBAC/provider authorization uses SQL;
			// the claim/audit registry and SQL transport are explicitly synthetic.
			m := &memoryRegistry{r: f.record, now: time.Now().UTC()}
			m.r.Claim = ""
			m.r.ClaimUntil = time.Time{}
			m.r.RowVersion = 1
			f.db.onBegin = func(int) {
				// This test makes real TLS/STS/S3/Transit calls. Let its SQL
				// clock advance for each new transaction instead of replaying
				// fixture-creation time past the production 5s freshness bound.
				// Session, owner, material and claim expirations remain original.
				stamp := time.Now().UTC().Truncate(time.Microsecond)
				for n := range f.db.plan {
					switch f.db.plan[n].match {
					case "SELECT @@server_uuid":
						f.db.plan[n].values[2] = stamp
					case "SELECT UTC_TIMESTAMP(6)":
						f.db.plan[n].values[0] = stamp
					}
				}
				f.db.plan[7].values[23] = m.r.Claim
				f.db.plan[7].values[24] = m.r.ClaimUntil
				f.db.plan[7].values[27] = m.r.RowVersion
				if revoked && x.decrypts.Load() > 0 {
					f.db.plan[5].values[4] = true
				}
			}
			runtime.handler.Service.Registry = downloadMemoryRegistry{memoryRegistry: m, actor: f.actor}
			runtime.handler.Auth = downloadTestAuthenticator{SQLDownloadAuthority: runtime.authority, stepUp: f.stepUp}
			// Preserve this older assembly test's explicit synthetic legacy
			// callback scope. The mounted runtime now rejects private rows unless
			// the new concrete admission/result path is supplied (tested below).
			legacy := runtime.handler
			legacy.publicOnly = false
			server := httptest.NewTLSServer(legacy)
			defer server.Close()
			r, _ := http.NewRequest("GET", server.URL+Path+f.record.Manifest.Identity.ID, nil)
			r.Header = f.request.Header.Clone()
			r.Header.Set("Range", "bytes=0-20")
			res, err := server.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			body, err := io.ReadAll(io.LimitReader(res.Body, 1024))
			if err != nil {
				t.Fatal(err)
			}
			if requests.Load() < 4 || x.logins.Load() != 1 || x.decrypts.Load() != 1 {
				t.Fatal("test did not exercise network chain", requests.Load(), x.logins.Load(), x.decrypts.Load(), res.StatusCode, string(body))
			}
			if revoked {
				if res.StatusCode != 503 || bytes.Contains(body, f.plain[:21]) {
					t.Fatal("revoked runtime released plaintext")
				}
			} else if res.StatusCode != 206 || !bytes.Equal(body, f.plain[:21]) {
				t.Fatal("runtime download failed", res.StatusCode, string(body))
			}
			if m.r.Claim != "" {
				t.Fatal("runtime retained download claim")
			}
			before := requests.Load()
			if runtime.handler.Service.Store.Put(f.ctx, f.record.Ref, strings.NewReader("x"), ObjectInfo{}, time.Now()) != ErrDenied || runtime.handler.Service.Store.Delete(f.ctx, f.record.Ref, ObjectInfo{}) != ErrDenied {
				t.Fatal("runtime store exposed writes")
			}
			if _, err := runtime.handler.Service.Store.Absent(f.ctx, f.record.Ref); err != ErrDenied {
				t.Fatal("runtime invented absence")
			}
			if before != requests.Load() {
				t.Fatal("denied mutation reached provider")
			}
			runtime.Close()
			runtime.Close()
			closed := httptest.NewRecorder()
			runtime.ServeHTTP(closed, r)
			if closed.Code != 503 || before != requests.Load() {
				t.Fatal("closed runtime accepted request")
			}
		})
	}
}

func TestDownloadRuntimeAdmittedHTTPWithAtomicSQLSTSAndTransit(t *testing.T) {
	for _, mode := range []string{"success", "revoked_after_decrypt", "revoked_after_headers", "stale_sql_after_provider_wait", "fresh_sql_after_provider_wait", "stale_capacity_after_provider_wait"} {
		t.Run(mode, func(t *testing.T) {
			var waitUntil atomic.Int64
			var waitOnce sync.Once
			var waited atomic.Bool
			cfg, x, requests := downloadRuntimeFixtureBeforeRead(t, func(ctx context.Context) {
				if !strings.HasSuffix(mode, "_after_provider_wait") {
					return
				}
				waitOnce.Do(func() {
					timer := time.NewTimer(time.Until(time.Unix(0, waitUntil.Load())))
					defer timer.Stop()
					select {
					case <-timer.C:
						waited.Store(true)
					case <-ctx.Done():
					}
				})
			})
			f, a := uncommittedConfiguredFixture(t, func(f *admissionTxFixture) {
				f.initial.Manifest = x.f.record.Manifest
				f.initial.Ref.ImmutableVersion = x.f.record.Ref.ImmutableVersion
				f.request.Header.Set("Range", "bytes=0-20")
			})
			a.c.Issuer, a.c.Audience, a.c.Subject = cfg.Authority.Issuer, cfg.Authority.Audience, cfg.Authority.Subject
			writeCommittedProviderToken(t, a)
			cfg.Authority = a.c
			cfg.S3.Store.Identity, cfg.S3.Store.Version = a.c.Store.Identity, a.c.Store.Version
			cfg.Admission = f.service
			var sampleResultCapacity func(time.Time) error
			cfg.Results, sampleResultCapacity = resultFixtureWithReportSampler(t, f)
			failures := 0
			cfg.Failure = func(context.Context, string, string) { failures++ }
			runtime, err := NewDownloadRuntime(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer runtime.Close()
			if runtime.admitted == nil {
				t.Fatal("new admission not mounted")
			}
			// Real SQL samples UTC on every clock query. Keep admission's
			// original proof acceptance and every original lease/deadline;
			// advance only subsequent SQL time, never an authorization limit.
			commitsBeforeAdmission := f.db.commits
			originalProof := f.request.Header.Get("X-Strong-Auth-Proof")
			originalReservation, originalAuthority, originalOwner := f.env.reservationUntil, f.env.validUntil, f.initial.OwnerDeadline
			if mode != "stale_sql_after_provider_wait" {
				f.db.ownerQuery = func(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, bool, error) {
					if f.db.commits > commitsBeforeAdmission && (strings.HasPrefix(q, "SELECT @@server_uuid,DATABASE(),UTC_TIMESTAMP(6)") || q == downloadIntentClockSQL) {
						f.db.now = time.Now().UTC().Truncate(time.Microsecond)
					}
					return nil, false, nil
				}
			}
			if mode == "revoked_after_decrypt" {
				policy := f.service.registry.Policy.(*committedTestPolicy)
				policy.onAuthorize = func() {
					if x.decrypts.Load() > 0 {
						f.db.sessionRevoked = true
					}
				}
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := sampleAAdmissionProofTime(f, time.Now().UTC().Truncate(time.Microsecond)); err != nil {
					t.Error("sample original runtime proof", err)
					http.Error(w, "test fixture unavailable", http.StatusInternalServerError)
					return
				}
				waitUntil.Store(f.db.now.Add(6 * time.Second).UnixNano())
				runtime.ServeHTTP(runtimeHeaderHook{ResponseWriter: w, after: func() {
					// Model a separate collector observation before the independent
					// result transaction. Never refresh its reservation after Reserve.
					if mode != "stale_capacity_after_provider_wait" {
						if err := sampleResultCapacity(f.db.now); err != nil {
							t.Error("sample result capacity", err)
						}
					}
					if mode == "revoked_after_headers" {
						f.db.sessionRevoked = true
					}
				}}, r)
			}))
			defer server.Close()
			req, err := http.NewRequest("GET", server.URL+Path+f.initial.Manifest.Identity.ID, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header = f.request.Header.Clone()
			res, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil && mode != "revoked_after_headers" {
				t.Fatal(err)
			}
			if strings.HasSuffix(mode, "_after_provider_wait") && !waited.Load() {
				t.Fatal("provider delay did not cross the SQL freshness bound")
			}
			if originalProof != f.request.Header.Get("X-Strong-Auth-Proof") || originalReservation != f.env.reservationUntil || originalAuthority != f.env.validUntil || originalOwner != f.initial.OwnerDeadline {
				t.Fatal("runtime SQL sampling changed original proof or authorization limits")
			}
			if mode == "stale_sql_after_provider_wait" {
				if res.StatusCode != http.StatusServiceUnavailable || bytes.Contains(body, x.f.plain[:21]) || requests.Load() == 0 || x.logins.Load() != 0 || x.decrypts.Load() != 0 {
					t.Fatal("stale SQL clock did not deny before Transit", res.StatusCode, requests.Load(), x.logins.Load(), x.decrypts.Load())
				}
				return
			}
			if requests.Load() < 4 || x.logins.Load() != 1 || x.decrypts.Load() != 1 {
				t.Fatal("atomic runtime did not reach real TLS provider chain", res.StatusCode, string(body), requests.Load(), x.logins.Load(), x.decrypts.Load())
			}
			if mode == "stale_capacity_after_provider_wait" {
				if res.StatusCode != 206 || !bytes.Equal(body, x.f.plain[:21]) || failures != 1 || f.db.resultInserts != 0 || f.db.record.Claim == "" {
					t.Fatal("stale result capacity was accepted or failure was lost", res.StatusCode, failures)
				}
				return
			}
			if mode == "revoked_after_headers" {
				if res.StatusCode != 206 || len(body) != 0 || err == nil || !bytes.Contains(f.db.resultBody, []byte(`"outcome":"interrupted"`)) {
					t.Fatal("headers already sent: plaintext/JSON emitted or truncation hidden", res.StatusCode, string(body), err)
				}
			} else if mode == "revoked_after_decrypt" {
				if res.StatusCode != 503 && res.StatusCode != 403 {
					t.Fatal("revoked status", res.StatusCode)
				}
				if bytes.Contains(body, x.f.plain[:21]) {
					t.Fatal("revoked runtime released plaintext")
				}
			} else if res.StatusCode != 206 || !bytes.Equal(body, x.f.plain[:21]) || res.Header.Get("X-System-Backup-Operation-Id") != f.db.m.op[0] {
				t.Fatal("atomic runtime binary response", res.StatusCode, string(body))
			}
			if f.db.inserts != 1 || f.db.resultInserts != 1 || len(f.db.nonce) != 16 || f.db.record.Claim != "" || failures != 0 {
				t.Fatal("runtime result/claim/nonce chain incomplete", failures, f.db.calls)
			}
		})
	}
}

type runtimeHeaderHook struct {
	http.ResponseWriter
	after func()
}

func (w runtimeHeaderHook) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w runtimeHeaderHook) WriteHeader(status int)      { w.ResponseWriter.WriteHeader(status); w.after() }

func TestDownloadRuntimeWithoutAdmissionNeverInvokesPrivateCallback(t *testing.T) {
	c, x, requests := downloadRuntimeFixture(t)
	r, err := NewDownloadRuntime(c)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	m := &memoryRegistry{r: x.f.record, now: time.Now().UTC()}
	m.r.Claim = ""
	m.r.ClaimUntil = time.Time{}
	r.handler.Service.Registry = downloadMemoryRegistry{memoryRegistry: m, actor: x.f.actor}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, x.f.request)
	if w.Code != 503 || requests.Load() != 0 || x.decrypts.Load() != 0 || x.f.stepUp.calls != 0 || m.r.Claim != "" || len(m.audits) != 0 {
		t.Fatal("private fallback reached callback/provider", w.Code, w.Body.String())
	}
}

func TestDownloadRuntimeRejectsDriftAndMissingPolicy(t *testing.T) {
	c, x, requests := downloadRuntimeFixture(t)
	for _, mode := range []string{"policy", "Failure", "store", "version", "root", "installation", "issuer", "audience", "Transit", "Admission_only", "Results_only"} {
		t.Run(mode, func(t *testing.T) {
			bad := c
			switch mode {
			case "policy":
				bad.Authority.Registry.Policy = nil
			case "Failure":
				bad.Failure = nil
			case "store":
				bad.S3.Store.Identity = strings.Repeat("e", 64)
			case "version":
				bad.S3.Store.Version = "other"
			case "root":
				bad.S3.Store.Root = "other"
			case "installation":
				bad.S3.Store.Installation = "installation_other"
			case "issuer":
				bad.S3.Issuer = "https://other.example"
			case "audience":
				bad.S3.Audience = "other"
			case "Transit":
				bad.Transit = nil
			case "Admission_only":
				bad.Admission = &DownloadAdmissionService{}
			case "Results_only":
				bad.Results = &SQLDownloadResults{}
			}
			r, err := NewDownloadRuntime(bad)
			if r != nil {
				r.Close()
			}
			if err == nil || r != nil || requests.Load() != 0 || x.logins.Load() != 0 {
				t.Fatal("invalid runtime constructed")
			}
		})
	}
}
