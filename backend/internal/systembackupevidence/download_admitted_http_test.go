package systembackupevidence

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	sec "clawreef/internal/systembackupsecurity"
)

type admittedHTTPFixture struct {
	f        *admissionTxFixture
	a        *SQLDownloadAuthority
	h        *admittedDownloadHandler
	store    *committedScopedReadStore
	plain    []byte
	failures int
	failure  DownloadFailureReference
}

func newAdmittedHTTPFixture(t *testing.T, classification string) *admittedHTTPFixture {
	t.Helper()
	p, plain, object, keys := fixture(t, 9000)
	if classification != "sensitive" {
		i := p.Manifest().Identity
		i.Classification = classification
		var out bytes.Buffer
		var err error
		p, err = Prepare(context.Background(), i, p.Manifest().Key, source(plain), testRedactor{}, keys, &out)
		if err != nil {
			t.Fatal(err)
		}
		object = out.Bytes()
	}
	f, a := uncommittedConfiguredFixture(t, func(f *admissionTxFixture) {
		f.initial.Manifest = p.Manifest()
		f.request.Header.Set("Range", "bytes=0-20")
	})
	if oneOf(classification, "public", "internal") {
		f.request.Header.Del(sec.StrongAuthProofHeader)
		f.request.Header.Del("Idempotency-Key")
		a.c.Registry.Policy.(*committedTestPolicy).legacy = true
	}
	writeCommittedProviderToken(t, a)
	s := &committedScopedReadStore{testStore: &testStore{data: object, present: true, info: ObjectInfo{Version: f.initial.Ref.ImmutableVersion, SHA256: hash(object), Size: int64(len(object))}}, authority: a}
	x := &admittedHTTPFixture{f: f, a: a, store: s, plain: plain}
	service := Service{Registry: f.service.registry, Store: s, Keys: DownloadKeys{Authority: a, Keys: keys}, Failure: func(ctx context.Context, _ string, code string) {
		x.failures++
		var ok bool
		x.failure, ok = DownloadFailureReferenceFrom(ctx)
		if !ok || ctx.Err() != nil || code != "download_result_audit_or_release_failed" {
			t.Error("failure sink lost fresh budget/correlation", ok, ctx.Err(), code)
		}
	}}
	var err error
	results, sampleResult := resultFixtureWithReportSampler(t, f)
	x.h, err = newAdmittedDownloadHandler(f.service, a, results, service, Handler{Service: service, Auth: a})
	if err != nil {
		t.Fatal(err)
	}
	// Sample the INITIAL request SQL clock only after file/provider setup.
	// Setup can exceed the production five-second skew budget on a busy host.
	// This creates the initial synthetic reservation before any Admit; it does
	// not re-sign a proof or renew session/provider/owner/claim/retention limits.
	now := time.Now().UTC().Truncate(time.Microsecond)
	if oneOf(classification, "public", "internal") {
		// Public/internal requests deliberately have no strong-auth header.
		f.db.now = now
	} else if err := sampleAAdmissionProofTime(f, now); err != nil {
		t.Fatal(err)
	}
	f.env.reservationUntil = f.db.now.Add(20 * time.Second)
	if err := sampleResult(f.db.now); err != nil {
		t.Fatal(err)
	}
	return x
}

func TestAdmittedHTTPFixtureStillRejectsStaleSQLClock(t *testing.T) {
	x := newAdmittedHTTPFixture(t, "sensitive")
	// Keep the original production skew rejection and all authority limits.
	if err := sampleAAdmissionProofTime(x.f, time.Now().UTC().Add(-6*time.Second).Truncate(time.Microsecond)); err != nil {
		t.Fatal(err)
	}
	w := admittedWriter()
	x.h.ServeHTTP(w, x.f.request)
	if w.Code < 400 || len(x.store.scopes) != 0 || bytes.Contains(w.Body.Bytes(), x.plain[:21]) {
		t.Fatal("stale SQL clock bypassed the original guard", w.Code)
	}
}

type admittedTestWriter struct {
	*httptest.ResponseRecorder
	deadline    time.Time
	onHeader    func()
	short       int
	writeErr    error
	deadlineErr error
	writes      int
}

func (w *admittedTestWriter) SetWriteDeadline(at time.Time) error {
	w.deadline = at
	return w.deadlineErr
}
func (w *admittedTestWriter) WriteHeader(status int) {
	w.ResponseRecorder.WriteHeader(status)
	if w.onHeader != nil {
		w.onHeader()
	}
}
func (w *admittedTestWriter) Write(body []byte) (int, error) {
	w.writes++
	if w.short > 0 {
		body = body[:w.short]
	}
	n, _ := w.ResponseRecorder.Write(body)
	return n, w.writeErr
}
func admittedWriter() *admittedTestWriter {
	return &admittedTestWriter{ResponseRecorder: httptest.NewRecorder()}
}

func TestAdmittedDownloadHTTPCompleteRangeAuditAndNoReplay(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(strconv.FormatBool(partial), func(t *testing.T) {
			x := newAdmittedHTTPFixture(t, "sensitive")
			if !partial {
				x.f.request.Header.Del("Range")
				x.f.sign(t, x.f.request.Header.Get("Idempotency-Key"), x.f.db.now.Add(-time.Minute), x.f.db.now.Add(time.Minute))
			}
			w := admittedWriter()
			x.h.ServeHTTP(w, x.f.request)
			expected := x.plain
			if w.deadline.IsZero() {
				t.Fatal("original deadline cleared before native final flush")
			}
			if partial {
				expected = expected[:21]
			}
			status := 200
			if partial {
				status = 206
			}
			if w.Code != status || !bytes.Equal(w.Body.Bytes(), expected) || w.Header().Get("X-System-Backup-Operation-Id") != x.f.db.m.op[0] || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "text/plain" || w.Header().Get("Content-Length") != strconv.Itoa(len(expected)) {
				t.Fatal("binary response", w.Code, w.Header(), w.Body.String())
			}
			if partial && w.Header().Get("Content-Range") != "bytes 0-20/9000" {
				t.Fatal("normalized response range")
			}
			if x.f.db.inserts != 1 || x.f.db.resultInserts != 1 || x.f.db.record.Claim != "" || x.failures != 0 || !bytes.Contains(x.f.db.resultBody, []byte(`"outcome":"local_write_complete"`)) {
				t.Fatal("missing original/result effects", x.f.db.calls)
			}
			before := len(x.store.scopes)
			again := admittedWriter()
			x.h.ServeHTTP(again, x.f.request)
			if again.Code != 409 || !strings.Contains(again.Body.String(), "idempotency_conflict") || len(x.store.scopes) != before || x.f.db.inserts != 1 || x.f.db.resultInserts != 1 {
				t.Fatal("same key resent", again.Code, again.Body.String())
			}
			x.f.sign(t, "new_download_key_012345", x.f.db.now.Add(-time.Minute), x.f.db.now.Add(time.Minute))
			replayed := admittedWriter()
			x.h.ServeHTTP(replayed, x.f.request)
			if replayed.Code != 401 || !strings.Contains(replayed.Body.String(), "strong_auth_replayed") || len(x.store.scopes) != before {
				t.Fatal("consumed nonce reused", replayed.Code, replayed.Body.String())
			}
		})
	}
}

func TestAdmittedDownloadHTTPRejectsBeforeProviderAndCommitUnknown(t *testing.T) {
	for _, mode := range []string{"missing_proof", "invalid_proof", "malformed_proof", "missing_key", "duplicate_range", "query", "empty_query", "raw_path", "fragment", "body", "no_tls", "post", "unknown_commit"} {
		t.Run(mode, func(t *testing.T) {
			x := newAdmittedHTTPFixture(t, "sensitive")
			want := 400
			switch mode {
			case "missing_proof":
				x.f.request.Header.Del(sec.StrongAuthProofHeader)
				want = 401
			case "invalid_proof":
				proof := x.f.proof
				proof.Signature.Value = strings.Repeat("A", len(proof.Signature.Value))
				raw, err := json.Marshal(proof)
				if err != nil {
					t.Fatal(err)
				}
				x.f.request.Header.Set(sec.StrongAuthProofHeader, base64.StdEncoding.EncodeToString(raw))
				want = 401
			case "malformed_proof":
				x.f.request.Header.Set(sec.StrongAuthProofHeader, "PRIVATE malformed proof")
			case "missing_key":
				x.f.request.Header.Del("Idempotency-Key")
			case "duplicate_range":
				x.f.request.Header.Add("Range", "bytes=1-2")
			case "query":
				x.f.request.URL.RawQuery = "unexpected=1"
			case "empty_query":
				x.f.request.URL.ForceQuery = true
			case "raw_path":
				x.f.request.URL.RawPath = x.f.request.URL.Path
			case "fragment":
				x.f.request.URL.Fragment = "hidden"
			case "body":
				x.f.request.Body = io.NopCloser(strings.NewReader("PRIVATE body"))
				x.f.request.ContentLength = 12
			case "no_tls":
				x.f.request.TLS = nil
				want = 401
			case "post":
				x.f.request.Method = "POST"
				want = 405
			case "unknown_commit":
				x.f.db.commitUnknown = true
				want = 503
			}
			w := admittedWriter()
			x.h.ServeHTTP(w, x.f.request)
			if w.Code != want || len(x.store.scopes) != 0 || x.f.db.resultInserts != 0 || w.Header().Get("X-System-Backup-Operation-Id") != "" || strings.Contains(w.Body.String(), "PRIVATE") {
				t.Fatal("pre-provider boundary", w.Code, w.Body.String(), x.f.db.calls)
			}
			if mode == "unknown_commit" {
				if x.f.db.commitAttempts != 1 || len(x.f.db.nonce) != 16 {
					t.Fatal("unknown commit retried/erased")
				}
			} else if x.f.db.inserts != 0 {
				t.Fatal("invalid request wrote intent")
			}
		})
	}
}

func TestAdmittedDownloadHTTPInterruptionRevocationAndResultFailure(t *testing.T) {
	for _, mode := range []string{"short_write", "write_error", "revoke_before_headers", "revoke_after_headers", "deadline_unsupported", "result_failure", "canceled_after_write"} {
		t.Run(mode, func(t *testing.T) {
			x := newAdmittedHTTPFixture(t, "sensitive")
			w := admittedWriter()
			wantOutcome := "interrupted"
			wantStatus := 206
			switch mode {
			case "short_write":
				w.short = 5
			case "write_error":
				w.writeErr = errors.New("PRIVATE socket")
			case "revoke_before_headers":
				x.store.testStore.onRead = func() { x.f.db.sessionRevoked = true }
				wantOutcome = "rejected"
				wantStatus = 503 // unwrap's public error is encryption_key_unavailable
			case "revoke_after_headers":
				w.onHeader = func() { x.f.db.sessionRevoked = true }
			case "deadline_unsupported":
				w.deadlineErr = errors.New("PRIVATE deadline")
				wantOutcome = "rejected"
				wantStatus = 503
			case "result_failure":
				x.f.db.fault = "result_insert"
				wantOutcome = "local_write_complete"
			case "canceled_after_write":
				ctx, cancel := context.WithCancel(x.f.request.Context())
				x.f.request = x.f.request.WithContext(ctx)
				w.onHeader = cancel
			}
			x.h.ServeHTTP(w, x.f.request)
			if w.Code != wantStatus {
				t.Fatal("wrong response", w.Code, w.Body.String())
			}
			if oneOf(mode, "revoke_after_headers", "canceled_after_write") && (w.writes != 0 || w.Body.Len() != 0) {
				t.Fatal("plaintext/JSON appended after header guard failed")
			}
			if mode == "revoke_before_headers" && bytes.Contains(w.Body.Bytes(), x.plain[:21]) {
				t.Fatal("revoked before header released plaintext")
			}
			if mode == "result_failure" {
				if x.failures != 1 || len(x.f.db.resultBody) != 0 || x.failure.OperationID != x.f.db.m.op[0] || x.failure.IntentAuditID != 1729 || !digestPattern.MatchString(x.failure.ClaimSHA256) || x.f.db.record.Claim == "" {
					t.Fatal("durable failure correlation/rollback", x.failures, x.failure)
				}
			} else if x.failures != 0 || x.f.db.record.Claim != "" || !bytes.Contains(x.f.db.resultBody, []byte(`"outcome":"`+wantOutcome+`"`)) {
				t.Fatal("missing result after interruption/revocation", x.failures, string(x.f.db.resultBody))
			}
			if strings.Contains(w.Body.String(), "PRIVATE") || x.f.db.inserts != 1 || len(x.f.db.nonce) != 16 {
				t.Fatal("private failure or admission replay")
			}
		})
	}
}

type beforeDownloadRegistry struct {
	Registry
	before func()
}

func (r beforeDownloadRegistry) WithLocked(ctx context.Context, id string, fn func(Locked) error) error {
	if r.before != nil {
		r.before()
	}
	return r.Registry.WithLocked(ctx, id, fn)
}

func TestAdmittedDownloadHTTPPublicInternalAndClassificationRace(t *testing.T) {
	for _, classification := range []string{"public", "internal", "race_to_private"} {
		t.Run(classification, func(t *testing.T) {
			kind := classification
			if classification == "race_to_private" {
				kind = "public"
			}
			x := newAdmittedHTTPFixture(t, kind)
			if classification == "race_to_private" {
				x.h.public.Service.Registry = beforeDownloadRegistry{Registry: x.h.public.Service.Registry, before: func() { x.f.db.record.Manifest.Identity.Classification = "sensitive" }}
			}
			w := admittedWriter()
			x.h.ServeHTTP(w, x.f.request)
			if classification == "race_to_private" {
				if w.Code != 503 || len(x.store.scopes) != 0 || x.f.db.record.Claim != "" {
					t.Fatal("classification race bypassed private admission", w.Code, w.Body.String())
				}
			} else if w.Code != 206 || !bytes.Equal(w.Body.Bytes(), x.plain[:21]) || w.Header().Get("X-System-Backup-Operation-Id") != "" {
				t.Fatal("non-sensitive request required proof/admission", w.Code, w.Body.String())
			}
			if x.f.db.inserts != 0 || x.f.db.resultInserts != 0 || len(x.f.db.nonce) != 0 {
				t.Fatal("non-sensitive classification consumed proof/nonce")
			}
		})
	}
}

func TestAdmittedDownloadErrorBoundaryNeverReturnsPrivateCause(t *testing.T) {
	for _, err := range []error{errors.New("PRIVATE provider password"), &sec.VerificationError{Code: "PRIVATE unknown code"}, ErrDownloadAdmissionCommitUnknown, ErrDownloadResultCommitUnknown} {
		w := httptest.NewRecorder()
		writeAdmittedDownloadError(w, err)
		if w.Code != 503 || strings.Contains(w.Body.String(), "PRIVATE") || !strings.Contains(w.Body.String(), "not_ready") {
			t.Fatal("unsafe error boundary", w.Code, w.Body.String())
		}
	}
}

func TestAdmittedDownloadHTTPMatchesOriginalMachineErrorDecision(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/evidence/system-backup-d-sensitive-download-contract-20261016.json")
	if err != nil {
		t.Fatal(err)
	}
	var decision struct {
		Mapping map[string][]json.RawMessage `json:"error_mapping"`
	}
	if json.Unmarshal(raw, &decision) != nil || len(decision.Mapping) < 18 {
		t.Fatal("missing original D error decision")
	}
	proofError := func(code sec.FailureCode) error { return &sec.VerificationError{Code: code} }
	for _, v := range []struct {
		key string
		err error
	}{
		{"malformed_or_duplicate_headers_or_missing_required_key", ErrInvalid}, {"missing_live_auth", ErrAuth},
		{"missing_proof", proofError(sec.FailureRequired)}, {"expired_proof", proofError(sec.FailureExpired)}, {"invalid_issuer", proofError(sec.FailureInvalidIssuer)},
		{"invalid_or_mismatched_proof", proofError(sec.FailureInvalid)}, {"nonce_replay", proofError(sec.FailureReplayed)},
		{"current_permission_denied", ErrDenied}, {"authorized_target_absent", ErrNotFound}, {"key_conflict", ErrDownloadAdmissionKeyConflict},
		{"active_claim_or_changed_manifest", ErrState}, {"claim_row_cas_failure", ErrConflict}, {"idempotency_marker_expired", ErrDownloadAdmissionKeyExpired},
		{"invalid_range", ErrRange}, {"physical_capacity_exhausted", ErrCapacity}, {"missing_material_schema_adapter_or_uncertain_commit", ErrDownloadAdmissionCommitUnknown},
		{"provider_read_failure_before_headers", ErrUnavailable}, {"provider_read_failure_before_headers", ErrKey},
		{"audit_or_internal_integrity_failure", ErrAudit}, {"audit_or_internal_integrity_failure", ErrIntegrity},
	} {
		t.Run(v.key+"/"+v.err.Error(), func(t *testing.T) {
			pair := decision.Mapping[v.key]
			if len(pair) != 2 {
				t.Fatal("missing mapping", v.key)
			}
			var status int
			var code string
			if json.Unmarshal(pair[0], &status) != nil || json.Unmarshal(pair[1], &code) != nil {
				t.Fatal("malformed decision")
			}
			gotStatus, gotCode := admittedDownloadHTTPError(v.err)
			if gotStatus != status || gotCode != code {
				t.Fatalf("%d/%s want %d/%s", gotStatus, gotCode, status, code)
			}
		})
	}
}
