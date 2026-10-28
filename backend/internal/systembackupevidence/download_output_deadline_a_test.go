package systembackupevidence

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

// Native TLS HTTP/1 and HTTP/2 writers buffer small bodies. A successful Write
// is not proof that the server has flushed them before a download deadline.
// SQL/provider/owner inputs remain synthetic; this tests the actual HTTP stack.
type aDownloadDeadlineResponse struct {
	http.ResponseWriter
	deadline     *time.Time
	clears       *int
	beforeResult func()
}

func (w aDownloadDeadlineResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w aDownloadDeadlineResponse) Write(body []byte) (int, error) {
	count, err := w.ResponseWriter.Write(body)
	if err == nil && count == len(body) && !w.deadline.IsZero() && w.beforeResult != nil {
		w.beforeResult()
	}
	return count, err
}
func (w aDownloadDeadlineResponse) SetWriteDeadline(at time.Time) error {
	if at.IsZero() {
		*w.clears++
	} else {
		*w.deadline = at
	}
	return http.NewResponseController(w.ResponseWriter).SetWriteDeadline(at)
}

type aDownloadDeadlineStore struct {
	Store
	localDeadline, sqlDeadline *time.Time
}

func (s aDownloadDeadlineStore) Stat(ctx context.Context, ref Ref) (ObjectInfo, error) {
	c := committedDownloadFrom(ctx)
	bound, ok := ctx.Deadline()
	if c == nil || !ok || !bound.Equal(c.localDeadline) ||
		!s.localDeadline.IsZero() && !s.localDeadline.Equal(c.localDeadline) ||
		!s.sqlDeadline.IsZero() && !s.sqlDeadline.Equal(c.deadlineAt) {
		return ObjectInfo{}, ErrDenied
	}
	*s.localDeadline, *s.sqlDeadline = c.localDeadline, c.deadlineAt
	return s.Store.Stat(ctx, ref)
}

func TestADownloadNativeBufferedOutputKeepsOriginalDeadline(t *testing.T) {
	for _, protocol := range []string{"http1", "http2"} {
		for _, mode := range []string{"before_deadline", "result_crosses_deadline"} {
			t.Run(protocol+"/"+mode, func(t *testing.T) {
				x := newAdmittedHTTPFixture(t, "sensitive")
				var deadline time.Time
				var originalReservation time.Time
				var sealedLocalDeadline, sealedSQLDeadline time.Time
				x.h.service.Store = aDownloadDeadlineStore{x.h.service.Store, &sealedLocalDeadline, &sealedSQLDeadline}
				clears := 0
				waited := false
				var observedResultContext context.Context
				lateChecks := 0
				query := x.f.db.ownerQuery
				x.f.db.ownerQuery = func(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, bool, error) {
					// QueryContext records the current query before this interceptor.
					// The last group audit read and its identity check precede the
					// final clock; earlier config clocks do not meet this boundary.
					if q == downloadIntentClockSQL && x.f.db.resultInserts == 1 && x.f.db.record.Claim == "" && len(x.f.db.queries) >= 3 && x.f.db.queries[len(x.f.db.queries)-2] == "SELECT @@server_uuid,DATABASE()" && x.f.db.queries[len(x.f.db.queries)-3] == downloadRetentionAuditSQL {
						// All result audit/release writes are staged. Delay the final
						// clock read, then execute its original model handler unchanged.
						// Waiting at the first owner lock consumed the independent
						// result budget before its remaining verification work.
						observedResultContext = ctx
						lateChecks++
						if mode == "result_crosses_deadline" {
							if deadline.IsZero() {
								t.Error("result did not follow the native write deadline")
								return nil, true, ErrAudit
							}
							timer := time.NewTimer(time.Until(deadline.Add(75 * time.Millisecond)))
							defer timer.Stop()
							select {
							case <-timer.C:
								waited = true
							case <-ctx.Done():
								return nil, true, ctx.Err()
							}
						}
					}
					if query != nil {
						return query(ctx, q, args)
					}
					return nil, false, nil
				}
				done := make(chan struct{})
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer close(done)
					// TLS setup and fixture construction are outside admission.
					// Freeze the ORIGINAL SQL time and reservation before Admit;
					// never refresh either after it starts. The success control keeps
					// the fixture's original normal budget on a busy test host. Only
					// the deliberate expiry case selects a short reservation, so the
					// result crosses that exact deadline within its separate 5s budget.
					if err := sampleAAdmissionProofTime(x.f, time.Now().UTC().Truncate(time.Microsecond)); err != nil {
						t.Error("resample original signed proof", err)
						http.Error(w, "test fixture unavailable", http.StatusInternalServerError)
						return
					}
					// Keep the normal original reservation for admission/provider work.
					// The writer below pauses BEFORE the independent result transaction;
					// only its final clock then crosses the unchanged native deadline.
					originalReservation = x.f.env.reservationUntil
					beforeResult := func() {
						if mode != "result_crosses_deadline" {
							return
						}
						// Leave two seconds of the ORIGINAL write limit when
						// the separate five-second result budget starts. This
						// wait is after native buffering and never renews a
						// committed reservation, SQL limit or local deadline.
						timer := time.NewTimer(time.Until(deadline.Add(-2 * time.Second)))
						defer timer.Stop()
						select {
						case <-timer.C:
						case <-r.Context().Done():
						}
					}
					x.h.ServeHTTP(aDownloadDeadlineResponse{w, &deadline, &clears, beforeResult}, r)
				}))
				server.EnableHTTP2 = protocol == "http2"
				server.StartTLS()
				defer server.Close()
				client := server.Client()
				client.Timeout = 30 * time.Second
				request, err := http.NewRequest(http.MethodGet, server.URL+x.f.request.URL.Path, nil)
				if err != nil {
					t.Fatal(err)
				}
				request.Header = x.f.request.Header.Clone()
				response, requestErr := client.Do(request)
				var body []byte
				var readErr error
				if response != nil {
					body, readErr = io.ReadAll(response.Body)
					response.Body.Close()
				}
				select {
				case <-done:
				case <-time.After(9 * time.Second):
					t.Fatal("result transaction did not finish")
				}
				var resultContextErr error
				if observedResultContext != nil {
					resultContextErr = observedResultContext.Err()
				}
				t.Logf("NATIVE_RESULT_BUDGET protocol=%s mode=%s result_context=%v result_rows=%d failures=%d waited=%t late_checks=%d", protocol, mode, resultContextErr, x.f.db.resultInserts, x.failures, waited, lateChecks)
				if lateChecks != 1 {
					t.Fatal("expected exactly one final result clock after audit/release", lateChecks)
				}
				// Admission translates the final SQL sample into a monotonic local
				// deadline once. Compare each clock with its own sealed original.
				if sealedLocalDeadline.IsZero() || !deadline.Equal(sealedLocalDeadline) || !sealedSQLDeadline.Equal(originalReservation) || !x.f.env.reservationUntil.Equal(originalReservation) {
					t.Fatal("native writer did not preserve the sealed original deadline", deadline, sealedLocalDeadline, sealedSQLDeadline, originalReservation)
				}
				if deadline.IsZero() || x.f.db.inserts != 1 || x.f.db.resultInserts != 1 || x.failures != 0 || x.f.db.record.Claim != "" || !bytes.Contains(x.f.db.resultBody, []byte(`"outcome":"local_write_complete"`)) {
					t.Fatal("native response did not reach independent result/release", requestErr, readErr, string(body), string(x.f.db.resultBody))
				}
				if mode == "result_crosses_deadline" {
					if !waited || time.Now().Before(deadline) {
						t.Fatal("original deadline was not crossed")
					}
					if bytes.Contains(body, x.plain[:21]) || requestErr == nil && readErr == nil {
						t.Fatal("buffered plaintext flushed after original deadline", protocol, "cleared", clears)
					}
				} else if requestErr != nil || readErr != nil || response.StatusCode != http.StatusPartialContent || !bytes.Equal(body, x.plain[:21]) || (response.ProtoMajor == 2) != (protocol == "http2") {
					t.Fatal("native success path", requestErr, readErr, string(body))
				}
				if clears != 0 {
					t.Fatal("handler cleared deadline before native server final flush", clears)
				}
			})
		}
	}
}

type aDownloadBorrowingWriter struct {
	*admittedTestWriter
	borrowed   []byte
	panicWrite bool
}

func (w *aDownloadBorrowingWriter) Write(body []byte) (int, error) {
	// Retain the address ONLY to inspect the handler's deferred wipe. A real
	// io.Writer is not permitted to retain this slice after Write returns.
	w.borrowed = body
	if w.panicWrite {
		panic(http.ErrAbortHandler)
	}
	return w.admittedTestWriter.Write(body)
}

func TestADownloadPlaintextWipedAfterWriteAndAbort(t *testing.T) {
	for _, mode := range []string{"complete", "short_write", "panic_write"} {
		t.Run(mode, func(t *testing.T) {
			x := newAdmittedHTTPFixture(t, "sensitive")
			w := &aDownloadBorrowingWriter{admittedTestWriter: admittedWriter(), panicWrite: mode == "panic_write"}
			if mode == "short_write" {
				w.short = 5
			}
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				x.h.ServeHTTP(w, x.f.request)
			}()
			if (recovered == http.ErrAbortHandler) != w.panicWrite || recovered != nil && recovered != http.ErrAbortHandler {
				t.Fatal("unexpected panic behavior", recovered)
			}
			if len(w.borrowed) != 21 || !bytes.Equal(w.borrowed, make([]byte, len(w.borrowed))) {
				t.Fatal("plaintext remained in the original output buffer")
			}
			outcome := "interrupted"
			if mode == "complete" {
				outcome = "local_write_complete"
			}
			if w.Code != http.StatusPartialContent || x.f.db.resultInserts != 1 || x.f.db.record.Claim != "" || x.failures != 0 || !bytes.Contains(x.f.db.resultBody, []byte(`"outcome":"`+outcome+`"`)) {
				t.Fatal("abort lost independent result/release", string(x.f.db.resultBody))
			}
		})
	}
}

type aDownloadBodyReader struct {
	read func([]byte) (int, error)
}

func (b *aDownloadBodyReader) Read(p []byte) (int, error) { return b.read(p) }
func (*aDownloadBodyReader) Close() error                 { return nil }

type aDownloadReadDeadlineWriter struct {
	*admittedTestWriter
	deadlines        []time.Time
	setErr, resetErr error
	onSet            func()
}

func (w *aDownloadReadDeadlineWriter) SetReadDeadline(at time.Time) error {
	w.deadlines = append(w.deadlines, at)
	if at.IsZero() {
		return w.resetErr
	}
	if w.onSet != nil {
		w.onSet()
	}
	return w.setErr
}

func TestADownloadEmptyBodyCheckedBeforeAdmissionWithBoundedRead(t *testing.T) {
	for _, mode := range []string{"eof", "data", "no_progress", "private_error", "read_unsupported", "reset_error", "canceled", "late_eof", "late_trailer", "positive_length", "unknown_length", "transfer", "trailer"} {
		t.Run(mode, func(t *testing.T) {
			x := newAdmittedHTTPFixture(t, "sensitive")
			w := &aDownloadReadDeadlineWriter{admittedTestWriter: admittedWriter()}
			reads := 0
			body := &aDownloadBodyReader{read: func(p []byte) (int, error) {
				reads++
				if len(p) != 1 {
					t.Error("request body read was not bounded to one byte")
				}
				switch mode {
				case "data":
					p[0] = 'x'
					return 1, io.EOF
				case "no_progress":
					return 0, nil
				case "private_error":
					return 0, errors.New("PRIVATE request read")
				case "late_eof":
					time.Sleep(time.Until(w.deadlines[0].Add(time.Millisecond)))
				case "late_trailer":
					x.f.request.Trailer = http.Header{"X-Late": {"PRIVATE trailer"}}
				}
				return 0, io.EOF
			}}
			x.f.request.Body = body
			wantStatus := http.StatusBadRequest
			switch mode {
			case "eof":
				wantStatus = http.StatusPartialContent
			case "read_unsupported":
				w.setErr = http.ErrNotSupported
				wantStatus = http.StatusServiceUnavailable
			case "reset_error":
				w.resetErr = errors.New("PRIVATE reset")
				wantStatus = http.StatusServiceUnavailable
			case "canceled":
				ctx, cancel := context.WithCancel(x.f.request.Context())
				defer cancel()
				x.f.request = x.f.request.WithContext(ctx)
				w.onSet = cancel
			case "positive_length":
				x.f.request.ContentLength = 1
			case "unknown_length":
				x.f.request.ContentLength = -1
			case "transfer":
				x.f.request.TransferEncoding = []string{"chunked"}
			case "trailer":
				x.f.request.Trailer = http.Header{"X-Trailer": {"PRIVATE trailer"}}
			}
			// Fixture signing and provider setup are outside admission. Sample
			// SQL time now, keeping the SAME proof and all original limits.
			if err := sampleAAdmissionProofTime(x.f, time.Now().UTC().Truncate(time.Microsecond)); err != nil {
				t.Fatal("sample pre-admission SQL time", err)
			}
			x.h.ServeHTTP(w, x.f.request)
			if w.Code != wantStatus || bytes.Contains(w.Body.Bytes(), []byte("PRIVATE")) || x.f.request.Body != body {
				t.Fatal("body validation response or original request changed", w.Code, w.Body.String())
			}
			if mode == "eof" {
				if !bytes.Equal(w.Body.Bytes(), x.plain[:21]) || x.f.db.inserts != 1 || x.f.db.resultInserts != 1 || x.f.db.record.Claim != "" {
					t.Fatal("empty body did not reach valid admission/result")
				}
			} else if len(x.f.db.queries) != 0 || x.f.db.begins != 0 || len(x.store.scopes) != 0 || x.f.db.inserts != 0 || x.f.db.resultInserts != 0 {
				t.Fatal("invalid or unbounded body reached SQL/provider")
			}
			if oneOf(mode, "positive_length", "unknown_length", "transfer", "trailer") {
				if reads != 0 || len(w.deadlines) != 0 {
					t.Fatal("invalid framing read a body")
				}
			} else if mode == "read_unsupported" {
				if reads != 0 || len(w.deadlines) != 1 {
					t.Fatal("unsupported deadline allowed a read")
				}
			} else if reads != 1 || len(w.deadlines) != 2 || w.deadlines[0].IsZero() || !w.deadlines[1].IsZero() {
				t.Fatal("read deadline was not set and cleared around one bounded read")
			}
		})
	}
}

// Deterministically model slow fixture construction without sleeping or
// weakening the production five-second SQL clock check. Sampling is permitted
// only before admission; it must not renew any original authorization limit.
func TestADownloadEmptyBodySQLClockFreshness(t *testing.T) {
	for _, stale := range []bool{true, false} {
		t.Run(map[bool]string{true: "stale", false: "fresh"}[stale], func(t *testing.T) {
			x := newAdmittedHTTPFixture(t, "sensitive")
			proofHeader := x.f.request.Header.Get("X-Strong-Auth-Proof")
			originalProof := x.f.proof
			reservation, authorityUntil, ownerDeadline := x.f.env.reservationUntil, x.f.env.validUntil, x.f.initial.OwnerDeadline
			now := time.Now().UTC().Truncate(time.Microsecond)
			if stale {
				now = now.Add(-6 * time.Second)
			}
			if err := sampleAAdmissionProofTime(x.f, now); err != nil {
				t.Fatal("sample original proof", err)
			}
			reads := 0
			x.f.request.Body = &aDownloadBodyReader{read: func(p []byte) (int, error) {
				reads++
				if len(p) != 1 {
					t.Error("unbounded body read")
				}
				return 0, io.EOF
			}}
			w := &aDownloadReadDeadlineWriter{admittedTestWriter: admittedWriter()}
			x.h.ServeHTTP(w, x.f.request)
			if reads != 1 || len(w.deadlines) != 2 || len(x.f.db.queries) == 0 {
				t.Fatal("did not reach SQL after bounded EOF")
			}
			if stale {
				// Admission is SQL-relative; the subsequent authority enforces
				// SQL/local freshness before any provider read or plaintext.
				if w.Code != http.StatusForbidden || x.f.db.inserts != 1 || len(x.store.scopes) != 0 || bytes.Contains(w.Body.Bytes(), x.plain[:21]) {
					t.Fatal("stale SQL clock bypassed post-admission authority", w.Code)
				}
			} else if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), x.plain[:21]) || x.f.db.inserts != 1 || x.f.db.resultInserts != 1 || x.f.db.record.Claim != "" {
				t.Fatal("fresh SQL clock did not complete original download", w.Code)
			}
			if !reflect.DeepEqual(x.f.proof, originalProof) || x.f.request.Header.Get("X-Strong-Auth-Proof") != proofHeader || x.f.env.reservationUntil != reservation || x.f.env.validUntil != authorityUntil || x.f.initial.OwnerDeadline != ownerDeadline {
				t.Fatal("SQL sampling renewed original authorization")
			}
		})
	}
}
