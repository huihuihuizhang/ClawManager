package systembackupevidence

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

type prepareBoundaryReader struct {
	io.Reader
	afterRead func(int, error)
	onClose   func() error
	closes    int
	reads     int
	borrowed  []byte
}

func (r *prepareBoundaryReader) Read(b []byte) (int, error) {
	r.reads++
	n, err := r.Reader.Read(b)
	if n > 0 {
		r.borrowed = b[:n]
	}
	if r.afterRead != nil {
		r.afterRead(n, err)
	}
	return n, err
}

func (r *prepareBoundaryReader) Close() error {
	r.closes++
	if r.onClose != nil {
		return r.onClose()
	}
	return nil
}

type prepareBoundaryKeys struct {
	testKeys
	afterWrap func([]byte)
	borrowed  []byte
	wraps     int
}

func (k *prepareBoundaryKeys) Wrap(ctx context.Context, ref KeyRef, dek []byte) ([]byte, error) {
	k.wraps++
	k.borrowed = dek
	wrapped, err := k.testKeys.Wrap(ctx, ref, dek)
	if k.afterWrap != nil {
		k.afterWrap(dek)
	}
	return wrapped, err
}

type prepareBoundaryWriter struct {
	bytes.Buffer
	afterWrite func(int)
	writes     int
}

func (w *prepareBoundaryWriter) Write(b []byte) (int, error) {
	w.writes++
	n, err := w.Buffer.Write(b)
	if w.afterWrite != nil {
		w.afterWrite(w.writes)
	}
	return n, err
}

type prepareBoundaryRedactor func(context.Context, Identity, io.Reader) error

func (r prepareBoundaryRedactor) Validate(ctx context.Context, i Identity, src io.Reader) error {
	return r(ctx, i, src)
}

func prepareBoundaryFixture() (Identity, KeyRef, []byte, *prepareBoundaryKeys) {
	plain := bytes.Repeat([]byte("abcdefgh"), 1125)
	i := Identity{Installation: "installation_test", ID: "sev_11111111-2222-4333-8444-555555555555", OwnerType: "backup", OwnerID: "sbk_11111111-2222-4333-8444-555555555555", Type: "verifier_report", Media: "text/plain", Classification: "sensitive", ContentHash: hash(plain), ContentSize: int64(len(plain))}
	return i, KeyRef{strings.Repeat("b", 64), "v1"}, plain, &prepareBoundaryKeys{testKeys: testKeys{key: bytes.Repeat([]byte{7}, 32)}}
}

func TestPrepareCancellationBoundaries(t *testing.T) {
	for _, stage := range []string{"before-call", "first-source", "first-read", "redactor", "first-close", "wrap", "prefix-write", "header-write", "second-source", "second-read", "frame-write", "final-eof", "second-close"} {
		t.Run(stage, func(t *testing.T) {
			i, key, plain, keys := prepareBoundaryFixture()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if stage == "before-call" {
				cancel()
			}
			var readers []*prepareBoundaryReader
			var sourceCalls, validations int
			src := func() (io.ReadCloser, error) {
				sourceCalls++
				pass := sourceCalls
				r := &prepareBoundaryReader{Reader: bytes.NewReader(plain)}
				r.afterRead = func(n int, err error) {
					if stage == "first-read" && pass == 1 || stage == "second-read" && pass == 2 && n > 0 || stage == "final-eof" && pass == 2 && err == io.EOF {
						cancel()
					}
				}
				r.onClose = func() error {
					if stage == "first-close" && pass == 1 || stage == "second-close" && pass == 2 {
						cancel()
					}
					return nil
				}
				readers = append(readers, r)
				if stage == "first-source" && pass == 1 || stage == "second-source" && pass == 2 {
					cancel()
				}
				return r, nil
			}
			redactor := prepareBoundaryRedactor(func(_ context.Context, _ Identity, r io.Reader) error {
				validations++
				_, err := io.Copy(io.Discard, r)
				if stage == "redactor" {
					cancel()
				}
				return err
			})
			keys.afterWrap = func([]byte) {
				if stage == "wrap" {
					cancel()
				}
			}
			dst := &prepareBoundaryWriter{afterWrite: func(n int) {
				if stage == "prefix-write" && n == 1 || stage == "header-write" && n == 2 || stage == "frame-write" && n == 3 {
					cancel()
				}
			}}
			p, err := Prepare(ctx, i, key, src, redactor, keys, dst)
			if err != ErrUnavailable || len(p.Manifest().Chunks) != 0 {
				t.Fatalf("canceled preparation err=%v chunks=%d", err, len(p.Manifest().Chunks))
			}
			for _, r := range readers {
				if r.closes != 1 {
					t.Fatalf("source not closed exactly once: %d", r.closes)
				}
			}
			if len(readers) == 2 && !bytes.Equal(readers[1].borrowed, make([]byte, len(readers[1].borrowed))) {
				t.Fatal("failed second pass retained plaintext buffer")
			}
			if stage == "before-call" && (sourceCalls != 0 || validations != 0 || keys.wraps != 0 || dst.writes != 0) {
				t.Fatal("already canceled call reached an adapter")
			}
			if stage == "first-source" && (validations != 0 || readers[0].reads != 0) {
				t.Fatal("canceled source callback proceeded to validation")
			}
			if oneOf(stage, "before-call", "first-source", "first-read", "redactor", "first-close") && (keys.wraps != 0 || dst.writes != 0) {
				t.Fatal("canceled validation proceeded to Wrap or staging")
			}
			if stage == "wrap" && (dst.writes != 0 || sourceCalls != 1) {
				t.Fatal("canceled Wrap proceeded to staging or second source")
			}
			if stage == "prefix-write" && (dst.writes != 1 || sourceCalls != 1) || stage == "header-write" && (dst.writes != 2 || sourceCalls != 1) {
				t.Fatal("canceled header staging continued")
			}
			if stage == "second-source" && readers[1].reads != 0 || stage == "second-read" && dst.writes != 2 || stage == "frame-write" && readers[1].reads != 1 {
				t.Fatal("canceled second pass continued reading or writing")
			}
			if !bytes.Equal(keys.borrowed, make([]byte, len(keys.borrowed))) {
				t.Fatal("failed preparation retained borrowed DEK")
			}
		})
	}
}

func TestPrepareRequiresBothSourceClosesSuccess(t *testing.T) {
	for _, failurePass := range []int{1, 2} {
		t.Run(string(rune('0'+failurePass)), func(t *testing.T) {
			i, key, plain, keys := prepareBoundaryFixture()
			var readers []*prepareBoundaryReader
			src := func() (io.ReadCloser, error) {
				r := &prepareBoundaryReader{Reader: bytes.NewReader(plain)}
				readers = append(readers, r)
				if len(readers) == failurePass {
					r.onClose = func() error { return errors.New("private staging close error") }
				}
				return r, nil
			}
			var dst bytes.Buffer
			p, err := Prepare(context.Background(), i, key, src, testRedactor{}, keys, &dst)
			if err != ErrIntegrity || len(p.Manifest().Chunks) != 0 {
				t.Fatal("source close failure produced evidence", err)
			}
			for _, r := range readers {
				if r.closes != 1 {
					t.Fatal("source close called twice or omitted", r.closes)
				}
			}
		})
	}
}

func TestPrepareRejectsDEKMutation(t *testing.T) {
	i, key, plain, keys := prepareBoundaryFixture()
	keys.afterWrap = func(b []byte) { wipe(b) }
	var dst bytes.Buffer
	p, err := Prepare(context.Background(), i, key, source(plain), testRedactor{}, keys, &dst)
	if err != ErrKey || len(p.Manifest().Chunks) != 0 || dst.Len() != 0 {
		t.Fatal("Wrap erased DEK after wrapping but preparation continued", err)
	}
}

func TestPrepareOwnsAndErasesWrapInput(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "success"
		if fail {
			name = "wrap-error"
		}
		t.Run(name, func(t *testing.T) {
			i, key, plain, keys := prepareBoundaryFixture()
			keys.fail = fail
			calls := 0
			src := func() (io.ReadCloser, error) {
				calls++
				if calls == 2 {
					if !bytes.Equal(keys.borrowed, make([]byte, 32)) {
						t.Fatal("Wrap input still live during second source callback")
					}
					// A retained adapter reference cannot change the private AES key.
					for n := range keys.borrowed {
						keys.borrowed[n] = 99
					}
				}
				return io.NopCloser(bytes.NewReader(plain)), nil
			}
			var dst bytes.Buffer
			p, err := Prepare(context.Background(), i, key, src, testRedactor{}, keys, &dst)
			if !bytes.Equal(keys.borrowed, make([]byte, 32)) {
				t.Fatal("borrowed DEK not erased on return")
			}
			if fail {
				if err != ErrKey || dst.Len() != 0 || len(p.Manifest().Chunks) != 0 {
					t.Fatal("Wrap failure reached staging", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			ref := Ref{strings.Repeat("a", 64), "v1", "evidence/test", "v1"}
			store := &testStore{present: true, data: dst.Bytes(), info: ObjectInfo{Version: "v1"}}
			got, err := OpenRange(context.Background(), p.Manifest(), ref, store, keys, 0, i.ContentSize-1)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatal("retained Wrap input changed encrypted body", err)
			}
			wipe(got)
		})
	}
}

func TestPrepareRejectsNilAdaptersBeforeCallbacks(t *testing.T) {
	for _, name := range []string{"context", "source", "redactor", "keys", "writer"} {
		t.Run(name, func(t *testing.T) {
			i, key, plain, keys := prepareBoundaryFixture()
			ctx := context.Background()
			calls := 0
			src := Source(func() (io.ReadCloser, error) { calls++; return io.NopCloser(bytes.NewReader(plain)), nil })
			var redactor Redactor = testRedactor{}
			var kms Keys = keys
			var dst io.Writer = io.Discard
			switch name {
			case "context":
				ctx = nil
			case "source":
				src = nil
			case "redactor":
				var absent *testRedactor
				redactor = absent
			case "keys":
				var absent *testKeys
				kms = absent
			case "writer":
				var absent *bytes.Buffer
				dst = absent
			}
			if p, err := Prepare(ctx, i, key, src, redactor, kms, dst); err != ErrInvalid || len(p.Manifest().Chunks) != 0 || calls != 0 {
				t.Fatal("invalid adapter reached preparation", err, calls)
			}
		})
	}
}

func TestPrepareClosesReadersReturnedWithErrors(t *testing.T) {
	for _, failurePass := range []int{1, 2} {
		for _, kind := range []string{"nil", "typed-nil", "reader-with-error"} {
			t.Run(string(rune('0'+failurePass))+"/"+kind, func(t *testing.T) {
				i, key, plain, keys := prepareBoundaryFixture()
				calls := 0
				var readers []*prepareBoundaryReader
				src := func() (io.ReadCloser, error) {
					calls++
					if calls == failurePass && kind == "nil" {
						return nil, nil
					}
					if calls == failurePass && kind == "typed-nil" {
						var absent *prepareBoundaryReader
						return absent, nil
					}
					r := &prepareBoundaryReader{Reader: bytes.NewReader(plain)}
					readers = append(readers, r)
					if calls == failurePass {
						return r, errors.New("private staging source error")
					}
					return r, nil
				}
				if p, err := Prepare(context.Background(), i, key, src, testRedactor{}, keys, io.Discard); err != ErrUnavailable || len(p.Manifest().Chunks) != 0 {
					t.Fatal("broken source produced evidence", err)
				}
				for _, r := range readers {
					if r.closes != 1 {
						t.Fatal("source returned with error was leaked", r.closes)
					}
				}
			})
		}
	}
}

func TestSystemCapabilityRejectsInvalidPreparationBeforeAuthority(t *testing.T) {
	for _, name := range []string{"nil-context", "canceled", "nil-writer"} {
		t.Run(name, func(t *testing.T) {
			i, body, authority, keys := smallSystemFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var dst io.Writer = io.Discard
			switch name {
			case "nil-context":
				ctx = nil
			case "canceled":
				cancel()
			case "nil-writer":
				var absent *bytes.Buffer
				dst = absent
			}
			if p, err := PrepareSystemCapability(ctx, i, KeyRef{strings.Repeat("b", 64), "v1"}, source(body), authority, keys, dst); err != ErrInvalid || len(p.Manifest().Chunks) != 0 || authority.calls != 0 {
				t.Fatal("invalid preparation reached authority", err, authority.calls)
			}
		})
	}
}

func TestTaskAndSystemPreparersRejectInvalidInputs(t *testing.T) {
	for _, kind := range []string{"task", "system"} {
		for _, name := range []string{"nil-context", "canceled", "nil-writer"} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				var i Identity
				var body []byte
				var parent context.Context
				var prepare func(context.Context, Identity, Source, io.Writer) (Prepared, error)
				var sideEffects func() bool
				if kind == "task" {
					x := newTaskPrepareFixture(t)
					i, body, parent, prepare = x.f.identity, x.f.body, x.f.ctx, x.p.Prepare
					sideEffects = func() bool { return x.db.begins != 0 || x.logins.Load() != 0 || x.encrypts.Load() != 0 }
				} else {
					x := newSystemTransitFixture(t, "")
					i, body, parent, prepare = x.i, x.body, context.Background(), x.p.Prepare
					sideEffects = func() bool { return x.checks.Load() != 0 || x.logins.Load() != 0 || x.encrypts.Load() != 0 }
				}
				ctx, cancel := context.WithCancel(parent)
				defer cancel()
				var dst io.Writer = io.Discard
				switch name {
				case "nil-context":
					ctx = nil
				case "canceled":
					cancel()
				case "nil-writer":
					var absent *bytes.Buffer
					dst = absent
				}
				calls := 0
				src := func() (io.ReadCloser, error) { calls++; return io.NopCloser(bytes.NewReader(body)), nil }
				if p, err := prepare(ctx, i, src, dst); err != ErrDenied || len(p.Manifest().Chunks) != 0 || calls != 0 || sideEffects() {
					t.Fatal("invalid preparer input reached authority, JWT, Wrap or source", err, calls)
				}
			})
		}
	}
}
