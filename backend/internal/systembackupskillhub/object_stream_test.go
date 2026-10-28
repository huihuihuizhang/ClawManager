package systembackupskillhub

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
)

type objectReaderFunc func(context.Context, string, string) (ObjectVersion, error)

func (f objectReaderFunc) OpenVersion(ctx context.Context, key, version string) (ObjectVersion, error) {
	return f(ctx, key, version)
}

type closeProbe struct {
	io.Reader
	closed bool
	err    error
}

func (p *closeProbe) Close() error { p.closed = true; return p.err }
func hashText(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func TestCopyFrozenObjectUsesExactVersionAndContentSHA256(t *testing.T) {
	body := &closeProbe{Reader: strings.NewReader("hello")}
	source := objectReaderFunc(func(_ context.Context, key, version string) (ObjectVersion, error) {
		if key != "private/source.zip" || version != "immutable-v7" {
			t.Fatal("lost exact version selector")
		}
		return ObjectVersion{Body: body, VersionID: "immutable-v7", Size: 5}, nil
	})
	var dst bytes.Buffer
	got, err := CopyFrozenObject(context.Background(), source, &dst, FrozenObject{Key: "private/source.zip", VersionID: "immutable-v7", Size: 5}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if dst.String() != "hello" || got.Size != 5 || got.SHA256 != hashText("hello") || !body.closed {
		t.Fatalf("incorrect transfer metadata: %#v", got)
	}
}

func TestCopyFrozenObjectFailureMatrix(t *testing.T) {
	for _, name := range []string{"wrong_version", "wrong_stat_size", "short_body", "long_body", "digest", "read_error", "write_error", "close_error", "open_error", "nil_body"} {
		t.Run(name, func(t *testing.T) {
			entry := FrozenObject{Key: "private.zip", VersionID: "v1", Size: 5, SHA256: hashText("hello")}
			body := &closeProbe{Reader: strings.NewReader("hello")}
			observed := ObjectVersion{Body: body, VersionID: "v1", Size: 5}
			var dst io.Writer = &bytes.Buffer{}
			privateError := errors.New("SECRET signed URL or workspace")
			switch name {
			case "wrong_version":
				observed.VersionID = "v2"
			case "wrong_stat_size":
				observed.Size = 6
			case "short_body":
				body.Reader = strings.NewReader("hell")
			case "long_body":
				body.Reader = strings.NewReader("hello!")
			case "digest":
				entry.SHA256 = hashText("other")
			case "read_error":
				body.Reader = readerFailure{err: privateError}
			case "write_error":
				dst = writerFailure{err: privateError}
			case "close_error":
				body.err = privateError
			case "nil_body":
				observed.Body = nil
			}
			source := objectReaderFunc(func(context.Context, string, string) (ObjectVersion, error) {
				if name == "open_error" {
					return observed, privateError
				}
				return observed, nil
			})
			got, err := CopyFrozenObject(context.Background(), source, dst, entry, 10)
			if err == nil || got != (ObjectDigest{}) {
				t.Fatalf("accepted invalid object: %#v %v", got, err)
			}
			if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "private") {
				t.Fatalf("unredacted error: %v", err)
			}
			if name != "nil_body" && !body.closed {
				t.Fatal("leaked reader")
			}
		})
	}
}

type readerFailure struct{ err error }

func (r readerFailure) Read([]byte) (int, error) { return 0, r.err }

type writerFailure struct{ err error }

func (w writerFailure) Write([]byte) (int, error) { return 0, w.err }

func TestCopyFrozenObjectRejectsInvalidPlanBeforeIO(t *testing.T) {
	for _, name := range []string{"negative_size", "over_capacity", "overflow_size", "no_version", "null_version", "no_key", "uppercase_digest", "md5_digest"} {
		t.Run(name, func(t *testing.T) {
			entry := FrozenObject{Key: "key", VersionID: "v1", Size: 5}
			switch name {
			case "negative_size":
				entry.Size = -1
			case "over_capacity":
				entry.Size = 11
			case "overflow_size":
				entry.Size = math.MaxInt64
			case "no_version":
				entry.VersionID = ""
			case "null_version":
				entry.VersionID = "null"
			case "no_key":
				entry.Key = ""
			case "uppercase_digest":
				entry.SHA256 = strings.Repeat("A", 64)
			case "md5_digest":
				entry.SHA256 = strings.Repeat("a", 32)
			}
			source := objectReaderFunc(func(context.Context, string, string) (ObjectVersion, error) {
				t.Fatal("invalid plan reached provider")
				return ObjectVersion{}, nil
			})
			if _, err := CopyFrozenObject(context.Background(), source, io.Discard, entry, 10); err == nil {
				t.Fatal("accepted invalid plan")
			}
		})
	}
}

func TestObjectEntryPointsRejectUnsafeKeysBeforeIO(t *testing.T) {
	for _, key := range []string{"", " ", "\t", "../escape", "/absolute", "nested/../escape", "a\\b", "C:/drive", "a//b", "a/", "a\x00b", string([]byte{0xff})} {
		t.Run(key, func(t *testing.T) {
			entry := FrozenObject{Key: key, VersionID: "v1", SHA256: hashText("")}
			reader := objectReaderFunc(func(context.Context, string, string) (ObjectVersion, error) {
				t.Error("invalid logical key reached storage adapter")
				return ObjectVersion{Body: io.NopCloser(strings.NewReader("")), VersionID: "v1"}, nil
			})
			if got, err := CopyFrozenObject(context.Background(), reader, io.Discard, entry, 0); !errors.Is(err, ErrObject) || got != (ObjectDigest{}) {
				t.Errorf("copy accepted invalid key: digest=%v error=%v", got, err)
			}
			if err := VerifyFrozenObject(context.Background(), reader, entry, 0); !errors.Is(err, ErrObject) {
				t.Errorf("verifier accepted invalid key: %v", err)
			}
			if _, err := PrepareObjectCapture(context.Background(), nil, []FrozenObject{entry}, ObjectCaptureLimits{MaxObjects: 1, MaxIndexBytes: 1 << 20}); !errors.Is(err, ErrObject) {
				t.Errorf("inventory accepted invalid key: %v", err)
			}
		})
	}
}

type cancelOnRead struct {
	cancel context.CancelFunc
	io.Reader
}

func (r cancelOnRead) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.cancel()
	return n, err
}
func TestCopyFrozenObjectCancellationClosesWithoutLaterWrites(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body := &closeProbe{Reader: cancelOnRead{cancel: cancel, Reader: strings.NewReader("hello")}}
	source := objectReaderFunc(func(context.Context, string, string) (ObjectVersion, error) {
		return ObjectVersion{Body: body, VersionID: "v1", Size: 5}, nil
	})
	var dst bytes.Buffer
	got, err := CopyFrozenObject(ctx, source, &dst, FrozenObject{Key: "key", VersionID: "v1", Size: 5}, 10)
	if !errors.Is(err, context.Canceled) || got != (ObjectDigest{}) || dst.Len() != 0 || !body.closed {
		t.Fatalf("cancel: digest=%v err=%v writes=%d closed=%v", got, err, dst.Len(), body.closed)
	}
}
func TestVerifyFrozenObjectRequiresAuthenticatedDigest(t *testing.T) {
	calls := 0
	source := objectReaderFunc(func(context.Context, string, string) (ObjectVersion, error) {
		calls++
		return ObjectVersion{Body: io.NopCloser(strings.NewReader("hello")), VersionID: "target-v2", Size: 5}, nil
	})
	entry := FrozenObject{Key: "target/key", VersionID: "target-v2", Size: 5}
	if err := VerifyFrozenObject(context.Background(), source, entry, 10); err == nil || calls != 0 {
		t.Fatal("verifier accepted missing digest")
	}
	entry.SHA256 = hashText("hello")
	if err := VerifyFrozenObject(context.Background(), source, entry, 10); err != nil {
		t.Fatal(err)
	}
	entry.SHA256 = hashText("wrong")
	if err := VerifyFrozenObject(context.Background(), source, entry, 10); !errors.Is(err, ErrObject) {
		t.Fatal("verifier accepted corrupt bytes")
	}
}

type boundedZeroReader struct {
	remaining  int64
	maxRequest int
}

func (r *boundedZeroReader) Read(p []byte) (int, error) {
	if len(p) > r.maxRequest {
		r.maxRequest = len(p)
	}
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}
	clear(p[:n])
	r.remaining -= int64(n)
	return n, nil
}
func TestCopyFrozenObjectBoundedBufferAndZeroByteObject(t *testing.T) {
	for _, size := range []int64{0, 32 << 20} {
		reader := &boundedZeroReader{remaining: size}
		source := objectReaderFunc(func(context.Context, string, string) (ObjectVersion, error) {
			return ObjectVersion{Body: io.NopCloser(reader), VersionID: "version", Size: size}, nil
		})
		got, err := CopyFrozenObject(context.Background(), source, io.Discard, FrozenObject{Key: "key", VersionID: "version", Size: size}, size)
		if err != nil || got.Size != size || !validSHA256(got.SHA256) {
			t.Fatalf("transfer=%v %v", got, err)
		}
		if reader.maxRequest > 64*1024 {
			t.Fatalf("unbounded read request: %d", reader.maxRequest)
		}
		if size == 0 && got.SHA256 != hashText("") {
			t.Fatal("wrong empty-object digest")
		}
	}
}
