package worker

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	c "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/recovery"
	"clawreef/internal/systembackup/testfixture"
	w "clawreef/internal/systembackupwire"
)

type sourceRedisFixtureUnwrapper struct{}

func (sourceRedisFixtureUnwrapper) Unwrap(ctx context.Context, expected w.KeyRequest, wrapped w.WrappedKey, consume w.WithDEK) error {
	if ctx.Err() != nil || expected != wrapped.Request || string(wrapped.Ciphertext) != "opaque-provider-ciphertext" {
		return ErrNotReady
	}
	key := bytes.Repeat([]byte{9}, 32)
	defer clear(key)
	return consume(key)
}

func TestFormalSourceRedisActualCollectorFramingAndIndependentReadback(t *testing.T) {
	for _, mode := range []string{"empty", "nonempty", "revoke-at-source", "unknown-end", "missing-source-authority", "cursor-cycle"} {
		t.Run(mode, func(t *testing.T) {
			i, env, key := formalInvocationFixture(t)
			i.Request.Operation = "capture-source-redis"
			i.Request.Binding.Path = "source_redis"
			i.ProviderKey.Request.Context.Part = "source_redis"
			i.Request.ArtifactName = "source-redis.enc"
			i.FormalCapture.EnvelopeName = "source-redis.envelope.json"
			i.FormalCapture.SourceConfigSHA256 = strings.Repeat("c", 64)
			i.Request.MaxFiles, i.Request.MaxFileBytes = 0, 0
			i.Request.MaxArchiveBytes, i.Request.MaxCompressedBytes = 1<<20, 1<<20
			i.WorkspacePath = ""
			i.Request.SourceRedis = &c.RedisCapturePolicy{Policy: recovery.RedisPolicy{Source: recovery.Reference{ID: "original_redis", Version: "source-v1", SHA256: strings.Repeat("b", 64)}, Topology: "shared_keyspace", CaptureMode: "scan_dump", TTLPolicy: "preserve_absolute", Purpose: "acceptance", DB: 2, Prefixes: []string{"app:"}, MaxItems: 100, MaxBytes: 1 << 20, MaxClockSkew: 3000}, ServerID: strings.Repeat("a", 40), ExcludePrefixes: []string{"app:control:"}}
			key.request = i.ProviderKey.Request
			var revoked atomic.Bool
			scenario := testfixture.RedisScenario{TLS: true, ServerID: i.Request.SourceRedis.ServerID, PageSize: 1}
			if mode != "empty" {
				scenario.Keys = []testfixture.RedisKey{{Key: "app:events", Type: "stream", Dump: []byte("named-dump-with-original-groups-and-pel"), PTTL: 5000, Groups: []any{[]any{[]byte("name"), []byte("original-workers"), []byte("consumers"), int64(1), []byte("pending"), int64(1), []byte("last-delivered-id"), []byte("1-0")}}}, {Key: "app:state", Type: "string", Dump: []byte("private-original-redis-value"), PTTL: -1}}
			}
			if mode == "revoke-at-source" {
				scenario.BeforeCommand = func(op string) {
					if op == "EVAL_RO" {
						revoked.Store(true)
					}
				}
			}
			if mode == "cursor-cycle" {
				scenario.RepeatCursor = true
			}
			fixture := testfixture.NewRedisProtocol(t, scenario)
			roots := x509.NewCertPool()
			roots.AppendCertsFromPEM(fixture.CAPEM)
			client, err := c.ConnectRedis(context.Background(), c.RedisOptions{Address: fixture.Address, Username: "original-reader", Password: "named-fixture-password", Database: 2, TLS: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "127.0.0.1"}, MaxReplyBytes: 4 << 20})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			env.Workspace = nil
			env.SourceRedis = client
			env.SourceValidUntil = time.Now().Add(time.Minute)
			checks := 0
			env.SourceAuthorize = func(context.Context, Invocation) error {
				checks++
				if revoked.Load() {
					return ErrNotReady
				}
				return nil
			}
			if mode == "missing-source-authority" {
				env.SourceAuthorize = nil
			}
			if mode == "unknown-end" {
				key.endError = true
			}
			if !ValidateRecordedInvocation(i) {
				t.Fatal("source Redis frozen invocation is invalid")
			}
			result, err := runFormalCapture(context.Background(), i, key, env)
			valid := mode == "empty" || mode == "nonempty"
			if !valid {
				if err == nil || !reflect.DeepEqual(result, FormalCaptureResult{}) {
					t.Fatal("failed source produced candidate receipt", mode, err)
				}
				directory, openErr := env.Staging.Open(".")
				if openErr != nil {
					t.Fatal(openErr)
				}
				entries, readErr := directory.ReadDir(-1)
				directory.Close()
				if readErr != nil {
					t.Fatal(readErr)
				}
				for _, entry := range entries {
					if mode != "unknown-end" || entry.Name() != i.Request.ArtifactName {
						t.Fatal("failed source retained a candidate/partial file", entry.Name())
					}
				}
				return
			}
			if err != nil || key.calls != 1 || checks < 5 || !ValidateFormalCaptureResult(i, &result) {
				t.Fatal("actual formal source capture failed", err)
			}
			frames, _ := env.Staging.ReadFile(result.Ciphertext.Name)
			envelope, _ := env.Staging.ReadFile(result.Envelope.Name)
			if !bytes.HasPrefix(frames, []byte("CMBKGC01")) || bytes.Contains(frames, []byte("private-original-redis-value")) {
				t.Fatal("source payload was not original C encryption")
			}
			items := -1
			_, err = w.InspectWrappedStream(context.Background(), w.StreamSpec{Request: i.ProviderKey.Request, Path: i.Request.ArtifactName, MaxPlaintextBytes: i.Request.MaxCompressedBytes, MaxFrames: i.FormalCapture.MaxFrames}, envelope, bytes.NewReader(frames), sourceRedisFixtureUnwrapper{}, func(compressed io.Reader) error {
				z, err := gzip.NewReader(compressed)
				if err != nil {
					return err
				}
				defer z.Close()
				snapshot, err := c.ReadSourceRedisSnapshot(context.Background(), z, *i.Request.SourceRedis)
				if err != nil {
					return err
				}
				defer c.ClearSourceRedisSnapshot(snapshot)
				items = len(snapshot.Items)
				if mode == "nonempty" && (snapshot.Items[0].PTTL != 5000 || len(snapshot.Items[0].StreamGroups) == 0 || snapshot.Items[0].ExpiresAt != snapshot.Items[0].CapturedAt+5000) {
					t.Error("original TTL/groups missing")
				}
				return z.Close()
			})
			expected := 0
			if mode == "nonempty" {
				expected = 2
			}
			if err != nil || items != expected {
				t.Fatal("independent source content readback failed", err, items)
			}
		})
	}
}
