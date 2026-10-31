package systembackup

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/systembackup/recovery"
	"clawreef/internal/systembackup/testfixture"
)

func redisSourcePolicyFixture() RedisCapturePolicy {
	return RedisCapturePolicy{Policy: recovery.RedisPolicy{Source: recovery.Reference{ID: "original_redis", Version: "source-v1", SHA256: strings.Repeat("b", 64)}, Topology: "shared_keyspace", CaptureMode: "scan_dump", TTLPolicy: "preserve_absolute", Purpose: "acceptance", DB: 2, Prefixes: []string{"app:"}, MaxItems: 100, MaxBytes: 1 << 20, MaxClockSkew: 3000}, ServerID: strings.Repeat("a", 40), ExcludePrefixes: []string{"app:control:"}}
}

func TestSourceRedisFiniteActualProtocolCaptureAndIndependentReadback(t *testing.T) {
	for _, mode := range []string{"empty", "nonempty", "stream-groups", "cross-page", "excluded-control", "cursor-cycle", "wrong-server", "wrong-database", "revoked-at-script", "clock-skew", "empty-clock-ahead", "empty-clock-behind", "all-excluded-clock-ahead", "all-excluded-clock-behind", "capacity"} {
		t.Run(mode, func(t *testing.T) {
			policy := redisSourcePolicyFixture()
			keys := []testfixture.RedisKey{{Key: "app:state", Type: "string", Dump: []byte{0, 255, 1, 2}, PTTL: -1}}
			scenario := testfixture.RedisScenario{TLS: true, ServerID: policy.ServerID, PageSize: 1}
			var revoked atomic.Bool
			switch mode {
			case "empty":
				keys = nil
			case "stream-groups":
				keys = []testfixture.RedisKey{{Key: "app:events", Type: "stream", Dump: []byte("named-stream-dump-including-group-pel"), PTTL: 5000, Groups: []any{[]any{[]byte("name"), []byte("workers"), []byte("consumers"), int64(1), []byte("pending"), int64(2), []byte("last-delivered-id"), []byte("1-0")}}}}
			case "cross-page":
				keys = append(keys, testfixture.RedisKey{Key: "app:session", Type: "hash", Dump: []byte("binary-hash"), PTTL: 7000}, testfixture.RedisKey{Key: "app:task", Type: "list", Dump: []byte("retained-task"), PTTL: -1})
			case "excluded-control":
				keys = append(keys, testfixture.RedisKey{Key: "app:control:lease", Type: "string", Dump: []byte("must-not-archive"), PTTL: -1})
			case "cursor-cycle":
				scenario.RepeatCursor = true
			case "wrong-server":
				scenario.ServerID = strings.Repeat("c", 40)
			case "wrong-database":
				policy.Policy.DB = 3
			case "revoked-at-script":
				scenario.BeforeCommand = func(op string) {
					if op == "EVAL_RO" {
						revoked.Store(true)
					}
				}
			case "clock-skew":
				scenario.ClockOffset = time.Minute
			case "empty-clock-ahead", "empty-clock-behind":
				keys = nil
				scenario.ClockOffset = time.Minute
				if strings.HasSuffix(mode, "behind") {
					scenario.ClockOffset = -time.Minute
				}
			case "all-excluded-clock-ahead", "all-excluded-clock-behind":
				keys = []testfixture.RedisKey{{Key: "app:control:lease", Type: "string", Dump: []byte("control"), PTTL: -1}}
				scenario.ClockOffset = time.Minute
				if strings.HasSuffix(mode, "behind") {
					scenario.ClockOffset = -time.Minute
				}
			case "capacity":
				policy.Policy.MaxBytes = 8
			}
			scenario.Keys = keys
			fixture := testfixture.NewRedisProtocol(t, scenario)
			roots := x509.NewCertPool()
			roots.AppendCertsFromPEM(fixture.CAPEM)
			client, err := ConnectRedis(context.Background(), RedisOptions{Address: fixture.Address, Username: "original-reader", Password: "named-fixture-password", Database: 2, TLS: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "127.0.0.1"}, MaxReplyBytes: 4 << 20})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			var data bytes.Buffer
			err = CaptureSourceRedis(context.Background(), client, &data, policy, func(context.Context) error {
				if revoked.Load() {
					return errors.New("revoked")
				}
				return nil
			})
			valid := mode == "empty" || mode == "nonempty" || mode == "stream-groups" || mode == "cross-page" || mode == "excluded-control"
			if !valid {
				if err == nil {
					t.Fatal("invalid original Redis source accepted", mode)
				}
				if strings.Contains(mode, "clock") && data.Len() != 0 {
					t.Fatal("out-of-bound original clock wrote a source header")
				}
				return
			}
			if err != nil {
				t.Fatal("real TCP/TLS source capture", err)
			}
			snapshot, err := ReadSourceRedisSnapshot(context.Background(), bytes.NewReader(data.Bytes()), policy)
			if err != nil {
				t.Fatal("independent source readback", err)
			}
			defer ClearSourceRedisSnapshot(snapshot)
			expected := len(keys)
			if mode == "excluded-control" {
				expected--
			}
			if len(snapshot.Items) != expected || snapshot.Header.Database != 2 || snapshot.Header.ServerID != policy.ServerID || snapshot.Header.Source != policy.Policy.Source {
				t.Fatal("lost original source scope")
			}
			if mode == "stream-groups" {
				item := snapshot.Items[0]
				if item.Type != "stream" || len(item.StreamGroups) == 0 || item.PTTL != 5000 || item.ExpiresAt != item.CapturedAt+5000 {
					t.Fatal("lost stream/absolute TTL/group metadata")
				}
			}
			if mode == "excluded-control" && bytes.Contains(data.Bytes(), []byte("must-not-archive")) {
				t.Fatal("control lease captured")
			}
			commands := fixture.Commands()
			scans, scripts := 0, 0
			for _, op := range commands {
				if op == "SCAN" {
					scans++
				}
				if op == "EVAL_RO" {
					scripts++
				}
				if op == "RESTORE" || op == "DEL" || op == "SET" {
					t.Fatal("capture mutated Redis")
				}
			}
			if scripts != 1 || scans < 1 || mode == "cross-page" && scans < 3 {
				t.Fatal("not one bounded atomic snapshot", scans, scripts)
			}
			var legacy bytes.Buffer
			if AdaptSourceRedisHistory(context.Background(), bytes.NewReader(data.Bytes()), &legacy, policy) != nil {
				t.Fatal("inert history adapter")
			}
			count := 0
			if readRedisSnapshot(bytes.NewReader(legacy.Bytes()), RedisBudget{MaxItems: 100, MaxBytes: 1 << 20, MaxInventoryBytes: 1 << 20}, func(RedisRecord) error { return nil }, func(item RedisRecord) error {
				if !reflect.DeepEqual(item.Dump, snapshot.Items[count].Dump) || item.ExpiresAtMillis != snapshot.Items[count].ExpiresAt {
					return errors.New("history mismatch")
				}
				count++
				return nil
			}) != nil || count != expected {
				t.Fatal("existing independent inert history reader disagrees")
			}
			if mode == "nonempty" {
				testSourceRedisMalformedReadback(t, data.Bytes(), policy)
			}
		})
	}
}

func testSourceRedisMalformedReadback(t *testing.T, original []byte, policy RedisCapturePolicy) {
	t.Helper()
	lines := bytes.Split(bytes.TrimSuffix(original, []byte{'\n'}), []byte{'\n'})
	for _, mode := range []string{"missing-end", "trailing-json", "wrong-count", "wrong-end-hash", "changed-dump", "wrong-source", "wrong-prefix", "wrong-database", "duplicate-key", "over-budget"} {
		t.Run("readback-"+mode, func(t *testing.T) {
			input := bytes.Clone(original)
			expected := policy
			switch mode {
			case "missing-end":
				input = bytes.Join(lines[:len(lines)-1], []byte{'\n'})
			case "trailing-json":
				input = append(input, []byte("{}\n")...)
			case "wrong-count", "wrong-end-hash":
				var end redisSourceEnd
				json.Unmarshal(lines[len(lines)-1], &end)
				if mode == "wrong-count" {
					end.Count++
				} else {
					end.SHA256 = strings.Repeat("0", 64)
				}
				raw, _ := json.Marshal(end)
				input = append(bytes.Join(lines[:len(lines)-1], []byte{'\n'}), '\n')
				input = append(input, raw...)
			case "changed-dump":
				var item recovery.RedisItem
				json.Unmarshal(lines[1], &item)
				item.Dump = []byte("replacement")
				raw, _ := json.Marshal(item)
				input = bytes.Join([][]byte{lines[0], raw, lines[2]}, []byte{'\n'})
			case "wrong-source":
				expected.Policy.Source.SHA256 = strings.Repeat("d", 64)
			case "wrong-prefix":
				expected.Policy.Prefixes = []string{"foreign:"}
			case "wrong-database":
				expected.Policy.DB = 4
			case "duplicate-key":
				input = bytes.Join([][]byte{lines[0], lines[1], lines[1], lines[2]}, []byte{'\n'})
			case "over-budget":
				expected.Policy.MaxBytes = 10
			}
			result, err := ReadSourceRedisSnapshot(context.Background(), bytes.NewReader(input), expected)
			if err == nil || !reflect.DeepEqual(result, RedisSourceSnapshot{}) {
				t.Fatal("unverified source rows escaped")
			}
			var sink bytes.Buffer
			if AdaptSourceRedisHistory(context.Background(), bytes.NewReader(input), &sink, expected) == nil || sink.Len() != 0 {
				t.Fatal("unverified source history escaped")
			}
		})
	}
}
