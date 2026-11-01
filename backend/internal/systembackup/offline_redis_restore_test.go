package systembackup

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"clawreef/internal/systembackup/testfixture"
)

// Real TCP/RESP + existing source capture/history codec/restorer/verifier.
// The target is a named protocol fixture, not a real Redis DUMP engine.
func TestOfflineNonemptyRedisCaptureToIsolatedHistoryTarget(t *testing.T) {
	for _, mode := range []string{"success", "cancel", "partial-failure"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			policy := redisSourcePolicyFixture()
			keys := []testfixture.RedisKey{{Key: "app:events", Type: "stream", Dump: []byte("named-stream-dump-with-pending-consumer-history"), PTTL: 5000}, {Key: "app:state", Type: "string", Dump: []byte{0, 255, 10}, PTTL: -1}}
			sourceFixture := testfixture.NewRedisProtocol(t, testfixture.RedisScenario{ServerID: policy.ServerID, Keys: keys, ExpectedUser: "source-reader", ExpectedPassword: "named-fixture-password"})
			source, err := ConnectRedis(ctx, RedisOptions{Address: sourceFixture.Address, Username: "source-reader", Password: "named-fixture-password", Database: 2, MaxReplyBytes: 1 << 20})
			if err != nil {
				t.Fatal(err)
			}
			var captured, history bytes.Buffer
			if err = CaptureSourceRedis(ctx, source, &captured, policy, func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
			source.Close()
			if err = AdaptSourceRedisHistory(ctx, bytes.NewReader(captured.Bytes()), &history, policy); err != nil {
				t.Fatal(err)
			}
			target := testfixture.NewRedisHistoryTarget(t, keys)
			if mode == "partial-failure" {
				target.SetFailAfter(1)
			}
			connect := func(user string) (*RedisClient, error) {
				return ConnectRedis(ctx, RedisOptions{Address: target.Address, Username: user, Password: "named-fixture-password", Database: 2, MaxReplyBytes: 1 << 20})
			}
			writer, err := connect("writer")
			if err != nil {
				t.Fatal(err)
			}
			run := "sdr_" + strings.Repeat("a", 32)
			budget := RedisBudget{MaxItems: 100, MaxBytes: 1 << 20, MaxInventoryBytes: 1 << 20}
			work, cancel := context.WithCancel(ctx)
			if mode == "cancel" {
				cancel()
			}
			err = RestoreRedisHistory(work, writer, bytes.NewReader(history.Bytes()), budget, run)
			cancel()
			if mode == "partial-failure" {
				before := target.Keys()
				attempts := target.RestoreAttempts()
				if err == nil || len(before) != 1 || attempts != 2 {
					t.Fatal("injected failure did not leave exactly one written key", err, len(before), attempts)
				}
				// Keep the original authenticated writer usable and remove the
				// injected failure. Only the nonempty-target guard may reject this
				// retry, before even an attempted RESTORE (including duplicate keys).
				target.SetFailAfter(0)
				if _, e := writer.command(ctx, []byte("INFO"), []byte("server")); e != nil {
					t.Fatal("writer no longer authenticated before retry", e)
				}
				retryErr := RestoreRedisHistory(ctx, writer, bytes.NewReader(history.Bytes()), budget, run)
				if retryErr == nil || retryErr.Error() != "Redis restore target must be empty" || target.RestoreAttempts() != attempts || !reflect.DeepEqual(before, target.Keys()) {
					t.Fatal("retry did not stop at nonempty guard before writes", retryErr)
				}
			}
			writer.Close()
			target.RevokeWriter()
			if probe, e := connect("writer"); e == nil {
				probe.Close()
				t.Fatal("revoked writer authenticated")
			}
			reader, e := connect("reader")
			if e != nil {
				t.Fatal(e)
			}
			defer reader.Close()
			if _, e = reader.command(ctx, []byte("RESTORE"), []byte("forbidden"), []byte("0"), []byte("x")); e == nil {
				t.Fatal("reader wrote")
			}
			count := len(target.Keys())
			if mode == "success" {
				if err != nil || count != 2 {
					t.Fatal("history restore", err, count)
				}
				if n, e := VerifyRedisHistory(ctx, reader, bytes.NewReader(history.Bytes()), budget, run); e != nil || n != 2 {
					t.Fatal("readback", n, e)
				}
			} else if err == nil || (mode == "cancel" && count != 0) || (mode == "partial-failure" && count != 1) {
				t.Fatal("failure isolation", err, count)
			}
			for _, k := range target.Keys() {
				if !strings.HasPrefix(k.Key, "cm:restore-history:"+run+":") || k.PTTL != -1 {
					t.Fatal("active queue replay or TTL loss")
				}
			}
			for _, op := range sourceFixture.Commands() {
				if op == "RESTORE" || op == "DEL" || op == "SET" {
					t.Fatal("source mutated")
				}
			}
			if mode == "partial-failure" {
				if _, e = VerifyRedisHistory(ctx, reader, bytes.NewReader(history.Bytes()), budget, run); e == nil {
					t.Fatal("independent verifier accepted incomplete target")
				}
			}
		})
	}
}
