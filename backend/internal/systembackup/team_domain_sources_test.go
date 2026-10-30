package systembackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"clawreef/internal/systembackup/team"
	"github.com/minio/minio-go/v7"
)

func TestTeamsRedisCaptureKeepsOnlyOriginalScopeAndAtomicTTL(t *testing.T) {
	c := redisFixture(t, "TEST_SYSTEM_BACKUP_REDIS_PORT")
	ctx := context.Background()
	for _, args := range [][][]byte{{[]byte("SET"), []byte("claw:team:20:events"), []byte("\x00\xff任务结果")}, {[]byte("SET"), []byte("claw:team:20:completion-state:1"), []byte("partial-result"), []byte("PX"), []byte("604800000")}, {[]byte("SET"), []byte("claw:team:99:events"), []byte("foreign-owner")}} {
		if _, e := c.command(ctx, args...); e != nil {
			t.Fatal(e)
		}
	}
	t.Cleanup(func() {
		c.command(ctx, []byte("DEL"), []byte("claw:team:20:events"), []byte("claw:team:20:completion-state:1"), []byte("claw:team:99:events"))
	})
	server, err := redisServerID(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	scope := team.RedisScope{ID: "redis_a", ServerID: server, Database: c.database, TeamIDs: []int{20}}
	budget := RedisBudget{MaxItems: 100, MaxBytes: 1 << 20, MaxInventoryBytes: 1 << 20}
	allow := func(context.Context) error { return nil }
	var data bytes.Buffer
	if err = CaptureTeamRedisScope(ctx, c, &data, budget, scope, allow); err != nil {
		t.Fatal(err)
	}
	count := 0
	var at int64
	err = readRedisSnapshot(bytes.NewReader(data.Bytes()), budget, func(h RedisRecord) error { at = h.CapturedAtMillis; return nil }, func(r RedisRecord) error {
		count++
		if !strings.HasPrefix(string(r.Key), "claw:team:20:") || (strings.Contains(string(r.Key), "completion-state") && r.ExpiresAtMillis <= at) {
			t.Fatal("foreign or invalid TTL data")
		}
		return nil
	})
	if err != nil || count != 2 || at <= 0 || bytes.Contains(data.Bytes(), []byte("foreign-owner")) {
		t.Fatal("scope/clock lost", err, count, at)
	}
	scope.ServerID = strings.Repeat("f", 40)
	if CaptureTeamRedisScope(ctx, c, io.Discard, budget, scope, allow) == nil {
		t.Fatal("replacement Redis accepted")
	}
	scope.ServerID = server
	scope.Database = (c.database + 1) % 16
	if CaptureTeamRedisScope(ctx, c, io.Discard, budget, scope, allow) == nil {
		t.Fatal("different Redis database accepted")
	}
	scope.Database = c.database
	if CaptureTeamRedisScope(ctx, c, io.Discard, budget, scope, func(context.Context) error { return errors.New("revoked") }) == nil {
		t.Fatal("revoked source grant accepted")
	}
	budget.MaxItems = 1
	if CaptureTeamRedisScope(ctx, c, io.Discard, budget, scope, allow) == nil {
		t.Fatal("partial scope succeeded over budget")
	}
}

func TestTeamsObjectCapturePinsVersionAndDigestWithoutListingBucket(t *testing.T) {
	store := testObjectStore(t)
	ctx := context.Background()
	body := []byte("中断前的产物\x00\xff")
	upload, err := store.Client.PutObject(ctx, store.Bucket, "results/20/report", bytes.NewReader(body), int64(len(body)), minio.PutObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Client.PutObject(ctx, store.Bucket, "results/20/report", strings.NewReader("new-version"), 11, minio.PutObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	ref := team.ObjectRef{TeamID: 20, Bucket: store.Bucket, Key: "results/20/report", Version: upload.VersionID, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body))}
	budget := ObjectBudget{MaxItems: 10, MaxBytes: 1 << 20}
	var data bytes.Buffer
	allow := func(context.Context) error { return nil }
	if err = CaptureTeamObjectRefs(ctx, store.Client, &data, budget, []team.ObjectRef{ref}, allow); err != nil {
		t.Fatal(err)
	}
	var restored bytes.Buffer
	count := 0
	err = ReadObjectSnapshot(ctx, bytes.NewReader(data.Bytes()), budget, func(m ObjectMetadata) (io.WriteCloser, error) {
		count++
		if m.Version != upload.VersionID {
			t.Fatal("latest pointer followed")
		}
		return teamTestWriteCloser{&restored}, nil
	})
	if err != nil || count != 1 || !bytes.Equal(body, restored.Bytes()) {
		t.Fatal("original artifact lost", err)
	}
	ref.SHA256 = strings.Repeat("0", 64)
	if CaptureTeamObjectRefs(ctx, store.Client, io.Discard, budget, []team.ObjectRef{ref}, allow) == nil {
		t.Fatal("wrong content digest accepted")
	}
	ref.Version = "missing-original"
	if CaptureTeamObjectRefs(ctx, store.Client, io.Discard, budget, []team.ObjectRef{ref}, allow) == nil {
		t.Fatal("missing original replaced with latest")
	}
}

type teamTestWriteCloser struct{ io.Writer }

func (teamTestWriteCloser) Close() error { return nil }
