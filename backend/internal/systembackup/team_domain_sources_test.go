package systembackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
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

func TestScopedTeamRedisRestoresOnlyInertHistoryWithIndependentReadback(t *testing.T) {
	source := redisFixture(t, "TEST_SYSTEM_BACKUP_REDIS_PORT")
	target := redisFixture(t, "TEST_SYSTEM_BACKUP_REDIS_TARGET_PORT")
	ctx := context.Background()
	scopeID, _, err := source.Identity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("claw:team:20:events")
	if _, err := source.command(ctx, []byte("SET"), key, []byte("中断前\x00\xff")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { source.command(ctx, []byte("DEL"), key) })
	run, _ := RandomID("sdr_")
	historyKey := []byte("cm:restore-history:" + run + ":" + hex.EncodeToString(key))
	t.Cleanup(func() { target.command(ctx, []byte("DEL"), historyKey) })
	var archive bytes.Buffer
	budget := RedisBudget{MaxItems: 20, MaxBytes: 1 << 20, MaxInventoryBytes: 1 << 20}
	if err := CaptureTeamRedisScope(ctx, source, &archive, budget, team.RedisScope{ID: "team_redis", ServerID: scopeID, Database: source.database, TeamIDs: []int{20}}, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := RestoreRedisHistory(ctx, source, bytes.NewReader(archive.Bytes()), budget, run); err == nil {
		t.Fatal("source server accepted as isolation target")
	}
	if err := RestoreRedisHistory(ctx, target, bytes.NewReader(archive.Bytes()), budget, run); err != nil {
		t.Fatal(err)
	}
	if n, err := target.command(ctx, []byte("EXISTS"), key); err != nil || n != int64(0) {
		t.Fatal("live Team stream was re-created", n, err)
	}
	user, _ := RandomID("verify_")
	password := base64.RawURLEncoding.EncodeToString([]byte(user)) // disposable fixture, not a credential example
	if _, err := target.command(ctx, []byte("ACL"), []byte("SETUSER"), []byte(user), []byte("on"), []byte(">"+password), []byte("~cm:restore-history:"+run+":*"), []byte("+select"), []byte("+eval_ro"), []byte("+dump"), []byte("+type"), []byte("+pttl"), []byte("+dbsize")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { target.command(ctx, []byte("ACL"), []byte("DELUSER"), []byte(user)) })
	reader, err := ConnectRedis(ctx, RedisOptions{Address: target.conn.RemoteAddr().String(), Username: user, Password: password, Database: target.database, MaxReplyBytes: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := reader.command(ctx, []byte("SET"), historyKey, []byte("wrong")); err == nil {
		t.Fatal("verifier identity can write")
	}
	if count, err := VerifyRedisHistory(ctx, reader, bytes.NewReader(archive.Bytes()), budget, run); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	if _, err := target.command(ctx, []byte("SET"), historyKey, []byte("corrupt")); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRedisHistory(ctx, reader, bytes.NewReader(archive.Bytes()), budget, run); err == nil {
		t.Fatal("corrupt Team history accepted")
	}
}

func TestPinnedTeamObjectRestoresIntoOwnedBucketAndVerifiesBytes(t *testing.T) {
	store := testObjectStore(t)
	ctx := context.Background()
	body := []byte("Team产物\x00\xff")
	upload, err := store.Client.PutObject(ctx, store.Bucket, "results/report.bin", bytes.NewReader(body), int64(len(body)), minio.PutObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	ref := team.ObjectRef{TeamID: 20, Bucket: store.Bucket, Key: "results/report.bin", Version: upload.VersionID, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body))}
	var archive bytes.Buffer
	budget := ObjectBudget{MaxItems: 10, MaxBytes: 1 << 20}
	if err := CaptureTeamObjectRefs(ctx, store.Client, &archive, budget, []team.ObjectRef{ref}, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	target, _ := RandomID("cm-restore-")
	if err := store.Client.MakeBucket(ctx, target, minio.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for item := range store.Client.ListObjects(ctx, target, minio.ListObjectsOptions{Recursive: true, WithVersions: true}) {
			if item.Err == nil {
				if err := store.Client.RemoveObject(ctx, target, item.Key, minio.RemoveObjectOptions{VersionID: item.VersionID}); err != nil {
					t.Error(err)
				}
			} else {
				t.Error(item.Err)
			}
		}
		if err := store.Client.RemoveBucket(ctx, target); err != nil {
			t.Error(err)
		}
	})
	mapping := map[string]string{store.Bucket: target}
	if err := RestoreObjects(ctx, store.Client, bytes.NewReader(archive.Bytes()), budget, mapping); err != nil {
		t.Fatal(err)
	}
	if count, err := VerifyObjects(ctx, store.Client, bytes.NewReader(archive.Bytes()), budget, mapping); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	if _, err := store.Client.PutObject(ctx, target, ref.Key, strings.NewReader("corrupt"), 7, minio.PutObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyObjects(ctx, store.Client, bytes.NewReader(archive.Bytes()), budget, mapping); err == nil {
		t.Fatal("corrupt Team object accepted")
	}
	original, err := store.Client.GetObject(ctx, store.Bucket, ref.Key, minio.GetObjectOptions{VersionID: ref.Version})
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	got, err := io.ReadAll(original)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatal("source artifact changed", err)
	}
}
