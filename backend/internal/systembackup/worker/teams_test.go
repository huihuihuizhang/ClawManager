package worker

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	c "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/team"
	w "clawreef/internal/systembackupwire"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func TestFormalTeamsCaptureRequiresIndependentSourceGrantAndProviderMode(t *testing.T) {
	port := os.Getenv("TEST_SYSTEM_BACKUP_REDIS_PORT")
	if port == "" {
		t.Skip("requires disposable local Redis")
	}
	teamRedisFixtureCommand(t, port, "SET", "claw:team:4242:events", "formal Team result")
	t.Cleanup(func() { teamRedisFixtureCommand(t, port, "DEL", "claw:team:4242:events") })
	client, err := c.ConnectRedis(context.Background(), c.RedisOptions{Address: "127.0.0.1:" + port, MaxReplyBytes: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, db, err := client.Identity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "missing-source-grant", "revoked-source", "revoked-during-source", "wrong-server", "functional-fallback", "mixed-scope"} {
		t.Run(mode, func(t *testing.T) {
			i, env, key := formalInvocationFixture(t)
			i.WorkspacePath = ""
			env.Workspace = nil
			i.Request.Operation = "capture-team-redis"
			i.Request.MaxFiles, i.Request.MaxFileBytes = 0, 0
			i.Request.PolicyVersion = ""
			i.Request.Files = nil
			i.Request.RuntimePolicy = nil
			i.Request.MaxArchiveBytes, i.Request.MaxCompressedBytes = 1<<20, 1<<20
			i.Request.Teams = &TeamCaptureSpec{InventorySHA256: strings.Repeat("a", 64), Redis: &team.RedisScope{ID: "redis_a", ServerID: server, Database: db, TeamIDs: []int{4242}}, MaxItems: 100}
			env.Teams = &TeamCaptureSources{Redis: client, Authorize: func(context.Context, Invocation) error { return nil }}
			switch mode {
			case "missing-source-grant":
				env.Teams.Authorize = nil
			case "revoked-source":
				env.Teams.Authorize = func(context.Context, Invocation) error { return errors.New("revoked") }
			case "revoked-during-source":
				checks := 0
				env.Teams.Authorize = func(context.Context, Invocation) error {
					checks++
					if checks > 2 {
						return errors.New("revoked")
					}
					return nil
				}
			case "wrong-server":
				i.Request.Teams.Redis.ServerID = strings.Repeat("f", 40)
			case "functional-fallback":
				i.ProviderKey = nil
			case "mixed-scope":
				i.Request.Teams.Objects = []team.ObjectRef{{TeamID: 20}}
			}
			result, err := runFormalCapture(context.Background(), i, key, env)
			if mode != "valid" {
				if err == nil || result.Ciphertext.Name != "" {
					t.Fatal("unsupported source accepted")
				}
				if (mode == "missing-source-grant" || mode == "revoked-source" || mode == "functional-fallback" || mode == "mixed-scope") && key.calls != 0 {
					t.Fatal("Generate called before valid source grant")
				}
				return
			}
			if err != nil || result.Envelope.Name == "" || key.calls != 1 {
				t.Fatal("actual C source not connected to formal stream", err)
			}
			ciphertext, _ := env.Staging.ReadFile(result.Ciphertext.Name)
			envelope, _ := env.Staging.ReadFile(result.Envelope.Name)
			if !bytes.HasPrefix(ciphertext, []byte("CMBKGC01")) || bytes.Contains(ciphertext, []byte("claw:team:")) || !json.Valid(envelope) || !bytes.Equal(key.borrowed, make([]byte, 32)) {
				t.Fatal("legacy/plaintext output or retained task key")
			}
			plain := openTeamCandidateForTest(t, i, ciphertext, envelope)
			keys := 0
			if e := c.ReadRedisSnapshot(bytes.NewReader(plain), c.RedisBudget{MaxItems: 100, MaxBytes: 1 << 20, MaxInventoryBytes: 1 << 20}, func(r c.RedisRecord) error {
				keys++
				if string(r.Key) != "claw:team:4242:events" || !bytes.Contains(r.Dump, []byte("formal Team result")) {
					t.Fatal("nonempty source data not preserved")
				}
				return nil
			}); e != nil || keys != 1 {
				t.Fatal("candidate did not contain real Team source", e, keys)
			}
			hash, _ := i.Hash()
			if validControl(ControlRequest{Invocation: i, InvocationSHA256: hash, Action: "acquire"}) {
				t.Fatal("formal source got functional DEK fallback")
			}
			if _, err = runFormalCapture(context.Background(), i, key, env); err == nil || key.calls != 1 {
				t.Fatal("original envelope overwritten or Generate replayed")
			}
		})
	}
}

func teamRedisFixtureCommand(t *testing.T, port string, args ...string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	var cmd strings.Builder
	fmt.Fprintf(&cmd, "*%d\r\n", len(args))
	for _, arg := range args {
		fmt.Fprintf(&cmd, "$%d\r\n%s\r\n", len(arg), arg)
	}
	if _, err = io.WriteString(conn, cmd.String()); err != nil {
		t.Fatal(err)
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || len(reply) == 0 || reply[0] == '-' {
		t.Fatal("local Redis fixture failed", err)
	}
}

func TestFormalTeamsObjectCandidateContainsPinnedOriginalBytes(t *testing.T) {
	port := os.Getenv("TEST_SYSTEM_BACKUP_MINIO_PORT")
	if port == "" {
		t.Skip("requires disposable local MinIO")
	}
	ctx := context.Background()
	client, err := minio.New("127.0.0.1:"+port, &minio.Options{Creds: credentials.NewStaticV4(os.Getenv("TEST_SYSTEM_BACKUP_MINIO_USER"), os.Getenv("TEST_SYSTEM_BACKUP_MINIO_PASSWORD"), ""), Secure: false})
	if err != nil {
		t.Fatal(err)
	}
	bucket, err := c.RandomID("teams-worker-")
	if err != nil {
		t.Fatal(err)
	}
	if err = client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for item := range client.ListObjects(ctx, bucket, minio.ListObjectsOptions{Recursive: true, WithVersions: true}) {
			if item.Err != nil {
				t.Error(item.Err)
				continue
			}
			if e := client.RemoveObject(ctx, bucket, item.Key, minio.RemoveObjectOptions{VersionID: item.VersionID}); e != nil {
				t.Error(e)
			}
		}
		if e := client.RemoveBucket(ctx, bucket); e != nil {
			t.Error(e)
		}
	})
	if err = client.SetBucketVersioning(ctx, bucket, minio.BucketVersioningConfiguration{Status: "Enabled"}); err != nil {
		t.Fatal(err)
	}
	body := []byte("formal Team original object\x00\xff")
	first, err := client.PutObject(ctx, bucket, "results/report", bytes.NewReader(body), int64(len(body)), minio.PutObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.PutObject(ctx, bucket, "results/report", strings.NewReader("replacement"), 11, minio.PutObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	i, env, key := formalInvocationFixture(t)
	i.WorkspacePath = ""
	env.Workspace = nil
	i.Request.Operation = "capture-team-objects"
	i.Request.MaxFiles, i.Request.MaxFileBytes = 0, 0
	i.Request.MaxArchiveBytes, i.Request.MaxCompressedBytes = 1<<20, 1<<20
	i.Request.PolicyVersion = ""
	i.Request.Files = nil
	i.Request.RuntimePolicy = nil
	sum := sha256.Sum256(body)
	i.Request.Teams = &TeamCaptureSpec{InventorySHA256: strings.Repeat("a", 64), Objects: []team.ObjectRef{{TeamID: 4242, Bucket: bucket, Key: "results/report", Version: first.VersionID, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body))}}, MaxItems: 10}
	i.Request.Binding.Path = "teams_objects"
	i.ProviderKey.Request.Context.Part = "teams_objects"
	key.request = i.ProviderKey.Request
	env.Teams = &TeamCaptureSources{Objects: client, Authorize: func(context.Context, Invocation) error { return nil }}
	result, err := runFormalCapture(ctx, i, key, env)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, _ := env.Staging.ReadFile(result.Ciphertext.Name)
	envelope, _ := env.Staging.ReadFile(result.Envelope.Name)
	plain := openTeamCandidateForTest(t, i, ciphertext, envelope)
	var out bytes.Buffer
	count := 0
	err = c.ReadObjectSnapshot(ctx, bytes.NewReader(plain), c.ObjectBudget{MaxItems: 10, MaxBytes: 1 << 20}, func(meta c.ObjectMetadata) (io.WriteCloser, error) {
		count++
		if meta.Version != first.VersionID {
			t.Fatal("replacement object captured")
		}
		return teamWorkerWriteCloser{&out}, nil
	})
	if err != nil || count != 1 || !bytes.Equal(body, out.Bytes()) {
		t.Fatal("formal C object data lost", err, count)
	}
}

type teamWorkerWriteCloser struct{ io.Writer }

func (teamWorkerWriteCloser) Close() error { return nil }

// Independent readback of the actual public C frames using only the fixture
// provider's key. This is not a production unwrap authority or acceptance.
func openTeamCandidateForTest(t *testing.T, i Invocation, frames, envelope []byte) []byte {
	t.Helper()
	var parsed struct {
		Entries []struct {
			KEK    json.RawMessage `json:"kek"`
			Chunks []w.StreamChunk `json:"chunks"`
		} `json:"entries"`
	}
	if json.Unmarshal(envelope, &parsed) != nil || len(parsed.Entries) != 1 {
		t.Fatal("invalid candidate envelope")
	}
	entry := parsed.Entries[0]
	kek := sha256.Sum256(entry.KEK)
	ctx := i.ProviderKey.Request.Context
	binding := w.ChunkBinding{SchemaVersion: w.FramingVersion, InstallationID: ctx.InstallationID, BackupPublicID: ctx.BackupPublicID, AttemptNo: ctx.AttemptNo, Phase: ctx.Phase, Part: ctx.Part, PartIndex: ctx.PartIndex, Path: i.Request.ArtifactName, EnvelopeID: ctx.EnvelopeID, CaptureContextHash: ctx.CaptureContextHash, KEKBindingSHA256: hex.EncodeToString(kek[:])}
	block, _ := aes.NewCipher(bytes.Repeat([]byte{9}, 32))
	gcm, _ := cipher.NewGCM(block)
	var compressed bytes.Buffer
	final := false
	for index, chunk := range entry.Chunks {
		length := 41 + int(chunk.CiphertextLength) + 16
		if length > len(frames) || chunk.Index != uint64(index) || final {
			t.Fatal("truncated/reordered frames")
		}
		frame := frames[:length]
		frames = frames[length:]
		sum := sha256.Sum256(frame)
		if hex.EncodeToString(sum[:]) != chunk.SHA256 {
			t.Fatal("frame digest mismatch")
		}
		aad, err := w.ChunkAAD(binding, uint64(index), chunk.PlaintextLength, chunk.Final)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := gcm.Open(nil, frame[29:41], frame[41:], aad)
		if err != nil {
			t.Fatal(err)
		}
		compressed.Write(plain)
		final = chunk.Final
	}
	if !final || len(frames) != 0 {
		t.Fatal("missing final frame or trailing bytes")
	}
	z, err := gzip.NewReader(&compressed)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	plain, err := io.ReadAll(io.LimitReader(z, 1<<20+1))
	if err != nil || len(plain) > 1<<20 {
		t.Fatal("invalid compressed payload", err)
	}
	return plain
}
