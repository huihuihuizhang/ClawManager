package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	c "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/recovery"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/testfixture"
	"clawreef/internal/systembackup/worker"
	d "clawreef/internal/systembackupdispatch"
	w "clawreef/internal/systembackupwire"
	corev1 "k8s.io/api/core/v1"
)

// Original real SQL task/plan/Job/candidate, actual production authorization
// wrapper and Evidence -> independent content observer -> ModuleResult custody.
// Source TLS/RESP/Kubernetes/Unwrap are named fixtures, not real Redis/Lua or
// six-part service readiness. The real task selector here is functional redis.
func TestSourceRedisMySQLActualPublicEvidenceRequiresIndependentContentProof(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires disposable local MySQL")
	}
	for _, mode := range []string{"valid-empty", "valid-nonempty", "missing-end", "trailing-json", "wrong-count", "wrong-source", "changed-dump", "wrong-expiry"} {
		t.Run(mode, func(t *testing.T) {
			options := &consumerFixtureOptions{PartName: "source_redis", Category: "source", RequestedParts: []string{"redis"}, PrepareSource: func(_ *os.Root, i *worker.Invocation) {
				i.Request.Operation = "capture-source-redis"
				i.Request.Binding.Path = "source_redis"
				i.ProviderKey.Request.Context.Part = "source_redis"
				i.WorkspacePath = ""
				i.Request.MaxFiles, i.Request.MaxFileBytes = 0, 0
				i.Request.SourceRedis = &c.RedisCapturePolicy{Policy: recovery.RedisPolicy{Source: recovery.Reference{ID: "original_redis", Version: "source-v1", SHA256: strings.Repeat("e", 64)}, Topology: "shared_keyspace", CaptureMode: "scan_dump", TTLPolicy: "preserve_absolute", Purpose: "functional_test", DB: 2, Prefixes: []string{"app:"}, MaxItems: 100, MaxBytes: 1 << 20, MaxClockSkew: 3000}, ServerID: strings.Repeat("a", 40)}
			}, ConfigureWorkload: func(request *kube.JobRequest) { request.Source = corev1.Volume{}; request.SourceSubPath = "" }, FormalMaterials: &kube.FormalJobMaterials{ConfigMap: "original-redis-materials", Inputs: []kube.FormalInputMount{{Volume: "formal-redis-source", Kind: "Secret", Name: "original-redis-source", Directory: "/run/backup/materials/redis-source", Items: []corev1.KeyToPath{{Key: "credential", Path: "credential.json"}}}}}}
			options.RewriteCandidate = func(_ *os.Root, i worker.Invocation, candidate worker.FormalCaptureResult, keys *candidateContentUnwrapper) (*os.Root, worker.FormalCaptureResult) {
				return forgeRedisSourceSQLCandidate(t, i, candidate, keys, mode)
			}
			owner, _, admin, _, authority, job, candidate, _, refresh := newConsumerMySQLFixtureOptions(t, options)
			refresh()
			ref, err := owner.Evidence(context.Background(), authority, job)
			valid := mode == "valid-empty" || mode == "valid-nonempty"
			if !valid {
				if err == nil || ref != nil {
					t.Fatal("bad authenticated source content became original evidence", mode, err)
				}
				var results, evidence int
				if admin.QueryRow("SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE result_sha256 IS NOT NULL").Scan(&results) != nil || admin.QueryRow("SELECT COUNT(*) FROM system_backup_v2_evidence").Scan(&evidence) != nil || results != 0 || evidence != 0 {
					t.Fatal("bad source content left SQL result/evidence")
				}
				return
			}
			if err != nil || ref == nil {
				t.Fatal("actual original Redis Evidence", err)
			}
			raw, err := owner.ReadResult(context.Background(), authority, job, *ref)
			if err != nil {
				t.Fatal(err)
			}
			var result d.ModuleResult
			if json.Unmarshal(raw, &result) != nil || result.Part != "source_redis" || result.Category != "source" || result.Status != "completed" || result.Statistics["sealed_bytes"] != uint64(candidate.Ciphertext.Size) {
				t.Fatal("original result lost real Redis part/custody")
			}
			var requested string
			if admin.QueryRow("SELECT requested_parts FROM system_backup_v2_backups WHERE public_id=?", authority.TaskPublicID).Scan(&requested) != nil || requested != "redis" {
				t.Fatal("Redis consumer fixture borrowed workspace selector")
			}
		})
	}
}

func forgeRedisSourceSQLCandidate(t *testing.T, inv worker.Invocation, candidate worker.FormalCaptureResult, keys *candidateContentUnwrapper, mode string) (*os.Root, worker.FormalCaptureResult) {
	t.Helper()
	policy := *inv.Request.SourceRedis
	scenario := testfixture.RedisScenario{TLS: true, ServerID: policy.ServerID}
	if mode != "valid-empty" {
		scenario.Keys = []testfixture.RedisKey{{Key: "app:state", Type: "string", Dump: []byte("named-original-private-value"), PTTL: 5000}}
	}
	fixture := testfixture.NewRedisProtocol(t, scenario)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(fixture.CAPEM)
	client, err := c.ConnectRedis(context.Background(), c.RedisOptions{Address: fixture.Address, Database: 2, TLS: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "127.0.0.1"}, MaxReplyBytes: 4 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var body bytes.Buffer
	if c.CaptureSourceRedis(context.Background(), client, &body, policy, func(context.Context) error { return nil }) != nil {
		t.Fatal("original source protocol capture")
	}
	payload := bytes.Clone(body.Bytes())
	defer clear(payload)
	lines := bytes.Split(bytes.TrimSuffix(payload, []byte{'\n'}), []byte{'\n'})
	switch mode {
	case "missing-end":
		payload = bytes.Join(lines[:len(lines)-1], []byte{'\n'})
	case "trailing-json":
		payload = append(payload, []byte("{}\n")...)
	case "wrong-count":
		var end struct {
			Kind   string
			Count  int64
			SHA256 string
		}
		json.Unmarshal(lines[len(lines)-1], &end)
		end.Count++
		lines[len(lines)-1], _ = json.Marshal(end)
		payload = bytes.Join(lines, []byte{'\n'})
	case "wrong-source":
		var header c.RedisSourceSnapshotHeader
		json.Unmarshal(lines[0], &header)
		header.Source.SHA256 = strings.Repeat("f", 64)
		lines[0], _ = json.Marshal(header)
		payload = bytes.Join(lines, []byte{'\n'})
	case "changed-dump", "wrong-expiry":
		var item recovery.RedisItem
		json.Unmarshal(lines[1], &item)
		if mode == "changed-dump" {
			item.Dump = []byte("replacement dump")
		} else {
			item.ExpiresAt++
		}
		lines[1], _ = json.Marshal(item)
		sum := sha256.Sum256(append(bytes.Clone(lines[1]), '\n'))
		lines[2], _ = json.Marshal(struct {
			Kind   string
			Count  int64
			SHA256 string
		}{"end", 1, hex.EncodeToString(sum[:])})
		payload = bytes.Join(lines, []byte{'\n'})
	}
	var frames bytes.Buffer
	spec := w.StreamSpec{Request: inv.ProviderKey.Request, Path: inv.Request.ArtifactName, MaxPlaintextBytes: inv.Request.MaxCompressedBytes, MaxFrames: inv.FormalCapture.MaxFrames}
	seal, err := w.EncryptStream(context.Background(), spec, keys.key, &frames, func(dst io.Writer) error {
		return staging.Compress(dst, func(z io.Writer) error { _, err := z.Write(payload); return err })
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := seal.EnvelopeJSON(w.WrappedKey{Request: spec.Request, Algorithm: "provider-native", Ciphertext: []byte("named producer original encrypted record fixture")})
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { source.Close() })
	receipt := func(name string, raw []byte) staging.Receipt {
		if source.WriteFile(name, raw, 0600) != nil {
			t.Fatal("owned encrypted candidate")
		}
		sum := sha256.Sum256(raw)
		return staging.Receipt{Name: name, Size: int64(len(raw)), SHA256: hex.EncodeToString(sum[:])}
	}
	candidate.Ciphertext = receipt(inv.Request.ArtifactName, frames.Bytes())
	candidate.Envelope = receipt(inv.FormalCapture.EnvelopeName, envelope)
	candidate.Files, candidate.Bytes = 0, 0
	return source, candidate
}
