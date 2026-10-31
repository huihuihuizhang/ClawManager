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
	"clawreef/internal/systembackup/recovery"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/testfixture"
	"clawreef/internal/systembackup/worker"
	w "clawreef/internal/systembackupwire"
)

func TestIndependentFormalRedisObserverRejectsValidAEADWithBadSourceRecords(t *testing.T) {
	for _, mode := range []string{"valid-empty", "valid-nonempty", "missing-end", "trailing-json", "wrong-count", "changed-dump", "wrong-source-database", "wrong-expiry"} {
		t.Run(mode, func(t *testing.T) {
			policy := c.RedisCapturePolicy{Policy: recovery.RedisPolicy{Source: recovery.Reference{ID: "original_redis", Version: "source-v1", SHA256: strings.Repeat("e", 64)}, Topology: "shared_keyspace", CaptureMode: "scan_dump", TTLPolicy: "preserve_absolute", Purpose: "acceptance", DB: 2, Prefixes: []string{"app:"}, MaxItems: 100, MaxBytes: 1 << 20, MaxClockSkew: 3000}, ServerID: strings.Repeat("a", 40)}
			_, custody, scope, inv, candidate, keys := formalObserverFixture(t, func(_ *os.Root, i *worker.Invocation) {
				i.Request.Operation = "capture-source-redis"
				i.Request.Binding.Path = "source_redis"
				i.ProviderKey.Request.Context.Part = "source_redis"
				i.WorkspacePath = ""
				i.Request.MaxFiles, i.Request.MaxFileBytes = 0, 0
				i.Request.SourceRedis = &policy
			})
			scenario := testfixture.RedisScenario{TLS: true, ServerID: policy.ServerID}
			if mode != "valid-empty" {
				scenario.Keys = []testfixture.RedisKey{{Key: "app:state", Type: "string", Dump: []byte("named-private-original-dump"), PTTL: 5000}}
			}
			fixture := testfixture.NewRedisProtocol(t, scenario)
			roots := x509.NewCertPool()
			roots.AppendCertsFromPEM(fixture.CAPEM)
			client, err := c.ConnectRedis(context.Background(), c.RedisOptions{Address: fixture.Address, Database: 2, TLS: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "127.0.0.1"}, MaxReplyBytes: 4 << 20})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			var captured bytes.Buffer
			if c.CaptureSourceRedis(context.Background(), client, &captured, policy, func(context.Context) error { return nil }) != nil {
				t.Fatal("named source protocol capture")
			}
			payload := bytes.Clone(captured.Bytes())
			lines := bytes.Split(bytes.TrimSuffix(payload, []byte{'\n'}), []byte{'\n'})
			switch mode {
			case "missing-end":
				payload = bytes.Join(lines[:len(lines)-1], []byte{'\n'})
			case "trailing-json":
				payload = append(payload, []byte("{}\n")...)
			case "wrong-count":
				var end map[string]any
				json.Unmarshal(lines[len(lines)-1], &end)
				end["Count"] = float64(99)
				raw, _ := json.Marshal(end)
				payload = bytes.Join(append(lines[:len(lines)-1], raw), []byte{'\n'})
			case "wrong-source-database":
				var header c.RedisSourceSnapshotHeader
				json.Unmarshal(lines[0], &header)
				header.Database++
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
				// The malicious producer also recomputes its own end checksum.
				// AEAD/checksum validity must not replace semantic validation.
				sum := sha256.Sum256(append(bytes.Clone(lines[1]), '\n'))
				lines[2], _ = json.Marshal(struct {
					Kind   string
					Count  int64
					SHA256 string
				}{"end", 1, hex.EncodeToString(sum[:])})
				payload = bytes.Join(lines, []byte{'\n'})
			}
			var frames bytes.Buffer
			streamSpec := w.StreamSpec{Request: inv.ProviderKey.Request, Path: inv.Request.ArtifactName, MaxPlaintextBytes: inv.Request.MaxCompressedBytes, MaxFrames: inv.FormalCapture.MaxFrames}
			seal, err := w.EncryptStream(context.Background(), streamSpec, keys.key, &frames, func(dst io.Writer) error {
				return staging.Compress(dst, func(z io.Writer) error { _, err := z.Write(payload); return err })
			})
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := seal.EnvelopeJSON(w.WrappedKey{Request: streamSpec.Request, Algorithm: "provider-native", Ciphertext: []byte("named malicious producer wrapped fixture")})
			if err != nil {
				t.Fatal(err)
			}
			source, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
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
			observed, err := observeOriginalFormalCandidate(context.Background(), source, custody, staging.CustodyPolicy{Installation: scope.Installation, MaxBytes: 16 << 20}, scope, inv, candidate, keys)
			valid := mode == "valid-empty" || mode == "valid-nonempty"
			if valid {
				if err != nil || observed.Reference() == "" {
					t.Fatal("independent source observer rejected original records", err)
				}
				return
			}
			if err == nil || observed.Reference() != "" || keys.calls != 1 {
				t.Fatal("valid AEAD/checksum laundered invalid Redis source", mode, err)
			}
			files, _, err := staging.OpenFormalObserved(context.Background(), custody, scope, candidate.Ciphertext, candidate.Envelope)
			files.Close()
			if err == nil {
				t.Fatal("invalid source became usable original custody")
			}
		})
	}
}
