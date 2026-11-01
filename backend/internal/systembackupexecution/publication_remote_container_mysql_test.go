package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

// Complete actual original capture/ten workers/certificate, then native local
// object transport DATA and a second independent complete remote C consumer.
// This deliberately does NOT claim an upload Job, MF/_COMMITTED/_ACCEPTANCE,
// signed catalog, cleanup or a succeeded task.
func TestDOriginalRemoteContainerCaptureNativeMySQL(t *testing.T) {
	store, state := newANativePublicationStore(t, 15*time.Minute)
	var targetInput PublicationTargetInput
	configure := func(options *dOriginalSixPartFixtureOptions) {
		options.PublicationTarget = &store.config
		beforeCore := options.BeforeCoreSeal
		options.BeforeCoreSeal = func(ctx context.Context, t *testing.T, f *dOriginalSixPartTask, core *DeploymentConfig) error {
			if err := beforeCore(ctx, t, f, core); err != nil {
				return err
			}
			// Use the ACTUAL original admitted refs; never rewrite task JSON/SHA.
			var original struct {
				References []security.BootstrapSecretRef `json:"references"`
			}
			if err := json.Unmarshal(f.config, &original); err != nil {
				return err
			}
			store.config.InstallationID, store.config.Root = core.InstallationID, core.InstallationID+"/"
			for _, ref := range original.References {
				switch ref.Purpose {
				case "artifact_read":
					store.config.ReadIdentityHash, store.config.ReadRefVersion = ref.IdentityHash, ref.Version
				case "artifact_write":
					store.config.WriteIdentityHash, store.config.WriteRefVersion = ref.IdentityHash, ref.Version
				case "artifact_ca":
					store.config.CAIdentityHash, store.config.CARefVersion = ref.IdentityHash, ref.Version
				}
			}
			raw, err := json.Marshal(store.config)
			if err != nil {
				return err
			}
			targetInput = PublicationTargetInput{File: filepath.Join(f.directory, "d-original-remote-target.json"), SHA256: hash(raw)}
			if err := os.WriteFile(targetInput.File, raw, 0600); err != nil {
				return err
			}
			core.PublicationTarget = &PublicationTargetReference{Protocol: publicationTargetVersion, Path: targetInput.File}
			return nil
		}
		beforeComposition := options.BeforeRuntimeComposition
		options.BeforeRuntimeComposition = func(ctx context.Context, t *testing.T, f *dOriginalSixPartTask) error {
			if err := beforeComposition(ctx, t, f); err != nil {
				return err
			}
			return f.service.loadPublicationTargetInput([]PublicationTargetInput{targetInput})
		}
	}
	runAOriginalSixPartCertificatePublicationConfigured(t, "current", configure, func(ctx context.Context, f *dOriginalSixPartTask, claim *c.ClaimToken, capture publicationVerifiedCapture) {
		policy := c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second}
		attempt := capture.Input.CaptureAttemptNo
		base := store.config.Root + f.publicID + "/" + strconv.FormatUint(attempt, 10) + "/"
		objects := publicationRemoteContainerObjects{Containers: map[string]ArtifactReadObject{}, Control: map[string]ArtifactReadObject{}}
		put := func(path string, body []byte, expected string) ArtifactReadObject {
			t.Helper()
			if hash(body) != expected {
				t.Fatal("unpublished original C bytes changed", path)
			}
			object, err := store.create(ctx, base+path, bytes.NewReader(body), int64(len(body)), expected, time.Now().Add(8*time.Second))
			if err != nil {
				t.Fatal("local native transport of actual original C DATA", path, err)
			}
			return ArtifactReadObject{Key: object.Key, Version: object.Version, Size: object.Size, SHA256: object.SHA256}
		}
		for _, requested := range []string{"mysql", "redis", "object_storage", "workspace", "deployment_resources", "secret_bundle"} {
			var body bytes.Buffer
			facts, err := f.service.writeOriginalPublicationContainer(ctx, claim, attempt, policy, capture, requested, &body)
			if err != nil {
				t.Fatal("same-task original container construction", requested, err)
			}
			objects.Containers[requested] = put("parts/"+requested+"/container.enc", body.Bytes(), facts.SHA256)
		}
		for _, part := range capture.Parts {
			if part.Part != ce.Part && part.Part != ce.ProofPart {
				continue
			}
			fresh, err := (c.ClaimCoordinator{Executor: f.control, InstallationID: f.service.Config.InstallationID}).Renew(ctx, *claim, policy)
			if err != nil {
				t.Fatal(err)
			}
			*claim = fresh
			files, err := f.service.openPublicationCaptureFiles(ctx, *claim, attempt, part.Part)
			if err != nil {
				t.Fatal(err)
			}
			func() {
				defer files.Close()
				for _, entry := range []struct {
					path, sha string
					size      int64
					src       io.Reader
				}{{part.CipherPath, part.CipherSHA256, part.CipherBytes, files.files.Ciphertext}, {part.EnvelopePath, part.EnvelopeSHA256, part.EnvelopeBytes, files.files.Envelope}} {
					body, err := io.ReadAll(io.LimitReader(entry.src, entry.size+1))
					if err != nil || int64(len(body)) != entry.size {
						t.Fatal("original guarded control C file", entry.path, err)
					}
					objects.Control[entry.path] = put(entry.path, body, entry.sha)
				}
			}()
		}
		// Each Range is independently version-pinned. No plaintext is sent to S3.
		ranges := 0
		deny := false
		state.onRead = func(dst http.ResponseWriter, request *http.Request) bool {
			value := request.Header.Get("Range")
			if value == "" {
				return false
			}
			ranges++
			if deny {
				http.Error(dst, "named denied original range", 403)
				return true
			}
			bounds, ok := strings.CutPrefix(value, "bytes=")
			left, right, cut := strings.Cut(bounds, "-")
			start, e1 := strconv.ParseInt(left, 10, 64)
			end, e2 := strconv.ParseInt(right, 10, 64)
			raw := state.objects[request.URL.Path]
			if !ok || !cut || e1 != nil || e2 != nil || start < 0 || end < start || end >= int64(len(raw)) || request.URL.Query().Get("versionId") != "original-v1" {
				http.Error(dst, "invalid original range", 403)
				return true
			}
			dst.Header().Set("x-amz-version-id", "original-v1")
			dst.Header().Set("Content-Range", "bytes "+left+"-"+right+"/"+strconv.Itoa(len(raw)))
			dst.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
			dst.WriteHeader(206)
			_, _ = dst.Write(raw[start : end+1])
			return true
		}
		receipt, err := f.service.verifyOriginalRemoteContainerCapture(ctx, claim, attempt, policy, store.config, capture, objects)
		if err != nil || receipt == nil || !receipt.checked(capture, objects) || ranges != 16 || state.puts != 10 {
			t.Fatal("actual original remote six-domain/control C verification", err, ranges, state.puts)
		}
		deny = true
		if denied, err := f.service.verifyOriginalRemoteContainerCapture(ctx, claim, attempt, policy, store.config, capture, objects); err == nil || denied != nil {
			t.Fatal("denied original range minted remote C receipt", err)
		}
		var status string
		var usable bool
		if f.control.QueryRowContext(ctx, "SELECT status,artifact_usable FROM system_backup_v2_backups WHERE public_id=?", f.publicID).Scan(&status, &usable) != nil || status != "validating" || usable || state.puts != 10 {
			t.Fatal("C leaf verification changed original publication terminal state", status, usable, state.puts)
		}
		t.Log("same original task, 8 remote business C members and both remote control C streams; independent current publisher Unwrap; no Job/MF/acceptance/catalog/terminal claim", f.publicID)
	})
}
