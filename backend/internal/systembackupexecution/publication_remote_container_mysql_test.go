package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
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
	runDOriginalRemoteContainerCaptureNativeMySQL(t, "current")
}

func TestDOriginalDescriptionRemoteContainerCaptureNativeMySQL(t *testing.T) {
	previous := debug.SetMemoryLimit(4 << 30)
	defer debug.SetMemoryLimit(previous)
	runDOriginalRemoteContainerCaptureNativeMySQL(t, "capture-description")
}

func runDOriginalRemoteContainerCaptureNativeMySQL(t *testing.T, mode string) {
	t.Helper()
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
	runAOriginalSixPartCertificatePublicationConfigured(t, mode, configure, func(ctx context.Context, f *dOriginalSixPartTask, claim *c.ClaimToken, capture publicationVerifiedCapture) {
		policy := c.LeasePolicy{TTL: 30 * time.Second, HeartbeatInterval: 5 * time.Second, ReconcileInterval: time.Second}
		attempt := capture.Input.CaptureAttemptNo
		description, err := originalRemoteCaptureHasDescription(capture)
		if err != nil || description != (mode == "capture-description") || description && len(capture.Parts) != 11 {
			t.Fatal("original protocol was not declared before capture", err, description, len(capture.Parts))
		}
		base := store.config.Root + f.publicID + "/" + strconv.FormatUint(attempt, 10) + "/"
		objects := publicationRemoteContainerObjects{Containers: map[string]ArtifactReadObject{}, Control: map[string]ArtifactReadObject{}, Metadata: map[string]ArtifactReadObject{}}
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
			if part.Part != ce.Part && part.Part != ce.ProofPart && part.Part != remoteCaptureDescriptionPart {
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
		if description {
			renew := func() (*security.SQLPublisherCaptureAuthority, error) {
				fresh, err := (c.ClaimCoordinator{Executor: f.control, InstallationID: f.service.Config.InstallationID}).Renew(ctx, *claim, policy)
				if err != nil {
					return nil, err
				}
				*claim = fresh
				return f.service.publicationAccess(ctx, *claim, attempt)
			}
			if _, err := renew(); err != nil {
				t.Fatal(err)
			}
			certificate, known, err := f.service.loadOriginalPublicationCaptureCertificate(ctx, *claim, attempt, capture)
			if err != nil || !known {
				t.Fatal("same original known certificate", err)
			}
			bootstrap, err := f.service.prepareOriginalPublicationBootstrap(ctx, claim, attempt, policy, capture)
			if err != nil {
				t.Fatal("same original certified bootstrap", err)
			}
			index, err := originalRemoteContainerIndex(capture, objects, bootstrap)
			if err != nil {
				t.Fatal("same original container index", err)
			}
			for path, raw := range map[string][]byte{"artifact-index.json": index, "control/capture-certificate.json": certificate.bytes, remoteCaptureBootstrapPath: bootstrap} {
				objects.Metadata[path] = put(path, raw, hash(raw))
			}
		}
		expectedPuts := 10
		if description {
			expectedPuts = 15
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
		if err != nil || receipt == nil || !receipt.checked(capture, objects) || ranges != 16 || state.puts != expectedPuts {
			t.Fatal("actual original remote six-domain/control C verification", err, ranges, state.puts)
		}
		deny = true
		if denied, err := f.service.verifyOriginalRemoteContainerCapture(ctx, claim, attempt, policy, store.config, capture, objects); err == nil || denied != nil {
			t.Fatal("denied original range minted remote C receipt", err)
		}
		deny = false
		if description {
			// Actual body faults in the same original remote objects. No new task,
			// signature, candidate or authority is manufactured for these probes.
			for _, path := range []string{remoteCaptureBootstrapPath, "artifact-index.json", "control/capture-certificate.json", "control/capture-description.json.enc", "control/evidence-proofs.json.enc", "parts/mysql/container.enc"} {
				key := "/" + store.config.Bucket + "/" + base + path
				state.mu.Lock()
				original := bytes.Clone(state.objects[key])
				state.objects[key][len(original)-1] ^= 1
				state.mu.Unlock()
				denied, err := f.service.verifyOriginalRemoteContainerCapture(ctx, claim, attempt, policy, store.config, capture, objects)
				state.mu.Lock()
				state.objects[key] = original
				state.mu.Unlock()
				if err == nil || denied != nil {
					t.Fatal("changed original remote bytes minted C receipt", path, err)
				}
			}
			for _, entry := range []struct {
				objects map[string]ArtifactReadObject
				path    string
			}{{objects.Metadata, remoteCaptureBootstrapPath}, {objects.Metadata, "control/capture-certificate.json"}, {objects.Control, "control/capture-description.json.enc"}, {objects.Containers, "mysql"}} {
				original := entry.objects[entry.path]
				changed := original
				changed.Version = "foreign-fixed-version-DATA"
				entry.objects[entry.path] = changed
				denied, err := f.service.verifyOriginalRemoteContainerCapture(ctx, claim, attempt, policy, store.config, capture, objects)
				entry.objects[entry.path] = original
				if err == nil || denied != nil {
					t.Fatal("foreign actual native version minted C receipt", entry.path, err)
				}
			}
			// Actual original SQL claim loss: release through the real coordinator,
			// acquire a legitimate new publisher claim, then prove the old token
			// cannot adopt it. No row/version/Until is rewritten by test SQL.
			lost := *claim
			if _, err := (c.ClaimCoordinator{Executor: f.control, InstallationID: f.service.Config.InstallationID}).Release(ctx, lost, time.Millisecond); err != nil {
				t.Fatal("real publisher claim release", err)
			}
			var version uint64
			var delay int64
			if err := f.control.QueryRowContext(ctx, `SELECT row_version,COALESCE(TIMESTAMPDIFF(MICROSECOND,UTC_TIMESTAMP(6),next_reconcile_at),0) FROM system_backup_v2_backups WHERE public_id=? AND controller_owner IS NULL`, f.publicID).Scan(&version, &delay); err != nil || delay > 1_000_000 {
				t.Fatal("real released claim row", err, delay)
			}
			if delay > 0 {
				timer := time.NewTimer(time.Duration(delay)*time.Microsecond + time.Millisecond)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			fresh, err := (c.SQLTaskClaimStore{DB: f.control, InstallationID: f.service.Config.InstallationID}).AcquireWithReceipt(ctx, lost.Target, lost.Owner, version, policy)
			if err != nil {
				t.Fatal("legitimate replacement publisher claim", err)
			}
			*claim = fresh
			if denied, err := f.service.verifyOriginalRemoteContainerCapture(ctx, &lost, attempt, policy, store.config, capture, objects); err == nil || denied != nil {
				t.Fatal("actually lost original claim adopted current row", err)
			}
		}
		var status string
		var usable bool
		if f.control.QueryRowContext(ctx, "SELECT status,artifact_usable FROM system_backup_v2_backups WHERE public_id=?", f.publicID).Scan(&status, &usable) != nil || status != "validating" || usable || state.puts != expectedPuts {
			t.Fatal("C leaf verification changed original publication terminal state", status, usable, state.puts)
		}
		t.Log("same original task remote business and administrative C; independent current publisher Unwrap; description layout", description, "objects", expectedPuts, "; no Job/MF/acceptance/catalog/terminal claim", f.publicID)
	})
}
