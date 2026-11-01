package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	ce "clawreef/internal/systembackupcontrolevidence"
	pc "clawreef/internal/systembackuppartcontainer"
	w "clawreef/internal/systembackupwire"
)

// Real local AES-GCM C bytes, explicitly codec DATA. No SQL capture, provider,
// plaintext business verification, public manifest or acceptance is implied.
func artifactContainerReadData(t *testing.T, installation string) (pc.Scope, map[string]string, []byte, pc.Facts) {
	t.Helper()
	scope := pc.Scope{Installation: installation, Backup: "sbk_container_read_DATA", Attempt: 1, ConfigVersion: 3, ConfigSHA256: strings.Repeat("a", 64), CaptureContextSHA256: strings.Repeat("b", 64), Part: "workspace"}
	part, inventory := "named_workspace_DATA", strings.Repeat("c", 64)
	spec := w.StreamSpec{Request: w.KeyRequest{Key: w.KeyBinding{Provider: "external-kms", IdentityHash: strings.Repeat("d", 64), RegistryVersion: "named-kek-r1", ProviderKeyID: "named-kek-DATA", ProviderVersion: "7"}, Context: w.KeyContext{InstallationID: scope.Installation, BackupPublicID: scope.Backup, AttemptNo: "1", Phase: "capture", Part: part, PartIndex: "3", EnvelopeID: "named-envelope-DATA", CaptureContextHash: scope.CaptureContextSHA256}}, Path: "original/workspace.enc", MaxPlaintextBytes: w.ChunkSize, MaxFrames: 2}
	key := bytes.Repeat([]byte{3}, 32)
	var cipher bytes.Buffer
	seal, err := w.EncryptStream(context.Background(), spec, key, &cipher, func(dst io.Writer) error {
		_, err := dst.Write(bytes.Repeat([]byte("nonempty local codec DATA"), 100))
		return err
	})
	clear(key)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := seal.EnvelopeJSON(w.WrappedKey{Request: spec.Request, Algorithm: "provider-native", Ciphertext: []byte("named opaque wrapped-key DATA")})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := b.Checkpoint{SchemaVersion: "system-backup-b-checkpoint.v1", InstallationID: scope.Installation, TaskPublicID: scope.Backup, ConfigVersion: scope.ConfigVersion, ConfigSHA256: scope.ConfigSHA256, AttemptNo: scope.Attempt, Phase: "capture", InventorySHA256: inventory, Part: part, InvocationSHA256: strings.Repeat("e", 64), ContentSHA256: seal.CiphertextSHA256(), JobUID: "named-original-job-DATA", JobGeneration: 1, SealedRef: "named-original-seal-DATA"}
	checkpointRaw, err := json.Marshal(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	canonicalCheckpoint, err := ce.Canonical(json.RawMessage(checkpointRaw))
	if err != nil {
		t.Fatal(err)
	}
	checkpoints := map[string]string{part: hash(canonicalCheckpoint)}
	input := pc.Input{Member: pc.Member{Part: part, Operation: "capture-workspace", Index: 3, CipherPath: "parts/3/cipher.enc", EnvelopePath: "parts/3/cipher.envelope.json", CipherBytes: seal.CiphertextBytes(), CipherSHA256: seal.CiphertextSHA256(), CipherFraming: w.FramingVersion, EnvelopeBytes: int64(len(envelope)), EnvelopeSHA256: hash(envelope), EnvelopeFraming: w.EnvelopeVersion, Stream: spec, Checkpoint: checkpointRaw}, Ciphertext: bytes.NewReader(cipher.Bytes()), Envelope: envelope}
	var encoded bytes.Buffer
	facts, err := pc.Write(context.Background(), &encoded, scope, inventory, []pc.Input{input}, checkpoints, 16<<30, 512<<20)
	if err != nil {
		t.Fatal(err)
	}
	return scope, checkpoints, encoded.Bytes(), facts
}

func TestArtifactReadOnlyContainerFixedVersionFullStream(t *testing.T) {
	for _, mode := range []string{"healthy", "whole-hash", "member-corruption-with-matching-whole-hash", "checkpoint", "scope", "wrong-version", "wrong-size", "foreign-key", "over-budget", "short-body", "credential-withdrawn", "deadline-during-body", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			store, state := newANativePublicationStore(t, time.Minute)
			if err := os.Remove(store.config.WriteCredentialFile); err != nil {
				t.Fatal(err)
			}
			reader, err := NewArtifactReadOnlyS3(artifactReadMaterials(store.config), ArtifactReadLimits{MaxArtifactBytes: 16 << 30, MaxIndexBytes: 512 << 20})
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			scope, checkpoints, raw, expected := artifactContainerReadData(t, store.config.InstallationID)
			key := store.config.Root + scope.Backup + "/1/parts/workspace/container.enc"
			object := ArtifactReadObject{Key: key, Version: "original-v1", SHA256: expected.SHA256, Size: expected.Size}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			until := time.Now().Add(5 * time.Second)
			switch mode {
			case "whole-hash":
				object.SHA256 = hash([]byte("foreign object DATA"))
			case "member-corruption-with-matching-whole-hash":
				raw[expected.Locations[0].CipherOffset+20] ^= 1
				object.SHA256 = hash(raw)
			case "checkpoint":
				checkpoints["named_workspace_DATA"] = hash([]byte("substitute checkpoint DATA"))
			case "scope":
				scope.ConfigSHA256 = hash([]byte("foreign config DATA"))
			case "wrong-version":
				state.wrongVersion = true
			case "wrong-size":
				object.Size++
			case "foreign-key":
				object.Key = store.config.Root + "foreign/container.enc"
			case "over-budget":
				object.Size = (16 << 30) + 1
			case "short-body":
				state.onRead = func(dst http.ResponseWriter, request *http.Request) bool {
					if request.Method != "GET" {
						return false
					}
					dst.Header().Set("x-amz-version-id", "original-v1")
					dst.Header().Set("Content-Length", strconv.Itoa(len(raw)))
					dst.WriteHeader(200)
					_, _ = dst.Write(raw[:len(raw)-3])
					return true
				}
			case "credential-withdrawn":
				state.onGet = func() {
					if err := os.Remove(store.config.ReadCredentialFile); err != nil {
						t.Error(err)
					}
				}
			case "deadline-during-body":
				state.delay = time.Second
				until = time.Now().Add(200 * time.Millisecond)
			case "canceled":
				cancel()
			}
			state.objects["/"+store.config.Bucket+"/"+key] = raw
			facts, err := reader.InspectPartContainer(ctx, object, scope, checkpoints, until)
			if mode == "healthy" {
				if err != nil || facts.SHA256 != expected.SHA256 || facts.Size != expected.Size || len(facts.Locations) != 1 || facts.Locations[0].ObjectVersion != "original-v1" || state.heads != 1 || state.gets != 1 || state.puts != 0 {
					t.Fatal("independent full native container read", facts, err, state.heads, state.gets, state.puts)
				}
			} else if err == nil || facts.SHA256 != "" || len(facts.Locations) != 0 {
				t.Fatal("invalid container returned usable content facts", mode, facts, err)
			}
			if mode == "deadline-during-body" && (state.heads != 1 || state.gets != 1) {
				t.Fatal("deadline case never entered the original GET body", state.heads, state.gets)
			}
			if state.puts != 0 || (mode == "foreign-key" || mode == "over-budget" || mode == "canceled") && (state.heads != 0 || state.gets != 0) {
				t.Fatal("reader sent writes or out-of-scope IO", mode, state.puts, state.heads, state.gets)
			}
		})
	}
}

func TestPublicationSequentialObjectRequiresRealEOFAndForwardReads(t *testing.T) {
	stream := &publicationSequentialObject{ctx: context.Background(), body: strings.NewReader("abc")}
	buf := make([]byte, 3)
	if n, err := stream.ReadAt(buf, 0); n != 3 || err != nil || stream.eof {
		t.Fatal("size annotation synthesized EOF", n, err, stream.eof)
	}
	if _, err := stream.ReadAt(buf, 0); err == nil || stream.eof {
		t.Fatal("backward read reused bytes")
	}
	if n, err := stream.ReadAt(buf[:1], 3); n != 0 || err != io.EOF || !stream.eof {
		t.Fatal("real EOF was not observed", n, err, stream.eof)
	}
}
