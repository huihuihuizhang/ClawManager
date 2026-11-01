package systembackuppartcontainer

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	b "clawreef/internal/systembackup/publicadapter"
	w "clawreef/internal/systembackupwire"
)

// Actual AES-GCM C bytes under named LOCAL test keys. These are codec DATA,
// not original capture/SQL/Job/provider authority or business verifier results.
func containerData(t *testing.T) (Scope, string, []Input, map[string]string, map[string][]byte) {
	t.Helper()
	scope := Scope{Installation: "installation_container_DATA", Backup: "sbk_container_DATA", Attempt: 1, ConfigVersion: 3, ConfigSHA256: strings.Repeat("a", 64), CaptureContextSHA256: strings.Repeat("b", 64), Part: "workspace"}
	source := strings.Repeat("c", 64)
	var inputs []Input
	checkpoints := map[string]string{}
	ciphers := map[string][]byte{}
	for _, index := range []uint32{3, 9} {
		name := fmt.Sprintf("named_workspace_DATA_%d", index)
		spec := w.StreamSpec{Request: w.KeyRequest{Key: w.KeyBinding{Provider: "external-kms", IdentityHash: strings.Repeat("d", 64), RegistryVersion: "named-kek-r1", ProviderKeyID: "named-kek-DATA", ProviderVersion: "7"}, Context: w.KeyContext{InstallationID: scope.Installation, BackupPublicID: scope.Backup, AttemptNo: "1", Phase: "capture", Part: name, PartIndex: fmt.Sprint(index), EnvelopeID: "named-envelope-" + name, CaptureContextHash: scope.CaptureContextSHA256}}, Path: "original/" + name + ".enc", MaxPlaintextBytes: w.ChunkSize, MaxFrames: 2}
		key := bytes.Repeat([]byte{byte(index)}, 32)
		var cipher bytes.Buffer
		seal, err := w.EncryptStream(context.Background(), spec, key, &cipher, func(dst io.Writer) error {
			_, err := dst.Write(bytes.Repeat([]byte("named nonempty plaintext DATA"), 100))
			return err
		})
		clear(key)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := seal.EnvelopeJSON(w.WrappedKey{Request: spec.Request, Algorithm: "provider-native", Ciphertext: []byte("named local opaque wrapped-key DATA")})
		if err != nil {
			t.Fatal(err)
		}
		checkpoint := b.Checkpoint{SchemaVersion: "system-backup-b-checkpoint.v1", InstallationID: scope.Installation, TaskPublicID: scope.Backup, ConfigVersion: scope.ConfigVersion, ConfigSHA256: scope.ConfigSHA256, AttemptNo: scope.Attempt, Phase: "capture", InventorySHA256: source, Part: name, InvocationSHA256: strings.Repeat("e", 64), ContentSHA256: seal.CiphertextSHA256(), JobUID: "named-original-job-DATA-" + name, JobGeneration: 1, SealedRef: "named-original-seal-DATA-" + name}
		checkpointRaw, _ := json.Marshal(checkpoint)
		canonicalCheckpoint, err := canonical(json.RawMessage(checkpointRaw))
		if err != nil {
			t.Fatal(err)
		}
		checkpoints[name] = checksum(canonicalCheckpoint)
		ciphers[name] = bytes.Clone(cipher.Bytes())
		inputs = append(inputs, Input{Member: Member{Part: name, Operation: "capture-workspace", Index: index, CipherPath: fmt.Sprintf("parts/%d/named-cipher.enc", index), EnvelopePath: fmt.Sprintf("parts/%d/named-cipher.envelope.json", index), CipherBytes: seal.CiphertextBytes(), CipherSHA256: seal.CiphertextSHA256(), CipherFraming: w.FramingVersion, EnvelopeBytes: int64(len(envelope)), EnvelopeSHA256: checksum(envelope), EnvelopeFraming: w.EnvelopeVersion, Stream: spec, Checkpoint: checkpointRaw}, Ciphertext: bytes.NewReader(cipher.Bytes()), Envelope: envelope})
	}
	return scope, source, inputs, checkpoints, ciphers
}

func TestContainerPreservesActualCBytesAndOriginalBindingsData(t *testing.T) {
	scope, source, inputs, checkpoints, ciphers := containerData(t)
	var encoded bytes.Buffer
	facts, err := Write(context.Background(), &encoded, scope, source, inputs, checkpoints, MaxBytes, MaxIndexBytes)
	if err != nil || facts.Size != int64(encoded.Len()) || facts.SHA256 != checksum(encoded.Bytes()) || len(facts.Locations) != 2 {
		t.Fatal("physical container bytes", err)
	}
	// Input order cannot change deterministic serialized original-index order.
	for index := range inputs {
		inputs[index].Ciphertext = bytes.NewReader(ciphers[inputs[index].Member.Part])
	}
	inputs[0], inputs[1] = inputs[1], inputs[0]
	var reordered bytes.Buffer
	if again, err := Write(context.Background(), &reordered, scope, source, inputs, checkpoints, MaxBytes, MaxIndexBytes); err != nil || again.SHA256 != facts.SHA256 || !bytes.Equal(encoded.Bytes(), reordered.Bytes()) {
		t.Fatal("source input enumeration changed physical framing", err)
	}
	version := "named-fixed-container-version-17"
	read, err := Inspect(context.Background(), FixedObject{Reader: bytes.NewReader(encoded.Bytes()), Version: version, SHA256: facts.SHA256, Size: facts.Size}, scope, checkpoints, MaxBytes, MaxIndexBytes)
	if err != nil || read.SHA256 != facts.SHA256 || read.Size != facts.Size || read.CipherBytes != facts.CipherBytes || read.EnvelopeBytes != facts.EnvelopeBytes {
		t.Fatal("independent complete physical readback", err)
	}
	for _, location := range read.Locations {
		if location.ObjectVersion != version {
			t.Fatal("fixed version was inferred or dropped")
		}
		memberBytes := encoded.Bytes()[location.CipherOffset : location.CipherOffset+location.CipherBytes]
		if !bytes.Equal(memberBytes, ciphers[location.Part]) || checksum(memberBytes) != location.CipherSHA256 {
			t.Fatal("original C framing/AAD stream was rewritten")
		}
	}
}

func reframeData(t *testing.T, raw []byte, mutate func(*Header), body func([]byte) []byte) []byte {
	t.Helper()
	headerSize := int(binary.BigEndian.Uint32(raw[8:12]))
	header, err := readHeader(bytes.NewReader(raw[12:12+headerSize]), int64(headerSize), MaxIndexBytes)
	if err != nil {
		t.Fatal(err)
	}
	mutate(&header)
	headerRaw, err := canonical(header)
	if err != nil {
		t.Fatal(err)
	}
	out := append([]byte{}, magic[:]...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(headerRaw)))
	out = append(out, headerRaw...)
	payload := bytes.Clone(raw[12+headerSize:])
	return append(out, body(payload)...)
}

func TestContainerReaderRejectsOmissionReorderReplacementAndTailsData(t *testing.T) {
	for _, mode := range []string{"magic", "header-limit", "unknown-header-field", "header-alias", "omit-member", "reorder-members", "gap", "overlap", "replace-cipher", "checkpoint-substitution", "scope", "truncate", "tail", "missing-version", "null-version", "latest-version", "control-version", "wrong-object-sha", "budget", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			scope, source, inputs, checkpoints, _ := containerData(t)
			var encoded bytes.Buffer
			facts, err := Write(context.Background(), &encoded, scope, source, inputs, checkpoints, MaxBytes, MaxIndexBytes)
			if err != nil {
				t.Fatal(err)
			}
			raw := bytes.Clone(encoded.Bytes())
			version := "named-fixed-container-version-17"
			limit := MaxBytes
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "magic":
				raw[0] ^= 1
			case "header-limit":
				binary.BigEndian.PutUint32(raw[8:12], MaxHeaderBytes+1)
			case "unknown-header-field", "header-alias":
				size := int(binary.BigEndian.Uint32(raw[8:12]))
				var fields map[string]json.RawMessage
				json.Unmarshal(raw[12:12+size], &fields)
				if mode == "unknown-header-field" {
					fields["unknown"] = json.RawMessage(`true`)
				} else {
					fields["SCOPE"], fields["scope"] = fields["scope"], nil
					delete(fields, "scope")
				}
				headerRaw, _ := canonical(fields)
				out := append([]byte{}, magic[:]...)
				out = binary.BigEndian.AppendUint32(out, uint32(len(headerRaw)))
				out = append(out, headerRaw...)
				raw = append(out, raw[12+size:]...)
			case "omit-member":
				raw = reframeData(t, raw, func(h *Header) { h.Members = h.Members[:1] }, func(data []byte) []byte { return data })
			case "reorder-members":
				raw = reframeData(t, raw, func(h *Header) { h.Members[0], h.Members[1] = h.Members[1], h.Members[0] }, func(data []byte) []byte { return data })
			case "gap":
				raw = reframeData(t, raw, func(h *Header) { h.Members[1].CipherOffset++ }, func(data []byte) []byte { return data })
			case "overlap":
				raw = reframeData(t, raw, func(h *Header) { h.Members[1].CipherOffset-- }, func(data []byte) []byte { return data })
			case "replace-cipher":
				raw[facts.Locations[0].CipherOffset] ^= 1
			case "checkpoint-substitution":
				raw = reframeData(t, raw, func(h *Header) {
					var checkpoint b.Checkpoint
					json.Unmarshal(h.Members[0].Checkpoint, &checkpoint)
					checkpoint.JobUID += "-replacement"
					h.Members[0].Checkpoint, _ = json.Marshal(checkpoint)
				}, func(data []byte) []byte { return data })
			case "scope":
				scope.ConfigSHA256 = strings.Repeat("f", 64)
			case "truncate":
				raw = raw[:len(raw)-1]
			case "tail":
				raw = append(raw, 1)
			case "missing-version":
				version = ""
			case "null-version":
				version = "null"
			case "latest-version":
				version = "latest"
			case "control-version":
				version = "bad\nversion"
			case "budget":
				limit = int64(len(raw) - 1)
			case "cancel":
				cancel()
			}
			// Recomputed outer hashes deliberately isolate independent inner
			// layout/checkpoint gates. They are DATA, not a replacement signed MF.
			sum := checksum(raw)
			if mode == "wrong-object-sha" {
				sum = strings.Repeat("0", 64)
			}
			actual, err := Inspect(ctx, FixedObject{Reader: bytes.NewReader(raw), Version: version, SHA256: sum, Size: int64(len(raw))}, scope, checkpoints, limit, MaxIndexBytes)
			if err == nil || actual.SHA256 != "" || actual.Size != 0 || len(actual.Locations) != 0 {
				t.Fatal("invalid physical container returned complete byte facts", mode, err)
			}
		})
	}
}

func TestContainerWriterNeverReturnsPartialFactsData(t *testing.T) {
	for _, mode := range []string{"extra-cipher", "short-cipher", "wrong-hash", "missing-member", "duplicate-index", "wrong-envelope", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			scope, source, inputs, checkpoints, ciphers := containerData(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "extra-cipher":
				inputs[0].Ciphertext = bytes.NewReader(append(bytes.Clone(ciphers[inputs[0].Member.Part]), 1))
			case "short-cipher":
				inputs[0].Ciphertext = bytes.NewReader(ciphers[inputs[0].Member.Part][:2])
			case "wrong-hash":
				inputs[0].Member.CipherSHA256 = strings.Repeat("0", 64)
			case "missing-member":
				inputs = inputs[:1]
			case "duplicate-index":
				inputs[1].Member.Index = inputs[0].Member.Index
			case "wrong-envelope":
				inputs[0].Envelope[0] ^= 1
			case "cancel":
				cancel()
			}
			var output bytes.Buffer
			actual, err := Write(ctx, &output, scope, source, inputs, checkpoints, MaxBytes, MaxIndexBytes)
			if err == nil || actual.SHA256 != "" || actual.Size != 0 {
				t.Fatal("partial/error bytes returned usable facts", mode, err)
			}
		})
	}
}
