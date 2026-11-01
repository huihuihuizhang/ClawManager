package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"runtime/debug"
	"strings"
	"testing"

	cd "clawreef/internal/systembackupcapturedescription"
	k "clawreef/internal/systembackupkms"
	w "clawreef/internal/systembackupwire"
)

// Real C/AEAD/EOF and file writer, using the existing explicit key-authority
// fixture. This does not claim the production SQL/mTLS description endpoint.
func TestFormalDescriptionDedicatedCollectorAndCompleteCipherReadback(t *testing.T) {
	originalMemory := debug.SetMemoryLimit(4 << 30)
	defer debug.SetMemoryLimit(originalMemory)
	for _, mode := range []string{"valid", "missing-source", "bad-description", "foreign-nonzero-attempt", "source-revoked", "unknown-key-end"} {
		t.Run(mode, func(t *testing.T) {
			i, env, key := formalInvocationFixture(t)
			seed := cd.Seed{Version: cd.SeedVersion, Members: []cd.Selection{{Part: "business_sql", Operation: "capture-database", PartIndex: 3}}}
			seed.MaxPlaintextBytes, _ = cd.Budget(1)
			i.Request.Operation = cd.Operation
			i.Request.Binding.Path = cd.Part
			i.Request.Binding.PartIndex = 0
			i.Request.ArtifactName = cd.LogicalCipherName
			i.Request.CaptureDescription = &seed
			i.Request.MaxArchiveBytes = seed.MaxPlaintextBytes
			i.Request.MaxCompressedBytes = seed.MaxPlaintextBytes
			i.Request.MaxFiles = 0
			i.Request.MaxFileBytes = 0
			i.WorkspacePath = ""
			i.ProviderKey.Request.Context.Part = cd.Part
			i.ProviderKey.Request.Context.PartIndex = "0"
			i.FormalCapture.MaxFrames = 64
			i.FormalCapture.SourceConfigSHA256 = strings.Repeat("e", 64)
			i.FormalCapture.PermitDelivery = &k.PermitDeliveryPin{Version: k.PermitDeliveryVersion, Issuer: bytes.Repeat([]byte{4}, 32), IssuerGrantSHA256: strings.Repeat("e", 64)}
			key.request = i.ProviderKey.Request
			env.Workspace = nil
			env.SourceValidUntil = i.Request.Deadline
			invRaw, _ := json.Marshal(i)
			invSHA, _ := i.Hash()
			packet := func(part, operation string, index uint32, raw []byte) cd.Invocation {
				return cd.Invocation{Selection: cd.Selection{Part: part, Operation: operation, PartIndex: index}, JSON: raw, SHA256: cd.SHA256(raw)}
			}
			original := []byte(`{"original_source_key":"source-fixture-secret"}`)
			empty := []byte(`{}`)
			keyContext := i.ProviderKey.Request.Context
			description := cd.Description{Version: cd.Version, Scope: cd.Scope{InstallationID: keyContext.InstallationID, TaskPublicID: keyContext.BackupPublicID, ConfigVersion: 1, ConfigSHA256: i.FormalCapture.SourceConfigSHA256, AttemptNo: 1, CaptureContextSHA256: keyContext.CaptureContextHash}, Seed: seed, SourceInventoryJSON: original, SourceInventorySHA256: cd.SHA256(original), Members: []cd.Member{{Invocation: packet("business_sql", "capture-database", 3, empty), CandidateJSON: empty, CandidateSHA256: cd.SHA256(empty), ResultSHA256: strings.Repeat("f", 64)}}, AdministrativeInvocations: []cd.Invocation{packet(cd.Part, cd.Operation, 0, invRaw), packet(cd.ControlPart, cd.ControlOperation, 1, empty), packet(cd.ProofPart, cd.ControlOperation, 2, empty)}}
			if mode == "foreign-nonzero-attempt" {
				description.Scope.AttemptNo++
			}
			raw, err := cd.Encode(description)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(raw)
			sourceReads := 0
			env.SourceAuthorize = func(ctx context.Context, _ Invocation) error {
				if ctx.Err() != nil || mode == "source-revoked" && sourceReads > 0 {
					return ErrNotReady
				}
				return nil
			}
			env.CaptureDescription = func(ctx context.Context, actual Invocation) ([]byte, error) {
				sourceReads++
				sha, _ := actual.Hash()
				if sha != invSHA {
					return nil, ErrNotReady
				}
				if mode == "bad-description" {
					return []byte(`{"reconstructed":true}`), nil
				}
				return bytes.Clone(raw), nil
			}
			if mode == "missing-source" {
				env.CaptureDescription = nil
			}
			if mode == "unknown-key-end" {
				key.endError = true
			}
			result, err := runFormalCapture(context.Background(), i, key, env)
			if mode != "valid" {
				if err == nil || result.Ciphertext.Name != "" {
					t.Fatal("failed original use returned candidate")
				}
				return
			}
			if err != nil || key.calls != 1 || sourceReads != 1 || result.Files != 0 || result.Bytes != 0 || result.Rows != 0 || result.Tables != 0 || !ValidateFormalCaptureResult(i, &result) {
				t.Fatal("dedicated collector", err)
			}
			cipher, _ := env.Staging.ReadFile(result.Ciphertext.Name)
			envelope, _ := env.Staging.ReadFile(result.Envelope.Name)
			if bytes.Contains(cipher, original) || bytes.Contains(cipher, []byte("source-fixture-secret")) {
				t.Fatal("plaintext descriptor exposed")
			}
			var decoded []byte
			verified, err := w.InspectWrappedStream(context.Background(), w.StreamSpec{Request: i.ProviderKey.Request, Path: i.Request.ArtifactName, MaxPlaintextBytes: i.Request.MaxCompressedBytes, MaxFrames: i.FormalCapture.MaxFrames}, envelope, bytes.NewReader(cipher), sourceRedisFixtureUnwrapper{}, func(plaintext io.Reader) error { var err error; decoded, err = io.ReadAll(plaintext); return err })
			defer clear(decoded)
			if err != nil || !bytes.Equal(decoded, raw) || verified.CiphertextSHA256() != result.Ciphertext.SHA256 || verified.CiphertextBytes() != result.Ciphertext.Size {
				t.Fatal("complete independent C readback", err)
			}
			if _, err = runFormalCapture(context.Background(), i, key, env); err == nil || key.calls != 1 {
				t.Fatal("known candidate reran Generate")
			}
		})
	}
}
