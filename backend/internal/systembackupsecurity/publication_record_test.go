package systembackupsecurity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

type publicationVector struct {
	Name  string
	Trust struct {
		Installation, Purpose string
		KeyID                 string `json:"key_id"`
		Version               string `json:"key_version"`
		Public                string `json:"public_key_base64url"`
		Before                string `json:"not_before"`
		After                 string `json:"not_after"`
	}
	Expected struct {
		Backup  string `json:"backup_public_id"`
		Attempt int64  `json:"attempt_no"`
	}
	Payload  string `json:"payload_json"`
	Input    string `json:"signing_input_ascii"`
	Record   string `json:"record_json"`
	Checksum string `json:"object_sha256"`
}

func publicationVectors(t *testing.T) []publicationVector {
	t.Helper()
	raw, err := os.ReadFile("../../../contracts/system-backup/v12/public-c-crypto-v1/signature-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct{ Vectors []publicationVector }
	if json.Unmarshal(raw, &file) != nil || len(file.Vectors) != 4 {
		t.Fatal("public C vectors unavailable")
	}
	return file.Vectors
}

func TestPublicationRecordPublicCContractVectors(t *testing.T) {
	vectors := publicationVectors(t)
	var keys []ArtifactSigningPublicKey
	for _, v := range vectors[:3] {
		pub, err := base64.RawURLEncoding.Strict().DecodeString(v.Trust.Public)
		if err != nil {
			t.Fatal(err)
		}
		before, _ := time.Parse(time.RFC3339, v.Trust.Before)
		after, _ := time.Parse(time.RFC3339, v.Trust.After)
		keys = append(keys, ArtifactSigningPublicKey{InstallationID: v.Trust.Installation, Purpose: v.Trust.Purpose, KeyID: v.Trust.KeyID, KeyVersion: v.Trust.Version, PublicKey: pub, NotBefore: before, NotAfter: after})
	}
	h, err := NewArtifactSigningKeyHistory(vectors[0].Trust.Installation, keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			task := ArtifactSigningTask{BackupPublicID: v.Expected.Backup, AttemptNo: v.Expected.Attempt}
			binding := TransitSigningBinding{InstallationID: v.Trust.Installation, Purpose: v.Trust.Purpose, KeyID: v.Trust.KeyID, KeyVersion: v.Trust.Version}
			input, _, err := publicationInput([]byte(v.Payload), task, binding)
			if err != nil || string(input) != v.Input {
				t.Fatal("public C signing bytes drift", err)
			}
			checksum, err := h.VerifyPublicationRecord([]byte(v.Record), task, v.Trust.Purpose)
			if err != nil || checksum != v.Checksum {
				t.Fatal("public C record verification drift", err)
			}
			for name, mutate := range map[string]func(*publicationEnvelope){
				"signature": func(e *publicationEnvelope) { e.Signature.Value = strings.Repeat("A", 86) },
				"purpose": func(e *publicationEnvelope) {
					e.Signature.Purpose = "acceptance_record"
					if v.Trust.Purpose == "acceptance_record" {
						e.Signature.Purpose = "catalog_record"
					}
				},
				"domain":  func(e *publicationEnvelope) { e.Signature.Domain += "-other" },
				"header":  func(e *publicationEnvelope) { e.Signature.Header += "=" },
				"version": func(e *publicationEnvelope) { e.Signature.KeyVersion += "-other" },
				"payload": func(e *publicationEnvelope) {
					e.Payload = bytes.Replace(e.Payload, []byte(v.Expected.Backup), []byte("sbk_other"), 1)
				},
			} {
				t.Run(name, func(t *testing.T) {
					var e publicationEnvelope
					if json.Unmarshal([]byte(v.Record), &e) != nil {
						t.Fatal("fixture")
					}
					mutate(&e)
					raw, _ := json.Marshal(e)
					raw, _ = jsoncanonicalizer.Transform(raw)
					if _, err := h.VerifyPublicationRecord(raw, task, v.Trust.Purpose); err == nil {
						t.Fatal("altered record accepted")
					}
				})
			}
			for name, raw := range map[string][]byte{"duplicate": []byte(strings.Replace(v.Record, `"payload":`, `"payload":{},"payload":`, 1)), "noncanonical": append([]byte(" "), []byte(v.Record)...), "extra": []byte(strings.Replace(v.Record, `"signature":{`, `"signature":{"extra":true,`, 1)), "trailing": []byte(v.Record + "{}")} {
				t.Run(name, func(t *testing.T) {
					if _, err := h.VerifyPublicationRecord(raw, task, v.Trust.Purpose); err == nil {
						t.Fatal("ambiguous framing accepted")
					}
				})
			}
			wrongTask := task
			wrongTask.AttemptNo++
			if _, err := h.VerifyPublicationRecord([]byte(v.Record), wrongTask, v.Trust.Purpose); err == nil {
				t.Fatal("other attempt accepted")
			}
		})
	}
	keys[0].Revoked = true
	revoked, _ := NewArtifactSigningKeyHistory(vectors[0].Trust.Installation, keys)
	if _, err := revoked.VerifyPublicationRecord([]byte(vectors[0].Record), ArtifactSigningTask{BackupPublicID: vectors[0].Expected.Backup, AttemptNo: 1}, "capture_certificate"); err == nil {
		t.Fatal("revoked historical key accepted")
	}
}

// Real public C payload templates; values are replaced only with local fixture
// identities/times. These do not fabricate production six-domain acceptance.
func publicationFixturePayload(t *testing.T, f *installationSigningFixture, b TransitSigningBinding) []byte {
	t.Helper()
	for _, v := range publicationVectors(t) {
		if v.Trust.Purpose == b.Purpose {
			var payload map[string]any
			if json.Unmarshal([]byte(v.Payload), &payload) != nil {
				t.Fatal("fixture payload")
			}
			payload["backup_public_id"] = f.task.BackupPublicID
			payload["attempt_no"] = f.task.AttemptNo
			if b.Purpose != "acceptance_record" {
				payload["origin_installation_id"] = b.InstallationID
			}
			payload["signing_key"] = PublicationSigningKey{b.Purpose, b.KeyID, b.KeyVersion}
			field := map[string]string{"capture_certificate": "issued_at", "acceptance_record": "decision_at", "catalog_record": "recorded_at"}[b.Purpose]
			payload[field] = time.Now().UTC().Format(time.RFC3339Nano)
			if b.Purpose == "capture_certificate" {
				var jobs, checkpoints, resources []map[string]any
				for _, part := range []string{"mysql", "redis", "object_storage", "workspace", "deployment_resources", "secret_bundle"} {
					sum := sha256.Sum256([]byte("local-checkpoint-" + part))
					checkpoints = append(checkpoints, map[string]any{"part": part, "checkpoint_hash": hex.EncodeToString(sum[:])})
					for instance := 0; instance < 2; instance++ {
						for _, phase := range []string{"capture", "verify"} {
							jobs = append(jobs, map[string]any{"uid": fmt.Sprintf("local-%s-%d-%s-%s", part, instance, phase, strings.Repeat("a", 48)), "generation": 1, "phase": phase})
						}
						resources = append(resources, map[string]any{"uid": fmt.Sprintf("local-staging-%s-%d-%s", part, instance, strings.Repeat("b", 48)), "location_hash": hex.EncodeToString(sum[:])})
					}
				}
				payload["jobs"] = jobs
				payload["checkpoints"] = checkpoints
				payload["staging_resources"] = resources
				payload["capture_completed_at"] = time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
				payload["expires_at"] = time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
			}
			raw, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}
	}
	t.Fatal("missing purpose template")
	return nil
}

func stagePreparedPublication(t *testing.T, db *sql.DB, p interface {
	Stage(context.Context, *sql.Tx) error
}, commit bool) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = p.Stage(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if commit {
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPreparedPublicationRecordCurrentClaimSQLToTLS(t *testing.T) {
	f, state, db, s := newSigningSQLFixture(t)
	ctx := context.Background()
	for _, mount := range f.mounts {
		payload := publicationFixturePayload(t, f, mount.Binding)
		p, err := s.PreparePublicationRecord(ctx, mount.Binding.Purpose, payload)
		if err != nil {
			t.Fatal(err)
		}
		if mount.Binding.Purpose == "capture_certificate" && len(p.input) <= 8192 {
			t.Fatal("full multi-Job certificate did not cross old inline boundary")
		}
		clear(payload) // prepared value must own its bytes
		beforeLogin := f.login
		stagePreparedPublication(t, db, p, false)
		if _, _, err = p.SignCommitted(ctx); err == nil || f.login != beforeLogin {
			t.Fatal("rollback reached provider")
		}
		stagePreparedPublication(t, db, p, true)
		raw, checksum, err := p.SignCommitted(ctx)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if checksum != hex.EncodeToString(sum[:]) {
			t.Fatal("object checksum")
		}
		h, _ := s.History(ctx)
		if got, err := h.VerifyPublicationRecord(raw, f.task, mount.Binding.Purpose); err != nil || got != checksum {
			t.Fatal("independent readback", err)
		}
		state.claim.RowVersion++
		if _, _, err = p.SignCommitted(ctx); err == nil {
			t.Fatal("stale publisher claim")
		}
		state.claim.RowVersion--
	}
}

func TestPublicationRecordOversizeCannotReachProvider(t *testing.T) {
	f, _, _, s := newSigningSQLFixture(t)
	b := s.owners["capture_certificate"].binding
	var payload map[string]any
	if json.Unmarshal(publicationFixturePayload(t, f, b), &payload) != nil {
		t.Fatal("fixture")
	}
	jobs := payload["jobs"].([]any)
	var raw []byte
	for i := 0; i < 100; i++ {
		jobs = append(jobs, map[string]any{"uid": fmt.Sprintf("oversize-local-job-%d-%s", i, strings.Repeat("x", 150)), "generation": 1, "phase": "capture"})
		payload["jobs"] = jobs
		raw, _ = json.Marshal(payload)
		if len(raw) > 12500 {
			break
		}
	}
	if len(raw) >= maxArtifactSigningInputBytes || len(raw) <= 12500 {
		t.Fatal("oversize fixture must exercise encoded input limit")
	}
	if p, err := s.PreparePublicationRecord(context.Background(), b.Purpose, raw); err == nil || p != nil || f.login != 0 {
		t.Fatal("oversized complete signing input was admitted")
	}
}
