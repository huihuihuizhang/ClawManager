package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	security "clawreef/internal/systembackupsecurity"
)

// Named cryptographic CONTENT fixture, not a real backup/task/publish success.
// Test-only private keys are never exposed through the production reader API.
func signArtifactCatalogContentFixture(t *testing.T, p artifactRegistrationPayload) ([]byte, *security.ArtifactSigningKeyHistory) {
	t.Helper()
	keys := []security.ArtifactSigningPublicKey{}
	var signing ed25519.PrivateKey
	for _, purpose := range []string{"capture_certificate", "acceptance_record", "catalog_record"} {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, security.ArtifactSigningPublicKey{InstallationID: p.Installation, Purpose: purpose, KeyID: purpose + "-explicit-content-fixture", KeyVersion: "v1", PublicKey: public, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)})
		if purpose == "catalog_record" {
			signing = private
		} else {
			clear(private)
		}
	}
	defer clear(signing)
	history, err := security.NewArtifactSigningKeyHistory(p.Installation, keys)
	if err != nil {
		t.Fatal(err)
	}
	p.Key = security.PublicationSigningKey{Purpose: "catalog_record", KeyID: "catalog_record-explicit-content-fixture", KeyVersion: "v1"}
	payload, err := ce.Canonical(p)
	if err != nil {
		t.Fatal(err)
	}
	header, _ := ce.Canonical(map[string]string{"alg": "EdDSA", "key_version": "v1", "kid": p.Key.KeyID, "purpose": "catalog_record", "typ": "clawmanager.system-backup.catalog_record.v1"})
	encoded := base64.RawURLEncoding.EncodeToString(header)
	signature := ed25519.Sign(signing, []byte(encoded+"."+base64.RawURLEncoding.EncodeToString(payload)))
	record, _ := ce.Canonical(map[string]any{"payload": json.RawMessage(payload), "signature": map[string]string{"algorithm": "EdDSA", "domain_separator": "clawmanager.system-backup.catalog_record.v1", "key_id": p.Key.KeyID, "key_purpose": "catalog_record", "key_version": "v1", "protected_header": encoded, "value": base64.RawURLEncoding.EncodeToString(signature)}})
	return record, history
}

func TestArtifactCatalogContentUsesSignedLocatorAndRetainedIndexVersions(t *testing.T) {
	for _, mode := range []string{"unchanged", "catalog-signature", "manifest-corruption", "index-corruption", "entry-corruption", "wrong-index-context", "foreign-identity", "list-permission-missing"} {
		t.Run(mode, func(t *testing.T) {
			store, state := newANativePublicationStore(t, time.Minute)
			material := artifactReadMaterials(store.config)
			if err := os.Remove(store.config.WriteCredentialFile); err != nil {
				t.Fatal(err)
			}
			reader, err := NewArtifactReadOnlyS3(material)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			backup := "sbk_explicit_content_fixture"
			base := material.Root + backup + "/1/"
			cipher := []byte("explicit opaque C bytes for content-chain fixture")
			contextHash := hash([]byte("explicit context DATA"))
			indexContext := contextHash
			if mode == "wrong-index-context" {
				indexContext = hash([]byte("foreign context DATA"))
			}
			index, _ := ce.Canonical(publicationArtifactIndex{Version: "system-backup-artifact-index.v1", Backup: backup, Attempt: 1, CaptureContext: indexContext, Entries: []publicationArtifactEntry{{Path: "parts/original.enc", Role: "encrypted_payload", Size: int64(len(cipher)), SHA256: hash(cipher), Framing: "content-fixture-only"}}})
			captureHash := hash([]byte("explicit capture record content DATA"))
			// Minimal parent binding DATA on purpose: ReadCatalogIndex is only a
			// content locator consumer, never full manifest/acceptance validation.
			manifest, _ := ce.Canonical(map[string]any{"schema_version": "system-backup.v1", "origin_installation_id": material.InstallationID, "backup_public_id": backup, "attempt_no": 1, "capture_context_hash": contextHash, "capture_certificate_hash": captureHash, "artifact_index": map[string]string{"path": "artifact-index.json", "checksum": hash(index)}})
			registration := artifactRegistrationPayload{Version: "system-backup-catalog-record.v1", Installation: material.InstallationID, Backup: backup, Attempt: 1, ID: "explicit-content-registration", At: time.Now().UTC().Format(time.RFC3339Nano), Event: "artifact_registered", Manifest: artifactCatalogManifestLocator{Provider: "s3", Identity: material.ReadIdentityHash, Key: base + "manifest.json", Version: "original-manifest-v1"}, ManifestSHA256: hash(manifest), MarkerSHA256: hash([]byte("explicit marker DATA")), AcceptanceSHA256: hash([]byte("explicit acceptance DATA")), CaptureSHA256: captureHash, IndexSHA256: hash(index)}
			if mode == "foreign-identity" {
				registration.Manifest.Identity = hash([]byte("foreign store DATA"))
			}
			catalog, history := signArtifactCatalogContentFixture(t, registration)
			if mode == "catalog-signature" {
				catalog = bytes.Replace(catalog, []byte(`"record_id":"explicit-content-registration"`), []byte(`"record_id":"altered-content-registration"`), 1)
			}
			type object struct {
				version string
				body    []byte
			}
			objects := map[string]object{base + "manifest.json": {"original-manifest-v1", bytes.Clone(manifest)}, base + "artifact-index.json": {"original-index-v1", bytes.Clone(index)}, base + "parts/original.enc": {"original-C-v1", bytes.Clone(cipher)}}
			if mode == "manifest-corruption" {
				value := objects[base+"manifest.json"]
				value.body[len(value.body)-1] ^= 1
				objects[base+"manifest.json"] = value
			}
			if mode == "index-corruption" {
				value := objects[base+"artifact-index.json"]
				value.body[len(value.body)-1] ^= 1
				objects[base+"artifact-index.json"] = value
			}
			if mode == "entry-corruption" {
				value := objects[base+"parts/original.enc"]
				value.body[len(value.body)-1] ^= 1
				objects[base+"parts/original.enc"] = value
			}
			requests, latest := 0, 0
			state.onRead = func(out http.ResponseWriter, r *http.Request) bool {
				requests++
				if _, ok := r.URL.Query()["versions"]; ok {
					if mode == "list-permission-missing" {
						out.WriteHeader(403)
						return true
					}
					key := r.URL.Query().Get("prefix")
					value, ok := objects[key]
					if !ok {
						out.WriteHeader(404)
						return true
					}
					page := artifactVersionPage{XMLName: xml.Name{Local: "ListVersionsResult"}, Name: material.Bucket, Prefix: key, Versions: []artifactNativeVersion{{Key: key, Version: "replaced-latest-v2", Size: int64(len(value.body)), Modified: time.Now()}, {Key: key, Version: value.version, Size: int64(len(value.body)), Modified: time.Now().Add(-time.Hour)}}}
					raw, _ := xml.Marshal(page)
					out.Write(raw)
					return true
				}
				key := r.URL.Path[len("/"+material.Bucket+"/"):]
				value, ok := objects[key]
				if !ok {
					out.WriteHeader(404)
					return true
				}
				version := r.URL.Query().Get("versionId")
				if version == "" {
					latest++
					out.WriteHeader(400)
					return true
				}
				body := value.body
				if version == "replaced-latest-v2" {
					body = bytes.Repeat([]byte{'x'}, len(body))
				} else if version != value.version {
					out.WriteHeader(404)
					return true
				}
				out.Header().Set("x-amz-version-id", version)
				out.Header().Set("Content-Length", strconv.Itoa(len(body)))
				if r.Method == "GET" {
					out.Write(body)
				}
				return true
			}
			budget := ArtifactVersionSearchBudget{MaxVersions: 10, MaxPages: 3, MaxReadBytes: 4 << 20}
			content, err := reader.ReadCatalogIndex(context.Background(), catalog, history, 1<<20, 32, budget, time.Now().Add(20*time.Second))
			if mode == "unchanged" || mode == "entry-corruption" {
				if err != nil || content == nil {
					t.Fatal("authenticated parent locator chain unavailable", err)
				}
				object, readErr := content.ResolveEntry(context.Background(), reader, "parts/original.enc", budget, time.Now().Add(20*time.Second))
				if mode == "entry-corruption" {
					if readErr == nil {
						t.Fatal("corrupt retained C bytes accepted")
					}
				} else if readErr != nil || object.Version != "original-C-v1" || object.SHA256 != hash(cipher) || !bytes.Equal(content.ManifestBytes(), manifest) || !bytes.Equal(content.IndexBytes(), index) {
					t.Fatal("retained signed content chain failed", readErr, object)
				}
			} else if err == nil || content != nil {
				t.Fatal("changed parent binding accepted", mode)
			}
			if (mode == "catalog-signature" || mode == "foreign-identity") && requests != 0 {
				t.Fatal("untrusted catalog selected native read")
			}
			if latest != 0 || state.puts != 0 {
				t.Fatal("content recovery used latest or a write", latest, state.puts)
			}
		})
	}
}
