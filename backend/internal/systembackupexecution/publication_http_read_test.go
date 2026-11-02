package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	read "clawreef/internal/systembackupread"
	security "clawreef/internal/systembackupsecurity"
)

// Explicit cryptographic CONTENT data, not a backup/Ready/read authorization
// receipt. Native GETs and independently owner-signed history use the actual
// production readers. Production request/transaction authorization is D/A's
// separate boundary; this test cannot install a key slice in the C constructor.
type publicationHTTPDataSQL struct {
	values []any
	task   read.TaskHeader
	clock  time.Time
}
type publicationHTTPDataRow struct {
	values []any
	err    error
}

func (r publicationHTTPDataRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return errors.New("content data column count")
	}
	for n, v := range r.values {
		reflect.ValueOf(dest[n]).Elem().Set(reflect.ValueOf(v))
	}
	return nil
}
func (q publicationHTTPDataSQL) QueryRow(query string, args ...any) read.CurrentFactsRow {
	if query == "SELECT UTC_TIMESTAMP(6)" {
		if len(args) != 0 || q.clock.IsZero() {
			return publicationHTTPDataRow{err: errors.New("content SQL clock requires exact zero-argument query and controlled observation")}
		}
		return publicationHTTPDataRow{values: []any{q.clock}}
	}
	if len(args) != 4 || args[0] != q.task.InstallationID || args[1] != q.task.PublicID || args[2] != q.task.RowVersion || args[3] != q.task.ConfigVersion {
		return publicationHTTPDataRow{err: errors.New("content lookup not bound to the original task")}
	}
	return publicationHTTPDataRow{values: q.values}
}

func TestPublicationHTTPReadOriginalSignedContentWithoutPublishingPermission(t *testing.T) {
	for _, fault := range []string{"current", "catalog-corruption", "manifest-corruption", "index-schema", "owner-signature", "foreign-task", "changed-version"} {
		t.Run(fault, func(t *testing.T) {
			artifact, objects := newANativePublicationStore(t, time.Minute)
			catalog, catalogObjects := newANativePublicationStore(t, time.Minute)
			a, c := artifactReadMaterials(artifact.config), artifactReadMaterials(catalog.config)
			c.ReadIdentityHash = hash([]byte("independent catalog read CONTENT"))
			c.Root = a.Root + "catalog/"
			for _, file := range []string{artifact.config.WriteCredentialFile, catalog.config.WriteCredentialFile} {
				if os.Remove(file) != nil {
					t.Fatal("remove all fixture write material")
				}
			}
			directory := t.TempDir()
			now := time.Now().UTC()
			issuer, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(private)
			record := security.InstallationSigningRecord{InstallationID: a.InstallationID, Revision: 1, NotBefore: now.Add(-2 * time.Hour), Until: now.Add(-time.Hour), Permissions: make([]security.InstallationSigningPermission, 3)}
			keys := map[string]ed25519.PrivateKey{}
			for _, purpose := range []string{"capture_certificate", "acceptance_record", "catalog_record"} {
				pub, key, e := ed25519.GenerateKey(rand.Reader)
				if e != nil {
					t.Fatal(e)
				}
				keys[purpose] = key
				defer clear(key)
				record.Keys = append(record.Keys, security.ArtifactSigningPublicKey{InstallationID: a.InstallationID, Purpose: purpose, KeyID: purpose + "-content", KeyVersion: "v1", PublicKey: pub, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
			}
			ownerRaw, _ := ce.Canonical(record)
			history := security.FileSigningRecordReader{RecordFile: filepath.Join(directory, "owner.json"), SignatureFile: filepath.Join(directory, "owner.sig")}
			if os.WriteFile(history.RecordFile, ownerRaw, 0600) != nil || os.WriteFile(history.SignatureFile, ed25519.Sign(private, append([]byte(security.InstallationSigningDomain), ownerRaw...)), 0600) != nil {
				t.Fatal("independent owner history")
			}
			materials := PublicationHTTPReadMaterials{Version: PublicationHTTPReadVersion, Artifacts: a, Catalog: c, History: history, HistoryPin: security.InstallationSigningPin{InstallationID: a.InstallationID, Revision: 1, RecordSHA256: hash(ownerRaw), Issuer: issuer}, Limits: ArtifactReadLimits{MaxArtifactBytes: 16 << 20, MaxIndexBytes: 1 << 20}, MaxReadSeconds: 20}
			materialRaw, _ := json.Marshal(materials)
			input := PublicationHTTPReadInput{File: filepath.Join(directory, "http-read.json"), SHA256: hash(materialRaw)}
			if os.WriteFile(input.File, materialRaw, 0600) != nil {
				t.Fatal("read-only material")
			}
			reader, e := NewPublicationHTTPReader(context.Background(), input)
			if e != nil {
				t.Fatal("authenticated expired SIGN permission must retain read history", e)
			}
			sign := func(payload any, purpose string) []byte {
				raw, e := ce.Canonical(payload)
				if e != nil {
					t.Fatal(e)
				}
				domain := "clawmanager.system-backup." + purpose + ".v1"
				if purpose == "acceptance_record" {
					domain = "clawmanager.system-backup.acceptance.v1"
				}
				header, _ := ce.Canonical(map[string]string{"alg": "EdDSA", "key_version": "v1", "kid": purpose + "-content", "purpose": purpose, "typ": domain})
				encoded := base64.RawURLEncoding.EncodeToString(header)
				sig := ed25519.Sign(keys[purpose], []byte(encoded+"."+base64.RawURLEncoding.EncodeToString(raw)))
				out, e := ce.Canonical(map[string]any{"payload": json.RawMessage(raw), "signature": map[string]string{"algorithm": "EdDSA", "domain_separator": domain, "key_id": purpose + "-content", "key_purpose": purpose, "key_version": "v1", "protected_header": encoded, "value": base64.RawURLEncoding.EncodeToString(sig)}})
				if e != nil {
					t.Fatal(e)
				}
				return out
			}
			h := read.TaskHeader{InstallationID: a.InstallationID, PublicID: "sbk_00000000-0000-4000-8000-000000000001", Kind: read.BackupTask, Status: "succeeded", RowVersion: 9, ConfigVersion: 1}
			// Original config reference CONTENT uses the actual frozen wire spelling.
			refs := []any{}
			for _, v := range []publicationConfigReference{{"artifact_read", a.ReadIdentityHash, a.ReadRefVersion}, {"artifact_ca", a.CAIdentityHash, a.CARefVersion}, {"catalog_read", c.ReadIdentityHash, c.ReadRefVersion}} {
				refs = append(refs, map[string]string{"purpose": v.Purpose, "identity_hash": v.Identity, "version": v.Version})
			}
			config, _ := ce.Canonical(map[string]any{"references": refs})
			m := publicationManifestDataV12(t)
			m.Installation = h.InstallationID
			m.Backup = h.PublicID
			m.Config.SHA256 = hash(config)
			indexData := publicationArtifactIndex{Version: "system-backup-artifact-index.v1", Backup: h.PublicID, Attempt: 1, CaptureContext: m.CaptureContext, Entries: []publicationArtifactEntry{{Path: "content-data.bin", Role: "encrypted_payload", Size: 1, SHA256: hash([]byte("indexed CONTENT")), Framing: "content-data-v1"}}}
			if fault == "index-schema" {
				indexData.Version = "unreviewed-index"
			}
			index, _ := ce.Canonical(indexData)
			m.Index.Checksum = hash(index)
			manifest, _ := ce.Canonical(m)
			base := a.Root + h.PublicID + "/1/"
			mf := ArtifactReadObject{Key: base + "manifest.json", Version: "original-v1", SHA256: hash(manifest), Size: int64(len(manifest))}
			marker, e := originalCommittedMarkerData(manifest, mf, h.InstallationID, h.PublicID, 1, a.Root)
			if e != nil {
				t.Fatal(e)
			}
			_, qualificationReasons, qualificationErr := publicationManifestEvaluation(m)
			if qualificationErr != nil {
				t.Fatal("complete ordinary manifest CONTENT", qualificationErr)
			}
			reasons, _ := ce.Canonical(qualificationReasons)
			acceptance := sign(publicationAcceptancePayload{Version: "system-backup-acceptance.v1", Backup: h.PublicID, Attempt: 1, ManifestSHA256: mf.SHA256, MarkerSHA256: hash(marker), CleanupID: "sev_content", CleanupSHA256: hash([]byte("cleanup reference CONTENT")), Reasons: qualificationReasons, ReasonsSHA256: hash(reasons), DecisionAt: now.Format(time.RFC3339Nano), ConfigVersion: 1, Key: security.PublicationSigningKey{Purpose: "acceptance_record", KeyID: "acceptance_record-content", KeyVersion: "v1"}}, "acceptance_record")
			id := publicationCatalogRecordID(h.InstallationID, h.PublicID, 1)
			catalogRaw := sign(artifactRegistrationPayload{Version: "system-backup-catalog-record.v1", Installation: h.InstallationID, Backup: h.PublicID, Attempt: 1, ID: id, At: now.Format(time.RFC3339Nano), Key: security.PublicationSigningKey{Purpose: "catalog_record", KeyID: "catalog_record-content", KeyVersion: "v1"}, Event: "artifact_registered", Manifest: artifactCatalogManifestLocator{Provider: "s3", Identity: a.ReadIdentityHash, Key: mf.Key, Version: mf.Version}, ManifestSHA256: mf.SHA256, IndexSHA256: hash(index), MarkerSHA256: hash(marker), AcceptanceSHA256: hash(acceptance), CaptureSHA256: m.CaptureCertificate}, "catalog_record")
			historyReader, e := security.LoadInstallationSigningHistory(context.Background(), history, materials.HistoryPin)
			if e != nil {
				t.Fatal("actual owner-signed history before content faults", e)
			}
			for purpose, raw := range map[string][]byte{"catalog_record": catalogRaw, "acceptance_record": acceptance} {
				if _, e = historyReader.VerifyPublicationRecord(raw, security.ArtifactSigningTask{BackupPublicID: h.PublicID, AttemptNo: 1}, purpose); e != nil {
					t.Fatal("original signed content must authenticate before fault injection", purpose, e)
				}
			}
			catalogKey := c.Root + "registrations/" + id + ".json"
			for key, body := range map[string][]byte{mf.Key: manifest, base + "artifact-index.json": index, base + "_COMMITTED": marker, base + "_ACCEPTANCE": acceptance} {
				objects.objects["/"+a.Bucket+"/"+key] = body
			}
			catalogObjects.objects["/"+c.Bucket+"/"+catalogKey] = catalogRaw
			uri := func(key string) string {
				value, _ := publicationTerminalLocator(artifact.config, ArtifactReadObject{Key: key, Version: "original-v1", SHA256: hash([]byte("locator DATA")), Size: 1})
				return value.URI
			}
			q := publicationHTTPDataSQL{task: h, clock: now, values: []any{config, hash(config), a.ReadIdentityHash, a.ReadRefVersion, a.CAIdentityHash, a.CARefVersion, uri(mf.Key), "original-v1", mf.SHA256, uri(base + "artifact-index.json"), "original-v1", hash(index), uri(base + "_COMMITTED"), "original-v1", hash(marker), uri(base + "_ACCEPTANCE"), "original-v1", hash(acceptance), id, hash(catalogRaw), m.CaptureCertificate, catalogKey, "original-v1", hash(catalogRaw), int64(len(catalogRaw)), catalogRaw, hash(catalogRaw), publicationActionKey(h.PublicID, 1, "catalog_registration_append"), uint64(1)}}
			switch fault {
			case "catalog-corruption":
				catalogObjects.objects["/"+c.Bucket+"/"+catalogKey] = []byte("corrupt")
			case "manifest-corruption":
				objects.objects["/"+a.Bucket+"/"+mf.Key] = []byte("corrupt")
			case "owner-signature":
				if os.WriteFile(history.SignatureFile, make([]byte, 64), 0600) != nil {
					t.Fatal("signature fault")
				}
			case "foreign-task":
				h.PublicID = "sbk_00000000-0000-4000-8000-000000000002"
			case "changed-version":
				q.values[22] = "different-original-version"
			}
			item, until, e := reader.Catalog(context.Background(), q, read.CatalogRecordControl{Task: h, RegistrationID: id, RegistrationSHA256: hash(catalogRaw)})
			if fault == "current" {
				if e != nil || item.ID != id || !bytes.Equal(item.Record, catalogRaw) || !time.Now().Before(until) {
					t.Fatal("original fixed-version signed READ content", e)
				}
			} else if e == nil {
				t.Fatal("read conflict accepted", fault)
			}
			if objects.puts != 0 || catalogObjects.puts != 0 {
				t.Fatal("HTTP reader performed a write")
			}
		})
	}
}
