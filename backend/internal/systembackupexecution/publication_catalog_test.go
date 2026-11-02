package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
	security "clawreef/internal/systembackupsecurity"
)

// Public content DATA only; no task, cleanup, accepted or registered authority.
func catalogPayloadData(t *testing.T) artifactRegistrationPayload {
	t.Helper()
	installation, backup := "installation_catalog_content_DATA", "sbk_11111111-1111-4111-8111-111111111111"
	return artifactRegistrationPayload{Version: "system-backup-catalog-record.v1", Installation: installation, Backup: backup, Attempt: 1, ID: publicationCatalogRecordID(installation, backup, 1), At: time.Now().UTC().Format(time.RFC3339Nano), Key: security.PublicationSigningKey{Purpose: "catalog_record", KeyID: "catalog_record-content-fixture", KeyVersion: "v1"}, Event: "artifact_registered", Manifest: artifactCatalogManifestLocator{Provider: "s3", Identity: hash([]byte("artifact read identity DATA")), Key: installation + "/" + backup + "/1/manifest.json", Version: "immutable-original-v1"}, ManifestSHA256: hash([]byte("manifest DATA")), MarkerSHA256: hash([]byte("marker DATA")), AcceptanceSHA256: hash([]byte("complete signed acceptance DATA")), CaptureSHA256: hash([]byte("complete certificate DATA")), IndexSHA256: hash([]byte("index DATA"))}
}

func TestPublicationCatalogStrictPublicPayload(t *testing.T) {
	p := catalogPayloadData(t)
	raw, _ := ce.Canonical(p)
	if _, err := decodePublicationCatalogPayload(raw); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"schema", "installation", "backup", "attempt", "unsafe-integer", "record-id", "purpose", "time", "manifest-checksum", "marker-checksum", "acceptance-checksum", "certificate-checksum", "index-checksum", "provider", "identity", "key", "long-key", "version", "long-version", "event", "unknown", "legacy", "tombstone", "duplicate", "alias", "missing"} {
		t.Run(mode, func(t *testing.T) {
			q := p
			switch mode {
			case "schema":
				q.Version = "legacy"
			case "installation":
				q.Installation = ""
			case "backup":
				q.Backup = "sbk_other:task"
			case "attempt":
				q.Attempt = 0
			case "unsafe-integer":
				q.Attempt = 9007199254740992
			case "record-id":
				q.ID = ""
			case "purpose":
				q.Key.Purpose = "acceptance_record"
			case "time":
				q.At = "not-time"
			case "manifest-checksum":
				q.ManifestSHA256 = ""
			case "marker-checksum":
				q.MarkerSHA256 = ""
			case "acceptance-checksum":
				q.AcceptanceSHA256 = ""
			case "certificate-checksum":
				q.CaptureSHA256 = ""
			case "index-checksum":
				q.IndexSHA256 = ""
			case "provider":
				q.Manifest.Provider = "legacy"
			case "identity":
				q.Manifest.Identity = ""
			case "key":
				q.Manifest.Key = "../manifest.json"
			case "long-key":
				q.Manifest.Key = strings.Repeat("a", 1025)
			case "version":
				q.Manifest.Version = "latest"
			case "long-version":
				q.Manifest.Version = strings.Repeat("a", 257)
			case "event":
				q.Event = "artifact_deleted"
			}
			body, _ := ce.Canonical(q)
			if mode == "unknown" || mode == "legacy" || mode == "tombstone" || mode == "alias" || mode == "missing" {
				var fields map[string]json.RawMessage
				_ = json.Unmarshal(body, &fields)
				switch mode {
				case "unknown":
					fields["unexpected"] = json.RawMessage(`true`)
				case "legacy":
					fields["identity"] = json.RawMessage(`"legacy DATA"`)
				case "tombstone":
					fields["registration_checksum"] = json.RawMessage(`"` + p.ManifestSHA256 + `"`)
				case "alias":
					fields["Record_ID"] = json.RawMessage(`"aliased DATA"`)
				case "missing":
					delete(fields, "recorded_at")
				}
				body, _ = ce.Canonical(fields)
			}
			if mode == "duplicate" {
				body = []byte(strings.TrimSuffix(string(body), "}") + `,"schema_version":"system-backup-catalog-record.v1"}`)
			}
			if _, err := decodePublicationCatalogPayload(body); err == nil {
				t.Fatal("accepted malformed registration", mode)
			}
		})
	}
}

func TestPublicationCatalogSignedBytesBindOriginalArtifacts(t *testing.T) {
	p := catalogPayloadData(t)
	keys := []security.ArtifactSigningPublicKey{}
	var signing ed25519.PrivateKey
	for _, purpose := range []string{"capture_certificate", "acceptance_record", "catalog_record"} {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, security.ArtifactSigningPublicKey{InstallationID: p.Installation, Purpose: purpose, KeyID: purpose + "-content-fixture", KeyVersion: "v1", PublicKey: public, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)})
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
	payload, _ := ce.Canonical(p)
	header, _ := ce.Canonical(map[string]string{"alg": "EdDSA", "key_version": p.Key.KeyVersion, "kid": p.Key.KeyID, "purpose": "catalog_record", "typ": "clawmanager.system-backup.catalog_record.v1"})
	encoded := base64.RawURLEncoding.EncodeToString(header)
	signature := ed25519.Sign(signing, []byte(encoded+"."+base64.RawURLEncoding.EncodeToString(payload)))
	raw, _ := ce.Canonical(map[string]any{"payload": json.RawMessage(payload), "signature": map[string]string{"algorithm": "EdDSA", "domain_separator": "clawmanager.system-backup.catalog_record.v1", "key_id": p.Key.KeyID, "key_purpose": "catalog_record", "key_version": p.Key.KeyVersion, "protected_header": encoded, "value": base64.RawURLEncoding.EncodeToString(signature)}})
	task := security.ArtifactSigningTask{BackupPublicID: p.Backup, AttemptNo: int64(p.Attempt)}
	if sha, err := verifyPublicationCatalogRecord(raw, payload, history, task); err != nil || sha != hash(raw) {
		t.Fatal("valid public catalog content signature", err)
	}
	for _, mode := range []string{"installation", "backup", "attempt", "record", "time", "purpose", "manifest", "marker", "acceptance", "certificate", "index", "locator-identity", "locator-key", "locator-version"} {
		t.Run(mode, func(t *testing.T) {
			q := p
			switch mode {
			case "installation":
				q.Installation += "-other"
			case "backup":
				q.Backup += "_other"
			case "attempt":
				q.Attempt++
			case "record":
				q.ID += "_other"
			case "time":
				q.At = time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)
			case "purpose":
				q.Key.Purpose = "acceptance_record"
			case "manifest":
				q.ManifestSHA256 = hash([]byte("other manifest"))
			case "marker":
				q.MarkerSHA256 = hash([]byte("other marker"))
			case "acceptance":
				q.AcceptanceSHA256 = hash([]byte("other acceptance"))
			case "certificate":
				q.CaptureSHA256 = hash([]byte("other certificate"))
			case "index":
				q.IndexSHA256 = hash([]byte("other index"))
			case "locator-identity":
				q.Manifest.Identity = hash([]byte("catalog identity"))
			case "locator-key":
				q.Manifest.Key += ".other"
			case "locator-version":
				q.Manifest.Version += "-other"
			}
			other, _ := ce.Canonical(q)
			if _, err := verifyPublicationCatalogRecord(raw, other, history, task); err == nil {
				t.Fatal("signature adopted altered original input", mode)
			}
		})
	}
	corrupt := bytes.Replace(raw, []byte(encoded), []byte(encoded+"x"), 1)
	if _, err = verifyPublicationCatalogRecord(corrupt, payload, history, task); err == nil {
		t.Fatal("bad protected header accepted")
	}
	task.AttemptNo++
	if _, err = verifyPublicationCatalogRecord(raw, payload, history, task); err == nil {
		t.Fatal("cross-attempt record accepted")
	}
}

func TestPublicationCatalogRejectsMissingTypedAcceptance(t *testing.T) {
	ctx := context.Background()
	for _, signed := range []*publicationSignedCatalog{nil, {}, {prepared: &preparedPublicationCatalog{}}} {
		if err := signed.verifyBytes(ctx); err == nil {
			t.Fatal("missing producer manufactured catalog signature")
		}
		if err := signed.recheckTx(ctx, nil, nil, c.ClaimToken{}, 1, PublicationTargetMaterials{}, publicationJSONIntent{}); err == nil {
			t.Fatal("missing original accepted proof admitted")
		}
	}
	for _, registered := range []*publicationRegisteredObject{nil, {}, {signed: &publicationSignedCatalog{prepared: &preparedPublicationCatalog{}}}} {
		if err := registered.recheckTx(ctx, nil); err == nil {
			t.Fatal("untyped catalog manufactured registered proof")
		}
	}
	for _, accepted := range []*publicationAcceptedObject{nil, {}, {signed: &publicationSignedAcceptance{prepared: &preparedPublicationAcceptance{}}}} {
		if _, err := catalogPayloadFromOriginal(accepted, security.PublicationSigningKey{}, time.Now()); err == nil {
			t.Fatal("missing producer manufactured registration payload")
		}
	}
}
