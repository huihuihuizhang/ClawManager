package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	c "clawreef/internal/systembackupcontroller"
)

// Actual original capture/worker/SQL/signing protocols with local TLS native
// transports. This is not real-page, installed Kubernetes or terminal success.
func TestPublicationCatalogOriginalHappyPathAndUnknownMySQL(t *testing.T) {
	if os.Getenv("TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires exclusively handed-over original SAN/TLS MySQL")
	}
	for _, mode := range []string{"current", "catalog-put-ack-lost", "catalog-sign-result-lost"} {
		t.Run(mode, func(t *testing.T) {
			catalog, state := newANativePublicationStore(t, 20*time.Minute)
			// Distinct actual credentials on a distinct local TLS endpoint.
			state.read.AccessKey, state.read.SecretKey = "catalog-read-local", strings.Repeat("c", 32)
			state.write.AccessKey, state.write.SecretKey = "catalog-append-local", strings.Repeat("a", 32)
			read, _ := json.Marshal(state.read)
			appendKey, _ := json.Marshal(state.write)
			if os.WriteFile(catalog.config.ReadCredentialFile, read, 0600) != nil || os.WriteFile(catalog.config.WriteCredentialFile, appendKey, 0600) != nil {
				t.Fatal("independent catalog credentials")
			}
			var material PublicationCatalogMaterials
			var signer *aSameTaskCertificateMaterials
			configure := func(o *dOriginalSixPartFixtureOptions, artifact *nativePublicationS3) {
				before := o.BeforeOriginalConfig
				o.BeforeOriginalConfig = func(ctx context.Context, t *testing.T, f *dOriginalSixPartTask, values map[string]any) error {
					if err := before(ctx, t, f, values); err != nil {
						return err
					}
					p := &artifact.config
					material = PublicationCatalogMaterials{Version: publicationCatalogMaterialsVersion, InstallationID: p.InstallationID, Endpoint: catalog.config.Endpoint, Region: catalog.config.Region, Bucket: catalog.config.Bucket, Root: p.InstallationID + "/catalog/", ReadIdentityHash: hash([]byte("independent catalog read DATA")), ReadRefVersion: "catalog-read-r1", AppendIdentityHash: hash([]byte("independent catalog append DATA")), AppendRefVersion: "catalog-append-r1", CAIdentityHash: p.CAIdentityHash, CARefVersion: p.CARefVersion, CAFile: catalog.config.CAFile, CASHA256: catalog.config.CASHA256, ReadCredentialFile: catalog.config.ReadCredentialFile, ReadCredentialSHA256: hash(read), AppendCredentialFile: catalog.config.WriteCredentialFile, AppendCredentialSHA256: hash(appendKey)}
					raw, err := json.Marshal(material)
					if err != nil {
						return err
					}
					p.CatalogMaterialsFile = filepath.Join(f.directory, "original-catalog-materials.json")
					p.CatalogMaterialsSHA256 = hash(raw)
					if err = os.WriteFile(p.CatalogMaterialsFile, raw, 0600); err != nil {
						return err
					}
					for _, entry := range values["references"].([]any) {
						ref := entry.(map[string]any)
						switch ref["purpose"] {
						case "catalog_read":
							ref["identity_hash"], ref["version"] = material.ReadIdentityHash, material.ReadRefVersion
						case "catalog_append":
							ref["identity_hash"], ref["version"] = material.AppendIdentityHash, material.AppendRefVersion
						}
					}
					return nil
				}
			}
			runAOriginalSixPartManifestUploadJobWithHooks(t, func(ctx context.Context, t *testing.T, f *dOriginalSixPartTask, claim *c.ClaimToken, capture publicationVerifiedCapture, artifact *nativePublicationS3, native *aNativePublicationServer) {
				proof := publicationOriginalFinalForTest(ctx, t, f, claim, capture, artifact, native)
				before := signer.signs.Load()
				accepted, err := f.service.completeOriginalPublicationAcceptance(ctx, proof)
				if err != nil || accepted == nil || signer.signs.Load() != before+1 {
					t.Fatal("actual original acceptance and one provider Sign", err, signer.signs.Load(), before)
				}
				if mode == "catalog-sign-result-lost" {
					signer.loseSignResult = true
				}
				if mode == "catalog-put-ack-lost" {
					state.mu.Lock()
					state.lostACK = true
					state.mu.Unlock()
				}
				registered, err := f.service.completeOriginalPublicationCatalog(ctx, accepted)
				if mode == "catalog-sign-result-lost" {
					if !errors.Is(err, c.ErrExecutionCommitUnknown) || registered != nil || signer.signs.Load() != before+2 {
						t.Fatal("lost actual provider result did not stop", err, signer.signs.Load())
					}
					if again, err := f.service.completeOriginalPublicationCatalog(ctx, accepted); !errors.Is(err, c.ErrExecutionCommitUnknown) || again != nil || signer.signs.Load() != before+2 {
						t.Fatal("unknown original Sign was replayed", err, signer.signs.Load())
					}
				} else {
					if err != nil || registered == nil || signer.signs.Load() != before+2 {
						t.Fatal("actual catalog Sign/independent append/full readback", err, signer.signs.Load())
					}
					payload, err := decodePublicationCatalogPayload(registered.signed.prepared.intent.Payload)
					if err != nil || payload.AcceptanceSHA256 != accepted.object.SHA256 || payload.Manifest.Key != proof.manifestObject.Key || payload.Manifest.Version != proof.manifestObject.Version || payload.Manifest.Identity != artifact.config.ReadIdentityHash || payload.ID != publicationCatalogRecordID(material.InstallationID, f.publicID, proof.attempt) || registered.object.Key != publicationCatalogKey(material, f.publicID, proof.attempt) {
						t.Fatal("registered payload substituted original artifacts", err)
					}
					root := catalogSigningID(material.InstallationID, f.publicID, proof.attempt)
					var phases int
					if f.control.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_backup_v2_evidence WHERE public_id IN (?,?,?)`, root+"_prepared", root+"_sent", root+"_result").Scan(&phases) != nil || phases != 3 {
						t.Fatal("catalog original signing phases missing", phases)
					}
					again, err := f.service.completeOriginalPublicationCatalog(ctx, accepted)
					if err != nil || again == nil || again.object.Key != registered.object.Key || again.object.Version != registered.object.Version || again.object.SHA256 != registered.object.SHA256 || !bytes.Equal(again.signed.raw, registered.signed.raw) || signer.signs.Load() != before+2 {
						t.Fatal("known catalog changed or re-signed", err, signer.signs.Load())
					}
					tx, err := f.control.BeginTx(ctx, nil)
					if err != nil {
						t.Fatal(err)
					}
					check := again.recheckTx(ctx, tx)
					_ = tx.Rollback()
					if check != nil {
						t.Fatal("actual registered same-tx proof", check)
					}
					// Owned SQL fault DATA: not an external provider-absence proof.
					if _, err = f.db.ExecContext(ctx, `UPDATE system_backup_v2_evidence SET observed_health='unknown' WHERE public_id=?`, root+"_result"); err != nil {
						t.Fatal(err)
					}
					if denied, err := f.service.completeOriginalPublicationCatalog(ctx, accepted); !errors.Is(err, c.ErrExecutionCommitUnknown) || denied != nil || signer.signs.Load() != before+2 {
						t.Fatal("unhealthy original result regenerated", err, signer.signs.Load())
					}
				}
				state.mu.Lock()
				puts, gets := state.puts, state.gets
				state.mu.Unlock()
				wantPuts := 1
				if mode == "catalog-sign-result-lost" {
					wantPuts = 0
				}
				if puts != wantPuts || wantPuts == 1 && gets < 2 {
					t.Fatal("independent catalog operation counts", puts, gets)
				}
				native.mu.Lock()
				artifactPuts := native.puts
				native.mu.Unlock()
				if artifactPuts != 19 {
					t.Fatal("catalog used artifact writer or replayed acceptance", artifactPuts)
				}
				var status string
				var usable, eligible bool
				if f.control.QueryRowContext(ctx, `SELECT status,artifact_usable,acceptance_eligible FROM system_backup_v2_backups WHERE public_id=?`, f.publicID).Scan(&status, &usable, &eligible) != nil || status != "publishing" || usable || eligible {
					t.Fatal("catalog manufactured terminal eligibility", status, usable, eligible)
				}
			}, &aOriginalPublicationUploadHooks{BeforeAdmission: configure, SigningFixture: func(f *aSameTaskCertificateMaterials) { signer = f }}, func(store *nativePublicationS3, native *aNativePublicationServer) {
				key := nativePublicationCredential{AccessKey: "catalog-test-delete-only", SecretKey: strings.Repeat("d", 32), NotBefore: time.Now().Add(-time.Minute), Until: native.deadline}
				raw, _ := json.Marshal(key)
				file := filepath.Join(filepath.Dir(store.config.ReadCredentialFile), "catalog-test-delete.json")
				if err := os.WriteFile(file, raw, 0600); err != nil {
					t.Fatal(err)
				}
				store.config.DeleteIdentityHash, store.config.DeleteRefVersion = hash([]byte("catalog fixture exact delete DATA")), "catalog-delete-v1"
				store.config.DeleteCredentialFile, store.config.DeleteCredentialSHA256 = file, hash(raw)
				native.remove = key
			})
		})
	}
}
