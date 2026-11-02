package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	c "clawreef/internal/systembackupcontroller"
)

// Same actual original task/worker/cleanup/final/acceptance/catalog chain.
// Native Kube/S3/provider endpoints remain local fixtures, not real-page PASS.
func runPublicationDecisionOriginalRegistered(t *testing.T, lose *atomic.Bool, after func(context.Context, *testing.T, *dOriginalSixPartTask, *publicationRegisteredObject, *aSameTaskCertificateMaterials, *aNativePublicationServer, *aNativePublicationServer, *atomic.Int64), completeNonDR ...bool) {
	t.Helper()
	if os.Getenv("TEST_D_SIXPART_TLS_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires exclusively handed-over original SAN/TLS MySQL")
	}
	clocks := &atomic.Int64{}
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
		o.ControlCommitACKLoss = lose
		previousQuery := o.ControlAfterQuery
		o.ControlAfterQuery = func(query string, cause error) {
			if previousQuery != nil {
				previousQuery(query, cause)
			}
			if cause == nil && strings.Contains(query, "/* original publication decision clock */") {
				clocks.Add(1)
			}
		}
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
		accepted, err := f.service.completeOriginalPublicationAcceptance(ctx, proof)
		if err != nil || accepted == nil {
			t.Fatal("actual original acceptance", err)
		}
		registered, err := f.service.completeOriginalPublicationCatalog(ctx, accepted)
		if err != nil || registered == nil {
			t.Fatal("actual original catalog registration", err)
		}
		if registered.signed.prepared.catalog != material {
			t.Fatal("catalog material drift")
		}
		after(ctx, t, f, registered, signer, native, state, clocks)
	}, &aOriginalPublicationUploadHooks{CompleteNonDR: len(completeNonDR) == 1 && completeNonDR[0], BeforeAdmission: configure, SigningFixture: func(f *aSameTaskCertificateMaterials) { signer = f }}, func(store *nativePublicationS3, native *aNativePublicationServer) {
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
}

type decisionSQLSnapshot struct {
	SHA                       string
	Bytes, Version            uint64
	Expires, Created, Updated time.Time
}

func decisionFixtureSnapshot(t *testing.T, ctx context.Context, f *dOriginalSixPartTask, id string) decisionSQLSnapshot {
	t.Helper()
	var out decisionSQLSnapshot
	if err := f.db.QueryRowContext(ctx, `SELECT content_checksum,content_size_bytes,row_version,expires_at,created_at,updated_at FROM system_backup_v2_evidence WHERE public_id=?`, id).Scan(&out.SHA, &out.Bytes, &out.Version, &out.Expires, &out.Created, &out.Updated); err != nil {
		t.Fatal(err)
	}
	return out
}

func decisionFixtureNoExternalWork(t *testing.T, ctx context.Context, f *dOriginalSixPartTask, signer *aSameTaskCertificateMaterials, artifact, catalog *aNativePublicationServer, before int64) {
	t.Helper()
	if signer.signs.Load() != before {
		t.Fatal("decision re-signed an external record", signer.signs.Load(), before)
	}
	artifact.mu.Lock()
	artifactPuts := artifact.puts
	artifact.mu.Unlock()
	catalog.mu.Lock()
	catalogPuts := catalog.puts
	catalog.mu.Unlock()
	if artifactPuts != 19 || catalogPuts != 1 {
		t.Fatal("decision re-published external objects", artifactPuts, catalogPuts)
	}
	var status string
	var usable, eligible bool
	if f.control.QueryRowContext(ctx, `SELECT status,artifact_usable,acceptance_eligible FROM system_backup_v2_backups WHERE public_id=?`, f.publicID).Scan(&status, &usable, &eligible) != nil || status != "publishing" || usable || eligible {
		t.Fatal("internal evidence manufactured terminal state", status, usable, eligible)
	}
}

func TestPublicationDecisionOriginalImmutableEvidenceMySQL(t *testing.T) {
	for _, mode := range []string{"current", "query-only-missing", "bad-before-first", "orphan-before-first", "unhealthy", "expired", "orphan", "missing"} {
		t.Run(mode, func(t *testing.T) {
			runPublicationDecisionOriginalRegistered(t, nil, func(ctx context.Context, t *testing.T, f *dOriginalSixPartTask, registered *publicationRegisteredObject, signer *aSameTaskCertificateMaterials, artifact, catalog *aNativePublicationServer, clocks *atomic.Int64) {
				before := signer.signs.Load()
				prepared, err := f.service.prepareOriginalPublicationDecision(ctx, registered)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "query-only-missing" {
					if result, err := prepared.Query(ctx); !errors.Is(err, c.ErrExecutionCommitUnknown) || result != nil {
						t.Fatal("missing query fabricated evidence", err)
					}
					if result, err := prepared.Persist(ctx); !errors.Is(err, c.ErrExecutionCommitUnknown) || result != nil {
						t.Fatal("query invocation became a fresh initializer", err)
					}
					if clocks.Load() != 0 || len(prepared.raw) != 0 {
						t.Fatal("query captured another decision clock")
					}
					decisionFixtureNoExternalWork(t, ctx, f, signer, artifact, catalog, before)
					return
				}
				if mode == "bad-before-first" || mode == "orphan-before-first" {
					proof := registered.signed.prepared.proof
					id := publicationDecisionID(proof.target.InstallationID, f.publicID, proof.attempt)
					if mode == "orphan-before-first" {
						id += "_orphan"
					}
					// Explicit owned malformed metadata DATA at the decision root,
					// copied from an actual unrelated protocol body, not authority.
					result, err := f.db.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence(origin_installation_id,public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at) SELECT origin_installation_id,?,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at FROM system_backup_v2_evidence WHERE public_id=?`, id, registered.signed.prepared.id()+"_prepared")
					if err != nil || publicationOneRow(result) != nil {
						t.Fatal("owned malformed decision metadata", err)
					}
					if evidence, err := prepared.Persist(ctx); err == nil || evidence != nil {
						t.Fatal("existing bad/orphan metadata became first decision", mode, err)
					}
					if evidence, err := prepared.Persist(ctx); err == nil || evidence != nil {
						t.Fatal("bad/orphan retry created decision", mode, err)
					}
					if clocks.Load() != 0 || len(prepared.raw) != 0 {
						t.Fatal("bad/orphan metadata refreshed original clock")
					}
					decisionFixtureNoExternalWork(t, ctx, f, signer, artifact, catalog, before)
					return
				}
				evidence, err := prepared.Persist(ctx)
				if err != nil || evidence == nil || clocks.Load() != 1 {
					t.Fatal("actual original immutable decision persistence", err, clocks.Load())
				}
				original := bytes.Clone(prepared.raw)
				decoded, at, err := decodePublicationDecision(original)
				if err != nil || evidence.ref.SHA256 != hash(original) || decoded.RegistrationSHA != registered.object.SHA256 || decoded.CleanupSHA256 != registered.signed.prepared.proof.cleanup.evidence.SHA256 {
					t.Fatal("decision substituted original evidence", err)
				}
				local, _ := decodePublicationAcceptancePayload(registered.signed.prepared.accepted.signed.prepared.intent.Payload)
				registration, _ := decodePublicationCatalogPayload(registered.signed.prepared.intent.Payload)
				localAt, _ := time.Parse(time.RFC3339Nano, local.DecisionAt)
				catalogAt, _ := time.Parse(time.RFC3339Nano, registration.At)
				var now time.Time
				if f.db.QueryRowContext(ctx, `SELECT UTC_TIMESTAMP(6)`).Scan(&now) != nil || !publicationDecisionClockValid(at, localAt, catalogAt, now) {
					t.Fatal("SQL decision time did not follow both signatures")
				}
				id := evidence.ref.PublicID
				snapshot := decisionFixtureSnapshot(t, ctx, f, id)
				again, err := prepared.Persist(ctx)
				if err != nil || again == nil || !bytes.Equal(again.row.raw, original) || again.ref != evidence.ref {
					t.Fatal("repeat changed original decision", err)
				}
				queried, err := f.service.queryOriginalPublicationDecision(ctx, registered)
				if err != nil || queried == nil || !bytes.Equal(queried.row.raw, original) || queried.ref != evidence.ref {
					t.Fatal("independent original decision query", err)
				}
				if after := decisionFixtureSnapshot(t, ctx, f, id); after != snapshot || clocks.Load() != 1 {
					t.Fatal("readback refreshed bytes/RV/retention/timestamps", after, snapshot, clocks.Load())
				}
				tx, err := f.control.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
				if err != nil {
					t.Fatal(err)
				}
				check := evidence.recheckTx(ctx, tx)
				_ = tx.Rollback()
				if check != nil {
					t.Fatal("actual read-only decision consumer", check)
				}
				if mode == "current" {
					for _, field := range []string{"config", "acceptance", "registration", "cleanup", "time"} {
						altered := decoded
						switch field {
						case "config":
							altered.ConfigSHA256 = hash([]byte("other config DATA"))
						case "acceptance":
							altered.AcceptanceSHA256 = hash([]byte("other signed acceptance DATA"))
						case "registration":
							altered.RegistrationSHA = hash([]byte("other signed catalog DATA"))
						case "cleanup":
							altered.CleanupSHA256 = hash([]byte("other cleanup DATA"))
						case "time":
							altered.DecisionAt = at.Add(-time.Hour).UTC().Format(time.RFC3339Nano)
						}
						body, _ := ce.Canonical(altered)
						fake := *evidence
						fake.row.raw, fake.row.sha = body, hash(body)
						fake.ref.SHA256 = fake.row.sha
						tx, err := f.control.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
						if err != nil {
							t.Fatal(err)
						}
						check := fake.recheckTx(ctx, tx)
						_ = tx.Rollback()
						if check == nil {
							t.Fatal("reshaped DTO replaced original committed decision", field)
						}
					}
				}
				if mode != "current" {
					// Owned fixture fault DATA, not an owner recovery or reissue.
					switch mode {
					case "unhealthy":
						_, err = f.db.ExecContext(ctx, `UPDATE system_backup_v2_evidence SET observed_health='unknown' WHERE public_id=?`, id)
					case "expired":
						_, err = f.db.ExecContext(ctx, `UPDATE system_backup_v2_evidence SET expires_at=DATE_SUB(UTC_TIMESTAMP(6),INTERVAL 1 SECOND) WHERE public_id=?`, id)
					case "orphan":
						_, err = f.db.ExecContext(ctx, `INSERT INTO system_backup_v2_evidence(origin_installation_id,public_id,owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at) SELECT origin_installation_id,CONCAT(public_id,'_orphan'),owner_target_type,owner_target_public_id,evidence_type,storage_state,inline_payload,content_checksum,content_size_bytes,media_type,encryption,redaction_classification,observed_health,expires_at FROM system_backup_v2_evidence WHERE public_id=?`, id)
					case "missing":
						_, err = f.db.ExecContext(ctx, `DELETE FROM system_backup_v2_evidence WHERE public_id=?`, id)
					}
					if err != nil {
						t.Fatal(err)
					}
					if result, err := prepared.Persist(ctx); err == nil || result != nil {
						t.Fatal("fault reminted original decision", mode, err)
					}
					if result, err := f.service.queryOriginalPublicationDecision(ctx, registered); err == nil || result != nil {
						t.Fatal("fault query fabricated decision", mode, err)
					}
					if !bytes.Equal(prepared.raw, original) || clocks.Load() != 1 {
						t.Fatal("fault replaced retained preimage or clock", clocks.Load())
					}
				}
				decisionFixtureNoExternalWork(t, ctx, f, signer, artifact, catalog, before)
			})
		})
	}
}

func TestPublicationDecisionCommitUnknownQueryOnlyMySQL(t *testing.T) {
	for _, mode := range []string{"committed", "original-row-lost"} {
		t.Run(mode, func(t *testing.T) {
			lose := &atomic.Bool{}
			runPublicationDecisionOriginalRegistered(t, lose, func(ctx context.Context, t *testing.T, f *dOriginalSixPartTask, registered *publicationRegisteredObject, signer *aSameTaskCertificateMaterials, artifact, catalog *aNativePublicationServer, clocks *atomic.Int64) {
				before := signer.signs.Load()
				prepared, err := f.service.prepareOriginalPublicationDecision(ctx, registered)
				if err != nil {
					t.Fatal(err)
				}
				lose.Store(true) // Existing native driver commits, then loses ONE write ACK.
				if evidence, err := prepared.Persist(ctx); !errors.Is(err, c.ErrExecutionCommitUnknown) || evidence != nil || lose.Load() || clocks.Load() != 1 {
					t.Fatal("actual decision commit ACK was not lost", err, clocks.Load())
				}
				original := bytes.Clone(prepared.raw)
				proof := registered.signed.prepared.proof
				id := publicationDecisionID(proof.target.InstallationID, f.publicID, proof.attempt)
				snapshot := decisionFixtureSnapshot(t, ctx, f, id)
				if snapshot.SHA != hash(original) {
					t.Fatal("unknown commit did not preserve actual preimage")
				}
				if mode == "original-row-lost" {
					// Deliberate owned SQL fault after the actual committed ACK loss;
					// missing original evidence grants no new clock/INSERT permission.
					if _, err = f.db.ExecContext(ctx, `DELETE FROM system_backup_v2_evidence WHERE public_id=?`, id); err != nil {
						t.Fatal(err)
					}
					if evidence, err := prepared.Persist(ctx); !errors.Is(err, c.ErrExecutionCommitUnknown) || evidence != nil {
						t.Fatal("missing unknown result reinitialized", err)
					}
					if evidence, err := prepared.Query(ctx); !errors.Is(err, c.ErrExecutionCommitUnknown) || evidence != nil {
						t.Fatal("missing unknown result manufactured proof", err)
					}
				} else {
					evidence, err := prepared.Query(ctx)
					if err != nil || evidence == nil || evidence.ref.SHA256 != snapshot.SHA || !bytes.Equal(evidence.row.raw, original) {
						t.Fatal("actual committed decision query-only recovery", err)
					}
					if evidence, err := prepared.Persist(ctx); err != nil || evidence == nil || !bytes.Equal(evidence.row.raw, original) {
						t.Fatal("repeat unknown path did not stay query-only", err)
					}
					if after := decisionFixtureSnapshot(t, ctx, f, id); after != snapshot {
						t.Fatal("ACK recovery refreshed original metadata", after, snapshot)
					}
				}
				if !bytes.Equal(prepared.raw, original) || clocks.Load() != 1 {
					t.Fatal("ACK recovery changed frozen clock/preimage", clocks.Load())
				}
				decisionFixtureNoExternalWork(t, ctx, f, signer, artifact, catalog, before)
			})
		})
	}
}
