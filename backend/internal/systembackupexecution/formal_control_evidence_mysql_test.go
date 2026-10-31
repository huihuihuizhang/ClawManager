package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/staging"
	"clawreef/internal/systembackup/worker"
	ce "clawreef/internal/systembackupcontrolevidence"
	d "clawreef/internal/systembackupdispatch"
	k "clawreef/internal/systembackupkms"
	w "clawreef/internal/systembackupwire"
	corev1 "k8s.io/api/core/v1"
)

// Real original SQL plan/candidate/Job/observer/result path. Source proof bodies,
// producer key/unwrap and Kubernetes/finished-use are explicit local fixtures;
// this is not the actual SQL producer or mTLS pull acceptance test.
func TestControlEvidenceOriginalSQLConsumerAndIndependentCustody(t *testing.T) {
	if os.Getenv("TEST_D_LOCAL_MYSQL_CREDENTIALS") == "" {
		t.Skip("requires disposable local MySQL")
	}
	for _, part := range []string{ce.Part, ce.ProofPart} {
		for _, mode := range []string{"valid", "suffix", "missing-proof", "wrong-hash"} {
			t.Run(part+"/"+mode, func(t *testing.T) {
				var prepared ce.PreparedSource
				options := &consumerFixtureOptions{PartName: part, Category: ce.Part, RequestedParts: []string{"mysql"}, JobDeadlineSeconds: 60}
				options.PrepareSource = func(_ *os.Root, i *worker.Invocation) {
					i.Request.Operation = ce.Operation
					i.WorkspacePath = ""
					i.Request.MaxFiles, i.Request.MaxFileBytes = 0, 0
					i.Request.Binding.Path = part
					i.ProviderKey.Request.Context.Part = part
					i.Request.ArtifactName = ce.LogicalCipherName
					i.Request.MaxArchiveBytes, i.Request.MaxCompressedBytes = ce.MaxBytes, ce.MaxBytes
					if part == ce.ProofPart {
						i.Request.ArtifactName = ce.LogicalProofCipherName
						i.Request.MaxArchiveBytes, i.Request.MaxCompressedBytes = ce.MaxProofBytes, ce.MaxProofBytes
					}
					i.FormalCapture.MaxFrames = 64
					i.FormalCapture.PermitDelivery = &k.PermitDeliveryPin{Version: k.PermitDeliveryVersion, Issuer: bytes.Repeat([]byte{4}, 32), IssuerGrantSHA256: strings.Repeat("e", 64)}
				}
				options.Configure = func(i *worker.Invocation, _ *sql.DB, _ *sql.DB, a d.Authority) {
					expected := ce.Expected{Scope: ce.Scope{Installation: a.InstallationID, Backup: a.TaskPublicID, Attempt: a.AttemptNo}, ConfigSHA256: a.ConfigSHA256, SourceIdentitySHA256: hash([]byte("named original source fixture")), SchemaRegistry: ce.RegistryPin{Version: "s1", SHA256: hash([]byte("schema"))}, RedactionRegistry: ce.RegistryPin{Version: "r1", SHA256: hash([]byte("redaction"))}}
					prepared = controlContentProposal(t, expected).Prepared
					i.Request.ControlEvidence = &prepared.Locator
					i.FormalCapture.SourceConfigSHA256 = a.ConfigSHA256
				}
				options.ConfigureWorkload = func(r *kube.JobRequest) { r.Source = corev1.Volume{}; r.SourceSubPath = "" }
				options.FormalMaterials = &kube.FormalJobMaterials{ConfigMap: "original-control-materials", Inputs: []kube.FormalInputMount{{Volume: "formal-control-source", Kind: "ConfigMap", Name: "original-control-source", Directory: "/run/backup/materials/control-source", Items: []corev1.KeyToPath{{Key: "grant.json", Path: "grant.json"}}}}}
				options.RewriteCandidate = func(_ *os.Root, i worker.Invocation, r worker.FormalCaptureResult, keys *candidateContentUnwrapper) (*os.Root, worker.FormalCaptureResult) {
					payload := bytes.Clone(prepared.SidecarJSON)
					if part == ce.ProofPart {
						payload = bytes.Clone(prepared.ProofsJSON)
					}
					defer clear(payload)
					if mode == "suffix" {
						payload = append(payload, []byte(`{}`)...)
					}
					if mode == "wrong-hash" {
						payload[0] = '['
					}
					if mode == "missing-proof" {
						if part == ce.ProofPart {
							var bundle ce.ProofBundle
							json.Unmarshal(payload, &bundle)
							bundle.Entries = bundle.Entries[1:]
							payload, _ = ce.CanonicalProofs(bundle)
						} else {
							payload = []byte(`{}`)
						}
					}
					return forgeControlContentCandidate(t, i, r, keys, payload)
				}
				owner, _, _, db, a, j, _, _, refresh := newConsumerMySQLFixtureOptions(t, options)
				refresh()
				ref, err := owner.Evidence(context.Background(), a, j)
				var results, evidence int
				if db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_runtime_resources WHERE result_sha256 IS NOT NULL").Scan(&results) != nil || db.QueryRow("SELECT COUNT(*) FROM system_backup_v2_evidence").Scan(&evidence) != nil {
					t.Fatal("original result count")
				}
				if mode == "valid" {
					if err != nil || ref == nil || results != 1 || evidence != 1 {
						t.Fatal("original CE content did not pass", err)
					}
				} else if err == nil || ref != nil || results != 0 || evidence != 0 {
					t.Fatal("valid AEAD malformed CE body produced original evidence", err)
				}
			})
		}
	}
}

func forgeControlContentCandidate(t *testing.T, i worker.Invocation, candidate worker.FormalCaptureResult, keys *candidateContentUnwrapper, payload []byte) (*os.Root, worker.FormalCaptureResult) {
	t.Helper()
	spec := w.StreamSpec{Request: i.ProviderKey.Request, Path: i.Request.ArtifactName, MaxPlaintextBytes: i.Request.MaxCompressedBytes, MaxFrames: i.FormalCapture.MaxFrames}
	var ciphertext bytes.Buffer
	seal, err := w.EncryptStream(context.Background(), spec, keys.key, &ciphertext, func(dst io.Writer) error { _, err := dst.Write(payload); return err })
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := seal.EnvelopeJSON(w.WrappedKey{Request: spec.Request, Algorithm: "provider-native", Ciphertext: []byte("named local original CE producer fixture")})
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { source.Close() })
	receipt := func(name string, body []byte) staging.Receipt {
		if source.WriteFile(name, body, 0600) != nil {
			t.Fatal("encrypted CE fixture write")
		}
		return staging.Receipt{Name: name, Size: int64(len(body)), SHA256: hash(body)}
	}
	candidate.Ciphertext, candidate.Envelope = receipt(i.Request.ArtifactName, ciphertext.Bytes()), receipt(i.FormalCapture.EnvelopeName, envelope)
	candidate.Files, candidate.Bytes, candidate.Rows, candidate.Tables = 0, 0, 0, 0
	return source, candidate
}
