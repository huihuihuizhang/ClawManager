package systembackupevidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawreef/internal/systembackupbusinessa"
)

// This adapter exercises real encrypted file bytes in an owned temporary
// directory. It is a test provider, not a production filesystem authority.
type businessReportFileStore struct {
	*testStore
	path string
}

func (s *businessReportFileStore) Put(ctx context.Context, ref Ref, r io.Reader, want ObjectInfo, until time.Time) error {
	if err := s.testStore.Put(ctx, ref, r, want, until); err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(s.data)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

type businessReportFileRange struct {
	io.Reader
	io.Closer
}

func (s *businessReportFileStore) Range(_ context.Context, ref Ref, offset, length int64) (io.ReadCloser, error) {
	s.reads++
	if ref.ImmutableVersion != s.info.Version || offset < 0 || length < 0 || offset > s.info.Size-length {
		return nil, ErrUnavailable
	}
	f, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	return businessReportFileRange{Reader: io.NewSectionReader(f, offset, length), Closer: f}, nil
}

// Synthetic capture authority is confined to this delivery test. Real SQL
// comparison/proof validation is covered by the separate MySQL entry point.
type businessReportDeliveryProof struct{}

func (businessReportDeliveryProof) VerifyCapture(context.Context, systembackupbusinessa.CaptureEvidence, systembackupbusinessa.CaptureEvidence) error {
	return nil
}

func businessReportDeliveryBody(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../systembackupbusinessa/testdata/schema-registry.json")
	if err != nil {
		t.Fatal(err)
	}
	var registry map[string]any
	if err := json.Unmarshal(raw, &registry); err != nil {
		t.Fatal(err)
	}
	registry["contract_status"] = "frozen"
	schema := registry["schema_hash"].(map[string]any)
	schema["status"], schema["hash"] = "observed", strings.Repeat("a", 64)
	schema["evidence"] = map[string]any{"public_id": "sev_fixture", "sha256": strings.Repeat("b", 64)}
	objects := registry["objects"].([]any)
	summary := registry["summary"].(map[string]any)
	summary["object_count"], summary["policy_recorded"] = len(objects), len(objects)
	summary["policy_pending"], summary["cross_review_pending"] = 0, 0
	for _, item := range objects {
		object := item.(map[string]any)
		object["decision_status"], object["approved_cross_reviewers"] = "frozen", object["required_cross_reviewers"]
	}
	raw, err = json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	scope, err := systembackupbusinessa.NewPinnedCaptureScope(raw, hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	emptyCost := sha256.Sum256([]byte("cost-record-aggregate-v1\n[]"))
	snapshot := systembackupbusinessa.SourceSnapshot{CostAggregateSHA256: hex.EncodeToString(emptyCost[:])}
	for _, name := range scope.Tables() {
		snapshot.Tables = append(snapshot.Tables, systembackupbusinessa.TableCount{Table: name})
	}
	evidence := systembackupbusinessa.CaptureEvidence{RegistrySHA256: scope.RegistrySHA256(), SchemaSHA256: scope.SchemaSHA256(),
		CheckpointHash: strings.Repeat("c", 64), CaptureContextHash: strings.Repeat("d", 64), EvidenceRef: "sev_fixture", Snapshot: snapshot}
	target := systembackupbusinessa.ReportTarget{Type: "backup", PublicID: "sbk_11111111-2222-4333-8444-555555555555"}
	reports, err := systembackupbusinessa.VerifyBackupReports(context.Background(), target, scope, evidence, evidence, businessReportDeliveryProof{})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.MarshalIndent(reports, "", "    ")
	if err != nil || len(body) <= 8192 {
		t.Fatal("report fixture must use the external-body path", len(body), err)
	}
	return body
}

func TestBusinessReportEncryptedFileAuthorizedDownloadAndAudit(t *testing.T) {
	body := businessReportDeliveryBody(t)
	for _, name := range []string{"authorized", "denied", "audit_unavailable", "file_tampered"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			id := Identity{Installation: "installation_test", ID: "sev_11111111-2222-4333-8444-555555555555",
				OwnerType: "backup", OwnerID: "sbk_11111111-2222-4333-8444-555555555555", Type: "verifier_report",
				Media: "application/json", Classification: "sensitive", ContentHash: hash(body), ContentSize: int64(len(body))}
			keys := testKeys{key: bytes.Repeat([]byte{7}, 32)}
			var encrypted bytes.Buffer
			prepared, err := Prepare(ctx, id, KeyRef{strings.Repeat("b", 64), "v1"}, source(body), testRedactor{}, keys, &encrypted)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			registry := &memoryRegistry{now: now}
			store := &businessReportFileStore{testStore: &testStore{authoritative: true}, path: filepath.Join(t.TempDir(), "encrypted-report.bin")}
			service := Service{Registry: registry, Store: store, Keys: keys, Failure: func(context.Context, string, string) {}}
			if err := service.Register(ctx, prepared, "evidence", Ref{Identity: strings.Repeat("a", 64), Version: "v1"}, now, now.Add(time.Hour), now.Add(2*time.Hour), now.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			if err := service.Publish(ctx, id.ID, source(encrypted.Bytes())); err != nil {
				t.Fatal(err)
			}
			stored, err := os.ReadFile(store.path)
			if err != nil || bytes.Contains(stored, []byte("system-backup-verifier-result.v1")) || bytes.Equal(stored, body) {
				t.Fatal("plaintext report stored on disk", err)
			}
			want := 200
			switch name {
			case "denied":
				registry.denied, want = true, 403
			case "audit_unavailable":
				registry.failAudit, want = true, 500
			case "file_tampered":
				stored[len(stored)-1] ^= 1
				if err := os.WriteFile(store.path, stored, 0600); err != nil {
					t.Fatal(err)
				}
				want = 409
			}
			r := httptest.NewRequest("GET", Path+id.ID, nil)
			r.TLS = &tls.ConnectionState{}
			w := httptest.NewRecorder()
			Handler{Service: service, Auth: testAuth{}}.ServeHTTP(w, r)
			if w.Code != want {
				t.Fatal("unexpected download status", w.Code, w.Body.String())
			}
			if name == "authorized" {
				if !bytes.Equal(w.Body.Bytes(), body) || len(registry.audits) != 2 || registry.audits[1].Outcome != "sent" {
					t.Fatal("report bytes or download audit missing")
				}
				for _, audit := range registry.audits {
					if audit.EvidenceID != id.ID || audit.ActorID != "admin" || audit.ID == "" {
						t.Fatal("audit lost report or actor binding", audit)
					}
				}
			} else if bytes.Contains(w.Body.Bytes(), []byte("system-backup-verifier-result.v1")) {
				t.Fatal("failed download leaked report")
			}
			if (name == "denied" || name == "audit_unavailable") && store.reads != 0 {
				t.Fatal("failed authorization/audit opened report file")
			}
		})
	}
}
