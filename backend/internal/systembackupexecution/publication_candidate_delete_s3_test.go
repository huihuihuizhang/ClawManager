package systembackupexecution

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newCandidateDeleteTransport(t *testing.T, handler func(http.ResponseWriter, *http.Request, nativePublicationCredential)) (*nativePublicationS3, ArtifactReadObject, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	deadline := now.Add(time.Minute)
	deleteKey := nativePublicationCredential{AccessKey: "dedicated-delete-only-local", SecretKey: strings.Repeat("d", 32), NotBefore: now.Add(-time.Minute), Until: deadline.Add(time.Minute)}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler(w, r, deleteKey) }))
	t.Cleanup(server.Close)
	root := t.TempDir()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	read, _ := json.Marshal(nativePublicationCredential{AccessKey: "independent-read-local", SecretKey: strings.Repeat("r", 32), NotBefore: now.Add(-time.Minute), Until: deadline.Add(time.Minute)})
	write, _ := json.Marshal(nativePublicationCredential{AccessKey: "immutable-write-local", SecretKey: strings.Repeat("w", 32), NotBefore: now.Add(-time.Minute), Until: deadline.Add(time.Minute)})
	remove, _ := json.Marshal(deleteKey)
	p := PublicationTargetMaterials{Version: publicationTargetVersion, InstallationID: "installation_delete_local", Endpoint: server.URL, Region: "local-1", Bucket: "formal-local", Root: "installation_delete_local/", RemoteStagingRoot: "staging/installation_delete_local/", ReadIdentityHash: hash([]byte("read")), ReadRefVersion: "r1", WriteIdentityHash: hash([]byte("write")), WriteRefVersion: "w1", CAIdentityHash: hash([]byte("ca")), CARefVersion: "ca1", DeleteIdentityHash: hash([]byte("delete")), DeleteRefVersion: "d1", CAFile: filepath.Join(root, "ca.pem"), CASHA256: hash(ca), ReadCredentialFile: filepath.Join(root, "read.json"), ReadCredentialSHA256: hash(read), WriteCredentialFile: filepath.Join(root, "write.json"), WriteCredentialSHA256: hash(write), DeleteCredentialFile: filepath.Join(root, "delete.json"), DeleteCredentialSHA256: hash(remove)}
	for path, raw := range map[string][]byte{p.CAFile: ca, p.ReadCredentialFile: read, p.WriteCredentialFile: write, p.DeleteCredentialFile: remove} {
		if os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("local transport fixture")
		}
	}
	store, err := newNativePublicationS3(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	object := ArtifactReadObject{Key: p.RemoteStagingRoot + "sbk_11111111-1111-4111-8111-111111111111/1/manifest-candidate.json", Version: "fixed-original-v1", SHA256: hash([]byte("candidate DATA")), Size: 14}
	return store, object, deadline
}

func TestCandidateDeleteUsesDedicatedPrincipalAndExactVersion(t *testing.T) {
	var deletes, reads atomic.Int32
	var removed atomic.Bool
	store, object, deadline := newCandidateDeleteTransport(t, func(w http.ResponseWriter, r *http.Request, key nativePublicationCredential) {
		if r.URL.Query().Get("versionId") != "fixed-original-v1" || !strings.HasSuffix(r.URL.Path, "/manifest-candidate.json") {
			http.Error(w, "denied", 403)
			return
		}
		if r.Method == http.MethodDelete {
			deletes.Add(1)
			if !aValidPublicationSignature(r, key, time.Now().Add(time.Minute)) {
				http.Error(w, "denied", 403)
				return
			}
			removed.Store(true)
			w.Header().Set("x-amz-version-id", "fixed-original-v1")
			w.WriteHeader(204)
			return
		}
		reads.Add(1)
		if r.Method != http.MethodGet || !strings.Contains(r.Header.Get("Authorization"), "Credential=independent-read-local/") {
			http.Error(w, "denied", 403)
			return
		}
		if !removed.Load() {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`<Error><Code>NoSuchVersion</Code><VersionId>fixed-original-v1</VersionId></Error>`))
	})
	backup := "sbk_11111111-1111-4111-8111-111111111111"
	if err := store.publicationCandidateVersionAbsent(context.Background(), backup, 1, object, deadline); err == nil {
		t.Fatal("present object became absent")
	}
	if _, err := loadNativePublicationCredential(store.config.DeleteCredentialFile, store.config.DeleteCredentialSHA256); err != nil {
		t.Fatal("dedicated local credential input", err)
	}
	if err := store.deleteFixedPublicationCandidateVersion(context.Background(), backup, 1, object, deadline); err != nil {
		t.Fatal("dedicated exact-version DELETE", err, "dispatch count", deletes.Load(), "scope valid", originalCandidateDeleteObject(store.config, backup, 1, object))
	}
	if err := store.publicationCandidateVersionAbsent(context.Background(), backup, 1, object, deadline); err != nil {
		t.Fatal("independent NoSuchVersion", err)
	}
	if deletes.Load() != 1 || reads.Load() != 2 {
		t.Fatal("unexpected provider requests", deletes.Load(), reads.Load())
	}
	for _, mode := range []string{"latest", "empty", "foreign-key", "artifact-key", "foreign-backup", "no-delete-mapping", "write-credential-file"} {
		copy := *store
		changed := object
		switch mode {
		case "latest":
			changed.Version = "latest"
		case "empty":
			changed.Version = ""
		case "foreign-key":
			changed.Key += "-foreign"
		case "artifact-key":
			changed.Key = store.config.Root + backup + "/1/manifest.json"
		case "foreign-backup":
			changed.Key = strings.ReplaceAll(changed.Key, backup, "sbk_22222222-2222-4222-8222-222222222222")
		case "no-delete-mapping":
			copy.config.DeleteIdentityHash = ""
			copy.config.DeleteRefVersion = ""
			copy.config.DeleteCredentialFile = ""
			copy.config.DeleteCredentialSHA256 = ""
		case "write-credential-file":
			copy.config.DeleteCredentialFile = copy.config.WriteCredentialFile
			copy.config.DeleteCredentialSHA256 = copy.config.WriteCredentialSHA256
		}
		if err := copy.deleteFixedPublicationCandidateVersion(context.Background(), backup, 1, changed, deadline); err == nil {
			t.Fatal("unauthorized delete transport", mode)
		}
	}
	if deletes.Load() != 1 {
		t.Fatal("foreign scope sent DELETE", deletes.Load())
	}
}

func TestCandidateDeleteUnknownAbsenceNeverSucceeds(t *testing.T) {
	if originalCandidateAbsenceBody([]byte(`<Error><Code>NoSuchVersion<Ambiguous>AccessDenied</Ambiguous></Code></Error>`), ArtifactReadObject{}) {
		t.Fatal("nested error code accepted")
	}
	for _, body := range []string{``, `<Error><Code>NoSuchKey</Code></Error>`, `<Error><Code>AccessDenied</Code></Error>`, `<Error><Code>NoSuchVersion</Code><Code>AccessDenied</Code></Error>`, `<Error><Code>AccessDenied</Code><Code>NoSuchVersion</Code></Error>`, `<Error><Code>NoSuchVersion</Code><VersionId>foreign</VersionId></Error>`, `<Error><Code>NoSuchVersion</Code><Key>foreign</Key></Error>`, `<Error><Code>NoSuchVersion</Code></Error><Error/>`, `<Error><Code>NoSuchVersion</Code>`, `<Denied><Code>NoSuchVersion</Code></Denied>`} {
		if originalCandidateAbsenceBody([]byte(body), ArtifactReadObject{Version: "original", Key: "original"}) {
			t.Fatal("unknown absence accepted", body)
		}
	}
	for _, mode := range []string{"403", "500", "generic404", "still-present", "wrong-xml-version"} {
		t.Run(mode, func(t *testing.T) {
			store, object, deadline := newCandidateDeleteTransport(t, func(w http.ResponseWriter, r *http.Request, _ nativePublicationCredential) {
				switch mode {
				case "403":
					w.WriteHeader(403)
				case "500":
					w.WriteHeader(500)
				case "still-present":
					w.WriteHeader(200)
				case "generic404":
					w.WriteHeader(404)
				case "wrong-xml-version":
					w.WriteHeader(404)
					_, _ = w.Write([]byte(`<Error><Code>NoSuchVersion</Code><VersionId>foreign</VersionId></Error>`))
				}
			})
			if err := store.publicationCandidateVersionAbsent(context.Background(), "sbk_11111111-1111-4111-8111-111111111111", 1, object, deadline); err == nil {
				t.Fatal("unknown remote state became cleanup success")
			}
		})
	}
}

func TestCandidateDeleteLostACKAndSuccessfulACKBothRequireIndependentAbsence(t *testing.T) {
	for _, mode := range []string{"lost-ack-but-absent", "successful-ack-but-retained"} {
		t.Run(mode, func(t *testing.T) {
			var sends atomic.Int32
			var removed atomic.Bool
			store, object, deadline := newCandidateDeleteTransport(t, func(w http.ResponseWriter, r *http.Request, key nativePublicationCredential) {
				if r.Method == http.MethodDelete {
					if r.URL.Query().Get("versionId") != "fixed-original-v1" || !aValidPublicationSignature(r, key, time.Now().Add(time.Minute)) {
						w.WriteHeader(403)
						return
					}
					sends.Add(1)
					if mode == "lost-ack-but-absent" {
						removed.Store(true)
						w.WriteHeader(503)
						return
					}
					w.Header().Set("x-amz-version-id", "fixed-original-v1")
					w.WriteHeader(204)
					return
				}
				if r.Method != http.MethodGet || r.URL.Query().Get("versionId") != "fixed-original-v1" || !strings.Contains(r.Header.Get("Authorization"), "Credential=independent-read-local/") {
					w.WriteHeader(403)
					return
				}
				if !removed.Load() {
					w.WriteHeader(200)
					return
				}
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`<Error><Code>NoSuchVersion</Code></Error>`))
			})
			backup := "sbk_11111111-1111-4111-8111-111111111111"
			ack := store.deleteFixedPublicationCandidateVersion(context.Background(), backup, 1, object, deadline)
			absence := store.publicationCandidateVersionAbsent(context.Background(), backup, 1, object, deadline)
			if mode == "lost-ack-but-absent" {
				if ack == nil || absence != nil {
					t.Fatal("lost ACK did not resolve by independent exact absence", ack, absence)
				}
			} else if ack != nil || absence == nil {
				t.Fatal("successful DELETE ACK substituted for real absence", ack, absence)
			}
			if sends.Load() != 1 {
				t.Fatal("unknown DELETE retried", sends.Load())
			}
		})
	}
}
