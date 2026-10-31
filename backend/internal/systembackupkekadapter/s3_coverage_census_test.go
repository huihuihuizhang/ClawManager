package systembackupkekadapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
)

func TestNativeS3CoverageCensusVersionsHoldsAndUnknownUploads(t *testing.T) {
	for _, mode := range []string{"valid", "zero-version", "no-object-lock", "lock-missing", "lock-duplicate", "lock-trailing-root", "retention-duplicate", "hold-duplicate", "metadata-trailing-root", "missing-size", "missing-etag", "missing-next", "repeated-next", "nonadjacent-cycle", "empty-truncated", "missing-eof-field", "wrong-prefix", "duplicate-version", "wrong-marker-echo", "reordered-keys", "upload-denied", "retention-denied", "credentials-changed"} {
		t.Run(mode, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "inventory-read.json")
			credential := []byte(`{"access_key":"local-read-only-access","secret_key":"local-inventory-test-secret","session_token":""}`)
			if os.WriteFile(file, credential, 0600) != nil {
				t.Fatal("credential fixture")
			}
			var writes, requests atomic.Int64
			version := func(key, id string, latest bool) string {
				size := "7"
				if mode == "zero-version" {
					size = "0"
				}
				raw := fmt.Sprintf(`<Version><Key>%s</Key><VersionId>%s</VersionId><IsLatest>%t</IsLatest><LastModified>2026-10-31T10:00:00Z</LastModified><ETag>"public-etag"</ETag><Size>%s</Size><StorageClass>STANDARD</StorageClass></Version>`, key, id, latest, size)
				if mode == "missing-size" {
					raw = strings.ReplaceAll(raw, "<Size>7</Size>", "")
				}
				if mode == "missing-etag" {
					raw = strings.ReplaceAll(raw, `<ETag>"public-etag"</ETag>`, "")
				}
				return raw
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				out.Header().Set("Content-Type", "application/xml")
				if r.Method != "GET" {
					writes.Add(1)
					out.WriteHeader(405)
					return
				}
				if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
					t.Error("native request was not signed")
				}
				q := r.URL.Query()
				switch {
				case q.Has("versioning"):
					fmt.Fprint(out, `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`)
				case q.Has("object-lock"):
					if mode == "no-object-lock" {
						out.WriteHeader(404)
						fmt.Fprint(out, `<Error><Code>ObjectLockConfigurationNotFoundError</Code></Error>`)
						return
					}
					if mode == "lock-missing" {
						fmt.Fprint(out, `<ObjectLockConfiguration/>`)
						return
					}
					if mode == "lock-duplicate" {
						fmt.Fprint(out, `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><ObjectLockEnabled></ObjectLockEnabled></ObjectLockConfiguration>`)
						return
					}
					if mode == "lock-trailing-root" {
						fmt.Fprint(out, `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration><Other/>`)
						return
					}
					fmt.Fprint(out, `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`)
				case q.Has("versions"):
					if mode == "nonadjacent-cycle" {
						key, token, nextKey, nextToken, item := "", "", "root/a", "va", version("root/a", "va", true)
						if q.Get("key-marker") == "root/a" {
							key, token, nextKey, nextToken, item = "root/a", "va", "root/b", "vb", version("root/b", "vb", true)
						}
						if q.Get("key-marker") == "root/b" {
							key, token, nextKey, nextToken, item = "root/b", "vb", "root/a", "va", version("root/c", "vc", true)
						}
						fmt.Fprintf(out, `<ListVersionsResult><Name>bucket</Name><Prefix>root/</Prefix><KeyMarker>%s</KeyMarker><VersionIdMarker>%s</VersionIdMarker><NextKeyMarker>%s</NextKeyMarker><NextVersionIdMarker>%s</NextVersionIdMarker><IsTruncated>true</IsTruncated>%s</ListVersionsResult>`, key, token, nextKey, nextToken, item)
						return
					}
					prefix := "root/"
					if mode == "wrong-prefix" {
						prefix = "neighbor/"
					}
					if q.Get("key-marker") == "" {
						entries := `<DeleteMarker><Key>root/a</Key><VersionId>delete-v3</VersionId><IsLatest>true</IsLatest><LastModified>2026-10-31T10:00:00Z</LastModified></DeleteMarker>` + version("root/a", "old-v2", false)
						next := `<NextKeyMarker>root/a</NextKeyMarker><NextVersionIdMarker>old-v2</NextVersionIdMarker>`
						if mode == "missing-next" {
							next = ""
						}
						if mode == "empty-truncated" {
							entries = ""
						}
						fmt.Fprintf(out, `<ListVersionsResult><Name>bucket</Name><Prefix>%s</Prefix><KeyMarker></KeyMarker><VersionIdMarker></VersionIdMarker><IsTruncated>true</IsTruncated>%s%s</ListVersionsResult>`, prefix, next, entries)
						if mode == "credentials-changed" {
							if os.WriteFile(file, []byte(`{}`), 0600) != nil {
								t.Error("credential replacement fixture")
							}
						}
					} else {
						marker := "root/a"
						if mode == "wrong-marker-echo" {
							marker = "root/wrong"
						}
						first := version("root/a", "old-v1", false)
						if mode == "duplicate-version" {
							first = version("root/a", "old-v2", false)
						}
						if mode == "reordered-keys" {
							first = version("root/0", "other", true)
						}
						last := `<IsTruncated>false</IsTruncated>`
						if mode == "missing-eof-field" {
							last = ""
						}
						if mode == "repeated-next" {
							last = `<IsTruncated>true</IsTruncated><NextKeyMarker>root/a</NextKeyMarker><NextVersionIdMarker>old-v2</NextVersionIdMarker>`
						}
						fmt.Fprintf(out, `<ListVersionsResult><Name>bucket</Name><Prefix>%s</Prefix><KeyMarker>%s</KeyMarker><VersionIdMarker>old-v2</VersionIdMarker>%s%s%s%s</ListVersionsResult>`, prefix, marker, last, first, version("root/b", "held-v4", true), version("root/legacy", "null", true))
					}
				case q.Has("retention"):
					if mode == "retention-duplicate" {
						fmt.Fprint(out, `<Retention><Mode>COMPLIANCE</Mode><Mode>GOVERNANCE</Mode><RetainUntilDate>2027-10-31T00:00:00Z</RetainUntilDate></Retention>`)
						return
					}
					if mode == "metadata-trailing-root" {
						fmt.Fprint(out, `<Retention/><Other/>`)
						return
					}
					if mode == "retention-denied" {
						out.WriteHeader(403)
						fmt.Fprint(out, `<Error><Code>AccessDenied</Code></Error>`)
						return
					}
					if r.URL.Path == "/bucket/root/b" {
						fmt.Fprint(out, `<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>2027-10-31T00:00:00Z</RetainUntilDate></Retention>`)
					} else {
						fmt.Fprint(out, `<Retention></Retention>`)
					}
				case q.Has("legal-hold"):
					if mode == "hold-duplicate" {
						fmt.Fprint(out, `<LegalHold><Status>ON</Status><Status>OFF</Status></LegalHold>`)
						return
					}
					status := "OFF"
					if r.URL.Path == "/bucket/root/b" {
						status = "ON"
					}
					fmt.Fprintf(out, `<LegalHold><Status>%s</Status></LegalHold>`, status)
				case q.Has("uploads"):
					if mode == "upload-denied" {
						out.WriteHeader(403)
						fmt.Fprint(out, `<Error><Code>AccessDenied</Code></Error>`)
						return
					}
					if q.Get("key-marker") == "" {
						fmt.Fprint(out, `<ListMultipartUploadsResult><Bucket>bucket</Bucket><Prefix>root/</Prefix><KeyMarker></KeyMarker><UploadIdMarker></UploadIdMarker><NextKeyMarker>root/unfinished</NextKeyMarker><NextUploadIdMarker>upload-1</NextUploadIdMarker><IsTruncated>true</IsTruncated><Upload><Key>root/unfinished</Key><UploadId>upload-1</UploadId><Initiated>2026-10-31T09:00:00Z</Initiated></Upload></ListMultipartUploadsResult>`)
					} else {
						fmt.Fprint(out, `<ListMultipartUploadsResult><Bucket>bucket</Bucket><Prefix>root/</Prefix><KeyMarker>root/unfinished</KeyMarker><UploadIdMarker>upload-1</UploadIdMarker><IsTruncated>false</IsTruncated><Upload><Key>root/unfinished</Key><UploadId>upload-2</UploadId><Initiated>2026-10-31T09:01:00Z</Initiated></Upload></ListMultipartUploadsResult>`)
					}
				default:
					t.Error("unexpected native inventory request")
					out.WriteHeader(403)
				}
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			hash := func(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
			scope := S3CoverageScope{Endpoint: server.URL, Region: "us-east-1", Bucket: "bucket", Prefix: "root", CASHA256: hash(ca), CredentialSHA256: hash(credential)}
			raw, _ := json.Marshal(scope)
			scanner, err := NewS3CoverageCensus(S3CoverageCensusConfig{Scope: scope, Source: reg.SourceRecord{SourceID: "original-storage-owner", RecordID: "original-version-inventory", RecordVersion: "v1", ContentSHA256: hash(raw)}, CAPEM: ca, CredentialsFile: file})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			census, err := scanner.Observe(ctx)
			if writes.Load() != 0 {
				t.Fatal("read census attempted a write")
			}
			positive := mode == "valid" || mode == "zero-version" || mode == "no-object-lock"
			if !positive {
				if err == nil || census != nil || requests.Load() == 0 {
					t.Fatal("incomplete/unprovable native inventory was accepted", mode)
				}
				return
			}
			if err != nil {
				t.Fatal("native version/hold/upload EOF census failed", err, requests.Load())
			}
			facts := census.Facts()
			if len(facts.Members) != 7 || len(facts.Pages) != 4 || !authorityHash.MatchString(facts.MembersSHA256) {
				t.Fatal("native history omitted", len(facts.Members), len(facts.Pages))
			}
			kinds := map[string]int{}
			held := false
			for _, member := range facts.Members {
				if mode == "zero-version" && member.Kind == "version" && member.Size != 0 {
					t.Fatal("legitimate explicit zero-byte version lost")
				}
				kinds[member.Kind]++
				if member.Key == "root/b" {
					held = member.RetentionMode == "COMPLIANCE" && member.LegalHold == "ON" && !member.RetainUntil.IsZero()
				}
			}
			if kinds["delete_marker"] != 1 || kinds["legacy_unversioned"] != 1 || kinds["multipart_unknown"] != 2 || held != (mode != "no-object-lock") {
				t.Fatal("deleted/legacy/unknown/protection facts were dropped", kinds, held)
			}
			facts.Members[0].Key = "caller mutation"
			if census.Facts().Members[0].Key == facts.Members[0].Key {
				t.Fatal("native facts alias caller")
			}
			if _, ok := any(census).(reg.PreparedCoverage); ok {
				t.Fatal("live native LIST census became complete adoption")
			}
		})
	}
}

type s3TrapTransport struct{ calls int }

func (t *s3TrapTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	return nil, ErrS3CoverageCensus
}

func TestNativeS3CensusTransportCannotWriteOrWidenRoot(t *testing.T) {
	for _, test := range []struct{ method, url string }{
		{"PUT", "https://store.invalid/bucket/root/a"},
		{"DELETE", "https://store.invalid/bucket/root/a?versionId=v1"},
		{"POST", "https://store.invalid/bucket?uploads"},
		{"GET", "https://other.invalid/bucket?versions&prefix=root%2F"},
		{"GET", "http://store.invalid/bucket?versions&prefix=root%2F"},
		{"GET", "https://store.invalid/bucket?versions&prefix=neighbor%2F"},
		{"GET", "https://store.invalid/bucket/root/a"},
		{"GET", "https://store.invalid/bucket/neighbor/a?legal-hold&versionId=v1"},
		{"GET", "https://store.invalid/bucket/root/a?legal-hold"},
	} {
		spy := &s3TrapTransport{}
		tpt := &s3CensusTransport{base: spy, host: "store.invalid", bucket: "bucket", prefix: "root/"}
		u, err := url.Parse(test.url)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tpt.RoundTrip(&http.Request{Method: test.method, URL: u}); err == nil || spy.calls != 0 {
			t.Fatal("inventory transport widened read scope", test.method, test.url)
		}
	}
}

func TestNativeS3CensusPageRejectsAmbiguousXML(t *testing.T) {
	// Parsing is applied to the actual transport response BEFORE SDK decoding,
	// so last-field-wins or an unrecognized entry cannot hide an incomplete page.
	for _, raw := range []string{
		`<ListVersionsResult><Name>bucket</Name><Prefix>root/</Prefix><IsTruncated>true</IsTruncated><IsTruncated>false</IsTruncated></ListVersionsResult>`,
		`<ListVersionsResult><Name>bucket</Name><Prefix>root/</Prefix><IsTruncated>false</IsTruncated><Upload><Key>root/a</Key><UploadId>x</UploadId><Initiated>2026-10-31T00:00:00Z</Initiated></Upload></ListVersionsResult>`,
		`<ListVersionsResult><Name>bucket</Name><Prefix>root/</Prefix><IsTruncated>false</IsTruncated><Version><Key>root/a</Key><Key>root/b</Key><VersionId>x</VersionId><IsLatest>true</IsLatest><LastModified>2026-10-31T00:00:00Z</LastModified></Version></ListVersionsResult>`,
		`<ListVersionsResult><Name>bucket</Name><Prefix>root/</Prefix><IsTruncated>false</IsTruncated></ListVersionsResult><ListVersionsResult/>`,
	} {
		if _, err := validateNativeS3CensusPage([]byte(raw), "versions", "bucket", "root/", nil); err == nil {
			t.Fatal("ambiguous native EOF page accepted")
		}
	}
}
