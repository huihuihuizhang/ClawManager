package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"clawreef/internal/systembackup/team"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Real HTTP/TLS + official MinIO client, deliberately a protocol component
// fixture. This is not a real MinIO/MySQL/field qualification or owner proof.
func TestTeamsNativeObjectObservationProtocolComponent(t *testing.T) {
	for _, name := range []string{"exact", "historical-reference", "empty-proven", "empty-hides-object", "missing-reference-version", "foreign-object", "wrong-content", "denied", "truncated-page-denied"} {
		t.Run(name, func(t *testing.T) {
			body := []byte("data")
			sum := sha256.Sum256(body)
			m, i := teamsSourceScopeFixture()
			i.Objects[0].SHA256 = hex.EncodeToString(sum[:])
			if strings.HasPrefix(name, "empty-") {
				i.Objects = []team.ObjectRef{}
			}
			var lists, gets atomic.Int32
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") == "" {
					t.Error("unsigned source request")
					w.WriteHeader(403)
					return
				}
				if name == "denied" {
					http.Error(w, "denied", 403)
					return
				}
				q := r.URL.Query()
				if q.Has("versioning") {
					fmt.Fprint(w, `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`)
					return
				}
				if q.Has("versions") {
					lists.Add(1)
					if name == "truncated-page-denied" && q.Get("key-marker") != "" {
						http.Error(w, "denied", 403)
						return
					}
					versions := `<Version><Key>results/a</Key><VersionId>original-version</VersionId><IsLatest>true</IsLatest><Size>4</Size><ETag>abc</ETag></Version>`
					if name == "empty-proven" {
						versions = ""
					}
					if name == "missing-reference-version" {
						versions = strings.ReplaceAll(versions, "original-version", "other-version")
					}
					if name == "historical-reference" {
						versions = strings.ReplaceAll(versions, "<IsLatest>true</IsLatest>", "<IsLatest>false</IsLatest>") + `<Version><Key>results/a</Key><VersionId>new-version</VersionId><IsLatest>true</IsLatest><Size>5</Size><ETag>new</ETag></Version>`
					}
					if name == "foreign-object" {
						versions += `<Version><Key>results/unreferenced</Key><VersionId>extra-version</VersionId><IsLatest>true</IsLatest><Size>4</Size><ETag>abc</ETag></Version>`
					}
					truncated := "false"
					extra := ""
					if name == "truncated-page-denied" {
						truncated = "true"
						extra = "<NextKeyMarker>results/a</NextKeyMarker><NextVersionIdMarker>original-version</NextVersionIdMarker>"
					}
					fmt.Fprintf(w, "<ListVersionsResult><Name>teams</Name><Prefix>results/</Prefix><IsTruncated>%s</IsTruncated>%s%s</ListVersionsResult>", truncated, extra, versions)
					return
				}
				if r.URL.Path != "/teams/results/a" || q.Get("versionId") != "original-version" {
					t.Error("widened immutable object read")
					w.WriteHeader(403)
					return
				}
				w.Header().Set("X-Amz-Version-Id", "original-version")
				w.Header().Set("Last-Modified", "Wed, 04 Nov 2026 01:00:00 GMT")
				w.Header().Set("Content-Length", "4")
				w.Header().Set("ETag", `"abc"`)
				if r.Method == http.MethodHead {
					return
				}
				gets.Add(1)
				if name == "wrong-content" {
					fmt.Fprint(w, "evil")
				} else {
					w.Write(body)
				}
			}))
			defer srv.Close()
			u, _ := url.Parse(srv.URL)
			client, e := minio.New(u.Host, &minio.Options{Secure: true, Region: "us-east-1", BucketLookup: minio.BucketLookupPath, Creds: credentials.NewStaticV4("component-key", "component-secret", ""), Transport: srv.Client().Transport})
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			d := TeamsSourceIssueDefinition{Source: m}
			e = observeTeamsObjects(ctx, client, d, i)
			pass := name == "exact" || name == "historical-reference" || name == "empty-proven"
			if (e == nil) != pass {
				t.Fatalf("wrong native observation result: %v", e)
			}
			if pass {
				if e = observeTeamsObjects(ctx, client, d, i); e != nil || lists.Load() != 2 {
					t.Fatalf("second complete observation: %v", e)
				}
				if name != "empty-proven" && gets.Load() != 2 {
					t.Fatal("exact immutable body not read twice")
				}
			}
		})
	}
}
