package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/xml"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"
)

// Native TLS read-only fixture only. No original DB, task, plan, private C,
// controller grant or write credential is supplied to the recovery reader.
// The expected hash/size here are named authenticated-index DATA; catalog/JWS
// and complete business recovery remain separate required consumers.
func TestArtifactReadOnlyVersionDiscoverySurvivesReplacedLatest(t *testing.T) {
	for _, mode := range []string{"overwritten-latest", "nested-root", "paginated-history", "old-version-missing", "tampered-old-version", "wrong-native-version", "list-permission-missing", "read-credential-withdrawn", "search-budget-exhausted", "repeated-page"} {
		t.Run(mode, func(t *testing.T) {
			store, state := newANativePublicationStore(t, time.Minute)
			material := artifactReadMaterials(store.config)
			if mode == "nested-root" {
				material.Root = "archive/" + material.InstallationID + "/"
				original := store.config
				original.Root = material.Root
				if original.validate() != nil {
					t.Fatal("nested root is not original legal target fixture")
				}
			}
			if err := os.Remove(store.config.WriteCredentialFile); err != nil {
				t.Fatal("remove named write fixture", err)
			}
			reader, err := NewArtifactReadOnlyS3(material)
			if err != nil {
				t.Fatal("independent read-only material", err)
			}
			defer reader.Close()
			body := []byte("original immutable C bytes")
			changed := []byte("substituted latest C data!")
			if len(body) != len(changed) {
				t.Fatal("equal-size corruption fixture")
			}
			key := material.Root + "sbk_disaster/1/parts/0/original.enc"
			lists, gets, latestReads := 0, 0, 0
			state.onRead = func(out http.ResponseWriter, r *http.Request) bool {
				q := r.URL.Query()
				if _, ok := q["versions"]; ok {
					lists++
					if mode == "list-permission-missing" {
						out.WriteHeader(403)
						return true
					}
					if r.URL.Path != "/"+material.Bucket+"/" || q.Get("prefix") != key || q.Get("max-keys") == "" {
						t.Error("unbounded/wrong native history request")
						out.WriteHeader(400)
						return true
					}
					page := artifactVersionPage{XMLName: xml.Name{Local: "ListVersionsResult"}, Name: material.Bucket, Prefix: key, KeyMarker: q.Get("key-marker"), VersionIDMarker: q.Get("version-id-marker"), Versions: []artifactNativeVersion{{Key: key, Version: "replacement-v2", Size: int64(len(changed)), Modified: time.Date(2026, 10, 31, 2, 0, 0, 0, time.UTC)}}}
					if mode != "old-version-missing" {
						page.Versions = append(page.Versions, artifactNativeVersion{Key: key, Version: "original-v1", Size: int64(len(body)), Modified: time.Date(2026, 10, 31, 1, 0, 0, 0, time.UTC)})
					}
					if mode == "repeated-page" {
						page.Truncated = true
						page.NextKeyMarker = key
						page.NextVersionIDMarker = "original-v1"
					}
					if mode == "paginated-history" {
						if lists == 1 {
							page.Versions = page.Versions[:1]
							page.Truncated = true
							page.NextKeyMarker = key
							page.NextVersionIDMarker = "replacement-v2"
						} else {
							if q.Get("key-marker") != key || q.Get("version-id-marker") != "replacement-v2" {
								t.Error("native version continuation lost")
								out.WriteHeader(400)
								return true
							}
							page.Versions = page.Versions[1:]
						}
					}
					raw, _ := xml.Marshal(page)
					out.Header().Set("Content-Type", "application/xml")
					out.Write(raw)
					return true
				}
				if r.URL.Path != "/"+material.Bucket+"/"+key {
					out.WriteHeader(404)
					return true
				}
				version := q.Get("versionId")
				if version == "" {
					latestReads++
					t.Error("reader requested latest")
					out.WriteHeader(400)
					return true
				}
				actual := changed
				if version == "original-v1" && mode != "tampered-old-version" && mode != "search-budget-exhausted" {
					actual = body
				}
				if version != "original-v1" && version != "replacement-v2" {
					out.WriteHeader(404)
					return true
				}
				out.Header().Set("x-amz-version-id", version)
				if mode == "wrong-native-version" {
					out.Header().Set("x-amz-version-id", "foreign-version")
				}
				out.Header().Set("Content-Length", strconv.Itoa(len(actual)))
				if r.Method == "GET" {
					gets++
					if mode == "read-credential-withdrawn" {
						if err := os.WriteFile(material.ReadCredentialFile, []byte("reader authority withdrawn during GET"), 0600); err != nil {
							t.Error(err)
						}
					}
					out.Write(actual)
				}
				return true
			}
			budget := ArtifactVersionSearchBudget{MaxVersions: 10, MaxPages: 3, MaxReadBytes: 1024}
			if mode == "search-budget-exhausted" {
				budget.MaxReadBytes = int64(len(body))
			}
			object, err := reader.ResolveIndexedObject(context.Background(), key, hash(body), int64(len(body)), budget, time.Now().Add(20*time.Second))
			if mode == "overwritten-latest" || mode == "paginated-history" || mode == "nested-root" {
				if err != nil || object.Version != "original-v1" || object.SHA256 != hash(body) || object.Size != int64(len(body)) || gets != 1 {
					t.Fatal("fixed retained version not recovered", object, err, gets)
				}
			} else if err == nil || object.Version != "" {
				t.Fatal("unproven/corrupt version accepted", mode, object, err)
			}
			if lists < 1 || latestReads != 0 || state.puts != 0 {
				t.Fatal("native read-only discovery contract", lists, latestReads, state.puts)
			}
			if mode == "search-budget-exhausted" && gets != 1 {
				t.Fatal("read byte budget exceeded", gets)
			}
			if _, err := reader.store.create(context.Background(), key, bytes.NewReader(body), int64(len(body)), hash(body), time.Now().Add(time.Second)); err == nil || state.puts != 0 {
				t.Fatal("read-only recovery gained native write")
			}
		})
	}
}
