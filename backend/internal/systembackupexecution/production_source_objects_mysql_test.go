package systembackupexecution

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"clawreef/internal/systembackup/worker"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func (f *dProductionSourceFixture) repinScope(t *testing.T) {
	t.Helper()
	scope, err := sourceMetadataScope(*f.base.x.history.service.captureMaterials)
	if err != nil {
		t.Fatal(err)
	}
	f.grant.ScopeSHA256 = scope
	f.writeGrant(t)
}

func TestProductionSourceObjectVersionSelectionOriginalAuthorityTLSMySQL(t *testing.T) {
	var mode atomic.Value
	mode.Store("valid")
	var calls atomic.Int32
	var f *dProductionSourceFixture
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || r.URL.Path != "/skill-bucket/" && r.URL.Path != "/skill-bucket" || !strings.Contains(r.Header.Get("Authorization"), "Credential=d-object-access/") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		if r.URL.Query().Has("versioning") {
			status := "Enabled"
			if mode.Load().(string) == "unversioned" {
				status = "Suspended"
			}
			fmt.Fprintf(w, `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>%s</Status></VersioningConfiguration>`, status)
			return
		}
		if !r.URL.Query().Has("versions") || r.URL.Query().Get("prefix") != "packages/" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		selected := mode.Load().(string)
		version, key := "immutable-original-v1", "packages/original.zip"
		if selected == "new-version" {
			version = "immutable-original-v2"
		}
		if selected == "null-version" {
			version = "null"
		}
		if selected == "foreign-prefix" {
			key = "other/original.zip"
		}
		if selected == "revoke-during-response" {
			if err := os.WriteFile(f.base.x.history.service.captureMaterials.Discovery.SourceAPI.TokenFile, []byte("replacement"), 0600); err != nil {
				t.Error(err)
			}
		}
		fmt.Fprintf(w, `<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>skill-bucket</Name><Prefix>packages/</Prefix><IsTruncated>false</IsTruncated><Version><Key>%s</Key><VersionId>%s</VersionId><IsLatest>true</IsLatest><Size>3</Size></Version><Version><Key>packages/unreferenced.zip</Key><VersionId>unreferenced-v1</VersionId><IsLatest>true</IsLatest><Size>2</Size></Version><DeleteMarker><Key>packages/deleted.zip</Key><VersionId>delete-v1</VersionId><IsLatest>true</IsLatest></DeleteMarker>`, key, version)
		if selected == "duplicate-latest" {
			fmt.Fprint(w, `<DeleteMarker><Key>packages/original.zip</Key><VersionId>delete-v2</VersionId><IsLatest>true</IsLatest></DeleteMarker>`)
		}
		if selected == "new-key" {
			fmt.Fprint(w, `<Version><Key>packages/new.zip</Key><VersionId>new-key-v1</VersionId><IsLatest>true</IsLatest><Size>1</Size></Version>`)
		}
		fmt.Fprint(w, `</ListVersionsResult>`)
	})
	f = newDProductionSourceFixture(t, handler)
	s, owner := f.base.x.history.service, f.base.x.history.owner
	m := s.captureMaterials
	m.SkillBucket, m.SkillPrefix = "skill-bucket", "packages"
	m.Objects.ObjectPrefixes = []worker.ObjectSourcePrefix{{Bucket: m.SkillBucket, Prefix: m.SkillPrefix + "/"}}
	f.repinScope(t)
	authority, err := s.sourceMetadataAuthority(context.Background(), owner, f.base.in)
	if err != nil {
		t.Fatal(err)
	}
	m = s.captureMaterials
	tlsConfig, err := sourceMetadataTLS(*m.Objects.Objects)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(f.server.URL)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig}
	t.Cleanup(transport.CloseIdleConnections)
	client, err := minio.New(u.Host, &minio.Options{Secure: true, Region: "us-east-1", BucketLookup: minio.BucketLookupPath, Creds: credentials.NewStaticV4("d-object-access", "named-local-fixture", ""), Transport: sourceMetadataTransport{authority, u.Host, transport}})
	if err != nil {
		t.Fatal(err)
	}
	_, source, _, _, _ := productionModuleFixture(t)
	clients := &productionMetadataClients{Objects: client}
	original, err := authority.skillObjectMetadata(context.Background(), clients, source.Skills)
	if err != nil || len(original.Objects) != 2 || original.Objects[1].Key != "unreferenced.zip" || original.Objects[0].VersionID != "immutable-original-v1" {
		t.Fatal("complete current version selection", err)
	}
	before, _ := json.Marshal(original)
	for _, fault := range []string{"new-version", "new-key", "null-version", "foreign-prefix", "duplicate-latest", "unversioned", "revoke-during-response"} {
		t.Run(fault, func(t *testing.T) {
			mode.Store(fault)
			observed, err := authority.skillObjectMetadata(context.Background(), clients, source.Skills)
			if fault == "new-version" || fault == "new-key" {
				raw, _ := json.Marshal(observed)
				if err != nil || string(raw) == string(before) {
					t.Fatal("source change lost from frozen selection", err)
				}
			} else if err == nil {
				t.Fatal("invalid/revoked original source returned selection")
			}
		})
	}
	if calls.Load() == 0 {
		t.Fatal("original signed TLS metadata client did not execute")
	}
}
