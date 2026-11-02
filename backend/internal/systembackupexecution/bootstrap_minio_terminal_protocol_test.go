package systembackupexecution

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	ma "clawreef/internal/systembackupminioauthority"
)

// Local native protocol model only. These tests do not prove real MinIO
// compatibility, enrolled SQL authority, A's complete terminal, or main3/30.
type minioTerminalProtocolFixture struct {
	r       *MinIOBootstrapTerminalResource
	p       *minioPermissionProductionInputs
	objects map[string]minioTerminalTestObject
	roles   map[string]int
	intent  MinIOBootstrapCapabilityIntent
}
type minioTerminalTestObject struct {
	body    []byte
	version string
}

func minioTerminalProtocolFixtureNew(t *testing.T, scenario string) *minioTerminalProtocolFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	f := &minioTerminalProtocolFixture{objects: map[string]minioTerminalTestObject{}, roles: map[string]int{}, p: &minioPermissionProductionInputs{}, r: &MinIOBootstrapTerminalResource{grant: ma.SQLGrant{AuthorityID: "original-authority", GrantID: "original-grant", Target: ma.Target{InstallationID: "original-installation"}, NotBefore: now.Add(-time.Minute), Until: now.Add(time.Minute)}}}
	f.intent = MinIOBootstrapCapabilityIntent{Version: minioTerminalProtocolProfile, InstallationID: f.r.grant.Target.InstallationID, AuthorityID: f.r.grant.AuthorityID, GrantID: f.r.grant.GrantID, Nonce: strings.Repeat("a", 64), NotBefore: now.Add(-time.Minute), Until: now.Add(time.Minute)}
	f.p.target.Bucket = "artifacts"
	f.p.target.RemoteStagingRoot = "original-installation_staging/"
	f.p.catalog.Bucket = "catalog"
	f.p.catalog.Root = "original-installation/catalog/"
	f.intent.ArtifactKey = f.p.target.RemoteStagingRoot + "bootstrap-probes/" + f.intent.Nonce + "/protocol.bin"
	f.intent.ArtifactBadChecksumKey = f.p.target.RemoteStagingRoot + "bootstrap-probes/" + f.intent.Nonce + "/reject-checksum.bin"
	f.intent.CatalogKey = f.p.catalog.Root + "bootstrap-probes/" + f.intent.Nonce + "/protocol.json"
	f.intent.CatalogBadChecksumKey = f.p.catalog.Root + "bootstrap-probes/" + f.intent.Nonce + "/reject-checksum.json"
	raw, e := ce.Canonical(f.intent)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	f.r.input.CapabilityIntentFile = filepath.Join(dir, "original-intent.json")
	f.r.input.CapabilityIntentSHA256 = hash(raw)
	if e = os.WriteFile(f.r.input.CapabilityIntentFile, raw, 0600); e != nil {
		t.Fatal(e)
	}
	serial := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, e := io.ReadAll(io.LimitReader(r.Body, 8193))
		if e != nil {
			t.Error(e)
			return
		}
		account := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential="), "/")[0]
		if !minioTerminalTestSignature(r, body, account, "original-protocol-secret-"+account) {
			t.Error("invalid actual SigV4 request")
			w.WriteHeader(403)
			return
		}
		f.roles[account]++
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
		if len(parts) != 2 {
			w.WriteHeader(400)
			return
		}
		bucket, key := parts[0], parts[1]
		id := bucket + "/" + key
		owned := key == f.intent.ArtifactKey || key == f.intent.ArtifactBadChecksumKey
		catalog := key == f.intent.CatalogKey || key == f.intent.CatalogBadChecksumKey
		if !owned && !catalog || owned && bucket != "artifacts" || catalog && bucket != "catalog" {
			t.Error("probe escaped exact original keys")
			w.WriteHeader(403)
			return
		}
		purpose := "artifact_"
		if catalog {
			purpose = "catalog_"
		}
		allowed := r.Method == "GET" && account == purpose+"read" || r.Method == "PUT" && account == purpose+map[bool]string{true: "append", false: "write"}[catalog] || r.Method == "DELETE" && owned && account == "artifact_delete"
		if !allowed {
			t.Error("cross-purpose credential use")
			w.WriteHeader(403)
			return
		}
		errorReply := func(status int, code string) {
			region := "<Region>us-east-1</Region>"
			if scenario == "no-region" {
				region = ""
			}
			if scenario == "wrong-region-checksum" && code == "XAmzContentChecksumMismatch" || scenario == "wrong-region-condition" && code == "PreconditionFailed" || scenario == "wrong-region-absence" && code == "NoSuchKey" || scenario == "wrong-region-delete-absence" && code == "NoSuchVersion" {
				region = "<Region>eu-west-1</Region>"
			}
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(status)
			fmt.Fprintf(w, "<Error><Code>%s</Code><Key>%s</Key><Message>native decision</Message>%s<RequestId>request</RequestId><HostId>host</HostId></Error>", code, key, region)
		}
		obj, exists := f.objects[id]
		version := r.URL.Query().Get("versionId")
		switch r.Method {
		case "PUT":
			digest, _ := hex.DecodeString(hash(body))
			if r.Header.Get("X-Amz-Checksum-Sha256") != base64.StdEncoding.EncodeToString(digest) {
				if scenario == "checksum-accepted" {
					w.WriteHeader(200)
				} else {
					errorReply(400, "XAmzContentChecksumMismatch")
				}
				return
			}
			if r.Header.Get("If-None-Match") != "*" {
				t.Error("missing immutable condition")
				w.WriteHeader(400)
				return
			}
			if exists && scenario != "overwrite" {
				errorReply(412, "PreconditionFailed")
				return
			}
			serial++
			obj = minioTerminalTestObject{append([]byte(nil), body...), fmt.Sprintf("original-version-%d", serial)}
			f.objects[id] = obj
			w.Header().Set("X-Amz-Version-Id", obj.version)
			w.WriteHeader(200)
		case "GET":
			if !exists || version != "" && version != obj.version {
				if version != "" {
					errorReply(404, "NoSuchVersion")
				} else {
					errorReply(404, "NoSuchKey")
				}
				return
			}
			v := obj.version
			if scenario == "wrong-version" {
				v = "foreign-version"
			}
			w.Header().Set("X-Amz-Version-Id", v)
			if r.Header.Get("Range") != "" {
				w.Header().Set("Content-Range", fmt.Sprintf("bytes 1-7/%d", len(obj.body)))
				w.WriteHeader(206)
				if scenario == "wrong-range" {
					w.Write([]byte("badbody"))
				} else {
					w.Write(obj.body[1:8])
				}
				return
			}
			if scenario == "truncated" {
				w.Header().Set("Content-Length", strconv.Itoa(len(obj.body)+10))
			}
			w.Write(obj.body)
		case "DELETE":
			if version == "" || !exists || version != obj.version {
				t.Error("delete was not an observed exact version")
				w.WriteHeader(400)
				return
			}
			if scenario != "delete-ack-only" {
				delete(f.objects, id)
			}
			w.Header().Set("X-Amz-Version-Id", obj.version)
			w.WriteHeader(204)
		}
	}))
	t.Cleanup(server.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	caFile := filepath.Join(dir, "original-ca.pem")
	if e = os.WriteFile(caFile, ca, 0600); e != nil {
		t.Fatal(e)
	}
	f.p.grant.Provider = minioPermissionProvider{Endpoint: server.URL, Region: "us-east-1", CAFile: caFile, CASHA256: hash(ca), SPKISHA256: hash(server.Certificate().RawSubjectPublicKeyInfo)}
	for _, purpose := range []string{"artifact_delete", "artifact_read", "artifact_write", "catalog_append", "catalog_read"} {
		f.p.uses = append(f.p.uses, minioPermissionUse{principal: minioPermissionPrincipal{Purpose: purpose}, credential: nativePublicationCredential{AccessKey: purpose, SecretKey: "original-protocol-secret-" + purpose, NotBefore: now.Add(-time.Minute), Until: now.Add(time.Minute)}})
	}
	return f
}

// Independent general SigV4 HMAC verifier, including payload, condition and
// checksum headers. The older GET-only fixture cannot verify these requests.
func minioTerminalTestSignature(r *http.Request, body []byte, account, secret string) bool {
	parts := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 "), ", ")
	if len(parts) != 3 || r.Header.Get("X-Amz-Content-Sha256") != hash(body) {
		return false
	}
	credential := strings.Split(strings.TrimPrefix(parts[0], "Credential="), "/")
	if len(credential) != 5 || credential[0] != account || credential[2] != "us-east-1" || credential[3] != "s3" || credential[4] != "aws4_request" {
		return false
	}
	signed := strings.TrimPrefix(parts[1], "SignedHeaders=")
	names := strings.Split(signed, ";")
	if !sort.StringsAreSorted(names) {
		return false
	}
	values := ""
	seen := map[string]bool{}
	for _, name := range names {
		value := r.Header.Get(name)
		if name == "host" {
			value = r.Host
		}
		if name == "content-length" {
			value = strconv.FormatInt(r.ContentLength, 10)
		}
		values += name + ":" + strings.Join(strings.Fields(value), " ") + "\n"
		seen[name] = true
	}
	if !seen["host"] || !seen["x-amz-date"] || !seen["x-amz-content-sha256"] || r.Method == "PUT" && (!seen["if-none-match"] || !seen["x-amz-checksum-sha256"]) {
		return false
	}
	date := r.Header.Get("X-Amz-Date")
	if len(date) != 16 || date[:8] != credential[1] {
		return false
	}
	canonical := r.Method + "\n" + r.URL.EscapedPath() + "\n" + strings.ReplaceAll(r.URL.Query().Encode(), "+", "%20") + "\n" + values + "\n" + signed + "\n" + hash(body)
	toSign := "AWS4-HMAC-SHA256\n" + date + "\n" + strings.Join(credential[1:], "/") + "\n" + hash([]byte(canonical))
	mac := func(key []byte, value string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(value))
		return h.Sum(nil)
	}
	key := mac([]byte("AWS4"+secret), credential[1])
	for _, part := range credential[2:] {
		key = mac(key, part)
	}
	return hmac.Equal([]byte(hex.EncodeToString(mac(key, toSign))), []byte(strings.TrimPrefix(parts[2], "Signature=")))
}

func TestMinIOBootstrapTerminalNativeProtocolAndRetainedProbe(t *testing.T) {
	for _, scenario := range []string{"with-region", "no-region"} {
		t.Run(scenario, func(t *testing.T) {
			f := minioTerminalProtocolFixtureNew(t, scenario)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var inventory []MinIOBootstrapProbeObject
			for i := 0; i < 2; i++ {
				if e := f.r.probeTerminalProtocol(ctx, f.p, time.Now().Add(8*time.Second), &inventory); e != nil {
					t.Fatal(e)
				}
				if len(inventory) != 4 || inventory[0].State != "deleted_exact_version" || inventory[2].State != "retained_reserved_probe" || inventory[2].Version == "" {
					t.Fatal("missing actual probe inventory")
				}
			}
			if len(f.objects) != 1 || f.objects["catalog/"+f.intent.CatalogKey].version != inventory[2].Version {
				t.Fatal("retained catalog inventory mismatch")
			}
			for _, role := range []string{"artifact_delete", "artifact_read", "artifact_write", "catalog_append", "catalog_read"} {
				if f.roles[role] == 0 {
					t.Fatalf("unused original role %s", role)
				}
			}
		})
	}
}
func TestMinIOBootstrapTerminalProtocolRejectsPartialOrUnsafeProvider(t *testing.T) {
	for _, scenario := range []string{"checksum-accepted", "overwrite", "wrong-version", "wrong-range", "delete-ack-only", "truncated", "wrong-spki", "expired-role", "foreign-key", "wrong-region-checksum", "wrong-region-condition", "wrong-region-absence", "wrong-region-delete-absence"} {
		t.Run(scenario, func(t *testing.T) {
			f := minioTerminalProtocolFixtureNew(t, scenario)
			switch scenario {
			case "wrong-spki":
				f.p.grant.Provider.SPKISHA256 = strings.Repeat("b", 64)
			case "expired-role":
				f.p.uses[0].credential.Until = time.Now().Add(-time.Second)
			case "foreign-key":
				f.p.target.RemoteStagingRoot = "foreign/"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var inventory []MinIOBootstrapProbeObject
			if e := f.r.probeTerminalProtocol(ctx, f.p, time.Now().Add(8*time.Second), &inventory); e == nil {
				t.Fatal("unsafe/partial protocol admitted")
			}
		})
	}
}

func TestMinIOBootstrapTerminalNativeErrorRegionStrictness(t *testing.T) {
	for _, native := range []struct {
		status int
		code   string
	}{{400, "XAmzContentChecksumMismatch"}, {412, "PreconditionFailed"}, {404, "NoSuchKey"}, {404, "NoSuchVersion"}} {
		t.Run(native.code, func(t *testing.T) {
			body := func(extra string) []byte {
				return []byte(fmt.Sprintf("<Error><Code>%s</Code><Key>owned/probe</Key><Message>native decision</Message>%s<RequestId>request</RequestId><HostId>host</HostId></Error>", native.code, extra))
			}
			for _, tc := range []struct {
				name, extra string
				want        bool
			}{
				{"omitted", "", true},
				{"original-signed-region", "<Region>us-east-1</Region>", true},
				{"wrong-region", "<Region>eu-west-1</Region>", false},
				{"empty-region", "<Region></Region>", false},
				{"duplicate-matching", "<Region>us-east-1</Region><Region>us-east-1</Region>", false},
				{"duplicate-conflicting", "<Region>us-east-1</Region><Region>eu-west-1</Region>", false},
				{"nested-region", "<Region><Value>us-east-1</Value></Region>", false},
				{"namespaced-region", "<Region xmlns='urn:foreign'>us-east-1</Region>", false},
				{"attributed-region", "<Region source='site'>us-east-1</Region>", false},
				{"unknown-field", "<Region>us-east-1</Region><Unexpected>anything</Unexpected>", false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					reply := minioTerminalReply{status: native.status, body: body(tc.extra)}
					if got := minioTerminalError(reply, native.status, native.code, "owned/probe", "us-east-1"); got != tc.want {
						t.Fatalf("Region finite profile got %t want %t", got, tc.want)
					}
				})
			}
			good := minioTerminalReply{status: native.status, body: body("<Region>us-east-1</Region>")}
			if minioTerminalError(good, native.status+1, native.code, "owned/probe", "us-east-1") || minioTerminalError(good, native.status, "AccessDenied", "owned/probe", "us-east-1") || minioTerminalError(good, native.status, native.code, "foreign/probe", "us-east-1") || minioTerminalError(good, native.status, native.code, "owned/probe", "") {
				t.Fatal("region handling weakened status/code/key/original region")
			}
			for _, raw := range [][]byte{append(append([]byte(nil), good.body...), []byte("<Error></Error>")...), good.body[:len(good.body)-1]} {
				if minioTerminalError(minioTerminalReply{status: native.status, body: raw}, native.status, native.code, "owned/probe", "us-east-1") {
					t.Fatal("incomplete or multiple XML documents accepted")
				}
			}
		})
	}
}
func TestMinIOBootstrapTerminalIdentityOnlyDeadlineAndFailureLatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s := &minioBootstrapTerminalCheck{ctx: ctx}
	s.origin = s
	if s.DependencyDeadline() != nil {
		t.Fatal("identity-only check exposed fresh admission")
	}
	child, stop := context.WithCancel(ctx)
	defer stop()
	if minioTerminalContext(child, ctx) {
		t.Fatal("different attempt context accepted")
	}
	if e := s.RecheckIdentity(child, nil); e == nil || !s.failed.Load() {
		t.Fatal("failure not latched")
	}
	if s.DependencyDeadline() != nil {
		t.Fatal("failed attempt renewed deadline")
	}
	if !bytes.Equal([]byte(strings.Join((&MinIOBootstrapTerminalResource{}).TerminalKeys(), ",")), []byte("reference:artifact_delete,reference:artifact_read,reference:artifact_write,reference:catalog_append,reference:catalog_read")) {
		t.Fatal("group keys changed")
	}
	r := &MinIOBootstrapTerminalResource{}
	if len(r.TerminalResources()) != 5 {
		t.Fatal("incomplete grouped owner map")
	}
	for _, resource := range r.TerminalResources() {
		if resource != r {
			t.Fatal("five keys did not share one owner")
		}
	}
}
