package systembackupexecution

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	"github.com/minio/minio-go/v7/pkg/signer"
)

// The existing enrolled issuer binds this exact canonical intent hash in ALL
// five signed references and the SQL grant. These four keys are reserved probe
// objects, never artifact/task/catalog record keys. Catalog's one good object
// is deliberately retained: the append credential has no delete authority.
// Failed/uncertain requests remain inventoried by these original fixed keys.
type MinIOBootstrapCapabilityIntent struct {
	Version, InstallationID, AuthorityID, GrantID, Nonce                   string
	ArtifactKey, ArtifactBadChecksumKey, CatalogKey, CatalogBadChecksumKey string
	NotBefore, Until                                                       time.Time
}

func (r *MinIOBootstrapTerminalResource) terminalIntent(p *minioPermissionProductionInputs, now time.Time) (MinIOBootstrapCapabilityIntent, error) {
	var in MinIOBootstrapCapabilityIntent
	raw, e := pinnedDeploymentFile(r.input.CapabilityIntentFile, r.input.CapabilityIntentSHA256, 16384)
	if e != nil || decodePublicationCanonical(raw, &in) != nil || in.Version != minioTerminalProtocolProfile || in.InstallationID != r.grant.Target.InstallationID || in.AuthorityID != r.grant.AuthorityID || in.GrantID != r.grant.GrantID || !formalCandidateDigest(in.Nonce) || now.Before(in.NotBefore) || !now.Before(in.Until) || in.NotBefore.After(r.grant.NotBefore) || in.Until.Before(r.grant.Until) {
		return in, minioPermissionFailure("terminal-protocol-original-intent")
	}
	staging := p.target.RemoteStagingRoot + "bootstrap-probes/" + in.Nonce + "/"
	catalog := p.catalog.Root + "bootstrap-probes/" + in.Nonce + "/"
	if in.ArtifactKey != staging+"protocol.bin" || in.ArtifactBadChecksumKey != staging+"reject-checksum.bin" || in.CatalogKey != catalog+"protocol.json" || in.CatalogBadChecksumKey != catalog+"reject-checksum.json" {
		return in, minioPermissionFailure("terminal-protocol-owned-keys")
	}
	for _, key := range []string{in.ArtifactKey, in.ArtifactBadChecksumKey, in.CatalogKey, in.CatalogBadChecksumKey} {
		if !safePublicationKey(key) {
			return in, minioPermissionFailure("terminal-protocol-key")
		}
	}
	return in, nil
}

type minioTerminalReply struct {
	status int
	header http.Header
	body   []byte
}

// The caller is private compiled probe code, not a reusable write/delete API.
// It uses actual role credentials and the same CA+SPKI pinned no-proxy client
// as native permission observations. Every body is bounded and read to EOF.
func minioTerminalProbeRequest(ctx context.Context, n *minioPermissionHTTP, bucket, key, version, method string, body []byte, badChecksum bool, byteRange string) (minioTerminalReply, error) {
	zero := minioTerminalReply{}
	if n == nil || ctx == nil || ctx.Err() != nil || !safePublicationKey(key) || time.Now().Before(n.credential.NotBefore) || !time.Now().Before(n.credential.Until) || len(body) > 4096 {
		return zero, minioPermissionFailure("terminal-protocol-request")
	}
	u, _ := url.Parse(n.provider.Endpoint)
	u.Path = "/" + bucket + "/" + key
	if version != "" {
		q := u.Query()
		q.Set("versionId", version)
		u.RawQuery = q.Encode()
	}
	req, e := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if e != nil {
		return zero, minioPermissionFailure("terminal-protocol-request")
	}
	req.Header.Set("X-Amz-Content-Sha256", hash(body))
	if method == http.MethodPut {
		req.ContentLength = int64(len(body))
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
		req.Header.Set("If-None-Match", "*")
		req.Header.Set("Content-Type", "application/octet-stream")
		if strings.HasSuffix(key, ".json") {
			req.Header.Set("Content-Type", "application/json")
		}
		digest, _ := hex.DecodeString(hash(body))
		if badChecksum {
			digest[0] ^= 0xff
		}
		req.Header.Set("X-Amz-Checksum-Sha256", base64.StdEncoding.EncodeToString(digest))
	}
	if byteRange != "" {
		req.Header.Set("Range", byteRange)
	}
	req = signer.SignV4(*req, n.credential.AccessKey, n.credential.SecretKey, "", n.provider.Region)
	response, e := n.client.Do(req)
	if e != nil {
		return zero, minioPermissionFailure("terminal-protocol-unknown-response")
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, 8193))
	if e != nil || len(raw) > 8192 || response.ContentLength >= 0 && int64(len(raw)) != response.ContentLength || response.Header.Get("Content-Encoding") != "" {
		return zero, minioPermissionFailure("terminal-protocol-complete-response")
	}
	return minioTerminalReply{response.StatusCode, response.Header.Clone(), raw}, nil
}

// Strict finite native S3 error vocabulary; denies/redirects/truncated bodies
// cannot masquerade as successful conditional/checksum/absence observations.
func minioTerminalError(reply minioTerminalReply, status int, code, key, expectedRegion string) bool {
	if reply.status != status || len(reply.body) == 0 || expectedRegion == "" {
		return false
	}
	d := xml.NewDecoder(bytes.NewReader(reply.body))
	fields := map[string]string{}
	open, closed := false, false
	for {
		t, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return false
		}
		switch v := t.(type) {
		case xml.StartElement:
			if closed || v.Name.Space != "" || len(v.Attr) != 0 {
				return false
			}
			if !open {
				if v.Name.Local != "Error" {
					return false
				}
				open = true
				continue
			}
			switch v.Name.Local {
			case "Code", "Message", "Key", "BucketName", "Resource", "RequestId", "HostId", "VersionId", "Region":
			default:
				return false
			}
			if _, exists := fields[v.Name.Local]; exists {
				return false
			}
			var value strings.Builder
			for {
				part, e := d.Token()
				if e != nil {
					return false
				}
				switch p := part.(type) {
				case xml.CharData:
					value.Write(p)
				case xml.EndElement:
					if p.Name != v.Name {
						return false
					}
					fields[v.Name.Local] = value.String()
					goto next
				default:
					return false
				}
			}
		case xml.EndElement:
			if !open || closed || v.Name.Local != "Error" || v.Name.Space != "" {
				return false
			}
			closed = true
		case xml.CharData:
			if len(bytes.TrimSpace(v)) != 0 {
				return false
			}
		case xml.ProcInst:
			if open || v.Target != "xml" {
				return false
			}
		default:
			return false
		}
	next:
	}
	// This finite release's APIErrorResponse includes globalSite.Region() with
	// omitempty. Absence is valid; a present value must match the ORIGINAL
	// provider region used to sign this exact request. Empty, duplicated,
	// nested or differently named Region elements do not widen this profile.
	region, hasRegion := fields["Region"]
	return open && closed && (!hasRegion || region == expectedRegion) && fields["Code"] == code && (fields["Key"] == "" || fields["Key"] == key) && fields["Message"] != "" && fields["RequestId"] != "" && fields["HostId"] != ""
}
func minioTerminalVersion(v string) bool {
	return v != "" && v != "null" && v != "latest" && v != "current" && len(v) <= 256 && !strings.ContainsAny(v, "\x00\r\n")
}

func minioTerminalProbePair(ctx context.Context, writer, reader *minioPermissionHTTP, bucket, key, badKey string, body []byte, withRange bool) (string, error) {
	fail := func() (string, error) { return "", minioPermissionFailure("terminal-protocol-capability") }
	// A bad checksum must be rejected BEFORE an object can be read. Correct
	// payload SHA isolates checksum rejection from request authentication.
	reply, e := minioTerminalProbeRequest(ctx, writer, bucket, badKey, "", http.MethodPut, body, true, "")
	if e != nil || !minioTerminalError(reply, 400, "XAmzContentChecksumMismatch", badKey, writer.provider.Region) {
		return fail()
	}
	reply, e = minioTerminalProbeRequest(ctx, reader, bucket, badKey, "", http.MethodGet, nil, false, "")
	if e != nil || !minioTerminalError(reply, 404, "NoSuchKey", badKey, reader.provider.Region) {
		return fail()
	}
	reply, e = minioTerminalProbeRequest(ctx, writer, bucket, key, "", http.MethodPut, body, false, "")
	if e != nil {
		return fail()
	}
	created := reply.status == 200 || reply.status == 201
	if !created && !minioTerminalError(reply, 412, "PreconditionFailed", key, writer.provider.Region) {
		return fail()
	}
	version := reply.header.Get("X-Amz-Version-Id")
	// Reuse of the owner's reserved catalog probe is possible across retries.
	// Authenticate its complete original body/version independently, then make
	// a DIFFERENT conditional PUT and prove it could not replace that version.
	current, e := minioTerminalProbeRequest(ctx, reader, bucket, key, "", http.MethodGet, nil, false, "")
	if e != nil || current.status != 200 || !bytes.Equal(current.body, body) || !minioTerminalVersion(current.header.Get("X-Amz-Version-Id")) || created && version != current.header.Get("X-Amz-Version-Id") {
		return fail()
	}
	version = current.header.Get("X-Amz-Version-Id")
	changed := append(append([]byte(nil), body...), byte('\n'))
	reply, e = minioTerminalProbeRequest(ctx, writer, bucket, key, "", http.MethodPut, changed, false, "")
	if e != nil || !minioTerminalError(reply, 412, "PreconditionFailed", key, writer.provider.Region) {
		return fail()
	}
	for _, v := range []string{"", version} {
		reply, e = minioTerminalProbeRequest(ctx, reader, bucket, key, v, http.MethodGet, nil, false, "")
		if e != nil || reply.status != 200 || reply.header.Get("X-Amz-Version-Id") != version || !bytes.Equal(reply.body, body) {
			return fail()
		}
	}
	if withRange {
		reply, e = minioTerminalProbeRequest(ctx, reader, bucket, key, version, http.MethodGet, nil, false, "bytes=1-7")
		if e != nil || reply.status != 206 || reply.header.Get("X-Amz-Version-Id") != version || reply.header.Get("Content-Range") != "bytes 1-7/"+strconv.Itoa(len(body)) || !bytes.Equal(reply.body, body[1:8]) {
			return fail()
		}
	}
	return version, nil
}

func (r *MinIOBootstrapTerminalResource) probeTerminalProtocol(ctx context.Context, p *minioPermissionProductionInputs, deadline time.Time, inventory *[]MinIOBootstrapProbeObject) error {
	in, e := r.terminalIntent(p, time.Now())
	if e != nil {
		return e
	}
	if in.Until.Before(deadline) {
		return minioPermissionFailure("terminal-protocol-intent-window")
	}
	*inventory = []MinIOBootstrapProbeObject{{p.target.Bucket, in.ArtifactKey, "", "outcome_unknown"}, {p.target.Bucket, in.ArtifactBadChecksumKey, "", "outcome_unknown"}, {p.catalog.Bucket, in.CatalogKey, "", "outcome_unknown"}, {p.catalog.Bucket, in.CatalogBadChecksumKey, "", "outcome_unknown"}}
	clients := map[string]*minioPermissionHTTP{}
	defer func() {
		for _, client := range clients {
			client.close()
		}
	}()
	for _, u := range p.uses {
		client, e := newMinioPermissionHTTP(p.grant.Provider, u.credential)
		if e != nil {
			return e
		}
		clients[u.principal.Purpose] = client
	}
	body, e := ce.Canonical(struct{ Version, InstallationID, AuthorityID, GrantID, Nonce, Kind string }{minioTerminalProtocolProfile, in.InstallationID, in.AuthorityID, in.GrantID, in.Nonce, "reserved-bootstrap-protocol-probe"})
	if e != nil {
		return minioPermissionFailure("terminal-protocol-body")
	}
	version, e := minioTerminalProbePair(ctx, clients["artifact_write"], clients["artifact_read"], p.target.Bucket, in.ArtifactKey, in.ArtifactBadChecksumKey, body, true)
	if e != nil {
		return e
	}
	(*inventory)[0].Version = version
	(*inventory)[1].State = "absent_after_checksum_rejection"
	deleted, e := minioTerminalProbeRequest(ctx, clients["artifact_delete"], p.target.Bucket, in.ArtifactKey, version, http.MethodDelete, nil, false, "")
	if e != nil || deleted.status != 204 || len(deleted.body) != 0 || deleted.header.Get("X-Amz-Version-Id") != version || deleted.header.Get("X-Amz-Delete-Marker") == "true" {
		return minioPermissionFailure("terminal-protocol-exact-delete")
	}
	absent, e := minioTerminalProbeRequest(ctx, clients["artifact_read"], p.target.Bucket, in.ArtifactKey, version, http.MethodGet, nil, false, "")
	if e != nil || !minioTerminalError(absent, 404, "NoSuchVersion", in.ArtifactKey, clients["artifact_read"].provider.Region) {
		return minioPermissionFailure("terminal-protocol-delete-readback")
	}
	(*inventory)[0].State = "deleted_exact_version"
	version, e = minioTerminalProbePair(ctx, clients["catalog_append"], clients["catalog_read"], p.catalog.Bucket, in.CatalogKey, in.CatalogBadChecksumKey, body, false)
	if e == nil {
		(*inventory)[2].Version = version
		(*inventory)[2].State = "retained_reserved_probe"
		(*inventory)[3].State = "absent_after_checksum_rejection"
	}
	return e
}
