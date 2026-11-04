package systembackupevidence

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func (g *OriginalC1OwnerChannel) exactVersionAbsence(ctx context.Context, ref Ref) error {
	if ref.Identity != g.owner.Upstream.Identity || ref.Version != g.owner.Upstream.Version || ref.ImmutableVersion != "" || !safeKey(ref.RelativeKey) {
		return ErrDenied
	}
	marker, version := "", ""
	seen := map[string]bool{}
	for page := 0; page < 10000; page++ {
		query := url.Values{"versions": {""}, "prefix": {ref.RelativeKey}, "max-keys": {"1000"}}
		if marker != "" {
			query.Set("key-marker", marker)
			query.Set("version-id-marker", version)
		}
		response, err := g.ownerRequest(ctx, http.MethodGet, "/"+g.owner.Upstream.Bucket, query, nil, nil)
		if err != nil {
			return ErrUnavailable
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		response.Body.Close()
		if readErr != nil || len(raw) > 1<<20 || response.StatusCode != http.StatusOK {
			return ErrDenied
		}
		if !c1UnambiguousVersionsXML(raw) {
			return ErrDenied
		}
		var result struct {
			XMLName                                                                      xml.Name
			Name, Prefix, KeyMarker, VersionIdMarker, NextKeyMarker, NextVersionIdMarker string
			IsTruncated                                                                  *bool
			Versions                                                                     []struct{ Key, VersionId string } `xml:"Version"`
			Markers                                                                      []struct{ Key, VersionId string } `xml:"DeleteMarker"`
		}
		decoder := xml.NewDecoder(bytes.NewReader(raw))
		decoder.Strict = true
		if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || result.XMLName.Local != "ListVersionsResult" || result.IsTruncated == nil || result.Name != g.owner.Upstream.Bucket || result.Prefix != ref.RelativeKey || result.KeyMarker != marker || result.VersionIdMarker != version {
			return ErrDenied
		}
		for _, entry := range result.Versions {
			if entry.Key == "" || entry.VersionId == "" || entry.Key == ref.RelativeKey {
				return ErrDenied
			}
		}
		for _, entry := range result.Markers {
			if entry.Key == "" || entry.VersionId == "" || entry.Key == ref.RelativeKey {
				return ErrDenied
			}
		}
		if !*result.IsTruncated {
			return nil
		}
		key := result.NextKeyMarker + "\x00" + result.NextVersionIdMarker
		if result.NextKeyMarker == "" || key == marker+"\x00"+version || seen[key] {
			return ErrDenied
		}
		seen[key] = true
		marker, version = result.NextKeyMarker, result.NextVersionIdMarker
	}
	return ErrDenied
}

// Reject ambiguous duplicate control fields before the typed XML read. In
// particular a later IsTruncated=false must never hide an earlier true value.
func c1UnambiguousVersionsXML(raw []byte) bool {
	d := xml.NewDecoder(bytes.NewReader(raw))
	d.Strict = true
	depth, roots := 0, 0
	top := map[string]bool{}
	child := map[string]bool{}
	parent := ""
	for {
		token, err := d.Token()
		if err == io.EOF {
			return depth == 0 && roots == 1
		}
		if err != nil {
			return false
		}
		switch t := token.(type) {
		case xml.StartElement:
			depth++
			if depth == 1 {
				roots++
				if roots != 1 || t.Name.Local != "ListVersionsResult" {
					return false
				}
			}
			if depth == 2 {
				parent = t.Name.Local
				child = map[string]bool{}
				repeated := parent == "Version" || parent == "DeleteMarker" || parent == "CommonPrefixes"
				if !repeated && top[parent] {
					return false
				}
				top[parent] = true
			}
			if depth == 3 && (parent == "Version" || parent == "DeleteMarker") {
				if (t.Name.Local == "Key" || t.Name.Local == "VersionId") && child[t.Name.Local] {
					return false
				}
				child[t.Name.Local] = true
			}
		case xml.EndElement:
			depth--
		case xml.Directive:
			return false
		case xml.ProcInst:
			if depth != 0 || roots != 0 || t.Target != "xml" {
				return false
			}
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(t)) != "" {
				return false
			}
		}
	}
}
