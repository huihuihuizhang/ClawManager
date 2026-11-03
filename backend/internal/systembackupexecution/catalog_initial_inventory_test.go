package systembackupexecution

import (
	"strings"
	"testing"
)

func TestCatalogInitialInventoryRejectsIncompleteOrNonemptyVersionLists(t *testing.T) {
	raw := `<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>original-catalog</Name><Prefix>installation/catalog/</Prefix><KeyMarker></KeyMarker><VersionIdMarker></VersionIdMarker><MaxKeys>1</MaxKeys><IsTruncated>false</IsTruncated></ListVersionsResult>`
	if !catalogInitialEmptyVersionList([]byte(raw), "original-catalog", "installation/catalog/") {
		t.Fatal("exact complete empty scope refused")
	}
	for name, bad := range map[string]string{
		"truncated": strings.Replace(raw, "<IsTruncated>false", "<IsTruncated>true", 1),
		"version":   strings.Replace(raw, "</ListVersionsResult>", "<Version><Key>registration</Key></Version></ListVersionsResult>", 1),
		"deleted":   strings.Replace(raw, "</ListVersionsResult>", "<DeleteMarker></DeleteMarker></ListVersionsResult>", 1),
		"prefixes":  strings.Replace(raw, "</ListVersionsResult>", "<CommonPrefixes></CommonPrefixes></ListVersionsResult>", 1),
		"duplicate": strings.Replace(raw, "</ListVersionsResult>", "<IsTruncated>false</IsTruncated></ListVersionsResult>", 1),
		"cursor":    strings.Replace(raw, "</ListVersionsResult>", "<NextKeyMarker>foreign</NextKeyMarker></ListVersionsResult>", 1),
		"scope":     strings.Replace(raw, "<Prefix>installation/catalog/", "<Prefix>foreign/", 1),
		"bucket":    strings.Replace(raw, "original-catalog", "foreign-catalog", 1),
		"unknown":   strings.Replace(raw, "</ListVersionsResult>", "<Unknown></Unknown></ListVersionsResult>", 1),
		"limit":     strings.Replace(raw, "<MaxKeys>1", "<MaxKeys>2", 1),
		"no-eof":    raw + "<Error/>",
	} {
		t.Run(name, func(t *testing.T) {
			if catalogInitialEmptyVersionList([]byte(bad), "original-catalog", "installation/catalog/") {
				t.Fatal("unproven empty scope admitted")
			}
		})
	}
}
