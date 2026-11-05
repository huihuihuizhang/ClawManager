package minionative

import (
	"bytes"
	"strings"
	"testing"
)

func TestSeptemberMetadataObserverReadbackExactContract(t *testing.T) {
	wire := `{"Version":"2012-10-17","Statement":[{"Action":["admin:GetUser","admin:ServerInfo","admin:GetPolicy"],"Effect":"Allow","Resource":["**"]},{"Action":["s3:GetBucketVersioning","s3:GetBucketPolicy"],"Effect":"Allow","Resource":["arn:aws:s3:::native-bucket"]}]}`
	want := `{"Statement":[{"Action":["admin:GetPolicy","admin:GetUser","admin:ServerInfo"],"Effect":"Allow","Resource":["*"]},{"Action":["s3:GetBucketPolicy","s3:GetBucketVersioning"],"Effect":"Allow","Resource":["arn:aws:s3:::native-bucket"]}],"Version":"2012-10-17"}`
	normalized, e := NormalizeSeptemberMetadataObserverReadback([]byte(wire))
	if e != nil || !bytes.Equal(normalized, []byte(want)) {
		t.Fatal("exact September representation did not retain original full policy")
	}
	cases := map[string]string{
		"condition":             strings.Replace(wire, `"Effect":"Allow"`, `"Condition":{},"Effect":"Allow"`, 1),
		"sid":                   strings.Replace(wire, `"Effect":"Allow"`, `"Sid":"extra","Effect":"Allow"`, 1),
		"unknown_document":      strings.Replace(wire, `"Version":`, `"Extra":true,"Version":`, 1),
		"extra_admin_action":    strings.Replace(wire, `"admin:GetUser"`, `"admin:CreateUser","admin:GetUser"`, 1),
		"wrong_admin_action":    strings.Replace(wire, `"admin:GetUser"`, `"admin:CreateUser"`, 1),
		"wrong_admin_resource":  strings.Replace(wire, `["**"]`, `["***"]`, 1),
		"extra_admin_resource":  strings.Replace(wire, `["**"]`, `["**","*"]`, 1),
		"scalar_admin_resource": strings.Replace(wire, `["**"]`, `"**"`, 1),
		"deny":                  strings.Replace(wire, `"Effect":"Allow"`, `"Effect":"Deny"`, 1),
		"s3_double_star":        strings.Replace(wire, `["arn:aws:s3:::native-bucket"]`, `["**"]`, 1),
		"s3_arn_wildcard":       strings.Replace(wire, `arn:aws:s3:::native-bucket`, `arn:aws:s3:::native-*`, 1),
		"generic_put_action":    strings.Replace(wire, `"s3:GetBucketPolicy"`, `"s3:PutObject"`, 1),
		"duplicate_action":      strings.Replace(wire, `"admin:GetUser"`, `"admin:GetUser","admin:GetUser"`, 1),
		"duplicate_key":         strings.Replace(wire, `"Version":`, `"Version":"2012-10-17","Version":`, 1),
		"trailing_json":         wire + `{}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := NormalizeSeptemberMetadataObserverReadback([]byte(raw)); e == nil {
				t.Fatal("out-of-profile representation accepted")
			}
		})
	}
}
