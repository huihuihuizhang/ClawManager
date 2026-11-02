package systembackupexecution

import (
	"bytes"
	"testing"
)

func TestMinIOEffectiveV2NormalizesNativeSetsWithoutDroppingAuthority(t *testing.T) {
	rules := []minioPermissionRule{{[]string{"s3:GetObject", "s3:GetObjectVersion"}, []string{"arn:aws:s3:::original/a/*", "arn:aws:s3:::original/b/*"}}}
	original := []byte(`{"Statement":[{"Action":["s3:GetObject","s3:GetObjectVersion"],"Effect":"Allow","Resource":["arn:aws:s3:::original/a/*","arn:aws:s3:::original/b/*"]}],"Version":"2012-10-17"}`)
	reordered := []byte(`{"Version":"2012-10-17","Statement":[{"Resource":["arn:aws:s3:::original/b/*","arn:aws:s3:::original/a/*"],"Effect":"Allow","Action":["s3:GetObjectVersion","s3:GetObject"]}]}`)
	normalized, e := minioPermissionNormalizedPolicyV2(reordered, hash(original), rules)
	if e != nil || !bytes.Equal(normalized, original) {
		t.Fatal("native set order changed original scope", e)
	}
	for _, raw := range [][]byte{
		bytes.Replace(reordered, []byte("s3:GetObjectVersion"), []byte("s3:*"), 1),
		bytes.Replace(reordered, []byte("Allow"), []byte("Deny"), 1),
		bytes.Replace(reordered, []byte(`"Effect":"Allow"`), []byte(`"Effect":"Allow","Condition":{}`), 1),
		bytes.Replace(reordered, []byte(`"Effect":"Allow"`), []byte(`"Effect":"Allow","Effect":"Allow"`), 1),
		append(append([]byte(nil), reordered...), []byte(` {}`)...),
	} {
		if _, e = minioPermissionNormalizedPolicyV2(raw, hash(original), rules); e == nil {
			t.Fatal("broader/ambiguous native policy accepted")
		}
	}
}

func TestMinIOEffectiveV2DeletePolicyIsStagingOnlyAndRequiresBothActions(t *testing.T) {
	rules, e := minioPermissionObjectRulesV2("artifact_delete", "original", "installation_original/", "installation_original_staging/")
	if e != nil || len(rules) != 1 || len(rules[0].Actions) != 2 || len(rules[0].Resources) != 1 || rules[0].Resources[0] != "arn:aws:s3:::original/installation_original_staging/*" {
		t.Fatal("v2 deletion scope", e)
	}
	raw := []byte(`{"Statement":[{"Action":["s3:DeleteObject","s3:DeleteObjectVersion"],"Effect":"Allow","Resource":["arn:aws:s3:::original/installation_original_staging/*"]}],"Version":"2012-10-17"}`)
	if _, e = minioPermissionNormalizedPolicyV2(raw, hash(raw), rules); e != nil {
		t.Fatal(e)
	}
	missing := bytes.Replace(raw, []byte(`"s3:DeleteObject",`), nil, 1)
	if _, e = minioPermissionNormalizedPolicyV2(missing, hash(missing), rules); e == nil {
		t.Fatal("v1 insufficient native deletion policy accepted")
	}
	broader := bytes.Replace(raw, []byte("installation_original_staging/*"), []byte("*"), 1)
	if _, e = minioPermissionNormalizedPolicyV2(broader, hash(broader), rules); e == nil {
		t.Fatal("deletion escaped staging")
	}
}
