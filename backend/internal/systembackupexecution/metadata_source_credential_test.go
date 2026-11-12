package systembackupexecution

import (
	"reflect"
	"testing"
)

func TestMetadataCredentialOriginalAndLegacyEncodings(t *testing.T) {
	want := metadataSourceCredential{Username: "reader", Password: []byte("secret")}
	for _, raw := range []string{
		`{"password":"c2VjcmV0","username":"reader"}`,
		`{"username":"reader","password":"c2VjcmV0"}`,
	} {
		var got metadataSourceCredential
		if decodeMetadataSourceCredential([]byte(raw), &got) != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("original and legacy encodings must preserve account and secret")
		}
	}
	var objects metadataSourceCredential
	if decodeMetadataSourceCredential([]byte(`{"access_key":"reader","secret_key":"c2VjcmV0"}`), &objects) != nil || string(objects.SecretKey) != "secret" {
		t.Fatal("existing object credential changed")
	}
}

func TestMetadataCredentialRejectsNoncanonicalOrAmbiguousInput(t *testing.T) {
	for _, raw := range []string{
		`{"username":"reader","password":"c2VjcmV0","extra":true}`,
		`{"username":"other","username":"reader","password":"c2VjcmV0"}`,
		`{"Username":"reader","password":"c2VjcmV0"}`,
		`{"username":"reader", "password":"c2VjcmV0"}`,
		`{"username":"reader","password":"c2VjcmV0"}` + "\n",
		`{"username":"reader","password":"c2VjcmV0"}{}`,
		`{"username":"reader","password":null}`,
		`{"username":"reader","password":"!invalid!"}`,
		`{"username":"reader","password":"c2VjcmV0","session_token":""}`,
		`{"username":"\u0072eader","password":"c2VjcmV0"}`,
	} {
		got := metadataSourceCredential{Username: "untouched"}
		if decodeMetadataSourceCredential([]byte(raw), &got) == nil || got.Username != "untouched" || got.Password != nil {
			t.Fatal("noncanonical credential accepted or output changed on refusal")
		}
	}
}
