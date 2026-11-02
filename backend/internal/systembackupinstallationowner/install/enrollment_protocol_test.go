package install

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"net/http"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
)

// Generated v0.32 client methods prefer protobuf for both SSAR and ConfigMap.
// Decode that real wire format as well as JSON; do not replace or project any
// original resource attribute before the fixture's exact scope assertions.
func decodeEnrollmentAPIRequest(r *http.Request, into runtime.Object, group, kind string) error {
	media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/json" && media != "application/vnd.kubernetes.protobuf" {
		return errors.New("unsupported test API request media type")
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, 262145))
	if e != nil || len(raw) == 0 || len(raw) > 262144 {
		return errors.New("invalid bounded test API request")
	}
	codec, ok := runtime.SerializerInfoForMediaType(scheme.Codecs.SupportedMediaTypes(), media)
	if !ok {
		return errors.New("missing official API serializer")
	}
	expected := schema.GroupVersionKind{Group: group, Version: "v1", Kind: kind}
	decoded, gvk, e := codec.Serializer.Decode(raw, &expected, into)
	if e != nil || decoded != into || gvk == nil || *gvk != expected {
		return errors.New("wrong test API request type")
	}
	return nil
}

func TestOwnerEnrollFixturePreservesJSONAndProtobufScope(t *testing.T) {
	for _, media := range []string{"application/json", "application/vnd.kubernetes.protobuf"} {
		t.Run(media, func(t *testing.T) {
			input := &authorizationv1.SelfSubjectAccessReview{TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}, Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorizationv1.ResourceAttributes{Namespace: "foreign-namespace", Verb: "delete", Resource: "secrets", Name: "foreign-resource", Group: ""}}}
			codec, ok := runtime.SerializerInfoForMediaType(scheme.Codecs.SupportedMediaTypes(), media)
			if !ok {
				t.Fatal("official serializer")
			}
			raw, e := runtime.Encode(codec.Serializer, input)
			if e != nil {
				t.Fatal(e)
			}
			r, e := http.NewRequest("POST", "https://api.invalid", bytes.NewReader(raw))
			if e != nil {
				t.Fatal(e)
			}
			r.Header.Set("Content-Type", media)
			var decoded authorizationv1.SelfSubjectAccessReview
			if e := decodeEnrollmentAPIRequest(r, &decoded, "authorization.k8s.io", "SelfSubjectAccessReview"); e != nil || decoded.Spec.ResourceAttributes == nil || *decoded.Spec.ResourceAttributes != *input.Spec.ResourceAttributes {
				t.Fatal("protocol decoder changed original scope", e)
			}
			r, e = http.NewRequest("POST", "https://api.invalid", bytes.NewReader(raw))
			if e != nil {
				t.Fatal(e)
			}
			r.Header.Set("Content-Type", media)
			if e := decodeEnrollmentAPIRequest(r, &decoded, "", "ConfigMap"); e == nil {
				t.Fatal("wrong wire GVK accepted")
			}
		})
	}
}
