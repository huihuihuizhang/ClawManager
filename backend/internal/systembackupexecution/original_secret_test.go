package systembackupexecution

import (
	"encoding/json"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

func TestOriginalIdentitySecretRejectsSameNameReplacement(t *testing.T) {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "identity", UID: "original"}, Data: map[string][]byte{"tls.crt": []byte("synthetic-certificate"), "tls.key": []byte("synthetic-nonkey")}}
	plain, _ := json.Marshal(secret.Data)
	raw, _ := json.Marshal(identityEnvelope{PlainSHA256: hash(plain), InvocationSHA256: "invocation", Cipher: []byte{1}})
	if !originalIdentitySecretMatches(secret, "original", hash(raw), raw, "invocation") {
		t.Fatal("original identity rejected")
	}
	replaced := secret.DeepCopy()
	replaced.UID = "replaced"
	if originalIdentitySecretMatches(replaced, "original", hash(raw), raw, "invocation") {
		t.Fatal("same-name replacement adopted")
	}
	changed := secret.DeepCopy()
	changed.Data["tls.crt"] = []byte("different")
	if originalIdentitySecretMatches(changed, "original", hash(raw), raw, "invocation") {
		t.Fatal("changed certificate adopted")
	}
	if originalIdentitySecretMatches(secret, "original", hash(raw), raw, "another-invocation") {
		t.Fatal("other invocation adopted")
	}
	if originalIdentitySecretMatches(secret, "original", hash([]byte("tamper")), raw, "invocation") {
		t.Fatal("tampered journal adopted")
	}
}
