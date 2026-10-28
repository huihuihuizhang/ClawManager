package assets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"testing"

	"clawreef/internal/systembackup/domain"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestAssetsCaptureRoundTripAndIdentityFailures(t *testing.T) {
	payload := []byte("isolated Skill package")
	sum := sha256.Sum256(payload)
	i := Inventory{Namespace: "source", Secrets: []SecretRef{{Namespace: "source", Name: "model", UID: "secret-uid", ResourceVersion: "3", Role: "model", Keys: []string{"key"}}}, Objects: []ObjectRef{{Key: "skills/pkg", VersionID: "immutable-v1", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(payload))}}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "model", Namespace: "source", UID: "secret-uid", ResourceVersion: "3"}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"key": []byte("source-private-credential")}}
	client := fake.NewSimpleClientset(secret)
	open := func(_ context.Context, ref ObjectRef) (io.ReadCloser, error) {
		if ref.VersionID != "immutable-v1" {
			t.Fatal("object version changed")
		}
		return io.NopCloser(bytes.NewReader(payload)), nil
	}
	set, e := Capture(context.Background(), client, i, open)
	if e != nil {
		t.Fatal(e)
	}
	defer set.Clear()
	raw, _ := json.Marshal(set)
	restored, e := Decode(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Clear()
	if !bytes.Equal(restored.Objects[0].Data, payload) || string(restored.Secrets[0].Data["key"]) != "source-private-credential" {
		t.Fatal("asset data lost")
	}
	for _, mode := range []string{"uid", "revision", "unclassified-key", "infrastructure"} {
		t.Run(mode, func(t *testing.T) {
			s := secret.DeepCopy()
			switch mode {
			case "uid":
				s.UID = "replacement"
			case "revision":
				s.ResourceVersion = "4"
			case "unclassified-key":
				s.Data["new"] = []byte("unknown")
			case "infrastructure":
				s.Type = corev1.SecretTypeServiceAccountToken
			}
			if _, e := Capture(context.Background(), fake.NewSimpleClientset(s), i, open); e == nil {
				t.Fatal("unsafe secret captured")
			}
		})
	}
	if _, e = Capture(context.Background(), client, i, func(context.Context, ObjectRef) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewBufferString("changed")), nil
	}); e == nil {
		t.Fatal("changed object accepted")
	}
}
func TestAssetReferencesRequireContentNotJustReference(t *testing.T) {
	i := Inventory{Namespace: "source"}
	s := domain.Snapshot{Tables: []domain.Table{{Name: "llm_models", Rows: []domain.Row{{"api_key_secret_ref": domain.Text("k8s-secret/source/model:key")}}}}}
	if i.CheckReferences(s) == nil {
		t.Fatal("missing model secret ignored")
	}
	i.Secrets = []SecretRef{{Namespace: "source", Name: "model", UID: "uid", ResourceVersion: "1", Role: "model", Keys: []string{"key"}}}
	if i.CheckReferences(s) != nil {
		t.Fatal("registered business secret rejected")
	}
}
