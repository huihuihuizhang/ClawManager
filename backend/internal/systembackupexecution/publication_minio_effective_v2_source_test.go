package systembackupexecution

import (
	ce "clawreef/internal/systembackupcontrolevidence"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMinIOEffectiveV2OwnerEpochUIDAndRevocation(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	cfg := minioEffectivePermissionConfiguration{Version: "minio-publication-effective-permission-source.v2", Installation: "installation", Namespace: "scope", NamespaceUID: "scope-uid", Issuer: public, MinimumEpoch: 3, Grant: minioPermissionObject{"grant", "grant-uid"}, Head: minioPermissionObject{"head", "head-uid"}, ObserverCredentialSHA256: hash([]byte("credential")), ObserverAccountSHA256: hash([]byte("observer")), ObserverPolicySHA256: hash([]byte("policy")), ObserverPolicyName: "observer"}
	grant := minioPermissionGrant{Version: "minio-permission-grant.v1", Installation: cfg.Installation, Namespace: cfg.Namespace, NamespaceUID: cfg.NamespaceUID, Profile: minioPermissionProfileV2, Epoch: 3, NotBefore: now.Add(-time.Second), Until: now.Add(time.Minute)}
	g, _ := ce.Canonical(grant)
	cfg.GrantSHA256 = hash(g)
	head := minioPermissionHead{Version: "minio-permission-head.v1", Installation: cfg.Installation, State: "active", GrantSHA256: cfg.GrantSHA256, Epoch: 3, NotBefore: grant.NotBefore, Until: grant.Until}
	object := func(ref minioPermissionObject, domain string, value any) *corev1.ConfigMap {
		raw, _ := ce.Canonical(value)
		return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: cfg.Namespace, UID: types.UID(ref.UID), ResourceVersion: "5"}, Data: map[string]string{"record.json": string(raw)}, BinaryData: map[string][]byte{"signature": ed25519.Sign(key, append([]byte(domain), raw...))}}
	}
	raw, _ := ce.Canonical(cfg)
	path := filepath.Join(t.TempDir(), "source.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := NewMinIOEffectivePublicationPermissionV2Reader(MinIOPublicationPermissionInput{path, hash(raw)})
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"original-active-no-engine-object", "revoked", "replayed-epoch", "wrong-namespace", "invalid-signature", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			changed := head
			nsUID := cfg.NamespaceUID
			at := now
			switch scenario {
			case "revoked":
				changed.State = "revoked"
			case "replayed-epoch":
				changed.Epoch = 2
			case "wrong-namespace":
				nsUID = "substitution"
			case "expired":
				at = now.Add(2 * time.Minute)
			}
			gcm, hcm := object(cfg.Grant, minioPermissionOwnerDomain, grant), object(cfg.Head, minioPermissionHeadDomain, changed)
			if scenario == "invalid-signature" {
				hcm.BinaryData["signature"][0] ^= 1
			}
			client := fake.NewSimpleClientset(gcm, hcm, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: cfg.Namespace, UID: types.UID(nsUID)}})
			owner, err := r.effectiveOwnerV2(context.Background(), client, at)
			if (err == nil) != (scenario == "original-active-no-engine-object") {
				t.Fatalf("original revocable authority source: %v", err)
			}
			if err == nil && owner.stamp == "" {
				t.Fatal("original authority stamp missing")
			}
		})
	}
}
