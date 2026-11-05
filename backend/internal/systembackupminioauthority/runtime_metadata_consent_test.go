package systembackupminioauthority

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// Cryptographic declaration component only. No native SQL enrollment,
// deployment workload, original owner issue or runtime reader is qualified.
func TestRuntimeMetadataConsentRequiresOriginalOwnerAndExactReadScope(t *testing.T) {
	f, d, _, _, now := recoveryProjectionFixture(t)
	pin, e := RuntimeMetadataPinSHA256(d.Pin)
	if e != nil {
		t.Fatal(e)
	}
	public, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key)
	descriptor := digest([]byte("independently-pinned-descriptor"))
	r := RuntimeMetadataConsent{Version: RuntimeMetadataConsentVersion, PinSHA256: pin, RecoveryDescriptorSHA256: descriptor, OriginalConfigSHA256: f.grant.ConfigSHA256, OriginalForwardSHA256: digest([]byte("actual-forward-file-required")), ForwardIssuer: public, RuntimeDatabaseAccount: "original_runtime@localhost", Actor: d.Actor, NotBefore: now, SignedAt: now, Until: f.grant.Until, Workload: RuntimeMetadataWorkload{NamespaceUID: d.Pin.Target.NamespaceUID, ControllerOwner: "runtime-owner", Deployment: ObjectIdentity{"controller", "dep-uid"}, ReplicaSet: ObjectIdentity{"controller-rs", "rs-uid"}, Pod: ObjectIdentity{"controller-pod", "pod-uid"}, ServiceAccount: ObjectIdentity{"controller-sa", "sa-uid"}}}
	seal := func(r RuntimeMetadataConsent) []byte {
		body, e := canonical(r)
		if e != nil {
			t.Fatal(e)
		}
		raw, e := canonical(SignedRuntimeMetadataConsent{body, ed25519.Sign(f.key, append([]byte(RuntimeMetadataConsentDomain), body...))})
		if e != nil {
			t.Fatal(e)
		}
		return raw
	}
	if _, e = DecodeRuntimeMetadataConsent(seal(r), d, descriptor); e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		name   string
		change func(*RuntimeMetadataConsent)
	}{
		{"business-account", func(x *RuntimeMetadataConsent) { x.RuntimeDatabaseAccount = d.Pin.Target.ConsumerDatabaseAccount }},
		{"installer-account", func(x *RuntimeMetadataConsent) { x.RuntimeDatabaseAccount = d.Actor.InstallerDatabaseAccount }},
		{"foreign-pin", func(x *RuntimeMetadataConsent) { x.PinSHA256 = digest([]byte("foreign")) }},
		{"foreign-source", func(x *RuntimeMetadataConsent) { x.RecoveryDescriptorSHA256 = digest([]byte("foreign")) }},
		{"foreign-actor", func(x *RuntimeMetadataConsent) { x.Actor.LocalAdminUserID++ }},
		{"missing-pod", func(x *RuntimeMetadataConsent) { x.Workload.Pod.UID = "" }},
		{"empty-forward-issuer", func(x *RuntimeMetadataConsent) { x.ForwardIssuer = nil }},
		{"expired-window", func(x *RuntimeMetadataConsent) { x.Until = x.NotBefore }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			copy := r
			tc.change(&copy)
			if _, e := DecodeRuntimeMetadataConsent(seal(copy), d, descriptor); e == nil {
				t.Fatal("out-of-scope metadata consent accepted")
			}
		})
	}
}
