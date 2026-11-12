package systembackupinstallationowner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestInstalledVaultPublicKeysEquivalentEncoding(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	original := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	pkcs1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)}))
	for _, actual := range []string{original, strings.TrimSpace(original), strings.ReplaceAll(original, "\n", "\r\n"), " \n" + original + "\t", pkcs1} {
		if !installedVaultPublicKeysEqual([]string{actual}, []string{original}) {
			t.Fatal("equivalent public key rejected")
		}
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	otherPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: otherDER}))
	if !installedVaultPublicKeysEqual([]string{otherPEM, pkcs1}, []string{original, otherPEM}) {
		t.Fatal("key order changed trust")
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	bad := [][]string{nil, {}, {otherPEM}, {original, original}, {original, pkcs1}, {original, otherPEM},
		{"junk\n" + original}, {original + "junk"}, {original + original}, {"-----BEGIN JUNK-----\n" + original},
		{string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER}))},
		{string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))},
		{string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der, Headers: map[string]string{"X": "Y"}}))}}
	for i, actual := range bad {
		if installedVaultPublicKeysEqual(actual, []string{original}) {
			t.Fatalf("invalid case %d accepted", i)
		}
	}
}
