package systembackupsecurity

import (
	"bytes"
	"testing"
	"time"
)

func TestTOTPRFC6238AndReplay(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, tc := range []struct {
		unix int64
		code string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"}} {
		if got := totpCode(secret, tc.unix/30, 8); got != tc.code {
			t.Fatalf("RFC vector %d: %s", tc.unix, got)
		}
		code := tc.code[2:]
		step, ok := matchTOTP(secret, code, time.Unix(tc.unix, 0), -1)
		if !ok {
			t.Fatal("valid TOTP rejected")
		}
		if _, ok = matchTOTP(secret, code, time.Unix(tc.unix, 0), step); ok {
			t.Fatal("TOTP step reused")
		}
	}
	if _, ok := matchTOTP(secret, " 287082", time.Unix(59, 0), -1); ok {
		t.Fatal("bad code accepted")
	}
}
func TestTOTPSecretBoxBindsUserAndInstallation(t *testing.T) {
	box, err := NewTOTPSecretBox(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{9}, 20)
	cipher, err := box.seal(secret, "installation-a/user:7")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := box.open(cipher, "installation-a/user:7")
	if err != nil || !bytes.Equal(raw, secret) {
		t.Fatal("round trip failed")
	}
	if _, err = box.open(cipher, "installation-b/user:7"); err == nil {
		t.Fatal("cross-installation seed reuse")
	}
	cipher[len(cipher)-1] ^= 1
	if _, err = box.open(cipher, "installation-a/user:7"); err == nil {
		t.Fatal("tampered seed accepted")
	}
}
