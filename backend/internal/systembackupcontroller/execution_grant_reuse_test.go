package systembackupcontroller

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	d "clawreef/internal/systembackupdispatch"
)

func pinnedGrantDataFixture(t testing.TB) (*PinnedExecutionIdentity, ExecutionGrant, d.Authority, []byte, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	directory := t.TempDir()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(private) })
	now := time.Now().UTC()
	grant := ExecutionGrant{Version: "system-backup-execution-grant.v1", InstallationID: "installation_" + strings.Repeat("a", 32), ControllerOwner: "controller-a", DatabaseAccount: "backup_controller@localhost", ServerUUID: "server", Database: "backup", ConfigVersion: 1, ConfigSHA256: strings.Repeat("b", 64), ProfileSHA256: strings.Repeat("c", 64), NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Actions: []string{"capture"}, RecordKeys: []ExecutionRecordKey{{Ref: "record-v1", SHA256: strings.Repeat("d", 64)}}, CaptureKeys: []ExecutionRecordKey{{Ref: "capture-v1", SHA256: strings.Repeat("e", 64)}}}
	raw := signPinnedGrantData(t, grant, private)
	path := filepath.Join(directory, "grant.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	identity, err := NewPinnedExecutionIdentity(path, recordHash(raw), directory, public)
	if err != nil {
		t.Fatal(err)
	}
	authority := d.Authority{InstallationID: grant.InstallationID, ClaimOwner: grant.ControllerOwner, ConfigVersion: grant.ConfigVersion, ConfigSHA256: grant.ConfigSHA256}
	return identity, grant, authority, raw, public, private
}

func signPinnedGrantData(t testing.TB, grant ExecutionGrant, key ed25519.PrivateKey) []byte {
	t.Helper()
	body, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(executionGrantEnvelope{Payload: base64.StdEncoding.EncodeToString(body), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, body))})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPinnedCurrentGrantDataRequiresOriginalCurrentFileAndTime(t *testing.T) {
	p, grant, authority, raw, public, key := pinnedGrantDataFixture(t)
	now := time.Now().UTC()
	if p.current(authority, now) != nil {
		t.Fatal("original current document rejected")
	}
	// Constructor trust bytes and public metadata are defensive copies.
	clear(public)
	copy := p.DeploymentBinding()
	copy.Actions[0] = "recover"
	copy.RecordKeys[0].SHA256 = strings.Repeat("f", 64)
	copy.CaptureKeys[0].Ref = "changed"
	callerBytes := bytes.Clone(raw)
	clear(raw)
	if p.current(authority, now) != nil || !bytes.Equal(p.authenticated, callerBytes) || p.grant.Actions[0] != "capture" || p.grant.RecordKeys[0] != grant.RecordKeys[0] || p.grant.CaptureKeys[0] != grant.CaptureKeys[0] {
		t.Fatal("caller changed private authenticated interpretation")
	}
	for _, change := range []string{"removed", "directory", "empty", "oversize", "trailing-byte", "corrupt-signature", "signed-renewal", "signed-purpose"} {
		t.Run(change, func(t *testing.T) {
			if err := os.Remove(p.path); err != nil {
				t.Fatal(err)
			}
			var replacement []byte
			switch change {
			case "removed":
			case "directory":
				if err := os.Mkdir(p.path, 0700); err != nil {
					t.Fatal(err)
				}
			case "empty":
				replacement = []byte{}
			case "oversize":
				replacement = bytes.Repeat([]byte{' '}, 65537)
			case "trailing-byte":
				replacement = append(bytes.Clone(callerBytes), '\n')
			case "corrupt-signature":
				replacement = bytes.Clone(callerBytes)
				replacement[len(replacement)-4] ^= 1
			case "signed-renewal":
				changed := grant
				changed.ExpiresAt = changed.ExpiresAt.Add(time.Minute)
				replacement = signPinnedGrantData(t, changed, key)
			case "signed-purpose":
				changed := grant
				changed.Actions = []string{"recover"}
				replacement = signPinnedGrantData(t, changed, key)
			}
			if replacement != nil {
				if err := os.WriteFile(p.path, replacement, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if p.current(authority, now) == nil {
				t.Fatal("replaced/removed current file reused old authentication")
			}
			if change == "directory" {
				if err := os.Remove(p.path); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(p.path, callerBytes, 0600); err != nil || p.current(authority, now) != nil {
				t.Fatal("healthy original document restoration failed", err)
			}
		})
	}
	for _, current := range []time.Time{grant.NotBefore.Add(-time.Nanosecond), grant.ExpiresAt, grant.ExpiresAt.Add(time.Nanosecond)} {
		if p.current(authority, current) == nil {
			t.Fatal("original fixed interval escaped")
		}
	}
	for _, field := range []string{"installation", "owner", "config-version", "config-hash"} {
		changed := authority
		switch field {
		case "installation":
			changed.InstallationID += "-other"
		case "owner":
			changed.ClaimOwner += "-other"
		case "config-version":
			changed.ConfigVersion++
		case "config-hash":
			changed.ConfigSHA256 = strings.Repeat("f", 64)
		}
		if p.current(changed, now) == nil {
			t.Fatal("current authority fields ignored", field)
		}
	}
}

func BenchmarkPinnedCurrentGrantData(b *testing.B) {
	p, grant, authority, _, _, _ := pinnedGrantDataFixture(b)
	now := time.Now().UTC()
	for _, mode := range []string{"legacy-repeat-authentication", "current-exact-data"} {
		b.Run(mode, func(b *testing.B) {
			b.ReportAllocs()
			for index := 0; index < b.N; index++ {
				if mode == "current-exact-data" {
					if p.current(authority, now) != nil {
						b.Fatal("current original file rejected")
					}
					continue
				}
				if authority.InstallationID != grant.InstallationID || authority.ClaimOwner != grant.ControllerOwner || authority.ConfigVersion != grant.ConfigVersion || authority.ConfigSHA256 != grant.ConfigSHA256 || now.Before(grant.NotBefore) || !now.Before(grant.ExpiresAt) {
					b.Fatal("legacy current scope")
				}
				raw, err := readExecutionFile(p.path, 65536)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := p.decode(raw); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
