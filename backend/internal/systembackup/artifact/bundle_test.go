package artifact

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"os"
	"strings"
	"testing"

	"clawreef/internal/systembackup/staging"
)

func bundleFixture(t *testing.T) (Directory, Bundle, ed25519.PrivateKey, *os.Root) {
	t.Helper()
	source, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { source.Close() })
	target, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { target.Close() })
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	keys := SecretKeys{"kek-1": bytes.Repeat([]byte{7}, 32)}
	d := Directory{Root: target, Keys: keys, VerifyKeys: map[string]ed25519.PublicKey{"sign-1": public}, MaxCiphertextBytes: 8 << 20, MaxPlaintextBytes: 8 << 20, Authorize: func(context.Context, string, string) error { return nil }}
	b := Bundle{Version: Version, ID: "backup-1", Purpose: "functional_test", Scope: []string{"users", "instances"}, PolicyVersion: "fixture-1", Users: 2, Instances: 1}
	for i, id := range []string{"database", "instance-7"} {
		binding := staging.Binding{BackupID: b.ID, Attempt: "1", Path: id, PartIndex: uint32(i), CaptureContextHash: strings.Repeat("a", 64), EnvelopeID: "envelope-" + id}
		dek := bytes.Repeat([]byte{byte(i + 1)}, 32)
		receipt, e := staging.SealFile(context.Background(), source, id+".enc", dek, binding, func(w io.Writer) error { _, e := w.Write([]byte("fixture-private-" + id)); return e })
		if e != nil {
			t.Fatal(e)
		}
		wrapped, e := keys.Wrap(context.Background(), binding, "kek-1", dek)
		if e != nil {
			t.Fatal(e)
		}
		b.Parts = append(b.Parts, Part{ID: id, Receipt: receipt, Binding: binding, Key: wrapped})
		clear(dek)
	}
	return d, b, private, source
}
func publishFixture(t *testing.T, d Directory, b Bundle, key ed25519.PrivateKey, source *os.Root) {
	t.Helper()
	if e := d.Publish(context.Background(), b, "sign-1", key, func(p Part) (io.ReadCloser, error) { return source.Open(p.Receipt.Name) }); e != nil {
		t.Fatal(e)
	}
}
func TestBundleCanBeReadAfterSourceDisappears(t *testing.T) {
	d, b, key, source := bundleFixture(t)
	publishFixture(t, d, b, key, source)
	publishFixture(t, d, b, key, source)
	source.Close()
	read, e := d.Read(context.Background(), b.ID)
	if e != nil || read.Users != 2 || read.Instances != 1 {
		t.Fatal(e)
	}
	raw, e := d.Root.ReadFile(indexName(b.ID))
	if e != nil || bytes.Contains(raw, []byte("fixture-private")) || bytes.Contains(raw, bytes.Repeat([]byte{7}, 32)) {
		t.Fatal("index leaked plaintext")
	}
	for _, p := range read.Parts {
		dek, e := d.Keys.Unwrap(context.Background(), p.Binding, p.Key)
		if e != nil {
			t.Fatal(e)
		}
		f, e := d.Root.Open(p.Receipt.Name)
		if e != nil {
			t.Fatal(e)
		}
		var output bytes.Buffer
		e = staging.Open(context.Background(), f, &output, dek, p.Binding, 8<<20)
		f.Close()
		clear(dek)
		if e != nil || output.String() != "fixture-private-"+p.ID {
			t.Fatal("offline payload changed", e)
		}
	}
}
func TestBundleRejectsTamperUnknownKeysAndIncompleteScope(t *testing.T) {
	for _, mode := range []string{"marker", "part", "key", "signature-key", "wrong-binding", "missing-part", "path", "authorization"} {
		t.Run(mode, func(t *testing.T) {
			d, b, key, source := bundleFixture(t)
			if mode == "missing-part" || mode == "path" || mode == "wrong-binding" {
				switch mode {
				case "missing-part":
					b.Parts = b.Parts[:1]
				case "path":
					b.Parts[0].Receipt.Name = "../outside"
				case "wrong-binding":
					b.Parts[0].Binding.EnvelopeID = "other"
				}
				if e := d.Publish(context.Background(), b, "sign-1", key, func(p Part) (io.ReadCloser, error) { return source.Open(p.Receipt.Name) }); e == nil {
					t.Fatal("unsafe publication")
				}
				return
			}
			publishFixture(t, d, b, key, source)
			switch mode {
			case "marker", "part":
				filename := markerName(b.ID)
				if mode == "part" {
					filename = objectName(b.ID, "database")
				}
				if e := d.Root.Chmod(filename, 0600); e != nil {
					t.Fatal(e)
				}
				if e := d.Root.WriteFile(filename, []byte("tampered"), 0600); e != nil {
					t.Fatal(e)
				}
			case "key":
				d.Keys = SecretKeys{"kek-1": bytes.Repeat([]byte{8}, 32)}
			case "signature-key":
				d.VerifyKeys = map[string]ed25519.PublicKey{}
			case "authorization":
				d.Authorize = func(context.Context, string, string) error { return ErrArtifact }
			}
			if _, e := d.Read(context.Background(), b.ID); e == nil {
				t.Fatal("unsafe read")
			}
		})
	}
}
