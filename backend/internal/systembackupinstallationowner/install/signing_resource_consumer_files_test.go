package install

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
)

func TestSigningResourceFileTransportRequiresOriginalSignedTuple(t *testing.T) {
	pin, bundle, f := originalSigningResourceBundleFixture(t)
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private source files")
	}
	write := func(name string, value any) (string, string) {
		t.Helper()
		raw, err := canonical(value)
		path := filepath.Join(directory, name)
		if err != nil || os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("private pinned source")
		}
		return path, hash(raw)
	}
	pinFile, pinSHA := write("pin.json", pin)
	bundleFile, bundleSHA := write("bundle.json", bundle)
	item := SigningResourceSQLFile{PinFile: pinFile, PinSHA256: pinSHA, BundleFile: bundleFile, BundleSHA256: bundleSHA}
	load := func(items []SigningResourceSQLFile) ([]SigningResourceSQLInput, error) {
		file, sha := write("inputs.json", SigningResourceSQLFiles{Version: SigningResourceSQLFilesVersion, Items: items})
		return LoadSigningResourceSQLInputs(file, sha)
	}
	queries, signs := f.s.auth.queries, f.signs.Load()
	inputs, err := load([]SigningResourceSQLFile{item})
	if err != nil || len(inputs) != 1 || inputs[0].Pin.Purpose != pin.Purpose {
		t.Fatal("actual original A codec transport failed", err)
	}
	if _, err := load([]SigningResourceSQLFile{item, item}); err == nil {
		t.Fatal("duplicate original purpose admitted")
	}
	// An independently re-pinned file hash is not a replacement issuer: the
	// original Grant/Head signatures must still authenticate the selected key.
	foreign := pin
	foreign.Issuer = bytes.Repeat([]byte{1}, 32)
	_, foreignSHA := write("pin.json", foreign)
	changed := item
	changed.PinSHA256 = foreignSHA
	if _, err := load([]SigningResourceSQLFile{changed}); err == nil {
		t.Fatal("file hash substituted an unauthenticated issuer")
	}
	write("pin.json", pin)
	bad := bundle
	bad.GrantSignature = bytes.Clone(bundle.GrantSignature)
	bad.GrantSignature[0] ^= 1
	_, changed.BundleSHA256 = write("bundle.json", bad)
	changed.PinSHA256 = pinSHA
	if _, err := load([]SigningResourceSQLFile{changed}); err == nil {
		t.Fatal("transport SHA replaced original signature verification")
	}
	if f.s.auth.queries != queries || f.signs.Load() != signs {
		t.Fatal("file transport touched SQL or a provider")
	}
}

func TestSigningResourceConsumerExportSnapshotRejectsClockBeforeOriginalFloor(t *testing.T) {
	f, model, input, _ := signerSQLFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := f.i.ImportSigningResourceSQLAuthority(ctx, f.password, f.enrollment, []SigningResourceSQLInput{input}); err != nil {
		t.Fatal(err)
	}
	operator, err := f.i.authenticate(ctx, f.password)
	if err != nil {
		t.Fatal(err)
	}
	changes, err := signingResourceSQLChanges(ctx, operator, f.enrollment, []SigningResourceSQLInput{input})
	if err != nil {
		t.Fatal(err)
	}
	writes := model.execs
	rows, floor, err := signingResourceExportSnapshot(ctx, operator, changes, operator.sqlTime)
	if err != nil || len(rows) != 1 || floor.Before(operator.sqlTime) {
		t.Fatal("actual codec/current-row snapshot failed", err)
	}
	if _, _, err := signingResourceExportSnapshot(ctx, operator, changes, floor.Add(30*time.Second)); err == nil {
		t.Fatal("independent export snapshot ignored its original SQL floor")
	}
	if model.execs != writes || model.captureReads != 0 || len(model.data.heads) != 1 || len(model.data.grants) != 1 {
		t.Fatal("export snapshot wrote/repaired authority or borrowed capture")
	}
}

func TestSigningResourceConsumerExportPreflightPreservesFrozenOutput(t *testing.T) {
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private output")
	}
	file := filepath.Join(directory, "signing-consumer.json")
	original := []byte("independently retained output")
	if os.WriteFile(file, original, 0600) != nil {
		t.Fatal("owned frozen output")
	}
	// A nil installer proves this fails before auth/SQL/provider access.
	var installer *Installer
	if _, err := installer.ExportSigningResourceConsumer(context.Background(), nil, EnrollmentPin{}, make([]SigningResourceSQLInput, 2), make([]SigningResourceConsumerAsset, 2), "", "", directory); err == nil {
		t.Fatal("existing consumer output accepted")
	}
	if raw, err := os.ReadFile(file); err != nil || !bytes.Equal(raw, original) {
		t.Fatal("frozen consumer output overwritten")
	}
	if err := CheckNewSigningResourceBundleDirectory(directory, owner.SigningResourcePurposes()[0]); err != nil {
		t.Fatal("unrelated retained file should not block exact bundle names", err)
	}
}
