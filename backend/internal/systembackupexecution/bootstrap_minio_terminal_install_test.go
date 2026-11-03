package systembackupexecution

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	ce "clawreef/internal/systembackupcontrolevidence"
	"clawreef/internal/systembackupinstallationowner/install"
)

func TestMinIOBootstrapTerminalInstallInputIsExactInertOriginalData(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	input := MinIOBootstrapTerminalInput{BundleFile: filepath.Join(dir, "original-bundle"), BundleSHA256: hash([]byte("original-bundle"))}
	raw, e := ce.Canonical(input)
	if e != nil {
		t.Fatal(e)
	}
	if e = writeMinioTerminalInput(dir, raw); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, minioTerminalInputFileName)
	loaded, e := ReadMinIOBootstrapTerminalInput(path, hash(raw))
	if e != nil || loaded.BundleFile != input.BundleFile {
		t.Fatal("exact original data decoding", e)
	}
	if _, e = NewMinIOBootstrapTerminalResource(nil, loaded); e == nil {
		t.Fatal("inert input substituted for actual owner dependencies")
	}
	if e = writeMinioTerminalInput(dir, []byte("overwrite")); e == nil {
		t.Fatal("existing independently pinned input overwritten")
	}
	after, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(raw, after) {
		t.Fatal("frozen source bytes changed", e)
	}
	for _, bad := range [][]byte{append(append([]byte(nil), raw...), byte('\n')), bytes.Replace(raw, []byte(`"BundleSHA256":`), []byte(`"bundleSHA256":`), 1), bytes.Replace(raw, []byte(`"BundleSHA256":`), []byte(`"BundleSHA256":"foreign","BundleSHA256":`), 1)} {
		if bytes.Equal(raw, bad) {
			t.Fatal("malformed original input case did not mutate")
		}
		if e = os.WriteFile(path, bad, 0600); e != nil {
			t.Fatal(e)
		}
		if _, e = ReadMinIOBootstrapTerminalInput(path, hash(bad)); e == nil {
			t.Fatal("noncanonical/duplicate/alias input accepted")
		}
	}
}

func TestMinIOBootstrapTerminalInstallEntrypointsRequireActualOriginalOwner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	enrollment := install.EnrollmentPin{}
	if receipt, e := ImportOriginalMinIOTerminalAuthority(ctx, nil, nil, nil, enrollment, "absent", "absent"); e == nil || receipt.Version != "" {
		t.Fatal("input supplied SQL authority without actual original owner")
	}
	if receipt, e := ExportOriginalMinIOTerminalInput(ctx, nil, nil, nil, enrollment, "absent", "absent", t.TempDir()); e == nil || receipt.Version != "" {
		t.Fatal("input exported readiness without actual original owner")
	}
	if receipt, e := PrepareOriginalMinIOTerminalInput(ctx, nil, nil, nil, enrollment, "absent", "absent", "absent", "absent", "absent", "absent", t.TempDir()); e == nil || receipt.Version != "" {
		t.Fatal("candidate manufactured source without actual original owner")
	}
}
