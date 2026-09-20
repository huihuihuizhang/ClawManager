package migrationcatalog

import (
	"os"
	"testing"
	"testing/fstest"
)

func TestComputeIsSortedLFNormalizedAndContentAddressed(t *testing.T) {
	filesystem := fstest.MapFS{
		"migrations/b.sql":     {Data: []byte("SELECT 2;\r\n")},
		"migrations/a.sql":     {Data: []byte("SELECT 1;\r")},
		"migrations/readme":    {Data: []byte("ignored")},
		"migrations/sub/c.sql": {Data: []byte("ignored")},
	}
	catalog, err := Compute(filesystem, "migrations")
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if catalog.Algorithm != Algorithm {
		t.Fatalf("algorithm = %q", catalog.Algorithm)
	}
	if len(catalog.Filenames) != 2 || catalog.Filenames[0] != "a.sql" || catalog.Filenames[1] != "b.sql" {
		t.Fatalf("filenames = %#v", catalog.Filenames)
	}
	const expectedHash = "a0c2b3e33bc6445232dc606c0ac5737d368a1df8ecd0668b8280c292594c5d53"
	if catalog.Hash != expectedHash {
		t.Fatalf("hash = %s, want %s", catalog.Hash, expectedHash)
	}

	lfCatalog, err := Compute(fstest.MapFS{
		"migrations/a.sql": {Data: []byte("SELECT 1;\n")},
		"migrations/b.sql": {Data: []byte("SELECT 2;\n")},
	}, "migrations")
	if err != nil {
		t.Fatalf("Compute LF: %v", err)
	}
	if lfCatalog.Hash != catalog.Hash {
		t.Fatalf("line endings changed hash: %s != %s", lfCatalog.Hash, catalog.Hash)
	}

	changed, err := Compute(fstest.MapFS{
		"migrations/a.sql": {Data: []byte("SELECT 1;\n")},
		"migrations/b.sql": {Data: []byte("SELECT 3;\n")},
	}, "migrations")
	if err != nil {
		t.Fatalf("Compute changed: %v", err)
	}
	if changed.Hash == catalog.Hash {
		t.Fatal("content change did not change hash")
	}
}

func TestComputeRejectsNilFilesystem(t *testing.T) {
	if _, err := Compute(nil, "migrations"); err == nil {
		t.Fatal("nil filesystem accepted")
	}
}

func TestRepositoryCatalogMatchesSystemBackupContract(t *testing.T) {
	catalog, err := Compute(os.DirFS("../.."), "internal/db/migrations")
	if err != nil {
		t.Fatalf("Compute repository catalog: %v", err)
	}
	const expectedHash = "b3fe27c26b2917b2b17a8c20b0af24b5c375188a5478fbe43c4fd15cd1375991"
	if catalog.Hash != expectedHash || len(catalog.Filenames) != 91 {
		t.Fatalf("repository catalog files=%d hash=%s", len(catalog.Filenames), catalog.Hash)
	}
}
