package install

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func TestOriginalSignerMutationFactoryRequiresIndependentPinsAndThreeAliases(t *testing.T) {
	directory := t.TempDir()
	files := OriginalSignerMutationSourceFiles{CaptureSourceFile: filepath.Join(directory, "capture.source"), CaptureSourcePinFile: filepath.Join(directory, "capture.pin"), CaptureSourceSHA256: strings.Repeat("a", 64), SigningSourceFile: filepath.Join(directory, "signing.source"), SigningSourcePinFile: filepath.Join(directory, "signing.pin"), SigningSourceSHA256: strings.Repeat("b", 64)}
	if _, e := NewOriginalSignerConfigMutationReferences(nil, files); e == nil {
		t.Fatal("missing actual DB admitted")
	}
	resource, e := NewOriginalSignerConfigMutationReferences(new(sql.DB), files)
	if e != nil {
		t.Fatal(e)
	}
	aliases := resource.References()
	if len(aliases) != 3 || aliases["capture_signing"] != resource || aliases["acceptance_signing"] != resource || aliases["catalog_signing"] != resource {
		t.Fatal("three actual factory aliases split")
	}
	changed := files
	changed.SigningSourcePinFile = changed.CaptureSourcePinFile
	if _, e := NewOriginalSignerConfigMutationReferences(new(sql.DB), changed); e == nil {
		t.Fatal("shared independent pin locator admitted")
	}
	changed = files
	changed.CaptureSourceSHA256 = ""
	if _, e := NewOriginalSignerConfigMutationReferences(new(sql.DB), changed); e == nil {
		t.Fatal("missing independent capture selection admitted")
	}
}
