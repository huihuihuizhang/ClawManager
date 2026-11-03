package systembackupbootstrapmaterials

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	kek "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	sec "clawreef/internal/systembackupsecurity"
	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// Public-pins constructor only; no successful observation/coverage/admission
// is fabricated. The actual source consumes the opaque input made by D's real
// resolver and real signed SQL evidence when invoked with its controlled DB.
func TestOriginalSQLMutationKEKLoaderRequiresIndependentPinsAndActualInput(t *testing.T) {
	raw, err := json.Marshal(originalKEKSourceFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, err = jsoncanonicalizer.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "original-mutation-kek-source.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	preparation, err := LoadOriginalSQLMutationKEKPreparation(file, hex.EncodeToString(sum[:]))
	if err != nil || preparation == nil {
		t.Fatal("independently pinned concrete mutation preparation", err)
	}
	if _, err := LoadOriginalSQLMutationKEKPreparation(file, strings.Repeat("f", 64)); err == nil {
		t.Fatal("unfixed mutation source accepted")
	}
	if resource, err := LoadOriginalSQLMutationKEKResource(nil, file, hex.EncodeToString(sum[:])); err == nil || resource != nil {
		t.Fatal("public source declarations supplied a resolver resource without the actual controlled DB")
	}
	if _, err := preparation.PrepareConfigMutationKEK(context.Background(), nil, sec.ConfigMutationResourceInput{}); err == nil {
		t.Fatal("source pins alone supplied an enabling admission")
	}
	if _, err := kek.NewSQLMutationAdmissionSource(kek.SQLMutationSourceConfig{}); err == nil {
		t.Fatal("missing actual SQL source/coverage owners supplied a source")
	}
	if _, err := kek.NewSQLMutationKEKPreparation(kek.SQLBootstrapKEKConfig{}); err == nil {
		t.Fatal("missing independent mapping/purpose/adoption pins supplied preparation")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (*kek.SQLMutationAdmissionSource)(nil).MutationAdmissionInput(ctx, sec.ConfigMutationResourceInput{}, reg.Snapshot{}); err == nil {
		t.Fatal("cancelled/missing actual mutation source admitted input")
	}
}
