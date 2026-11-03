package install

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSigningResourceAuthenticatedExportLoadAndActualMainPointerLinkComponent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newSignerConsumerDeliveryFixture(t, ctx)
	c := f.capture
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private consumer output")
	}
	writes, signs := f.model.execs, c.f.signs.Load()
	receipt, err := c.f.i.ExportSigningResourceConsumer(ctx, c.f.password, c.f.enrollment, f.inputs, f.assets, c.document.KubeconfigFile, c.document.KubeconfigSHA256, directory)
	if err != nil || len(receipt.Items) != 2 || receipt.Items[0].Comparison.State != "active" || receipt.Items[1].Comparison.State != "active" || f.model.execs != writes || c.f.signs.Load() != signs {
		t.Fatal("real authenticated exporter/actual material/current tuple failed or signed/wrote SQL", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 11 {
		t.Fatal("unexpected secret/output file set", err)
	}
	source, pinFile := filepath.Join(directory, "signing-consumer.json"), filepath.Join(directory, "signing-consumer.sha256")
	pin, err := ReadPrivateFile(pinFile, 64)
	if err != nil {
		t.Fatal(err)
	}
	files := BootstrapTerminalFiles{MappingSHA256: strings.Repeat("a", 64)}
	original, err := NewBootstrapTerminalOriginal(c.source, files, nil)
	if err != nil {
		t.Fatal(err)
	}
	base, err := original.Owners()
	if err != nil {
		t.Fatal(err)
	}
	queries := c.f.s.auth.queries
	linked, terminal, handle, err := LinkSigningResourceConsumerOwners(ctx, base, original, source, pinFile, string(pin))
	if err != nil {
		t.Fatal("actual production main linker failed after authenticated export", err)
	}
	defer handle.Close()
	if terminal.capture != original.capture || terminal.files != original.files || terminal.capture != c.source || linked.References["capture_signing"] != c.source || linked.References["acceptance_signing"] != handle.resource || linked.References["catalog_signing"] != handle.resource || len(original.resources) != 0 || len(terminal.resources) != 2 || len(terminal.MissingTerminalResources()) != 27 || linked.KEK != base.KEK {
		t.Fatal("two aliases/capture/original map changed or missing owners became admitted")
	}
	if binding, err := handle.resource.BindingSHA256(); err != nil || !digestPattern.MatchString(binding) {
		t.Fatal("actual A constructor binding unavailable", err)
	}
	if c.f.s.auth.queries != queries || f.model.execs != writes || c.f.signs.Load() != signs || f.model.captureReads != 0 {
		t.Fatal("consumer/link opened SQL, borrowed capture permission or probed provider")
	}
	// The same actual main operation rejects alias collisions before a second
	// owner can replace the already selected pointer.
	if _, _, duplicate, err := LinkSigningResourceConsumerOwners(ctx, linked, terminal, source, pinFile, string(pin)); err == nil || duplicate != nil {
		t.Fatal("existing signer aliases overwritten")
	}
	if _, err := c.f.i.ExportSigningResourceConsumer(ctx, c.f.password, c.f.enrollment, f.inputs, f.assets, c.document.KubeconfigFile, c.document.KubeconfigSHA256, directory); err == nil {
		t.Fatal("consumer output overwritten on replay")
	}
	handle.Close()
	if _, _, err := original.WithSigningResourceConsumer(handle); err == nil {
		t.Fatal("closed consumer assembly reused")
	}
}

func TestSigningResourcePinnedConsumerRejectsForeignSelectionBeforeNestedIOComponent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := newSignerConsumerDeliveryFixture(t, ctx)
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil {
		t.Fatal("private output")
	}
	c := f.capture
	if _, err := c.f.i.ExportSigningResourceConsumer(ctx, c.f.password, c.f.enrollment, f.inputs, f.assets, c.document.KubeconfigFile, c.document.KubeconfigSHA256, directory); err != nil {
		t.Fatal(err)
	}
	source, pin := filepath.Join(directory, "signing-consumer.json"), filepath.Join(directory, "signing-consumer.sha256")
	api, queries, signs := c.apiCalls.Load(), c.f.s.auth.queries, c.f.signs.Load()
	if loaded, err := OpenPinnedSigningResourceConsumer(ctx, source, pin, strings.Repeat("f", 64)); err == nil || loaded != nil || c.apiCalls.Load() != api || c.f.s.auth.queries != queries || c.f.signs.Load() != signs {
		t.Fatal("different main selection opened nested credentials/API or replaced selected source")
	}
	c.enrollmentDrift.Store(true)
	if loaded, err := OpenSigningResourceConsumer(ctx, source, pin); err == nil || loaded != nil || c.f.signs.Load() != signs || c.f.s.auth.queries != queries {
		t.Fatal("foreign immutable registration accepted or provider/SQL touched")
	}
}
