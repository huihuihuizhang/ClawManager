package install

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCaptureConsumerAuthenticatedExporterProducesLoadableCreateOnlyInputs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := newCaptureConsumerFixture(t, ctx)
	// Reconstruct only transport from the exact committed model source. This
	// is not an authority path: the exporter independently authenticates it.
	s, e := c.f.i.authenticate(ctx, c.f.password)
	if e != nil {
		t.Fatal(e)
	}
	current, _, e := snapshot(ctx, s)
	if e != nil {
		t.Fatal(e)
	}
	request, e := canonical(c.f.files)
	if e != nil {
		t.Fatal(e)
	}
	pack, e := encodeBundle(AuthorityBundle{SchemaVersion: AuthorityBundleVersion, PlanSHA256: c.f.i.planHash, Enrollment: c.f.enrollment, Pin: s.pinFor(c.f.record, current.cas.GrantSHA256, current.cas.HeadRevision), RequestFilesSHA256: hash(request), Record: current.recordRaw, RecordSignature: current.recordSig, Head: current.headRaw, HeadSignature: current.headSig})
	if e != nil {
		t.Fatal(e)
	}
	directory := t.TempDir()
	if e := os.Chmod(directory, 0700); e != nil {
		t.Fatal("private consumer export directory", e)
	}
	signs, writes := c.f.signs.Load(), c.f.s.writes
	r, e := c.f.i.ExportBootstrapCaptureConsumer(ctx, c.f.password, c.f.enrollment, pack, hash(pack), c.f.files, c.document.KubeconfigFile, c.document.KubeconfigSHA256, directory)
	if e != nil || r.State != "active" || c.f.signs.Load() != signs || c.f.s.writes != writes {
		t.Fatal("authenticated producer signed/wrote authority or failed exact source export", e)
	}
	entries, e := os.ReadDir(directory)
	if e != nil || len(entries) != 8 {
		t.Fatal("producer emitted unexpected secret/input files", e)
	}
	source := NewCaptureSigningConsumer(filepath.Join(directory, "capture-consumer.json"), filepath.Join(directory, "capture-consumer.sha256"))
	if _, e := source.Prepare(ctx, c.f.grant, c.f.config); e != nil {
		t.Fatal("authenticated output not consumable by actual loader", e)
	}
	if _, e := c.f.i.ExportBootstrapCaptureConsumer(ctx, c.f.password, c.f.enrollment, pack, hash(pack), c.f.files, c.document.KubeconfigFile, c.document.KubeconfigSHA256, directory); e == nil {
		t.Fatal("original consumer inputs overwritten")
	}
}
