package systembackupexecution

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"clawreef/internal/systembackupinstallationowner/install"
)

// Calls the real offline library action chain, not CLI TLS credential loading
// or actual field SQL/MinIO. SQL/Kube transports remain explicitly modeled.
func TestMinIOSeptemberFirstInstallOriginalOwnerQualifiedInputImportExportComponent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	f := newMinioSeptemberFirstInstallFixture(t, ctx, "")
	candidate, e := f.prepare(t, ctx)
	if e != nil {
		t.Fatal("actual original preauthorization and taskless input generation", e)
	}
	if candidate.Version != "original-minio-terminal-input-candidate.v1" || candidate.BindingSHA256 == "" || f.f.requests.Load() == 0 || f.model.execs != 0 || f.model.data.head != nil {
		t.Fatal("candidate skipped actual qualification or fabricated installed rows")
	}
	receipt, e := ImportOriginalMinIOTerminalAuthority(ctx, f.owner, f.f.kube, f.password, f.enrollment, candidate.File, candidate.SHA256)
	if e != nil || receipt.State != "active" || receipt.Replayed || f.model.execs != 7 || f.model.writeCommits != 1 || len(f.model.data.refs) != 5 {
		t.Fatal("actual original seven-row qualified import", e)
	}
	if f.f.model.open.Load() != 0 || f.model.auth.openTx.Load() != 0 {
		t.Fatal("original qualification left transaction open")
	}
	exported, e := ExportOriginalMinIOTerminalInput(ctx, f.owner, f.f.kube, f.password, f.enrollment, candidate.File, candidate.SHA256, septemberFirstInstallPrivateDirectory(t))
	if e != nil || exported.Version != "original-minio-terminal-input-export.v1" || exported.Metadata.State != "active" || exported.BindingSHA256 != candidate.BindingSHA256 {
		t.Fatal("actual current SQL/probe/source export tails", e)
	}
	if len(exported.ProbeInventory) != 4 || exported.ProbeInventory[2].State != "retained_reserved_probe" || exported.ProbeInventory[2].Version == "" {
		t.Fatal("actual reserved catalog probe not inventoried")
	}
	input, e := ReadMinIOBootstrapTerminalInput(exported.File, exported.SHA256)
	if e != nil {
		t.Fatal(e)
	}
	resource, e := NewMinIOBootstrapTerminalResource(f.f.kube, input)
	if e != nil {
		t.Fatal("same concrete owner type used by D", e)
	}
	binding, e := resource.BindingSHA256()
	if e != nil || binding != exported.BindingSHA256 || len(resource.TerminalResources()) != 5 {
		t.Fatal("export changed original runtime binding", e)
	}
	for _, source := range resource.TerminalResources() {
		if source != resource {
			t.Fatal("exported input did not construct one shared owner")
		}
	}
	replayed, e := ImportOriginalMinIOTerminalAuthority(ctx, f.owner, f.f.kube, f.password, f.enrollment, candidate.File, candidate.SHA256)
	if e != nil || !replayed.Replayed || f.model.execs != 7 || f.model.writeCommits != 1 {
		t.Fatal("same original input replay rewrote/resigned scope", e)
	}
}

func TestMinIOSeptemberFirstInstallOriginalOwnerRefusalAndUnknownResolveComponent(t *testing.T) {
	t.Run("actual-operator-before-native", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		f := newMinioSeptemberFirstInstallFixture(t, ctx, "")
		before := f.f.requests.Load()
		candidate, e := PrepareOriginalMinIOTerminalInput(ctx, f.owner, f.f.kube, []byte("foreign-operator-password"), f.enrollment, f.intentFile, f.intentSHA, f.f.input.BundleFile, f.f.input.BundleSHA256, f.materialsFile, f.materialsSHA, septemberFirstInstallPrivateDirectory(t))
		if e == nil || candidate.Version != "" || f.f.requests.Load() != before || f.model.execs != 0 {
			t.Fatal("foreign operator reached native probes/installation")
		}
	})
	t.Run("actual-protocol-before-insert", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		f := newMinioSeptemberFirstInstallFixture(t, ctx, "checksum-accepted")
		candidate, e := f.prepare(t, ctx)
		if e == nil || candidate.Version != "" || f.f.requests.Load() == 0 || f.model.execs != 0 || f.model.data.head != nil {
			t.Fatal("failed actual protocol created installed/source-success state")
		}
	})
	t.Run("lost-ack-independent-current-resolve", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		f := newMinioSeptemberFirstInstallFixture(t, ctx, "")
		candidate, e := f.prepare(t, ctx)
		if e != nil {
			t.Fatal(e)
		}
		f.model.lostAck = true
		receipt, e := ImportOriginalMinIOTerminalAuthority(ctx, f.owner, f.f.kube, f.password, f.enrollment, candidate.File, candidate.SHA256)
		if !errors.Is(e, install.ErrCommitUnknown) || receipt.Version != "" || f.model.execs != 7 || f.model.writeCommits != 1 {
			t.Fatal("lost metadata acknowledgement became success or rewrote original", e)
		}
		raw, e := os.ReadFile(f.f.input.BundleFile)
		if e != nil {
			t.Fatal(e)
		}
		before := f.f.requests.Load()
		resolved, e := f.owner.ResolveMinIOSQLAuthority(ctx, f.password, f.enrollment, f.f.input.Pin, raw, f.f.input.BundleSHA256)
		if e != nil || resolved.State != "active" || f.f.requests.Load() != before || f.model.execs != 7 {
			t.Fatal("independent exact frozen tuple resolve performed probe/rewrite", e)
		}
		exported, e := ExportOriginalMinIOTerminalInput(ctx, f.owner, f.f.kube, f.password, f.enrollment, candidate.File, candidate.SHA256, septemberFirstInstallPrivateDirectory(t))
		if e != nil || exported.Metadata.State != "active" || exported.BindingSHA256 != candidate.BindingSHA256 || f.model.execs != 7 {
			t.Fatal("post-resolve fresh qualification/source export", e)
		}
	})
}
