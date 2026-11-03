package install

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func newAuthenticatedBootstrapSourceIdentity(t *testing.T, ctx context.Context, window time.Duration) (*captureConsumerFixture, *PreparedBootstrapSourceRegistries, BootstrapSourceRegistryDefinition) {
	t.Helper()
	c, selection, pack := newBootstrapSourceAuthenticatedConsumer(t, ctx, window)
	d, definition := bootstrapSourceProtocolDefinition(t, ctx, c.f)
	signed, err := c.f.i.IssueBootstrapSourceRegistries(ctx, c.f.password, c.f.enrollment, pack, hash(pack), definition.File, definition.SHA256, selection, c.f.files, c.f.key)
	if err != nil {
		t.Fatal("actual independent original source association issuer", err)
	}
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil || SaveFrozenBootstrapSourceRegistries(dir, signed) != nil {
		t.Fatal("original source association transport")
	}
	files := BootstrapSourceRegistryFiles{RecordFile: filepath.Join(dir, "bootstrap-source-registries.record.json"), RecordSHA256: hash(signed.Record), SignatureFile: filepath.Join(dir, "bootstrap-source-registries.signature")}
	p, err := c.source.PrepareBootstrapSourceRegistries(ctx, c.f.grant, c.f.config, selection, files)
	if err != nil || p == nil {
		t.Fatal("actual independently authenticated original source consumer", err)
	}
	if _, err = p.Association(); err != nil {
		t.Fatal("positive authenticated comparison", err)
	}
	return c, p, d
}

func waitBootstrapSourceOriginalExpiry(t *testing.T, ctx context.Context, until time.Time) {
	t.Helper()
	timer := time.NewTimer(time.Until(until.Add(time.Millisecond)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal("test context must remain live beyond the original signed window")
	}
	if ctx.Err() != nil || time.Now().Before(until) {
		t.Fatal("actual signed expiry was not reached")
	}
}

func TestBootstrapSourceRegistryConsumerOriginalWindowRejectsPrivateRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, p, d := newAuthenticatedBootstrapSourceIdentity(t, ctx, 6*time.Second)
	pin := d.Connections[len(d.Connections)-1].Credential
	originalUntil := p.record.Until
	positive, err := p.ReadSelectedFile(ctx, pin)
	if err != nil || len(positive) == 0 {
		t.Fatal("positive private read must reach the selected real file", err)
	}
	clear(positive)
	waitBootstrapSourceOriginalExpiry(t, ctx, originalUntil)
	if raw, err := p.ReadSelectedFile(ctx, pin); err == nil || raw != nil || !p.failed.Load() {
		clear(raw)
		t.Fatal("expired original window returned private bytes")
	}
	if !p.record.Until.Equal(originalUntil) || p.RecheckSelectedFile(ctx, pin) == nil {
		t.Fatal("original signed window renewed or expired attempt revived")
	}
}

func TestBootstrapSourceRegistryConsumerDeliveryTailClearsBytesAndLatches(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, p, d := newAuthenticatedBootstrapSourceIdentity(t, ctx, 6*time.Second)
	pin := d.Connections[len(d.Connections)-1].Credential
	if raw, err := p.ReadSelectedFile(ctx, pin); err != nil || len(raw) == 0 {
		t.Fatal("positive public entry before delivery-tail fault", err)
	} else {
		clear(raw)
	}
	// Acquire actual selected bytes while the original signed consumer is live,
	// then delay their delivery across its real expiry. This exercises the SAME
	// post-read completion function used by the public entry, with no fake clock
	// or synthetic prepared object and an observable buffer-clearing assertion.
	raw, err := readBootstrapSourcePin(pin, 262144)
	if err != nil || len(raw) == 0 || !time.Now().Before(p.record.Until) {
		t.Fatal("delivery fault must follow an actual successful selected read", err)
	}
	until := p.record.Until
	waitBootstrapSourceOriginalExpiry(t, ctx, until)
	returned, err := p.finishSelectedRead(ctx, raw, nil)
	if err == nil || returned != nil || !bytes.Equal(raw, make([]byte, len(raw))) || !p.failed.Load() {
		clear(raw)
		t.Fatal("bytes survived expired original delivery tail")
	}
	// Restore the same physical bytes and keep the exact still-live context;
	// neither action can reset this failed opaque attempt or its original Until.
	if os.WriteFile(pin.File, []byte("original credential source_sql"), 0600) != nil {
		t.Fatal("restore original selected fixture bytes")
	}
	if value, err := p.ReadSelectedFile(ctx, pin); err == nil || value != nil || !p.record.Until.Equal(until) {
		clear(value)
		t.Fatal("restoring a source revived the expired original attempt")
	}
}

func TestBootstrapSourceRegistryConsumerAssociationCopyPoisonsOriginal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, p, d := newAuthenticatedBootstrapSourceIdentity(t, ctx, 6*time.Second)
	copy := reflect.New(reflect.TypeOf(p).Elem()).Interface().(*PreparedBootstrapSourceRegistries)
	reflect.ValueOf(copy).Elem().Set(reflect.ValueOf(p).Elem())
	if _, err := copy.Association(); err == nil || !p.failed.Load() {
		t.Fatal("copied getter did not poison the original authenticated source")
	}
	if _, err := p.Association(); err == nil {
		t.Fatal("original association revived after copied getter failure")
	}
	if raw, err := p.ReadSelectedFile(ctx, d.Connections[0].Credential); err == nil || raw != nil {
		clear(raw)
		t.Fatal("original private source revived after copied getter failure")
	}
	if _, err := p.AuthorizeIdentity(ctx, nil); err == nil {
		t.Fatal("original SQL authority revived after copied getter failure")
	}
}
