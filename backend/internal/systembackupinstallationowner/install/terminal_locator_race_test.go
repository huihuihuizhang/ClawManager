package install

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	evidence "clawreef/internal/systembackupevidence"
	pd "clawreef/internal/systembackupproducer"
)

// Exercise the REAL consumer load then the shared production key-selection
// boundary used by both terminal entries. No clock sleeps, injected production
// read callback, generic success owner, provider probe or full admission stub.
func transientTerminalLocatorFixture(t *testing.T, native bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := newCaptureConsumerFixture(t, ctx)
	loaded, e := c.source.load(ctx)
	if e != nil {
		t.Fatal("original enrolled source load", e)
	}
	defer loaded.request.observer.Close()
	locator, plan, public, e := readBootstrapOriginalPublicSource(ctx, c.source, loaded)
	if e != nil || locator.PlanSHA256 != c.document.PlanSHA256 || plan.Target != c.f.record.Target || !bytes.Equal(public, c.f.i.public) {
		t.Fatal("original selected public source", e)
	}
	originalLocator, e := os.ReadFile(c.source.sourceFile)
	if e != nil {
		t.Fatal(e)
	}
	foreign, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(private)
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private race fixture directory")
	}
	write := func(name string, raw []byte) string {
		path := filepath.Join(dir, name)
		if os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("race fixture file")
		}
		return path
	}
	foreignPlan := plan
	foreignPlan.IssuerPublicKeySHA256 = hash(foreign)
	foreignPlanRaw, e := canonical(foreignPlan)
	if e != nil {
		t.Fatal(e)
	}
	changed := locator
	changed.PlanFile, changed.PlanSHA256 = write("foreign-plan.json", foreignPlanRaw), hash(foreignPlanRaw)
	changed.IssuerPublicFile, changed.IssuerPublicSHA256 = write("foreign.public", foreign), hash(foreign)
	changedRaw, e := canonical(changed)
	if e != nil || hash(changedRaw) == hash(originalLocator) {
		t.Fatal("changed locator fixture", e)
	}
	r := c.f.record
	b := r.Binding
	digest := strings.Repeat("d", 64)
	mapping := BootstrapOriginalMapping{SchemaVersion: BootstrapOriginalMappingVersion, PlanSHA256: changed.PlanSHA256, CaptureRecordSHA256: hash(loadedRecord(t, locator.RecordFile)), SelectionSHA256: r.SelectionSHA256, ProducerIssuerIdentitySHA256: digest, EvidenceSourceSHA256: digest, CapacityReportFile: filepath.Join(dir, "original-capacity"), Enrollment: c.f.enrollment, Target: r.Target, Actor: r.Actor, NotBefore: r.NotBefore, Until: r.Until, Owners: []BootstrapOriginalOwnerBinding{{Key: "reference:capture_signing", SHA256: hash(loadedRecord(t, locator.RecordFile))}}, Hosts: []BootstrapOriginalHost{{WorkloadIdentitySHA256: digest, Namespace: b.Namespace, NamespaceUID: b.NamespaceUID, Pod: b.PodName, PodUID: b.PodUID, ServiceAccount: b.ServiceAccountName, ServiceAccountUID: b.ServiceAccountUID, PodSpecSHA256: digest}}}
	var signed, pinned []byte
	if native {
		// The first terminal mapping is genuinely signed by the enrolled key.
		// Only the EXTRA native record uses the non-enrolled substituted key.
		mapping.PlanSHA256 = locator.PlanSHA256
		original, e := canonical(mapping)
		if e != nil {
			t.Fatal(e)
		}
		originalSig := ed25519.Sign(c.f.key, append([]byte(BootstrapOriginalMappingDomain), original...))
		if _, e := verifyBootstrapOriginalMapping(original, originalSig, c.f.i.public); e != nil {
			t.Fatal("enrolled original mapping", e)
		}
		input := evidence.BootstrapOriginalHostInput{Scope: pd.Scope{ServerUUID: pd.ServerUUID(r.Target.ServerUUID), Database: pd.Database(r.Target.Database), Installation: pd.Installation(r.Target.InstallationID)}, ClusterUID: r.Target.ClusterID, Namespace: b.Namespace, NamespaceUID: b.NamespaceUID, Pod: b.PodName, PodUID: b.PodUID, ServiceAccount: b.ServiceAccountName, ServiceAccountUID: b.ServiceAccountUID, Container: "original-container", Volume: "peer", PeerPath: "/run/peer/peer.json", PodSpecSHA256: digest, ContainerImageID: "original-image-id", PeerConfigMap: "original-peer", PeerConfigMapUID: "original-peer-uid", PeerKey: "peer.json", PeerSHA256: digest}
		n := BootstrapNativeHostMapping{SchemaVersion: BootstrapNativeHostMappingVersion, OriginalMappingSHA256: hash(original), PlanSHA256: mapping.PlanSHA256, SelectionSHA256: mapping.SelectionSHA256, Target: mapping.Target, Actor: mapping.Actor, Enrollment: mapping.Enrollment, NotBefore: mapping.NotBefore, Until: mapping.Until, Bindings: []BootstrapNativeHostBinding{{WorkloadIdentitySHA256: digest, ProducerIssuerIdentitySHA256: digest, Source: input}}}
		pinned, e = canonical(n)
		if e != nil {
			t.Fatal(e)
		}
		signed = ed25519.Sign(private, append([]byte(BootstrapNativeHostMappingDomain), pinned...))
		if _, e := verifyNativeHostMapping(pinned, signed, foreign, mapping, hash(original)); e != nil {
			t.Fatal("exact native forgery fixture", e)
		}
		if _, e := verifyNativeHostMapping(pinned, signed, c.f.i.public, mapping, hash(original)); e == nil {
			t.Fatal("foreign native signature accepted enrolled key")
		}
	} else {
		pinned, e = canonical(mapping)
		if e != nil {
			t.Fatal(e)
		}
		signed = ed25519.Sign(private, append([]byte(BootstrapOriginalMappingDomain), pinned...))
		if _, e := verifyBootstrapOriginalMapping(pinned, signed, foreign); e != nil {
			t.Fatal("exact mapping forgery fixture", e)
		}
		if _, e := verifyBootstrapOriginalMapping(pinned, signed, c.f.i.public); e == nil {
			t.Fatal("foreign mapping signature accepted enrolled key")
		}
	}
	mapFile, sigFile := write("exact-pinned.record", pinned), write("exact-pinned.signature", signed)
	mapSHA := hash(pinned)
	// The enrolled load is already finished. Replace only the SECOND locator
	// read; restore it before the old final current-files check could see drift.
	if os.WriteFile(c.source.sourceFile, changedRaw, 0600) != nil {
		t.Fatal("transient locator substitution")
	}
	_, _, selected, selectionErr := readBootstrapOriginalPublicSource(ctx, c.source, loaded)
	if os.WriteFile(c.source.sourceFile, originalLocator, 0600) != nil {
		t.Fatal("restore original locator")
	}
	if selectionErr == nil || selected != nil || !loaded.failed.Load() {
		t.Fatal("transient non-enrolled key selected after authenticated load")
	}
	if loaded.current(ctx) == nil {
		t.Fatal("restoring locator revived rejected loaded source")
	}
	if got, e := os.ReadFile(mapFile); e != nil || hash(got) != mapSHA || !bytes.Equal(got, pinned) {
		t.Fatal("pinned signed record drifted", e)
	}
	if got, e := os.ReadFile(sigFile); e != nil || !bytes.Equal(got, signed) {
		t.Fatal("pinned signature drifted", e)
	}
	// Restoration is real, not a permanent corruption that makes all negatives
	// fail early. A NEW independent enrolled load still succeeds after restore.
	restored, e := c.source.load(ctx)
	if e != nil {
		t.Fatal("original source not restored", e)
	}
	defer restored.request.observer.Close()
}

func loadedRecord(t *testing.T, path string) []byte {
	t.Helper()
	raw, e := ReadPrivateFile(path, 262144)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestBootstrapTerminalLocatorRejectsTransientNonEnrolledMappingKey(t *testing.T) {
	transientTerminalLocatorFixture(t, false)
}
func TestNativeHostTerminalLocatorRejectsTransientNonEnrolledNativeKey(t *testing.T) {
	transientTerminalLocatorFixture(t, true)
}
