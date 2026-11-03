package install

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
	kek "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	sec "clawreef/internal/systembackupsecurity"
)

// Public source-pin setup only: constructors issue NO witness/adoption receipt,
// capability or PreparedAdmission. Real source records remain mandatory.
func originalKEKWindowPreparationFixture(t *testing.T, f *authorityFixture) *kek.SQLBootstrapKEKPreparation {
	t.Helper()
	ref, err := kekWindowReference(f.config)
	if err != nil {
		t.Fatal(err)
	}
	source := func(id string) reg.SourceRecord {
		return reg.SourceRecord{SourceID: "original-source-owner", RecordID: id, RecordVersion: "v1", ContentSHA256: strings.Repeat("a", 64)}
	}
	cfg := kek.SQLBootstrapKEKConfig{Database: reg.DatabaseIdentity{ServerUUID: f.i.plan.Target.ServerUUID, Database: f.i.plan.Target.Database}, InstallationID: f.i.plan.Target.InstallationID, Mapping: reg.ReferencePin{IdentityHash: ref.IdentityHash, Version: ref.Version}, MappingIssuer: f.i.public, Generate: kek.ProviderCapabilityPin{Source: source("sev_original_generate"), Issuer: f.i.public}, Unwrap: kek.ProviderCapabilityPin{Source: source("sev_original_unwrap"), Issuer: f.i.public}, Adoption: kek.CoverageOwnerPin{Source: source("sev_original_adoption"), Issuer: f.i.public}}
	for _, partition := range []reg.Partition{reg.RetainedArtifacts, reg.InflightAndUnknownWrites, reg.HoldsAndCatalog, reg.RestoreAndPrune} {
		for _, kind := range []string{"original_sql_census", "immutable_external_snapshot", "original_writer_fence", "historical_backfill"} {
			cfg.Witnesses = append(cfg.Witnesses, kek.CoverageWitnessPin{CoverageOwnerPin: kek.CoverageOwnerPin{Source: source(fmt.Sprintf("sev_witness_%d", len(cfg.Witnesses))), Issuer: f.i.public}, Partition: partition, Kind: kind, ScopeSHA256: strings.Repeat("b", 64)})
		}
	}
	p, err := kek.NewSQLBootstrapKEKPreparation(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBootstrapKEKWindowUsesDistinctOriginalAssociationDomain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f, _, selection, _ := terminalMappingIssueFixture(t, ctx)
	p := originalKEKWindowPreparationFixture(t, f)
	_, sourceSHA, err := kekWindowPreparation(p)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := kekWindowReference(f.config)
	if err != nil {
		t.Fatal(err)
	}
	r := BootstrapKEKWindowRecord{SchemaVersion: BootstrapKEKWindowVersion, PlanSHA256: f.i.planHash, CaptureRecordSHA256: hash(f.draft), PreparationSHA256: sourceSHA, Target: f.record.Target, Actor: f.record.Actor, Enrollment: f.enrollment, NotBefore: f.record.NotBefore, Until: f.record.Until, Selection: selection, Reference: ref, MappingSource: reg.SourceRecord{SourceID: "original-mapping-owner", RecordID: "sev_mapping", RecordVersion: "v1", ContentSHA256: strings.Repeat("c", 64)}, SourceRevision: "mapping-v1", BindingSHA256: strings.Repeat("d", 64), SnapshotFactsSHA256: strings.Repeat("e", 64)}
	r.SnapshotFactsProfile = BootstrapKEKWindowSnapshotProfile
	r.BindingSHA256 = r.MappingSource.ContentSHA256
	raw, err := canonical(r)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(f.key, append([]byte(BootstrapKEKWindowDomain), raw...))
	if _, err := verifyKEKWindow(raw, sig, f.i.public); err != nil {
		t.Fatal("signed comparison DATA", err)
	}
	for _, domain := range []string{owner.RecordDomain, BootstrapOriginalMappingDomain, FunctionalClassificationDomain, "system-backup-original-kek.v1\x00"} {
		wrong := ed25519.Sign(f.key, append([]byte(domain), raw...))
		if _, err := verifyKEKWindow(raw, wrong, f.i.public); err == nil {
			t.Fatal("other authority/domain reinterpreted as KEK association")
		}
	}
	r.Target.Database = "foreign_database"
	raw, err = canonical(r)
	if err != nil {
		t.Fatal(err)
	}
	sig = ed25519.Sign(f.key, append([]byte(BootstrapKEKWindowDomain), raw...))
	if _, err := verifyKEKWindow(raw, sig, f.i.public); err == nil {
		t.Fatal("foreign original selection scope accepted")
	}
}

func TestBootstrapKEKWindowPreservesConcretePreparationAndMissingSources(t *testing.T) {
	f := newAuthorityFixture(t)
	p := originalKEKWindowPreparationFixture(t, f)
	_, before, err := kekWindowPreparation(p)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := p.OriginalConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	cfg.MappingIssuer[0] ^= 1
	cfg.Witnesses[0].Issuer[0] ^= 1
	cfg.Witnesses = cfg.Witnesses[:1]
	_, after, err := kekWindowPreparation(p)
	if err != nil || before != after {
		t.Fatal("public configuration mutated concrete original source", err)
	}
	capture, files, resources := terminalSevenConcreteSources(t)
	terminal, err := NewBootstrapTerminalOriginal(capture, files, resources)
	if err != nil {
		t.Fatal(err)
	}
	window := BootstrapKEKWindowFiles{RecordFile: filepath.Join(t.TempDir(), "absent-window"), RecordSHA256: strings.Repeat("a", 64), SignatureFile: filepath.Join(t.TempDir(), "absent-signature")}
	linked, bridge, err := terminal.WithOriginalWindowKEK(p, window)
	if err != nil || bridge.preparation != p || linked.capture != capture || linked.resources["reference:kek"] != bridge || len(linked.MissingTerminalResources()) != 22 || len(terminal.MissingTerminalResources()) != 23 {
		t.Fatal("lost exact original source or invented other owners", err)
	}
	if prepared, err := bridge.PrepareTerminalResource(context.Background(), sec.OfflineBootstrapGrant{}, sec.BootstrapConfig{}); err == nil || prepared != nil {
		t.Fatal("missing real association became a resource check")
	}
	if actual, err := bridge.PrepareBootstrapKEK(context.Background(), nil, sec.OfflineBootstrapGrant{}, sec.BootstrapConfig{}); err == nil || actual != nil {
		t.Fatal("no original attempt/source produced a KEK admission")
	}
	check := &originalWindowKEKCheck{owner: bridge, ctx: context.Background()}
	check.origin = check
	if deadline, err := check.AuthorizeIdentity(check.ctx, nil); err == nil || deadline != nil || check.DependencyDeadline() != nil {
		t.Fatal("omitted independent KEK preparation activated the reference")
	}
}

func TestBootstrapKEKWindowSnapshotDigestMatchesOriginalFactsBoundary(t *testing.T) {
	snapshot := reg.Snapshot{Database: reg.DatabaseIdentity{ServerUUID: "01234567-89ab-cdef-0123-456789abcdef", Database: "original"}, InstallationID: "installation_original", Epoch: 7, ObservedAt: time.Now().UTC().Truncate(time.Microsecond), Coverage: []reg.CoverageSource{}, Bindings: []reg.BindingFacts{}, References: []reg.Reference{}}
	a, err := kekWindowSnapshotSHA(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.ObservedAt = snapshot.ObservedAt.Add(time.Second)
	b, err := kekWindowSnapshotSHA(snapshot)
	if err != nil || a != b {
		t.Fatal("SQL sample was incorrectly made binding identity")
	}
	snapshot.Epoch++
	c, err := kekWindowSnapshotSHA(snapshot)
	if err != nil || a == c {
		t.Fatal("original complete snapshot facts were not bound")
	}
	snapshot.Epoch = 9007199254740992
	high, err := kekWindowSnapshotSHA(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Epoch++
	next, err := kekWindowSnapshotSHA(snapshot)
	if err != nil || high == next {
		t.Fatal("adjacent uint64 original epochs aliased through JSON precision")
	}
}
