//go:build systembackup_mysql

package systembackupkekadapter

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
	wire "clawreef/internal/systembackupwire"
)

// Deliberately TEST-ONLY source authority. This native test proves the SQL
// composition/atomic boundary, not real B/C history, physical pause or key use.
type retainedOriginalSQLModel struct {
	ctx      context.Context
	tx       *sql.Tx
	before   reg.Snapshot
	bindings []reg.Binding
	refs     []reg.Reference
	until    time.Time
}

func (p *retainedOriginalSQLModel) Bindings() []reg.Binding        { return p.bindings }
func (p *retainedOriginalSQLModel) References() []reg.Reference    { return p.refs }
func (p *retainedOriginalSQLModel) ExpectedSnapshot() reg.Snapshot { return p.before }
func (p *retainedOriginalSQLModel) ValidUntil() time.Time          { return p.until }
func (p *retainedOriginalSQLModel) RecheckOriginalRetained(ctx context.Context, view reg.SQLReadView, s reg.LockedSnapshot, now time.Time) error {
	if ctx != p.ctx || view != p.tx || !reg.SameSnapshotFacts(s.Facts(), p.before) || !now.Before(p.until) {
		return reg.ErrKEKCoverage
	}
	return nil
}

type retainedCoverageSQLModel struct {
	ctx      context.Context
	tx       *sql.Tx
	snapshot reg.Snapshot
	sources  []reg.CoverageSource
	auth     *AuthenticatedFirstAdoption
	until    time.Time
}

func (p *retainedCoverageSQLModel) Sources() []reg.CoverageSource { return p.sources }
func (p *retainedCoverageSQLModel) References() []reg.Reference   { return p.snapshot.References }
func (p *retainedCoverageSQLModel) ExpectedEpoch() uint64         { return p.snapshot.Epoch }
func (p *retainedCoverageSQLModel) ValidUntil() time.Time         { return p.until }
func (p *retainedCoverageSQLModel) Recheck(ctx context.Context, view reg.SQLReadView, s reg.LockedSnapshot, now time.Time) error {
	if ctx != p.ctx || view != p.tx || !reg.SameSnapshotFacts(s.Facts(), p.snapshot) || !now.Before(p.until) {
		return reg.ErrKEKCoverage
	}
	return p.auth.Recheck(ctx, view, s, now)
}

func nativeRetainedBindingFixture(installation string) (reg.Binding, []reg.Reference) {
	source := reg.SourceRecord{SourceID: "TEST-MODEL-original-retained", RecordID: "retained-model-original-receipt", RecordVersion: "v1", ContentSHA256: strings.Repeat("a", 64)}
	b := reg.Binding{InstallationID: installation, ConfigRef: reg.ReferencePin{IdentityHash: strings.Repeat("b", 64), Version: "evidence-v1"}, Key: wire.KeyBinding{Provider: reg.RetainedEvidenceProvider, IdentityHash: strings.Repeat("b", 64), RegistryVersion: "evidence-v1", ProviderKeyID: "dedicated-evidence-key", ProviderVersion: "1"}, Provider: reg.ProviderBinding{Endpoint: "https://vault.model.invalid", KeyName: "dedicated-evidence-key", ProviderIdentityHash: strings.Repeat("c", 64), ScopeHash: strings.Repeat("d", 64), CAPEMSHA256: strings.Repeat("e", 64), CASource: source}, Retention: &reg.RetainedEvidenceSource{Purpose: reg.RetainedEvidencePurpose, Source: source, KeyContextSHA256: strings.Repeat("d", 64)}}
	fingerprint, _ := reg.BindingFingerprint(b)
	refs := []reg.Reference{}
	for _, part := range []reg.Partition{reg.RetainedArtifacts, reg.HoldsAndCatalog} {
		refs = append(refs, reg.Reference{Partition: part, State: reg.ReferenceRetained, SourceRecordID: "original-model-evidence", SourceRecordVersion: "3", EnvelopeID: "original-model-envelope", Key: b.Key, BindingSHA256: fingerprint, MappingSource: source, ExpectedRequestSource: source, LifecycleSource: source})
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Partition < refs[j].Partition })
	return b, refs
}

func TestRetainedBackfillSeventeenAndAdoptionOneOriginalTransactionMySQL(t *testing.T) {
	if os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE") == "" || os.Getenv("A_SIGNING_MYSQL_SERVER_UUID") == "" {
		t.Fatal("explicit independent disposable TLS MySQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	db, identity := censusOriginalMySQL(t, ctx)
	installation := "installation_retained_original_transaction"
	// Success commits last. All previous failures must leave the same original
	// source database empty, including the KEK fence first created by Bind.
	for _, mode := range []string{"wrong-installation", "expired", "foreign-transaction", "missing-proof", "revoked-proof", "rollback", "commit"} {
		t.Run(mode, func(t *testing.T) {
			scanner, err := NewSQLCoverageCensus(db, identity, installation)
			if err != nil {
				t.Fatal(err)
			}
			observed, err := scanner.Observe(ctx)
			if err != nil {
				t.Fatal(err)
			}
			binding, refs := nativeRetainedBindingFixture(installation)
			pins, records := originalControlReferencesFixture(t, observed, refs, 1, mode == "revoked-proof")
			owner, err := NewSQLCoverageOwnerPreparation(SQLCoverageOwnerConfig{DB: db, Database: identity, InstallationID: installation, Adoption: pins.Adoption, Witnesses: pins.Witnesses})
			if err != nil {
				t.Fatal(err)
			}
			original, err := scanner.BeginOriginalTransaction(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer original.Tx().Rollback()
			cut, err := scanner.PrepareOriginalAdoptionControlCut(ctx, original, observed, pins, time.Now().Add(45*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			defer cut.Abort()
			bound, locked, err := (reg.SQLStore{}).Bind(ctx, original.Tx(), installation)
			if err != nil {
				t.Fatal(err)
			}
			before := locked.Facts()
			prepared := &retainedOriginalSQLModel{ctx: ctx, tx: original.Tx(), before: before, bindings: []reg.Binding{binding}, refs: refs, until: before.ObservedAt.Add(40 * time.Second)}
			var foreign *sql.Tx
			switch mode {
			case "wrong-installation":
				prepared.bindings[0].InstallationID = "installation_foreign"
			case "expired":
				prepared.until = before.ObservedAt
			case "foreign-transaction":
				foreign, err = db.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer foreign.Rollback()
				prepared.tx = foreign
			}
			err = bound.StageInitialRetainedEvidence(ctx, prepared)
			badBackfill := mode == "wrong-installation" || mode == "expired" || mode == "foreign-transaction"
			if badBackfill {
				if err == nil {
					t.Fatal("invalid retained source accepted", mode)
				}
			} else {
				if err != nil {
					t.Fatal("actual retained bindings/ref insert/readback", err)
				}
				if bound.Snapshot().Facts().Epoch != before.Epoch || len(bound.Snapshot().Facts().References) != 2 || len(bound.Snapshot().Facts().Bindings) != 1 {
					t.Fatal("backfill advanced epoch or lost rows")
				}
				if mode == "missing-proof" {
					delete(records, pins.Witnesses[0].Source.RecordID)
				}
				err = cut.Stage(ctx, records)
				if mode == "missing-proof" || mode == "revoked-proof" {
					if err == nil {
						t.Fatal("missing/revoked proof accepted", mode)
					}
				} else {
					if err != nil {
						t.Fatal("actual 17 control writes", err)
					}
					bound, auth, err := owner.BindFirstAdoptionControls(ctx, cut)
					if err != nil {
						t.Fatal("original 17 authentication against actual retained refs", err)
					}
					if len(auth.RecordSources()) != 17 {
						t.Fatal("incomplete proof authentication")
					}
					var adoption CoverageAdoptionRecord
					if json.Unmarshal(records[pins.Adoption.Source.RecordID].Record, &adoption) != nil {
						t.Fatal("signed fixture adoption")
					}
					coverage := &retainedCoverageSQLModel{ctx: ctx, tx: original.Tx(), snapshot: bound.Snapshot().Facts(), auth: auth, until: auth.ValidUntil()}
					for _, p := range adoption.Facts.Partitions {
						coverage.sources = append(coverage.sources, reg.CoverageSource{Partition: p.Partition, SourceID: p.SourceID, SnapshotRevision: p.SnapshotRevision, FenceRevision: p.FenceRevision, AdoptionSource: adoption.Source})
					}
					sort.Slice(coverage.sources, func(i, j int) bool { return coverage.sources[i].Partition < coverage.sources[j].Partition })
					if bound.RequireUnrevoked(binding.ConfigRef, reg.GenerateRevocation) == nil || bound.RequireUnrevoked(binding.ConfigRef, reg.UnwrapRevocation) == nil {
						t.Fatal("retained key became executable")
					}
					if !reflect.DeepEqual(coverage.References(), refs) {
						t.Fatal("retained reference source mismatch")
					}
					if err := bound.AdoptCoverage(ctx, coverage); err != nil {
						t.Fatal("actual adoption", err)
					}
					if err := bound.RecheckAdoption(ctx, coverage); err != nil {
						t.Fatal("actual derived index readback", err)
					}
				}
			}
			if foreign != nil {
				if err := foreign.Rollback(); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "commit" {
				if err := original.Tx().Commit(); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := original.Tx().Rollback(); err != nil {
					t.Fatal(err)
				}
			}
			want := map[string]int{"system_backup_v2_evidence": 0, "system_backup_v2_evidence_chunks": 0, "system_backup_v2_kek_bindings": 0, "system_backup_v2_kek_references": 0, "system_backup_v2_kek_coverage": 0, "system_backup_v2_kek_fences": 0}
			if mode == "commit" {
				want["system_backup_v2_evidence"] = 17
				want["system_backup_v2_kek_bindings"] = 1
				want["system_backup_v2_kek_references"] = 2
				want["system_backup_v2_kek_coverage"] = 4
				want["system_backup_v2_kek_fences"] = 1
			}
			for table, n := range want {
				var count int
				if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+table+"`").Scan(&count); err != nil || count != n {
					t.Fatal("partial or missing original transaction result", mode, table, count, n, err)
				}
			}
			if mode == "commit" {
				var epoch uint64
				if err := db.QueryRowContext(ctx, "SELECT epoch FROM system_backup_v2_kek_fences WHERE installation_id=?", installation).Scan(&epoch); err != nil || epoch != 1 {
					t.Fatal("adoption must advance exactly once", epoch, err)
				}
			}
		})
	}
}
