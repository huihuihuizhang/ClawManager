//go:build systembackup_mysql

package systembackupkekadapter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// This changes only a signed test declaration, with its independently selected
// TEST issuer pin. It does not issue a production physical/history proof. The
// signature must remain valid so expiry/revocation refusal is actually tested.
func firstAdoptionNegativeSignedFixture(t *testing.T, pins *OriginalAdoptionControlPins, records OriginalAdoptionControlRecords, adoption, revoked bool) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	id, domain := pins.Adoption.Source.RecordID, OriginalCoverageDomain
	if !adoption {
		id, domain = pins.Witnesses[0].Source.RecordID, OriginalCoverageWitnessDomain
		pins.Witnesses[0].Issuer = public
	} else {
		pins.Adoption.Issuer = public
	}
	signed := records[id]
	var record any
	if adoption {
		var r CoverageAdoptionRecord
		if json.Unmarshal(signed.Record, &r) != nil {
			t.Fatal("fixture adoption")
		}
		if revoked {
			r.Revoked = true
		} else {
			r.Until = r.NotBefore
		}
		record = r
	} else {
		var r CoverageWitnessRecord
		if json.Unmarshal(signed.Record, &r) != nil {
			t.Fatal("fixture witness")
		}
		if revoked {
			r.Revoked = true
		} else {
			r.Until = r.NotBefore
		}
		record = r
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	signed = SignedCoverageOwnerRecord{Record: raw, Signature: ed25519.Sign(key, append([]byte(domain), raw...))}
	if !ed25519.Verify(public, append([]byte(domain), raw...), signed.Signature) {
		t.Fatal("negative fixture signature invalid")
	}
	records[id] = signed
}

// Actual full177 disposable MySQL, RR source locks, real17 row writes and
// original KEK Bind. B/C signatures are model declarations; this authenticates
// SQL transport/refusal/rollback only, never complete physical adoption.
func TestFirstAdoptionNativeMySQLAuthorizationCounterexamples(t *testing.T) {
	if os.Getenv("A_SIGNING_MYSQL_CREDENTIALS_FILE") == "" || os.Getenv("A_SIGNING_MYSQL_SERVER_UUID") == "" {
		t.Fatal("explicit independently UUID-pinned disposable MySQL required")
	}
	outer, stop := context.WithTimeout(context.Background(), 8*time.Minute)
	defer stop()
	db, identity := censusOriginalMySQL(t, outer)
	for _, fault := range []string{"valid_then_rollback", "foreign_transaction", "foreign_context", "foreign_installation", "expired_witness", "expired_adoption", "revoked_witness", "revoked_adoption", "missing_witness", "missing_adoption"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(outer, time.Minute)
			defer cancel()
			installation := "installation_negative_" + fault
			scanner, err := NewSQLCoverageCensus(db, identity, installation)
			if err != nil {
				t.Fatal(err)
			}
			observed, err := scanner.Observe(ctx)
			if err != nil {
				t.Fatal(err)
			}
			pins, records := originalControlBatchFixture(t, observed)
			switch fault {
			case "expired_witness":
				firstAdoptionNegativeSignedFixture(t, &pins, records, false, false)
			case "expired_adoption":
				firstAdoptionNegativeSignedFixture(t, &pins, records, true, false)
			case "revoked_witness":
				firstAdoptionNegativeSignedFixture(t, &pins, records, false, true)
			case "revoked_adoption":
				firstAdoptionNegativeSignedFixture(t, &pins, records, true, true)
			case "missing_witness":
				delete(records, pins.Witnesses[0].Source.RecordID)
			case "missing_adoption":
				delete(records, pins.Adoption.Source.RecordID)
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
			err = cut.Stage(ctx, records)
			stageRefusal := fault == "expired_witness" || fault == "expired_adoption" || fault == "revoked_witness" || fault == "revoked_adoption" || fault == "missing_witness" || fault == "missing_adoption"
			if stageRefusal {
				if err == nil || !cut.failed {
					t.Fatal("invalid mandatory proof admitted")
				}
			} else {
				if err != nil {
					t.Fatal("valid control transport", err)
				}
				selectedInstallation := installation
				if fault == "foreign_installation" {
					selectedInstallation = "installation_foreign"
				}
				owner, err := NewSQLCoverageOwnerPreparation(SQLCoverageOwnerConfig{DB: db, Database: identity, InstallationID: selectedInstallation, Adoption: pins.Adoption, Witnesses: pins.Witnesses})
				if err != nil {
					t.Fatal(err)
				}
				bound, auth, err := owner.BindFirstAdoptionControls(ctx, cut)
				if fault == "foreign_installation" {
					if err == nil || bound != nil || auth != nil || !cut.failed {
						t.Fatal("foreign installation accepted or partial handle escaped")
					}
				} else {
					if err != nil || bound == nil || auth == nil {
						t.Fatal("actual original Bind", err)
					}
					var stamp time.Time
					if err := original.Tx().QueryRowContext(ctx, "SELECT UTC_TIMESTAMP(6)").Scan(&stamp); err != nil {
						t.Fatal(err)
					}
					switch fault {
					case "foreign_transaction":
						foreign, err := db.BeginTx(ctx, nil)
						if err != nil {
							t.Fatal(err)
						}
						defer foreign.Rollback()
						if auth.Recheck(ctx, foreign, bound.Snapshot(), stamp) == nil {
							t.Fatal("foreign transaction accepted")
						}
					case "foreign_context":
						foreign, cancelForeign := context.WithCancel(ctx)
						defer cancelForeign()
						if auth.Recheck(foreign, original.Tx(), bound.Snapshot(), stamp) == nil {
							t.Fatal("foreign context accepted")
						}
					default:
						if auth.Recheck(ctx, original.Tx(), bound.Snapshot(), stamp) != nil {
							t.Fatal("same original transaction refused")
						}
					}
					if fault != "valid_then_rollback" && (!cut.failed || !auth.failed || auth.Recheck(ctx, original.Tx(), bound.Snapshot(), stamp) == nil) {
						t.Fatal("failed authentication handle reused")
					}
				}
			}
			if err := cut.Abort(); err != nil {
				t.Fatal("original rollback unconfirmed", err)
			}
			for _, table := range []string{"system_backup_v2_evidence", "system_backup_v2_evidence_chunks", "system_backup_v2_kek_fences", "system_backup_v2_kek_coverage"} {
				var count int
				if db.QueryRowContext(outer, "SELECT COUNT(*) FROM `"+table+"`").Scan(&count) != nil || count != 0 {
					t.Fatal("partial adoption state survived rollback", table, count)
				}
			}
		})
	}
}
