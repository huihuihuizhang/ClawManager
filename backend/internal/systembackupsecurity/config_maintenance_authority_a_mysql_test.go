//go:build systembackup_mysql

package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

// Real SQL orchestration, explicitly SYNTHETIC verified-fact suppliers. No
// signature/holder/archive/installed-schema/physical-capacity authenticator is
// provided by this fixture. The production composition itself is exercised.
type maintenanceAuthorityMySQLProbe struct {
	f                                                        *maintenanceMySQLFixture
	authority                                                *pinnedConfigMaintenanceAuthority
	current                                                  configMaintenanceAuthorityPins
	write, observation                                       configMaintenanceGrantFacts
	source                                                   configMaintenanceSourceFacts
	writeCalls, observationCalls, archiveCalls, reserveCalls int
	denyWrite                                                bool
	onGrant                                                  func(context.Context, *sql.Tx) error
	onArchive                                                func(context.Context, *sql.Tx) error
	capacityExpiry                                           bool
	reached                                                  bool
}

func newMaintenanceAuthorityMySQLProbe(t *testing.T, ctx context.Context, f *maintenanceMySQLFixture) *maintenanceAuthorityMySQLProbe {
	t.Helper()
	return maintenanceAuthorityMySQLProbeAt(t, f, configProofDBNow(t, ctx, f.db))
}

func maintenanceAuthorityMySQLProbeAt(t *testing.T, f *maintenanceMySQLFixture, now time.Time) *maintenanceAuthorityMySQLProbe {
	t.Helper()
	p := &maintenanceAuthorityMySQLProbe{f: f}
	p.current = configMaintenanceAuthorityPins{database: f.identity, installation: f.installation, actor: f.scope.identity.Actor, schemaSHA256: f.scope.identity.SchemaSHA, catalogSHA256: f.scope.identity.CatalogSHA, migrationSHA256: f.scope.identity.MigrationSHA}
	p.write = configMaintenanceGrantFacts{actorIssuer: "https://synthetic-maintenance.invalid", principal: "probe-subject", issuer: "https://synthetic-maintenance.invalid", grantID: "probe-grant", version: "synthetic-v1", grantBytesSHA256: registrationHash("synthetic-not-authenticated-write-grant"), revocationVersion: "synthetic-revocation-v1", purpose: configMaintenanceWrite, bindings: f.scope.identity, key: f.scope.key, requestSHA256: f.scope.hash, notBefore: now.Add(-time.Minute), expiresAt: now.Add(2 * time.Minute)}
	p.observation = p.write
	p.observation.purpose = configMaintenanceObserve
	p.observation.grantID = "synthetic-independent-observation-grant"
	p.observation.version = "synthetic-observation-v1"
	p.observation.grantBytesSHA256 = registrationHash("synthetic-not-authenticated-observation-grant")
	p.source = configMaintenanceSourceFacts{provenance: ConfigBackfillProvenanceFacts{TargetServerUUID: f.identity.ServerUUID, TargetDatabase: f.identity.Database, InstallationID: f.installation, Version: 1, ConfigSizeBytes: int64(len(f.original)), ConfigSHA256: registrationHash(string(f.original)), SourceIssuer: "synthetic-maintenance-probe", SourceID: "generated-fixture", SourceVersion: "v1", AttestationSHA256: registrationHash("synthetic-no-source-authentication")}, verificationVersion: "synthetic-archive-v1", notBefore: now.Add(-time.Minute), expiresAt: now.Add(2 * time.Minute)}
	sources := configMaintenanceAuthoritySources{
		CurrentTarget: func(call context.Context, tx *sql.Tx, _ time.Time) (configMaintenanceAuthorityPins, error) {
			if err := f.identity.check(call, tx); err != nil {
				return configMaintenanceAuthorityPins{}, err
			}
			return p.current, nil // Deliberately synthetic schema/ledger facts.
		},
		WriteGrant: func(call context.Context, tx *sql.Tx, _ configMaintenanceScope, _ time.Time) (configMaintenanceGrantFacts, error) {
			p.writeCalls++
			if p.denyWrite {
				return configMaintenanceGrantFacts{}, ErrRegistrationPermission
			}
			if p.writeCalls == 2 && p.onGrant != nil {
				if err := p.onGrant(call, tx); err != nil {
					return configMaintenanceGrantFacts{}, err
				}
			}
			return p.write, nil
		},
		ObservationGrant: func(context.Context, *sql.Tx, configMaintenanceScope, time.Time) (configMaintenanceGrantFacts, error) {
			p.observationCalls++
			return p.observation, nil
		},
		OriginalArchive: func(call context.Context, tx *sql.Tx, _ configMaintenanceScope, original []byte, _ time.Time) (configMaintenanceSourceFacts, error) {
			p.archiveCalls++
			if !bytes.Equal(original, f.original) {
				return configMaintenanceSourceFacts{}, ErrRegistrationPermission
			}
			if p.archiveCalls == 2 && p.onArchive != nil {
				if err := p.onArchive(call, tx); err != nil {
					return configMaintenanceSourceFacts{}, err
				}
			}
			return p.source, nil
		},
		ReserveMetadata: func(_ context.Context, tx *sql.Tx, _ configMaintenanceScope, budget configMaintenanceBudget, at time.Time) (ConfigMutationCapacityReservation, error) {
			p.reserveCalls++
			if budget.canonicalWriteBytes != len(f.original) || budget.receiptMaxBytes < 2 || budget.intentBytes < 2 || budget.resultBytes < 2 {
				return nil, ErrRegistrationUnavailable
			}
			until := at.Add(time.Minute)
			if p.capacityExpiry {
				until = at.Add(5 * time.Second)
			}
			return &maintenanceAuthorityMySQLCapacity{p: p, tx: tx, until: until}, nil
		},
	}
	var err error
	p.authority, err = newPinnedConfigMaintenanceAuthority(p.current, sources)
	mysqlMust(t, err)
	return p
}

type maintenanceAuthorityMySQLCapacity struct {
	p     *maintenanceAuthorityMySQLProbe
	tx    *sql.Tx
	until time.Time
}

func (r *maintenanceAuthorityMySQLCapacity) ValidUntil() time.Time { return r.until }
func (r *maintenanceAuthorityMySQLCapacity) Recheck(ctx context.Context, tx *sql.Tx, _ time.Time) error {
	if tx != r.tx {
		return ErrRegistrationUnavailable
	}
	if r.p.capacityExpiry {
		if err := backfillMySQLUncommitted(ctx, tx, r.p.f.installation); err != nil {
			return err
		}
		if err := waitConfigWriterADBExpiry(ctx, r.until, configWriterASample(tx)); err != nil {
			return err
		}
		r.until = r.until.Add(time.Hour) // Must not renew A's wrapper deadline.
		r.p.reached = true
	}
	return nil
}

func (p *maintenanceAuthorityMySQLProbe) staged(ctx context.Context, tx *sql.Tx) error {
	if err := backfillMySQLUncommitted(ctx, tx, p.f.installation); err != nil {
		return err
	}
	p.reached = true
	return nil
}

func TestAConfigMaintenanceAuthorityMySQL(t *testing.T) {
	ctx, db, _, identity := maintenanceProbeDatabase(t)
	for _, name := range []string{"grant_target_mismatch", "independent_observation", "grant_same_version_bytes_drift", "archive_verifier_drift", "installed_target_drift", "grant_expires_after_staging", "source_expires_after_staging", "capacity_expires_after_staging"} {
		if !t.Run(name, func(t *testing.T) {
			f := newMaintenanceMySQLFixture(t, ctx, db, identity)
			installationBefore := backfillMySQLSeedInstallation(t, ctx, f)
			defer func() {
				if !bytes.Equal(installationBefore, backfillMySQLInstallationSnapshot(t, ctx, f)) {
					t.Error("authority composition changed active/deployment/monitoring state")
				}
			}()
			p := newMaintenanceAuthorityMySQLProbe(t, ctx, f)
			svc, err := newConfigCanonicalBackfillService(db, identity, f.installation, f.scope.identity.Actor, p.authority)
			mysqlMust(t, err)
			want := ErrRegistrationUnavailable
			switch name {
			case "grant_target_mismatch":
				p.write.bindings.Database += "_foreign"
				want = ErrRegistrationPermission
			case "independent_observation":
				first, e := svc.apply(ctx, f.scope.key, f.scope.canonical, f.original)
				mysqlMust(t, e)
				f.assert(t, ctx, 1, 2, true)
				p.denyWrite = true
				observed, e := svc.observe(ctx, f.scope.key, f.scope.canonical, f.original)
				mysqlMust(t, e)
				if !observed.replayed || !bytes.Equal(first.bytes(), observed.bytes()) || p.writeCalls != 2 || p.observationCalls != 2 || p.reserveCalls != 1 {
					t.Fatal("independent observation reused write grant or changed original receipt")
				}
				p.observation.purpose = configMaintenanceWrite
				denied, e := svc.observe(ctx, f.scope.key, f.scope.canonical, f.original)
				backfillMySQLEmpty(t, denied, e)
				if !errors.Is(e, ErrRegistrationPermission) {
					t.Fatal("write-purpose grant admitted observation", e)
				}
				denied, e = svc.apply(ctx, f.scope.key, f.scope.canonical, f.original)
				backfillMySQLEmpty(t, denied, e)
				if !errors.Is(e, ErrRegistrationPermission) {
					t.Fatal("write denial fell back to observation", e)
				}
				f.assert(t, ctx, 1, 2, true)
				return
			case "grant_same_version_bytes_drift":
				p.onGrant = func(call context.Context, tx *sql.Tx) error {
					if err := p.staged(call, tx); err != nil {
						return err
					}
					p.write.grantBytesSHA256 = registrationHash("different synthetic grant bytes at original version")
					return nil
				}
			case "archive_verifier_drift":
				p.onArchive = func(call context.Context, tx *sql.Tx) error {
					if err := p.staged(call, tx); err != nil {
						return err
					}
					p.source.verificationVersion = "synthetic-archive-v2"
					return nil
				}
			case "installed_target_drift":
				p.onGrant = func(call context.Context, tx *sql.Tx) error {
					if err := p.staged(call, tx); err != nil {
						return err
					}
					p.current.catalogSHA256 = registrationHash("different synthetic installed catalog facts")
					return nil
				}
			case "grant_expires_after_staging":
				p.write.expiresAt = configProofDBNow(t, ctx, db).Add(5 * time.Second)
				want = ErrRegistrationPermission
				p.onGrant = func(call context.Context, tx *sql.Tx) error {
					if err := p.staged(call, tx); err != nil {
						return err
					}
					return waitConfigWriterADBExpiry(call, p.write.expiresAt, configWriterASample(tx))
				}
			case "source_expires_after_staging":
				p.source.expiresAt = configProofDBNow(t, ctx, db).Add(5 * time.Second)
				want = ErrRegistrationPermission
				p.onArchive = func(call context.Context, tx *sql.Tx) error {
					if err := p.staged(call, tx); err != nil {
						return err
					}
					return waitConfigWriterADBExpiry(call, p.source.expiresAt, configWriterASample(tx))
				}
			case "capacity_expires_after_staging":
				p.capacityExpiry = true
			}
			r, err := svc.apply(ctx, f.scope.key, f.scope.canonical, f.original)
			backfillMySQLEmpty(t, r, err)
			if !errors.Is(err, want) {
				t.Fatal("wrong authority-composition rejection class", err)
			}
			if name == "grant_target_mismatch" {
				if p.archiveCalls != 0 || p.reserveCalls != 0 {
					t.Fatal("foreign grant reached archive/capacity")
				}
			} else if !p.reached {
				t.Fatal("required real staged effects were not observed")
			}
			f.assert(t, ctx, 0, 0, false)
			if name == "grant_target_mismatch" {
				t.Log("PASS A composition foreign grant rejected before archive/capacity; no committed effects; synthetic verified facts only")
			} else {
				t.Log("PASS A composition rejected before commit; actual SQL effects observed and rolled back; synthetic verified facts only")
			}
		}) {
			return
		}
	}
	t.Log("PASS A maintenance authority real SQL composition; eight cases; synthetic_verified_facts=yes actual_authentication=no production_approval=no")
}

func TestAConfigMaintenanceAuthorityMySQLSeed(t *testing.T) {
	config, err := DecodeBootstrapConfig(bootstrapFixture(t))
	mysqlMust(t, err)
	f := &maintenanceMySQLFixture{identity: DatabaseIdentity{"12345678-1234-1234-1234-123456789abc", "synthetic_db"}, installation: "installation_authority_seed", original: config.CanonicalJSON()}
	f.scope, err = maintenanceProbeScope(f.identity, f.installation, "authority_seed_key_012345", f.original, registrationHash("synthetic no SQL row"))
	mysqlMust(t, err)
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	for _, name := range []string{"write-facts-match", "observation-facts-match", "archive-provenance-match", "wrong-binding-rejected", "wrong-purpose-rejected", "wrong-manifest-rejected"} {
		t.Run(name, func(t *testing.T) {
			p := maintenanceAuthorityMySQLProbeAt(t, f, now)
			switch name {
			case "write-facts-match":
				if !p.write.matches(f.scope, configMaintenanceWrite, now) {
					t.Fatal("compiled write fixture facts do not match")
				}
			case "observation-facts-match":
				if !p.observation.matches(f.scope, configMaintenanceObserve, now) {
					t.Fatal("compiled observation fixture facts do not match")
				}
			case "archive-provenance-match":
				if !p.source.matches(f.scope, f.original, now) {
					t.Fatal("compiled archive provenance differs from request")
				}
			case "wrong-binding-rejected":
				p.write.bindings.Database += "_foreign"
				if p.write.matches(f.scope, configMaintenanceWrite, now) {
					t.Fatal("foreign compiled grant facts matched")
				}
			case "wrong-purpose-rejected":
				if p.write.matches(f.scope, configMaintenanceObserve, now) {
					t.Fatal("write purpose admitted as observation")
				}
			case "wrong-manifest-rejected":
				p.source.provenance.AttestationSHA256 = registrationHash("foreign synthetic manifest")
				if p.source.matches(f.scope, f.original, now) {
					t.Fatal("foreign manifest matched")
				}
			}
		})
	}
	t.Log("PASS A composition offline seed only; no database or runtime authentication")
}
