package systembackupsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// Synthetic VERIFIED facts only. These functions do not parse or authenticate
// a real grant/archive, and these fixtures are never production adapters.
type maintenanceAuthorityAFixture struct {
	a                                                        *pinnedConfigMaintenanceAuthority
	pins                                                     configMaintenanceAuthorityPins
	target                                                   configMaintenanceAuthorityPins
	sources                                                  configMaintenanceAuthoritySources
	m                                                        *maintenanceServiceModel
	tx                                                       *sql.Tx
	scope                                                    configMaintenanceScope
	original                                                 []byte
	write, observation                                       configMaintenanceGrantFacts
	source                                                   configMaintenanceSourceFacts
	writeCalls, observationCalls, sourceCalls, capacityCalls int
	denyWrite, denyObservation                               bool
	onGrant                                                  func(configMaintenanceScope)
	onSource                                                 func(configMaintenanceScope, []byte)
	onCapacity, capacityRecheck                              func()
	capacityUntil                                            time.Time
}
type maintenanceAuthorityACapacity struct{ f *maintenanceAuthorityAFixture }

func (r *maintenanceAuthorityACapacity) ValidUntil() time.Time { return r.f.capacityUntil }
func (r *maintenanceAuthorityACapacity) Recheck(context.Context, *sql.Tx, time.Time) error {
	if r.f.capacityRecheck != nil {
		r.f.capacityRecheck()
	}
	return nil
}
func newMaintenanceAuthorityAFixture(t *testing.T) *maintenanceAuthorityAFixture {
	t.Helper()
	s, m, _, oldScope, original := maintenanceServiceFixture(t)
	f := &maintenanceAuthorityAFixture{m: m, original: original, capacityUntil: m.store.base.now.Add(time.Minute)}
	actor, err := ConfigMaintenanceActorSHA256("https://synthetic-auth.invalid", "maintenance-subject")
	if err != nil {
		t.Fatal(err)
	}
	grant, err := ConfigMaintenanceGrantIdentitySHA256("https://synthetic-grants.invalid", "grant-001")
	if err != nil {
		t.Fatal(err)
	}
	f.source = configMaintenanceSourceFacts{provenance: ConfigBackfillProvenanceFacts{TargetServerUUID: oldScope.identity.Server, TargetDatabase: oldScope.identity.Database, InstallationID: oldScope.identity.Installation, Version: oldScope.identity.Version, ConfigSHA256: registrationHash(string(original)), ConfigSizeBytes: int64(len(original)), SourceIssuer: "synthetic-archive-verifier", SourceID: "record-001", SourceVersion: "original-v1", AttestationSHA256: registrationHash("synthetic authenticated manifest")}, verificationVersion: "archive-auth-v1", notBefore: m.store.base.now.Add(-time.Hour), expiresAt: m.store.base.now.Add(time.Minute)}
	_, provenance, err := CanonicalConfigBackfillProvenance(f.source.provenance)
	if err != nil {
		t.Fatal(err)
	}
	var request map[string]any
	if json.Unmarshal(oldScope.canonical, &request) != nil {
		t.Fatal("fixture request")
	}
	request["maintenance_actor_sha256"], request["grant_identity_sha256"], request["grant_version"], request["source_provenance_sha256"] = actor, grant, "grant-v1", provenance
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	f.scope, err = newConfigMaintenanceScope(oldScope.database, oldScope.identity.Installation, actor, oldScope.key, raw)
	if err != nil {
		t.Fatal(err)
	}
	f.write = configMaintenanceGrantFacts{actorIssuer: "https://synthetic-auth.invalid", principal: "maintenance-subject", issuer: "https://synthetic-grants.invalid", grantID: "grant-001", version: "grant-v1", grantBytesSHA256: registrationHash("synthetic write grant"), revocationVersion: "generation-001", purpose: configMaintenanceWrite, bindings: f.scope.identity, key: f.scope.key, requestSHA256: f.scope.hash, notBefore: m.store.base.now.Add(-time.Hour), expiresAt: m.store.base.now.Add(2 * time.Minute)}
	f.observation = f.write
	f.observation.purpose = configMaintenanceObserve
	f.observation.grantID = "independent-observation-grant"
	f.observation.version = "observation-v2"
	f.observation.grantBytesSHA256 = registrationHash("synthetic independent observation grant")
	f.pins = configMaintenanceAuthorityPins{database: f.scope.database, installation: f.scope.identity.Installation, actor: actor, schemaSHA256: f.scope.identity.SchemaSHA, catalogSHA256: f.scope.identity.CatalogSHA, migrationSHA256: f.scope.identity.MigrationSHA}
	f.target = f.pins
	f.sources = configMaintenanceAuthoritySources{
		CurrentTarget: func(context.Context, *sql.Tx, time.Time) (configMaintenanceAuthorityPins, error) {
			return f.target, nil
		},
		WriteGrant: func(_ context.Context, _ *sql.Tx, scope configMaintenanceScope, _ time.Time) (configMaintenanceGrantFacts, error) {
			f.writeCalls++
			if f.denyWrite {
				return configMaintenanceGrantFacts{}, ErrRegistrationPermission
			}
			if f.onGrant != nil {
				f.onGrant(scope)
			}
			return f.write, nil
		},
		ObservationGrant: func(_ context.Context, _ *sql.Tx, scope configMaintenanceScope, _ time.Time) (configMaintenanceGrantFacts, error) {
			f.observationCalls++
			if f.denyObservation {
				return configMaintenanceGrantFacts{}, ErrRegistrationPermission
			}
			if f.onGrant != nil {
				f.onGrant(scope)
			}
			return f.observation, nil
		},
		OriginalArchive: func(_ context.Context, _ *sql.Tx, scope configMaintenanceScope, original []byte, _ time.Time) (configMaintenanceSourceFacts, error) {
			f.sourceCalls++
			if f.onSource != nil {
				f.onSource(scope, original)
			}
			return f.source, nil
		},
		ReserveMetadata: func(_ context.Context, _ *sql.Tx, _ configMaintenanceScope, _ configMaintenanceBudget, _ time.Time) (ConfigMutationCapacityReservation, error) {
			f.capacityCalls++
			if f.onCapacity != nil {
				f.onCapacity()
			}
			return &maintenanceAuthorityACapacity{f}, nil
		},
	}
	f.a, err = newPinnedConfigMaintenanceAuthority(f.pins, f.sources)
	if err != nil {
		t.Fatal(err)
	}
	f.tx, err = s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.tx.Rollback() })
	return f
}
func maintenanceAuthorityAWrite(t *testing.T, f *maintenanceAuthorityAFixture) configMaintenanceAdmission {
	t.Helper()
	p, err := f.a.AuthorizeWrite(context.Background(), f.tx, f.scope, f.original, f.m.store.base.now)
	if err != nil || nilConfigMutationBoundary(p) {
		t.Fatal("synthetic verified facts not admitted", err)
	}
	return p
}

func TestConfigMaintenanceAuthorityARejectsMissingDeploymentSourcesAndPins(t *testing.T) {
	for _, name := range []string{"current-target", "write", "observation", "archive", "capacity", "database", "installation", "actor", "schema", "catalog", "migration"} {
		t.Run(name, func(t *testing.T) {
			f := newMaintenanceAuthorityAFixture(t)
			pins, sources := f.pins, f.sources
			switch name {
			case "current-target":
				sources.CurrentTarget = nil
			case "write":
				sources.WriteGrant = nil
			case "observation":
				sources.ObservationGrant = nil
			case "archive":
				sources.OriginalArchive = nil
			case "capacity":
				sources.ReserveMetadata = nil
			case "database":
				pins.database.Database = "../foreign"
			case "installation":
				pins.installation = "admin"
			case "actor":
				pins.actor = "admin:1"
			case "schema":
				pins.schemaSHA256 = ""
			case "catalog":
				pins.catalogSHA256 = ""
			case "migration":
				pins.migrationSHA256 = ""
			}
			if a, err := newPinnedConfigMaintenanceAuthority(pins, sources); err == nil || a != nil {
				t.Fatal("missing deployment binding defaulted open")
			}
		})
	}
}

func TestConfigMaintenanceAuthorityAIndependentGrantAndSourceBindings(t *testing.T) {
	for _, name := range []string{"principal", "actor-issuer", "grant-issuer", "grant-id", "grant-version", "grant-bytes", "revocation", "purpose", "key", "request-hash", "target-server", "target-database", "installation", "actor-digest", "config-version", "config-hash", "config-size", "row-fingerprint", "provenance", "schema", "catalog", "migration", "grant-not-yet", "grant-expired", "source-target", "source-version", "source-hash", "source-size", "source-issuer", "source-id", "source-original-version", "source-attestation", "source-verifier", "source-not-yet", "source-expired"} {
		t.Run(name, func(t *testing.T) {
			f := newMaintenanceAuthorityAFixture(t)
			g := &f.write
			switch name {
			case "principal":
				g.principal = "foreign-subject"
			case "actor-issuer":
				g.actorIssuer += "/foreign"
			case "grant-issuer":
				g.issuer += "/foreign"
			case "grant-id":
				g.grantID = "foreign-grant"
			case "grant-version":
				g.version = "v2"
			case "grant-bytes":
				g.grantBytesSHA256 = ""
			case "revocation":
				g.revocationVersion = ""
			case "purpose":
				g.purpose = configMaintenanceObserve
			case "key":
				g.key = "another-maintenance-key"
			case "request-hash":
				g.requestSHA256 = strings.Repeat("f", 64)
			case "target-server":
				g.bindings.Server = "22345678-1234-1234-1234-123456789abc"
			case "target-database":
				g.bindings.Database += "_other"
			case "installation":
				g.bindings.Installation += "_other"
			case "actor-digest":
				g.bindings.Actor = strings.Repeat("b", 64)
			case "config-version":
				g.bindings.Version++
			case "config-hash":
				g.bindings.ConfigSHA = strings.Repeat("b", 64)
			case "config-size":
				g.bindings.ConfigSize++
			case "row-fingerprint":
				g.bindings.RowSHA = strings.Repeat("b", 64)
			case "provenance":
				g.bindings.ProvenanceSHA = strings.Repeat("b", 64)
			case "schema":
				g.bindings.SchemaSHA = strings.Repeat("b", 64)
			case "catalog":
				g.bindings.CatalogSHA = strings.Repeat("b", 64)
			case "migration":
				g.bindings.MigrationSHA = strings.Repeat("b", 64)
			case "grant-not-yet":
				g.notBefore = f.m.store.base.now.Add(time.Second)
			case "grant-expired":
				g.expiresAt = f.m.store.base.now
			case "source-target":
				f.source.provenance.TargetDatabase += "_other"
			case "source-version":
				f.source.provenance.Version++
			case "source-hash":
				f.source.provenance.ConfigSHA256 = strings.Repeat("b", 64)
			case "source-size":
				f.source.provenance.ConfigSizeBytes++
			case "source-issuer":
				f.source.provenance.SourceIssuer += "-other"
			case "source-id":
				f.source.provenance.SourceID += "-other"
			case "source-original-version":
				f.source.provenance.SourceVersion = "original-v2"
			case "source-attestation":
				f.source.provenance.AttestationSHA256 = strings.Repeat("b", 64)
			case "source-verifier":
				f.source.verificationVersion = ""
			case "source-not-yet":
				f.source.notBefore = f.m.store.base.now.Add(time.Second)
			case "source-expired":
				f.source.expiresAt = f.m.store.base.now
			}
			p, err := f.a.AuthorizeWrite(context.Background(), f.tx, f.scope, f.original, f.m.store.base.now)
			if !errors.Is(err, ErrRegistrationPermission) || !nilConfigMutationBoundary(p) {
				t.Fatal("foreign/unverified binding admitted", name, err)
			}
			if !strings.HasPrefix(name, "source-") && f.sourceCalls != 0 {
				t.Fatal("foreign grant reached archive verifier")
			}
		})
	}
}

func TestConfigMaintenanceAuthorityARequestCannotSelectDeploymentPins(t *testing.T) {
	for _, name := range []string{"server", "database", "installation", "actor", "schema", "catalog", "migration"} {
		t.Run(name, func(t *testing.T) {
			f := newMaintenanceAuthorityAFixture(t)
			pins := f.pins
			switch name {
			case "server":
				pins.database.ServerUUID = "22345678-1234-1234-1234-123456789abc"
			case "database":
				pins.database.Database += "_other"
			case "installation":
				pins.installation += "_other"
			case "actor":
				pins.actor = strings.Repeat("b", 64)
			case "schema":
				pins.schemaSHA256 = strings.Repeat("b", 64)
			case "catalog":
				pins.catalogSHA256 = strings.Repeat("b", 64)
			case "migration":
				pins.migrationSHA256 = strings.Repeat("b", 64)
			}
			a, err := newPinnedConfigMaintenanceAuthority(pins, f.sources)
			if err != nil {
				t.Fatal(err)
			}
			p, err := a.AuthorizeWrite(context.Background(), f.tx, f.scope, f.original, f.m.store.base.now)
			if err == nil || !nilConfigMutationBoundary(p) || f.writeCalls != 0 || f.sourceCalls != 0 {
				t.Fatal("request overrode independent deployment pins")
			}
		})
	}
}

func TestConfigMaintenanceAuthorityACurrentTargetIsIndependentOfGrantPins(t *testing.T) {
	for _, name := range []string{"initial-catalog", "schema-after-grant", "ledger-after-source", "capacity-target-drift"} {
		t.Run(name, func(t *testing.T) {
			f := newMaintenanceAuthorityAFixture(t)
			switch name {
			case "initial-catalog":
				f.target.catalogSHA256 = strings.Repeat("b", 64)
			case "schema-after-grant":
				f.onGrant = func(configMaintenanceScope) { f.target.schemaSHA256 = strings.Repeat("b", 64) }
			case "ledger-after-source":
				f.onSource = func(configMaintenanceScope, []byte) { f.target.migrationSHA256 = strings.Repeat("b", 64) }
			case "capacity-target-drift":
				f.onCapacity = func() { f.target.catalogSHA256 = strings.Repeat("b", 64) }
				r, err := f.a.Reserve(context.Background(), f.tx, f.scope, configMaintenanceBudget{receiptMaxBytes: 4096, intentBytes: 2048, resultBytes: 2048}, f.m.store.base.now)
				if !errors.Is(err, ErrRegistrationUnavailable) || !nilConfigMutationBoundary(r) {
					t.Fatal("capacity accepted changed installed target", err)
				}
				return
			}
			p, err := f.a.AuthorizeWrite(context.Background(), f.tx, f.scope, f.original, f.m.store.base.now)
			if !errors.Is(err, ErrRegistrationUnavailable) || !nilConfigMutationBoundary(p) {
				t.Fatal("valid grant pins replaced current target verification", err)
			}
			if name == "initial-catalog" && (f.writeCalls != 0 || f.sourceCalls != 0) {
				t.Fatal("wrong installed catalog reached grant/archive verification")
			}
		})
	}
}

func TestConfigMaintenanceAuthorityARecheckPinsEveryOriginalObservation(t *testing.T) {
	for _, name := range []string{"grant-bytes-same-version", "grant-revocation", "grant-rotation", "grant-extended", "source-extended", "source-verifier-rotation", "source-attestation", "write-revoked", "wrong-tx", "callback-expiry", "target-drift", "clock-backwards"} {
		t.Run(name, func(t *testing.T) {
			f := newMaintenanceAuthorityAFixture(t)
			p := maintenanceAuthorityAWrite(t, f)
			until := p.ValidUntil()
			switch name {
			case "grant-bytes-same-version":
				f.write.grantBytesSHA256 = registrationHash("different grant same version")
			case "grant-revocation":
				f.write.revocationVersion = "generation-002"
			case "grant-rotation":
				f.write.version = "grant-v2"
			case "grant-extended":
				f.write.expiresAt = f.write.expiresAt.Add(time.Hour)
			case "source-extended":
				f.source.expiresAt = f.source.expiresAt.Add(time.Hour)
			case "source-verifier-rotation":
				f.source.verificationVersion = "archive-auth-v2"
			case "source-attestation":
				f.source.provenance.AttestationSHA256 = registrationHash("replaced attestation")
			case "write-revoked":
				f.denyWrite = true
			case "wrong-tx":
				if p.Recheck(context.Background(), &sql.Tx{}, f.m.store.base.now) == nil {
					t.Fatal("admission crossed transactions")
				}
				return
			case "callback-expiry":
				f.onSource = func(configMaintenanceScope, []byte) { f.m.store.base.now = until }
			case "target-drift":
				f.onSource = func(configMaintenanceScope, []byte) { f.m.store.base.wrongDatabase = true }
			case "clock-backwards":
				f.onSource = func(configMaintenanceScope, []byte) { f.m.store.base.now = f.m.store.base.now.Add(-time.Microsecond) }
			}
			if err := p.Recheck(context.Background(), f.tx, f.m.store.base.now); err == nil {
				t.Fatal("recheck adopted changed authenticated facts")
			}
			if !p.ValidUntil().Equal(until) {
				t.Fatal("admission deadline renewed")
			}
		})
	}
}

func TestConfigMaintenanceAuthorityAObservationUsesIndependentCurrentGrant(t *testing.T) {
	f := newMaintenanceAuthorityAFixture(t)
	f.denyWrite = true
	p, err := f.a.AuthorizeObservation(context.Background(), f.tx, f.scope, f.original, f.m.store.base.now)
	if err != nil || nilConfigMutationBoundary(p) || f.writeCalls != 0 || f.observationCalls != 1 {
		t.Fatal("observation borrowed old write authorization", err)
	}
	if !p.ValidUntil().Equal(f.source.expiresAt) {
		t.Fatal("source deadline not included")
	}
	if err := p.Recheck(context.Background(), f.tx, f.m.store.base.now); err != nil {
		t.Fatal(err)
	}
	f.denyObservation = true
	if err := p.Recheck(context.Background(), f.tx, f.m.store.base.now); !errors.Is(err, ErrRegistrationPermission) {
		t.Fatal("revoked observation remained usable", err)
	}
	if _, err := json.Marshal(p); err == nil {
		t.Fatal("private grant/source admission serialized")
	}
	f.denyObservation = false
	f.observation = f.write
	if wrong, err := f.a.AuthorizeObservation(context.Background(), f.tx, f.scope, f.original, f.m.store.base.now); !errors.Is(err, ErrRegistrationPermission) || !nilConfigMutationBoundary(wrong) {
		t.Fatal("write-purpose grant was reused as independent observation permission", err)
	}
}

func TestConfigMaintenanceAuthorityACallbackCannotRewriteFrozenBytes(t *testing.T) {
	f := newMaintenanceAuthorityAFixture(t)
	original := append([]byte(nil), f.original...)
	scope := cloneConfigMaintenanceScope(f.scope)
	f.onGrant = func(s configMaintenanceScope) { s.canonical[0] = '!'; scope.canonical[0] = '!'; original[0] = '!' }
	f.onSource = func(s configMaintenanceScope, source []byte) {
		if !bytes.Equal(source, f.original) || !s.valid() {
			t.Fatal("grant callback rewrote archive inputs")
		}
		source[0] = '!'
		s.canonical[0] = '!'
	}
	p, err := f.a.AuthorizeWrite(context.Background(), f.tx, scope, original, f.m.store.base.now)
	if err != nil || nilConfigMutationBoundary(p) {
		t.Fatal("callbacks rewrote authoritative byte copies", err)
	}
	f.onGrant = nil
	f.onSource = nil
	if err := p.Recheck(context.Background(), f.tx, f.m.store.base.now); err != nil {
		t.Fatal("returned admission retained callback aliases", err)
	}
}

func TestConfigMaintenanceAuthorityAReservationFrozenDeadlineAndTransaction(t *testing.T) {
	for _, name := range []string{"normal", "wrong-budget", "wrong-tx", "nil-reservation", "typed-nil-reservation", "expiry-during-reserve", "extension-during-recheck"} {
		t.Run(name, func(t *testing.T) {
			f := newMaintenanceAuthorityAFixture(t)
			budget := configMaintenanceBudget{canonicalWriteBytes: len(f.original), receiptMaxBytes: 4096, intentBytes: 2048, resultBytes: 2048}
			if name == "wrong-budget" {
				budget.canonicalWriteBytes++
			}
			if name == "expiry-during-reserve" {
				f.onCapacity = func() { f.m.store.base.now = f.capacityUntil }
			}
			if name == "nil-reservation" {
				f.a.sources.ReserveMetadata = func(context.Context, *sql.Tx, configMaintenanceScope, configMaintenanceBudget, time.Time) (ConfigMutationCapacityReservation, error) {
					return nil, nil
				}
			}
			if name == "typed-nil-reservation" {
				f.a.sources.ReserveMetadata = func(context.Context, *sql.Tx, configMaintenanceScope, configMaintenanceBudget, time.Time) (ConfigMutationCapacityReservation, error) {
					var empty *maintenanceAuthorityACapacity
					return empty, nil
				}
			}
			r, err := f.a.Reserve(context.Background(), f.tx, f.scope, budget, f.m.store.base.now)
			if name == "wrong-budget" || name == "expiry-during-reserve" || name == "nil-reservation" || name == "typed-nil-reservation" {
				if err == nil || !nilConfigMutationBoundary(r) {
					t.Fatal("invalid reservation admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			until := r.ValidUntil()
			tx := f.tx
			if name == "wrong-tx" {
				tx = &sql.Tx{}
			}
			if name == "extension-during-recheck" {
				f.capacityRecheck = func() { f.m.store.base.now = until; f.capacityUntil = until.Add(time.Hour) }
			}
			err = r.Recheck(context.Background(), tx, f.m.store.base.now)
			if name == "normal" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("reservation crossed transaction or renewed deadline")
			}
			if !r.ValidUntil().Equal(until) {
				t.Fatal("capacity original deadline changed")
			}
			if _, err := json.Marshal(r); err == nil {
				t.Fatal("private reservation serialized")
			}
		})
	}
}

// The original storage transport has a fixed synthetic actor. This independent
// SELECT path checks the derived actor used here without translating the SQL
// argument or accepting a request-supplied actor as the expected binding.
type maintenanceAuthorityAConnector struct {
	m     *maintenanceServiceModel
	actor string
}

func (maintenanceAuthorityAConnector) Driver() driver.Driver { return registrationTestDriver{} }
func (c maintenanceAuthorityAConnector) Connect(context.Context) (driver.Conn, error) {
	return &maintenanceAuthorityAConn{maintenanceServiceConn: maintenanceServiceConn{maintenanceReceiptConn: maintenanceReceiptConn{backfillLockedConn: backfillLockedConn{s: c.m.store.base}, s: c.m.store}, m: c.m}, actor: c.actor}, nil
}

type maintenanceAuthorityAConn struct {
	maintenanceServiceConn
	actor string
}

func (c *maintenanceAuthorityAConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if q != configMaintenanceReceiptSelect {
		return c.maintenanceReceiptConn.QueryContext(ctx, q, args)
	}
	facts := c.m.store.base.facts
	want := []driver.Value{facts.TargetServerUUID, facts.TargetDatabase, facts.InstallationID, c.actor, "maintenance-key-0001"}
	if len(args) != len(want) {
		return nil, errors.New("authority receipt scope arity")
	}
	for i, v := range want {
		if args[i].Value != v {
			return nil, errors.New("authority receipt query binding")
		}
	}
	values := make([]driver.Value, len(c.m.store.columns))
	for i, name := range c.m.store.columns {
		values[i] = c.m.store.receipt[name]
	}
	count := 0
	if c.m.store.receipt != nil {
		count = 1
	}
	return &maintenanceReceiptRows{s: c.m.store, values: values, count: count}, nil
}

func TestConfigMaintenanceAuthorityAComposesWithWholeBackfillAndIndependentObservation(t *testing.T) {
	f := newMaintenanceAuthorityAFixture(t)
	if err := f.tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(maintenanceAuthorityAConnector{m: f.m, actor: f.pins.actor})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	s, err := newConfigCanonicalBackfillService(db, f.pins.database, f.pins.installation, f.pins.actor, f.a)
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.apply(context.Background(), f.scope.key, f.scope.canonical, f.original)
	if err != nil || len(first.bytes()) < 2 {
		t.Fatal("verified-facts composition could not commit candidate", err)
	}
	f.denyWrite = true
	observed, err := s.observe(context.Background(), f.scope.key, f.scope.canonical, f.original)
	if err != nil || !observed.replayed || !bytes.Equal(first.bytes(), observed.bytes()) {
		t.Fatal("separate current observation not integrated", err)
	}
	if f.m.commits != 2 || f.m.fills != 1 || f.m.auditWrites != 2 || f.m.store.inserts != 1 || f.capacityCalls != 1 || f.writeCalls != 2 || f.observationCalls != 2 || f.sourceCalls != 4 {
		t.Fatal("composition bypassed recheck or observation wrote metadata")
	}
}

func TestConfigMaintenanceAuthorityAFinalSourceRecheckRejectsWholeTransaction(t *testing.T) {
	f := newMaintenanceAuthorityAFixture(t)
	if err := f.tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(maintenanceAuthorityAConnector{m: f.m, actor: f.pins.actor})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	s, err := newConfigCanonicalBackfillService(db, f.pins.database, f.pins.installation, f.pins.actor, f.a)
	if err != nil {
		t.Fatal(err)
	}
	f.onSource = func(configMaintenanceScope, []byte) {
		if f.sourceCalls == 2 {
			f.source.verificationVersion = "archive-auth-v2"
		}
	}
	r, err := s.apply(context.Background(), f.scope.key, f.scope.canonical, f.original)
	maintenanceServiceEmpty(t, r, err)
	if !errors.Is(err, ErrRegistrationUnavailable) || f.m.commits != 0 || f.m.rollbacks != 2 || f.m.store.receipt != nil || len(f.m.store.audits) != 0 || f.m.store.base.cells["canonical_config_json"] != nil {
		t.Fatal("changed source admission did not roll back complete candidate", err)
	}
}

func TestConfigMaintenanceAuthorityAImmutableFactsAndPermissionErrorsRemainDistinct(t *testing.T) {
	for _, name := range []string{"same-grant-version-different-bytes", "same-grant-version-different-validity", "source-verifier-changed", "current-write-denied"} {
		t.Run(name, func(t *testing.T) {
			f := newMaintenanceAuthorityAFixture(t)
			p := maintenanceAuthorityAWrite(t, f)
			want := ErrRegistrationUnavailable
			switch name {
			case "same-grant-version-different-bytes":
				f.write.grantBytesSHA256 = registrationHash("another authenticated grant under original immutable version")
			case "same-grant-version-different-validity":
				f.write.expiresAt = f.write.expiresAt.Add(time.Hour)
			case "source-verifier-changed":
				f.source.verificationVersion = "archive-auth-v2"
			case "current-write-denied":
				f.denyWrite = true
				want = ErrRegistrationPermission
			}
			if err := p.Recheck(context.Background(), f.tx, f.m.store.base.now); !errors.Is(err, want) {
				t.Fatal("immutable-fact drift and actual permission denial were conflated", err)
			}
		})
	}
}
