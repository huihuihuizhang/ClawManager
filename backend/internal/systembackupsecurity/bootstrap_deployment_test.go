package systembackupsecurity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func deploymentFixture(t *testing.T) (string, string, BootstrapDeploymentConfig, BootstrapOwnerAdapters, *bootstrapTestState, BootstrapAdmissionSources) {
	t.Helper()
	_, g, raw, sources, state := admissionFixture(t)
	dir := t.TempDir()
	c := BootstrapDeploymentConfig{SchemaVersion: "system-backup-bootstrap-deployment.v1", InstallationID: g.InstallationID, ExpectedServerUUID: g.ServerUUID, ExpectedDatabase: g.Database,
		ConfigFile: filepath.Join(dir, "config.json"), ConfigSHA256: g.ConfigSHA256, GrantFile: filepath.Join(dir, "grant.json"), RegistryDirectory: filepath.Join(dir, "registries"), NonceDirectory: filepath.Join(dir, "nonce"), CapacityReportFile: filepath.Join(dir, "capacity.json"), DSNFile: filepath.Join(dir, "dsn")}
	writeDeploymentFile(t, c.ConfigFile, raw)
	grantRaw, _ := json.Marshal(BootstrapGrantFile{"system-backup-offline-bootstrap-grant.v1", time.Now().UTC().Add(-time.Hour), time.Now().UTC().Add(time.Hour), g})
	writeDeploymentFile(t, c.GrantFile, grantRaw)
	c.GrantSHA256 = registrationHash(string(grantRaw))
	config, err := DecodeBootstrapConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range config.Registries() {
		b, _ := sources.RegistryBytes(r.Kind, r.Version, r.SHA256)
		writeDeploymentFile(t, filepath.Join(c.RegistryDirectory, r.Kind, r.Version, r.SHA256+".json"), b)
	}
	for _, r := range config.References() {
		if r.Purpose == "nonce_hmac" {
			writeDeploymentFile(t, filepath.Join(c.NonceDirectory, r.IdentityHash, r.Version), make([]byte, 32))
		}
	}
	p := filepath.Join(dir, "deployment.json")
	b, _ := json.Marshal(c)
	writeDeploymentFile(t, p, b)
	return p, registrationHash(string(b)), c, BootstrapOwnerAdapters{Registries: sources.Registries, References: sources.References, CrossResources: sources.CrossResources}, state, sources
}

func writeDeploymentFile(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

type deploymentContextResource struct {
	prepared context.Context
	checks   int
}

func (r *deploymentContextResource) Prepare(ctx context.Context, _ OfflineBootstrapGrant, _ BootstrapConfig) (BootstrapResourceCheck, error) {
	if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
		return nil, ErrRegistrationUnavailable
	}
	r.prepared = ctx
	return r, nil
}

func (r *deploymentContextResource) Recheck(ctx context.Context, _ *sql.Tx, _ time.Time) error {
	if ctx != r.prepared || ctx.Err() != nil {
		return ErrRegistrationUnavailable
	}
	r.checks++
	return nil
}

func TestDeploymentLegacyAttemptKeepsPreparationContextThroughSQL(t *testing.T) {
	p, h, _, owners, state, sources := deploymentFixture(t)
	resource := &deploymentContextResource{}
	owners.CrossResources = resource
	d, err := LoadBootstrapDeployment(p, h, owners)
	if err != nil {
		t.Fatal(err)
	}
	d.sources.ReserveMetadata = sources.ReserveMetadata
	opens := 0
	d.openDatabase = func() (*sql.DB, error) {
		opens++
		if resource.prepared == nil || resource.prepared.Err() != nil {
			t.Fatal("credentials preceded bounded preparation")
		}
		return sql.OpenDB(bootstrapConnector{state}), nil
	}
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := d.Apply(parent)
	if err != nil || result.Version != 1 || opens != 1 || resource.checks == 0 {
		t.Fatal("legacy deployment replaced original preparation context", result, err)
	}
	if parent.Err() != nil || resource.prepared.Err() == nil {
		t.Fatal("attempt lifetime leaked or canceled parent")
	}
}

func TestDeploymentLegacyRejectsTypedNilOwnersBeforeCredentials(t *testing.T) {
	p, h, _, owners, _, _ := deploymentFixture(t)
	var absent *admissionTestValidator
	owners.CrossResources = absent
	d, err := LoadBootstrapDeployment(p, h, owners)
	if err != nil {
		t.Fatal(err)
	}
	d.openDatabase = func() (*sql.DB, error) { t.Fatal("typed-nil owner opened credentials"); return nil, nil }
	report, err := d.Inspect()
	if err != nil || report.Status != "blocked" || len(report.MissingAdapters) != 1 || report.MissingAdapters[0] != "cross_resources" {
		t.Fatal("typed-nil owner hidden by inspection", report, err)
	}
	if _, err := d.Apply(context.Background()); err == nil {
		t.Fatal("typed-nil owner admitted")
	}
}

func TestDeploymentLegacyClosesDatabaseReturnedWithOpenError(t *testing.T) {
	p, h, _, owners, state, _ := deploymentFixture(t)
	d, err := LoadBootstrapDeployment(p, h, owners)
	if err != nil {
		t.Fatal(err)
	}
	returned := sql.OpenDB(bootstrapConnector{state})
	d.openDatabase = func() (*sql.DB, error) { return returned, errors.New("PRIVATE opener diagnostic") }
	result, err := d.Apply(context.Background())
	if err == nil || result != (ConfigBootstrapResult{}) || strings.Contains(err.Error(), "PRIVATE") || len(state.committed) != 0 {
		t.Fatal("opener failure leaked or performed SQL work", result, err)
	}
	if returned.PingContext(context.Background()) == nil {
		returned.Close()
		t.Fatal("failed opener leaked database ownership")
	}
}

func TestDeploymentInspectionNeverCallsOwnersOrReadsCredentials(t *testing.T) {
	p, h, c, owners, _, _ := deploymentFixture(t)
	// DSN/capacity files intentionally do not exist. Poison owner callbacks:
	// inspection must not accidentally turn into a provider/SQL dry-run.
	poison := &admissionTestValidator{prepare: func(context.Context, OfflineBootstrapGrant, BootstrapConfig) (BootstrapResourceCheck, error) {
		t.Fatal("owner called during input inspection")
		return nil, nil
	}}
	for k := range owners.Registries {
		owners.Registries[k] = poison
	}
	for k := range owners.References {
		owners.References[k] = poison
	}
	owners.CrossResources = poison
	d, err := LoadBootstrapDeployment(p, h, owners)
	if err != nil {
		t.Fatal(err)
	}
	delete(owners.Registries, "parts") // copied at composition, cannot replace table
	r, err := d.Inspect()
	if err != nil || r.Status != "inputs_checked" || r.DatabaseOpened || r.ConfigurationMutated || r.ProviderAdmission != "not_run" {
		t.Fatal(r, err)
	}
	if _, err = os.Stat(c.DSNFile); !os.IsNotExist(err) {
		t.Fatal("fixture DSN must be absent")
	}
}

func TestDeploymentRejectsEveryMissingOwnerBeforeDatabase(t *testing.T) {
	requirements := MissingBootstrapOwnerAdapters(BootstrapOwnerAdapters{})
	if len(requirements) != 30 {
		t.Fatal(requirements)
	}
	for _, missing := range requirements {
		t.Run(missing, func(t *testing.T) {
			p, h, _, owners, state, _ := deploymentFixture(t)
			switch {
			case strings.HasPrefix(missing, "registry:"):
				delete(owners.Registries, strings.TrimPrefix(missing, "registry:"))
			case strings.HasPrefix(missing, "reference:"):
				delete(owners.References, strings.TrimPrefix(missing, "reference:"))
			default:
				owners.CrossResources = nil
			}
			d, err := LoadBootstrapDeployment(p, h, owners)
			if err != nil {
				t.Fatal(err)
			}
			d.openDatabase = func() (*sql.DB, error) { t.Fatal("database opened without all owners"); return nil, nil }
			r, err := d.Inspect()
			if err != nil || r.Status != "blocked" || len(r.MissingAdapters) != 1 || r.MissingAdapters[0] != missing {
				t.Fatal(r, err)
			}
			if _, err = d.Apply(context.Background()); err == nil || len(state.committed) != 0 {
				t.Fatal("missing owner bypass", err)
			}
		})
	}
}

func TestDeploymentTargetAndPinnedInputRejections(t *testing.T) {
	for _, fault := range []string{"deployment_hash", "config_hash", "grant_hash", "database", "server", "installation", "relative_path", "duplicate_field", "unknown_field", "expired_grant", "future_grant"} {
		t.Run(fault, func(t *testing.T) {
			p, h, c, owners, _, _ := deploymentFixture(t)
			switch fault {
			case "config_hash":
				c.ConfigSHA256 = strings.Repeat("0", 64)
			case "grant_hash":
				c.GrantSHA256 = strings.Repeat("0", 64)
			case "database":
				c.ExpectedDatabase = "other_database"
			case "server":
				c.ExpectedServerUUID = "22222222-2222-2222-2222-222222222222"
			case "installation":
				c.InstallationID = "installation_other"
			case "relative_path":
				c.DSNFile = "./dsn"
			case "expired_grant", "future_grant":
				b, _ := os.ReadFile(c.GrantFile)
				var g BootstrapGrantFile
				_ = json.Unmarshal(b, &g)
				if fault == "expired_grant" {
					g.NotBefore = time.Now().Add(-2 * time.Hour)
					g.ExpiresAt = time.Now().Add(-time.Hour)
				} else {
					g.NotBefore = time.Now().Add(time.Hour)
					g.ExpiresAt = time.Now().Add(2 * time.Hour)
				}
				b, _ = json.Marshal(g)
				writeDeploymentFile(t, c.GrantFile, b)
				c.GrantSHA256 = registrationHash(string(b))
			}
			b, _ := json.Marshal(c)
			if fault == "duplicate_field" {
				b = []byte(strings.Replace(string(b), `"dsn_file":`, `"dsn_file":"PRIVATE","dsn_file":`, 1))
			}
			if fault == "unknown_field" {
				b = append(b[:len(b)-1], []byte(`,"approved":true}`)...)
			}
			writeDeploymentFile(t, p, b)
			h = registrationHash(string(b))
			if fault == "deployment_hash" {
				h = strings.Repeat("0", 64)
			}
			if _, err := LoadBootstrapDeployment(p, h, owners); err == nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("bad deployment admitted", err)
			}
		})
	}
}

func TestDeploymentApplyUsesAtomicBootstrapAndPreservesUnknownCommitKey(t *testing.T) {
	p, h, _, owners, state, sources := deploymentFixture(t)
	d, err := LoadBootstrapDeployment(p, h, owners)
	if err != nil {
		t.Fatal(err)
	}
	// Synthetic SQL capacity accounting; not real database capacity evidence.
	d.sources.ReserveMetadata = sources.ReserveMetadata
	opens := 0
	d.openDatabase = func() (*sql.DB, error) { opens++; return sql.OpenDB(bootstrapConnector{state}), nil }
	state.commitUnknown = true
	if _, err = d.Apply(context.Background()); err != ErrRegistrationCommitUnknown {
		t.Fatal(err)
	}
	state.commitUnknown = false
	receipt, err := d.Apply(context.Background())
	if err != nil || !receipt.Replayed || receipt.Version != 1 || opens != 2 || len(state.committed) != 6 {
		t.Fatal(receipt, err, state.committed)
	}
	// Same prepared caller must re-read authorization before a retry.
	if err = os.Remove(d.config.GrantFile); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Apply(context.Background()); err != ErrRegistrationPermission || opens != 2 {
		t.Fatal("revoked retry", err, opens)
	}
}

func TestDeploymentPreparationFailureAndRevocationCannotOpenDatabase(t *testing.T) {
	for _, fault := range []string{"owner_error", "grant_removed", "registry_changed", "context_canceled"} {
		t.Run(fault, func(t *testing.T) {
			p, h, c, owners, _, _ := deploymentFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			owners.CrossResources = &admissionTestValidator{prepare: func(context.Context, OfflineBootstrapGrant, BootstrapConfig) (BootstrapResourceCheck, error) {
				switch fault {
				case "owner_error":
					return nil, errors.New("PRIVATE owner diagnostic")
				case "grant_removed":
					if err := os.Remove(c.GrantFile); err != nil {
						t.Fatal(err)
					}
				case "registry_changed":
					config, _ := DecodeBootstrapConfig(mustReadDeployment(t, c.ConfigFile))
					r := config.Registries()[0]
					writeDeploymentFile(t, filepath.Join(c.RegistryDirectory, r.Kind, r.Version, r.SHA256+".json"), []byte("changed"))
				case "context_canceled":
					cancel()
				}
				return &admissionTestValidator{}, nil
			}}
			d, err := LoadBootstrapDeployment(p, h, owners)
			if err != nil {
				t.Fatal(err)
			}
			d.openDatabase = func() (*sql.DB, error) { t.Fatal("unsafe credential/database open"); return nil, nil }
			if _, err = d.Apply(ctx); err == nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal(err)
			}
		})
	}
}

func mustReadDeployment(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDeploymentDSNRefusesWrongDatabaseAndUnsafeOptions(t *testing.T) {
	for _, dsn := range []string{"PRIVATE@tcp(127.0.0.1:1)/other", "PRIVATE@tcp(127.0.0.1:1)/synthetic?multiStatements=true", "PRIVATE@tcp(127.0.0.1:1)/synthetic?allowAllFiles=true", "not a DSN"} {
		path := filepath.Join(t.TempDir(), "dsn")
		writeDeploymentFile(t, path, []byte(dsn))
		if _, err := openBootstrapDatabase(BootstrapDeploymentConfig{DSNFile: path, ExpectedDatabase: "synthetic"}); err != ErrRegistrationUnavailable {
			t.Fatal("unsafe DSN", err)
		}
	}
}
