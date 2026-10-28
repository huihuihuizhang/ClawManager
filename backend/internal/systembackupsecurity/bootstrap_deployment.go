package systembackupsecurity

// D owns this deployment composition boundary. Owner implementations are
// linked as Go adapters; files cannot supply executable code or approval flags.
// This file does not implement A's security policy, B's relay, or C's providers.
import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

type BootstrapOwnerAdapters struct {
	Registries     map[string]BootstrapResourceValidator
	References     map[string]BootstrapResourceValidator
	CrossResources BootstrapResourceValidator
	Candidates     *BootstrapDeploymentCandidates // Fixed Go composition only; never loaded from deployment JSON.
}

// All paths belong to a SHA-pinned deployment document, never an HTTP body.
// ConfigSHA256 is the canonical ConfigValues hash; the other two hashes bind
// exact file bytes. Secrets themselves are never present in this document.
type BootstrapDeploymentConfig struct {
	SchemaVersion      string `json:"schema_version"`
	InstallationID     string `json:"installation_id"`
	ExpectedServerUUID string `json:"expected_server_uuid"`
	ExpectedDatabase   string `json:"expected_database"`
	ConfigFile         string `json:"config_file"`
	ConfigSHA256       string `json:"config_sha256"`
	GrantFile          string `json:"grant_file"`
	GrantSHA256        string `json:"grant_sha256"`
	RegistryDirectory  string `json:"registry_directory"`
	NonceDirectory     string `json:"nonce_directory"`
	CapacityReportFile string `json:"capacity_report_file"`
	DSNFile            string `json:"dsn_file"`
}

type BootstrapDeploymentReport struct {
	Status               string   `json:"status"`
	ConfigSHA256         string   `json:"config_sha256"`
	MissingAdapters      []string `json:"missing_adapters"`
	MissingInputs        []string `json:"missing_inputs"`
	ProviderAdmission    string   `json:"provider_admission"`
	DatabaseOpened       bool     `json:"database_opened"`
	ConfigurationMutated bool     `json:"configuration_mutated"`
}

type BootstrapDeployment struct {
	config       BootstrapDeploymentConfig
	grant        OfflineBootstrapGrant
	raw          []byte
	sources      BootstrapAdmissionSources
	openDatabase func() (*sql.DB, error)
	candidates   *BootstrapDeploymentCandidates
}

// MissingBootstrapOwnerAdapters reports only owner integration dependencies.
// D supplies grant/file/nonce/capacity plumbing itself; no dummy validator is
// substituted for a missing owner implementation.
func MissingBootstrapOwnerAdapters(a BootstrapOwnerAdapters) []string {
	missing := []string{}
	for _, k := range bootstrapRegistryKinds {
		if candidateAuthorityNil(a.Registries[k]) {
			missing = append(missing, "registry:"+k)
		}
	}
	for _, p := range bootstrapReferencePurposes {
		if candidateAuthorityNil(a.References[p]) {
			missing = append(missing, "reference:"+p)
		}
	}
	if candidateAuthorityNil(a.CrossResources) {
		missing = append(missing, "cross_resources")
	}
	return missing
}

func LoadBootstrapDeployment(path, digest string, owners BootstrapOwnerAdapters) (*BootstrapDeployment, error) {
	if owners.Candidates != nil && !owners.Candidates.valid() {
		return nil, ErrRegistrationUnavailable
	}
	raw, err := boundedFile(path, 16384)
	var c BootstrapDeploymentConfig
	if err != nil || decodePinnedRegistry(raw, digest, &c) != nil || c.SchemaVersion != "system-backup-bootstrap-deployment.v1" || !(DatabaseIdentity{ServerUUID: c.ExpectedServerUUID, Database: c.ExpectedDatabase}).valid() {
		return nil, ErrRegistrationUnavailable
	}
	for _, p := range []string{c.ConfigFile, c.GrantFile, c.RegistryDirectory, c.NonceDirectory, c.CapacityReportFile, c.DSNFile} {
		if !filepath.IsAbs(p) || strings.ContainsRune(p, '\x00') {
			return nil, ErrRegistrationUnavailable
		}
	}
	configRaw, err := boundedFile(c.ConfigFile, 262144)
	if err != nil {
		return nil, ErrBootstrapConfig
	}
	config, err := DecodeBootstrapConfig(configRaw)
	if err != nil || config.SHA256() != c.ConfigSHA256 {
		return nil, ErrBootstrapConfig
	}
	g, start, end, err := ReadBootstrapGrantFile(c.GrantFile, c.GrantSHA256)
	if err != nil || !liveBootstrapGrant(start, end, time.Now().UTC()) {
		return nil, ErrRegistrationPermission
	}
	if g.InstallationID != c.InstallationID || g.ServerUUID != c.ExpectedServerUUID || g.Database != c.ExpectedDatabase || g.ConfigSHA256 != config.SHA256() {
		return nil, ErrRegistrationUnavailable
	}
	files := RegistrationFiles{RegistryDirectory: c.RegistryDirectory, NonceDirectory: c.NonceDirectory}
	sources := BootstrapAdmissionSources{
		ReadGrant: func() (OfflineBootstrapGrant, time.Time, time.Time, error) {
			return ReadBootstrapGrantFile(c.GrantFile, c.GrantSHA256)
		},
		RegistryBytes: files.RegistryBytes, Registries: map[string]BootstrapResourceValidator{}, References: map[string]BootstrapResourceValidator{},
		CrossResources: owners.CrossResources, ReserveMetadata: RegistrationCapacity{ReportFile: c.CapacityReportFile}.Reserve,
		NonceMaterial: func(identity, version string) ([]byte, error) {
			if !providerHashPattern.MatchString(identity) || !registryVersionPath.MatchString(version) || strings.Contains(version, "..") {
				return nil, ErrRegistrationUnavailable
			}
			return boundedFile(filepath.Join(c.NonceDirectory, identity, version), 32)
		},
	}
	// Copy the adapter tables so subsequent mutation of caller maps cannot
	// replace implementations after deployment input validation.
	for k, v := range owners.Registries {
		sources.Registries[k] = v
	}
	for k, v := range owners.References {
		sources.References[k] = v
	}
	d := &BootstrapDeployment{config: c, grant: g, raw: configRaw, sources: sources}
	if owners.Candidates != nil {
		// Copy the outer object too: replacing the caller's factory variable
		// cannot replace the immutable selection/authority after loading.
		d.candidates = &BootstrapDeploymentCandidates{state: owners.Candidates.state}
	}
	d.openDatabase = func() (*sql.DB, error) { return openBootstrapDatabase(c) }
	return d, nil
}

func liveBootstrapGrant(start, end, now time.Time) bool {
	return !start.IsZero() && end.After(start) && !now.Before(start) && now.Before(end)
}

// Inspect only reads public registry bytes and offline authorization. It does
// not open the DSN/nonce/capacity files, dial providers, open SQL or run adapters.
// inputs_checked means precisely that; it is never a live admission success.
func (d *BootstrapDeployment) Inspect() (BootstrapDeploymentReport, error) {
	r := BootstrapDeploymentReport{Status: "blocked", ConfigSHA256: d.config.ConfigSHA256, MissingAdapters: MissingBootstrapAdapters(d.sources), MissingInputs: []string{}, ProviderAdmission: "not_run"}
	// Original source checks also reject typed-nil owner interfaces before any
	// legacy or candidate Prepare may call a method on them.
	owners := BootstrapOwnerAdapters{Registries: d.sources.Registries, References: d.sources.References, CrossResources: d.sources.CrossResources}
	for _, missing := range MissingBootstrapOwnerAdapters(owners) {
		found := false
		for _, prior := range r.MissingAdapters {
			if prior == missing {
				found = true
				break
			}
		}
		if !found {
			r.MissingAdapters = append(r.MissingAdapters, missing)
		}
	}
	g, start, end, err := d.sources.ReadGrant()
	if err != nil || g != d.grant || !liveBootstrapGrant(start, end, time.Now().UTC()) {
		return r, ErrRegistrationPermission
	}
	c, err := DecodeBootstrapConfig(d.raw)
	if err != nil {
		return r, err
	}
	for _, ref := range c.Registries() {
		raw, e := d.sources.RegistryBytes(ref.Kind, ref.Version, ref.SHA256)
		if e != nil || !json.Valid(raw) || !providerJSONUnicode(raw) || !providerUniqueJSON(json.NewDecoder(bytes.NewReader(raw))) {
			r.MissingInputs = append(r.MissingInputs, "registry:"+ref.Kind)
		}
	}
	if len(d.sources.Registries) > len(bootstrapRegistryKinds) || len(d.sources.References) > len(bootstrapReferencePurposes) {
		return r, ErrRegistrationUnavailable
	}
	if len(r.MissingAdapters) == 0 && len(r.MissingInputs) == 0 {
		r.Status = "inputs_checked"
	}
	return r, nil
}

// Apply prepares owner checks BEFORE opening the credential file/database,
// then invokes the existing atomic disabled-v1 bootstrap transaction. It never
// migrates SQL, starts a listener, enables backup work or synthesizes MFA.
func (d *BootstrapDeployment) Apply(ctx context.Context) (ConfigBootstrapResult, error) {
	var zero ConfigBootstrapResult
	if d == nil || candidateAuthorityNil(ctx) || ctx.Err() != nil {
		return zero, ErrRegistrationUnavailable
	}
	if d.candidates != nil {
		return d.applyCandidates(ctx)
	}
	config, err := DecodeBootstrapConfig(d.raw)
	if err != nil {
		return zero, err
	}
	// One original operation budget covers EVERY legacy owner preparation,
	// source reinspection, credential open, SQL wait and final commit check.
	ctx, cancel := context.WithTimeout(ctx, time.Duration(config.numbers["operation_deadline_seconds"])*time.Second)
	defer cancel()
	r, err := d.Inspect()
	if err != nil {
		return zero, err
	}
	if r.Status != "inputs_checked" {
		return zero, ErrRegistrationUnavailable
	}
	admission, err := PrepareBootstrapAdmission(ctx, d.grant, d.raw, d.sources)
	if err != nil {
		return zero, err
	}
	// Provider preparation can outlive the grant or race a file revocation.
	// Re-read the pinned inputs before opening credentials; the SQL transaction
	// still performs its own authoritative authorization check afterwards.
	r, err = d.Inspect()
	if err != nil {
		return zero, err
	}
	if ctx.Err() != nil || r.Status != "inputs_checked" {
		return zero, ErrRegistrationUnavailable
	}
	database, err := d.openDatabase()
	if database != nil {
		defer database.Close()
	}
	if err != nil || database == nil {
		return zero, ErrRegistrationUnavailable
	}
	return (ConfigBootstrapService{DB: database, Admission: admission}).bootstrapLegacyPrepared(ctx, d.grant, config)
}

func openBootstrapDatabase(c BootstrapDeploymentConfig) (*sql.DB, error) {
	raw, err := boundedFile(c.DSNFile, 8192)
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	defer wipeSecret(raw)
	cfg, err := mysql.ParseDSN(strings.TrimSpace(string(raw)))
	if err != nil || cfg.DBName != c.ExpectedDatabase || cfg.MultiStatements || cfg.AllowAllFiles {
		return nil, ErrRegistrationUnavailable
	}
	cfg.ParseTime, cfg.Loc, cfg.MultiStatements = true, time.UTC, false
	cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout = 10*time.Second, 30*time.Second, 30*time.Second
	if cfg.Params == nil {
		cfg.Params = map[string]string{}
	}
	cfg.Params["time_zone"] = "'+00:00'"
	database, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, ErrRegistrationUnavailable
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(0)
	return database, nil
}
