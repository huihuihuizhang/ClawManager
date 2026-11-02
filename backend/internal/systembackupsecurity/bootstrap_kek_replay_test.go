package systembackupsecurity

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	reg "clawreef/internal/systembackupkekregistry"
	wire "clawreef/internal/systembackupwire"
)

// Synthetic historical SQL row transport only. No initial KEK admission,
// provider/coverage proof, source receipt or real database is manufactured.
type bootstrapKEKReplayConnector struct {
	state                   *consumerIntegrationState
	installation, operation string
	row                     []driver.Value
	reads                   *int
}

func (bootstrapKEKReplayConnector) Driver() driver.Driver { return registrationTestDriver{} }
func (c bootstrapKEKReplayConnector) Connect(ctx context.Context) (driver.Conn, error) {
	base, err := (consumerIntegrationConnector{c.state}).Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &bootstrapKEKReplayConn{base.(*consumerIntegrationConn), c}, nil
}

type bootstrapKEKReplayConn struct {
	*consumerIntegrationConn
	config bootstrapKEKReplayConnector
}

func (c *bootstrapKEKReplayConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.HasPrefix(query, "SELECT b.core_json,b.core_sha256,b.binding_sha256,") {
		*c.config.reads++
		if len(args) != 2 || args[0].Value != c.config.installation || args[1].Value != c.config.operation || strings.Contains(query, "FOR UPDATE") || strings.Contains(query, "FOR SHARE") {
			return nil, errors.New("historical scope/lock mismatch")
		}
		rows := &consumerIntegrationRows{columns: []string{"core", "core_sha", "binding_sha", "obs", "obs_sha", "identity", "version", "config"}}
		if c.config.row != nil {
			rows.rows = [][]driver.Value{c.config.row}
		}
		return rows, nil
	}
	return c.consumerIntegrationConn.QueryContext(ctx, query, args)
}

func bootstrapKEKReplayFixtureRow(t *testing.T, f *deploymentCandidateFixtureState, mode string) []driver.Value {
	t.Helper()
	grant := f.deployment.grant
	var pin reg.ReferencePin
	config, err := DecodeBootstrapConfig(f.deployment.raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range config.References() {
		if ref.Purpose == "kek" {
			pin = reg.ReferencePin{IdentityHash: ref.IdentityHash, Version: ref.Version}
		}
	}
	typed := func(raw string) reg.TypedReference {
		return reg.TypedReference{RawJSON: []byte(raw), SHA256: registrationHash(raw)}
	}
	binding := reg.Binding{InstallationID: grant.InstallationID, ConfigRef: pin, Key: wire.KeyBinding{Provider: "external-kms", IdentityHash: pin.IdentityHash, RegistryVersion: pin.Version, ProviderKeyID: "original-key", ProviderVersion: "1"}, Provider: reg.ProviderBinding{Endpoint: "https://original.invalid", KeyName: "original-key", ProviderIdentityHash: strings.Repeat("b", 64), ScopeHash: strings.Repeat("c", 64), CAPEMSHA256: strings.Repeat("d", 64)}, GenerateRef: typed(`{"purpose":"data_key_generation"}`), UnwrapRef: typed(`{"purpose":"kek_unwrap"}`)}
	if mode == "wrong-binding" {
		binding.ConfigRef.Version = "foreign-version"
	}
	observation := reg.AdmissionObservation{InstallationID: grant.InstallationID, ConfigSHA256: grant.ConfigSHA256, SourceRevision: "historical-revision", NotBefore: f.sql.now.Add(-2 * time.Hour), ValidUntil: f.sql.now.Add(-time.Hour)}
	if mode == "wrong-config" {
		observation.ConfigSHA256 = strings.Repeat("f", 64)
	}
	core, _ := json.Marshal(binding)
	semantic := binding
	semantic.GenerateRef.SHA256, semantic.UnwrapRef.SHA256 = "", ""
	semanticRaw, _ := json.Marshal(semantic)
	fingerprint, err := reg.BindingFingerprint(binding)
	if err != nil {
		t.Fatal(err)
	}
	obs, _ := json.Marshal(struct {
		Observation            reg.AdmissionObservation
		GenerateRef, UnwrapRef reg.TypedReference
	}{observation, binding.GenerateRef, binding.UnwrapRef})
	row := []driver.Value{core, registrationHash(string(semanticRaw)), fingerprint, obs, registrationHash(string(obs)), binding.Key.IdentityHash, binding.Key.RegistryVersion, observation.ConfigSHA256}
	if mode == "corrupt-history" {
		row[1] = strings.Repeat("0", 64)
	}
	if mode == "missing-history" {
		return nil
	}
	return row
}

func TestBootstrapKEKSameKeyReplayDoesNotNeedExpiredMaterialOrNewBound(t *testing.T) {
	for _, mode := range []string{"expired-material", "unused-preparation", "missing-history", "corrupt-history", "wrong-binding", "wrong-config", "grant-removed", "rbac-removed"} {
		t.Run(mode, func(t *testing.T) {
			f := newDeploymentCandidateFixture(t)
			first, err := f.deployment.Apply(context.Background())
			if err != nil || first.Replayed {
				t.Fatal("synthetic original bootstrap fixture", err)
			}
			stable := consumerIntegrationClone(f.sql.rows)
			reads, prepares := 0, 0
			row := bootstrapKEKReplayFixtureRow(t, f, mode)
			f.deployment.openDatabase = func() (*sql.DB, error) {
				f.opens++
				return sql.OpenDB(bootstrapKEKReplayConnector{f.sql, f.deployment.grant.InstallationID, first.OperationPublicID, row, &reads}), nil
			}
			f.deployment.kek = &deploymentKEKPreparation{prepare: func(context.Context, *sql.DB, OfflineBootstrapGrant, BootstrapConfig) (reg.PreparedAdmission, error) {
				prepares++
				if mode == "unused-preparation" {
					return &bootstrapEvidenceAdmission{}, nil
				}
				return nil, errors.New("historical material expired")
			}}
			if mode == "grant-removed" {
				if err := os.Remove(f.sql.grantFile); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "rbac-removed" {
				if err := os.Remove(f.sql.registryFiles["rbac_bindings"]); err != nil {
					t.Fatal(err)
				}
			}
			replay, err := f.deployment.Apply(context.Background())
			if mode == "expired-material" || mode == "unused-preparation" {
				if err != nil || !replay.Replayed || replay.OperationPublicID != first.OperationPublicID || reads != 2 || prepares != 1 || f.sql.commits != 2 || f.sql.reserves != 1 {
					t.Fatal("historical KEK read reconsumed/renewed or demanded fresh bound", replay, err, reads, prepares)
				}
			} else if err == nil {
				t.Fatal("unproven/revoked historical KEK accepted", mode)
			}
			if mode == "grant-removed" || mode == "rbac-removed" {
				if reads != 0 || prepares != 0 || f.opens != 1 {
					t.Fatal("revoked current identity reached credentials/provider", reads, prepares, f.opens)
				}
			}
			if !reflect.DeepEqual(stable, f.sql.rows) || f.sql.reserves != 1 {
				t.Fatal("historical retry mutated original rows/reserved again")
			}
		})
	}
}
