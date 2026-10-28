package systembackupsecurity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	pd "clawreef/internal/systembackupproducer"
)

// Real deployment loader, fixed-file authority, A attempt and D consumer;
// only the independent original authority and SQL/provider facts are synthetic.
type deploymentCandidateAuthority struct {
	original     BootstrapCandidateAuthority
	prepares     int
	preparedCtx  context.Context
	afterPrepare func() error
}

func (a *deploymentCandidateAuthority) PrepareBootstrapCandidates(ctx context.Context, g OfflineBootstrapGrant, c BootstrapConfig, r pd.BootstrapConsumptionRequest) (PreparedBootstrapCandidateAuthority, error) {
	a.prepares++
	a.preparedCtx = ctx
	p, err := a.original.PrepareBootstrapCandidates(ctx, g, c, r)
	if err == nil && a.afterPrepare != nil {
		err = a.afterPrepare()
	}
	return p, err
}

type deploymentCandidateFixtureState struct {
	deployment *BootstrapDeployment
	factory    *BootstrapDeploymentCandidates
	authority  *deploymentCandidateAuthority
	sql        *consumerIntegrationState
	opens      int
	databases  []*sql.DB
}

func newDeploymentCandidateFixture(t *testing.T) *deploymentCandidateFixtureState {
	t.Helper()
	svc, g, raw, state := consumerIntegrationFixture(t)
	original := svc.Candidates.authority.(*bootstrapCandidateFileAuthority)
	authority := &deploymentCandidateAuthority{original: original.snapshot.original}
	factory, err := NewBootstrapDeploymentCandidates(svc.Candidates.request.Candidates, authority)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	grantRaw, err := os.ReadFile(state.grantFile)
	if err != nil {
		t.Fatal(err)
	}
	// This fixture's producer facts use a fixed SQL clock. Create the NEW
	// synthetic bootstrap grant before any Prepare, covering that clock and
	// the loader's real wall clock. Never refresh the committed observation.
	var grantFile BootstrapGrantFile
	if err = json.Unmarshal(grantRaw, &grantFile); err != nil {
		t.Fatal(err)
	}
	wall := time.Now().UTC()
	grantFile.NotBefore, grantFile.ExpiresAt = state.now.Add(-time.Hour), state.now.Add(48*time.Hour)
	if start := wall.Add(-time.Hour); start.Before(grantFile.NotBefore) {
		grantFile.NotBefore = start
	}
	if end := wall.Add(48 * time.Hour); end.After(grantFile.ExpiresAt) {
		grantFile.ExpiresAt = end
	}
	grantRaw, err = json.Marshal(grantFile)
	if err != nil {
		t.Fatal(err)
	}
	writeDeploymentFile(t, state.grantFile, grantRaw)
	profile := BootstrapDeploymentConfig{SchemaVersion: "system-backup-bootstrap-deployment.v1", InstallationID: g.InstallationID,
		ExpectedServerUUID: g.ServerUUID, ExpectedDatabase: g.Database, ConfigFile: filepath.Join(dir, "config.json"), ConfigSHA256: g.ConfigSHA256,
		GrantFile: state.grantFile, GrantSHA256: registrationHash(string(grantRaw)), RegistryDirectory: original.profile.registryDirectory,
		NonceDirectory: filepath.Join(dir, "nonce"), CapacityReportFile: state.reportFile, DSNFile: filepath.Join(dir, "dsn")}
	writeDeploymentFile(t, profile.ConfigFile, raw)
	deploymentPath := filepath.Join(dir, "deployment.json")
	profileRaw, _ := json.Marshal(profile)
	writeDeploymentFile(t, deploymentPath, profileRaw)
	poison := &admissionTestValidator{prepare: func(context.Context, OfflineBootstrapGrant, BootstrapConfig) (BootstrapResourceCheck, error) {
		t.Fatal("candidate Apply repeated legacy owner preparation")
		return nil, nil
	}}
	owners := BootstrapOwnerAdapters{Registries: map[string]BootstrapResourceValidator{}, References: map[string]BootstrapResourceValidator{}, CrossResources: poison, Candidates: factory}
	for _, kind := range bootstrapRegistryKinds {
		owners.Registries[kind] = poison
	}
	for _, purpose := range bootstrapReferencePurposes {
		owners.References[purpose] = poison
	}
	d, err := LoadBootstrapDeployment(deploymentPath, registrationHash(string(profileRaw)), owners)
	if err != nil {
		t.Fatal(err)
	}
	f := &deploymentCandidateFixtureState{deployment: d, factory: factory, authority: authority, sql: state}
	d.openDatabase = func() (*sql.DB, error) {
		f.opens++
		if authority.prepares != f.opens || authority.preparedCtx == nil || authority.preparedCtx.Err() != nil {
			t.Fatal("DB preceded original preparation or replaced context")
		}
		db := sql.OpenDB(consumerIntegrationConnector{state})
		f.databases = append(f.databases, db)
		return db, nil
	}
	return f
}

func TestBootstrapDeploymentCandidatesImmutableComposition(t *testing.T) {
	f := newDeploymentCandidateFixture(t)
	before := detachedDeploymentSelections(t, f.factory.state.selections)
	input := detachedDeploymentSelections(t, before)
	created, err := NewBootstrapDeploymentCandidates(input, f.authority)
	if err != nil {
		t.Fatal(err)
	}
	input[0].Request.Admission.Unconfigured.PolicyHash = pd.Hash(strings.Repeat("e", 64))
	if !reflect.DeepEqual(created.state.selections, before) {
		t.Fatal("caller changed captured selection")
	}
	*f.factory = BootstrapDeploymentCandidates{}
	if !f.deployment.candidates.valid() {
		t.Fatal("caller replaced loaded deployment factory")
	}
	for _, value := range []any{created, *created} {
		if fmt.Sprintf("%v %#v", value, value) != "BootstrapDeploymentCandidates BootstrapDeploymentCandidates" {
			t.Fatal("composition leaked")
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrRegistrationUnavailable) {
			t.Fatal("composition serialized", err)
		}
	}
	var zero BootstrapDeploymentCandidates
	if json.Unmarshal([]byte(`{}`), &zero) == nil || zero.valid() {
		t.Fatal("JSON minted composition")
	}
	for _, selection := range [][]pd.BootstrapCandidateSelection{nil, make([]pd.BootstrapCandidateSelection, 21), {{}}} {
		if _, err := NewBootstrapDeploymentCandidates(selection, f.authority); err == nil {
			t.Fatal("invalid selection captured")
		}
	}
	if _, err := NewBootstrapDeploymentCandidates(before, nil); err == nil {
		t.Fatal("missing original authority accepted")
	}
	if f.opens != 0 || f.authority.prepares != 0 {
		t.Fatal("composition performed work")
	}
}

func detachedDeploymentSelections(t *testing.T, in []pd.BootstrapCandidateSelection) []pd.BootstrapCandidateSelection {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out []pd.BootstrapCandidateSelection
	if json.Unmarshal(raw, &out) != nil {
		t.Fatal("selection copy")
	}
	return out
}

func TestBootstrapDeploymentCandidatesApplyConsumerAndHistoricalRetry(t *testing.T) {
	for _, mode := range []string{"normal", "commit_unknown", "late_rollback", "replay_missing_non_rbac", "replay_grant_removed", "replay_rbac_removed"} {
		t.Run(mode, func(t *testing.T) {
			f := newDeploymentCandidateFixture(t)
			before := consumerIntegrationClone(f.sql.rows)
			f.sql.late = mode == "late_rollback"
			f.sql.bridge.base.commitUnknown = mode == "commit_unknown"
			first, err := f.deployment.Apply(context.Background())
			if mode == "late_rollback" {
				if err == nil || first != (ConfigBootstrapResult{}) || f.sql.commits != 0 || f.sql.reserves != 0 || !reflect.DeepEqual(before, f.sql.rows) {
					t.Fatal("deployment bypassed shared rollback", first, err)
				}
				return
			}
			if mode == "commit_unknown" {
				if !errors.Is(err, ErrRegistrationCommitUnknown) || first != (ConfigBootstrapResult{}) {
					t.Fatal("unknown commit reported success", first, err)
				}
			} else if err != nil || first.Version != 1 || first.Replayed {
				t.Fatal("deployment did not enter real consumer", first, err)
			}
			if f.opens != 1 || f.authority.prepares != 1 || f.sql.commits != 1 || f.sql.reserves != 1 {
				t.Fatal("duplicate prepare/commit/reservation")
			}
			if f.databases[0].PingContext(context.Background()) == nil {
				t.Fatal("attempt leaked DB ownership")
			}
			stable := consumerIntegrationClone(f.sql.rows)
			switch mode {
			case "replay_missing_non_rbac":
				err = os.Remove(f.sql.nonRBACFile)
			case "replay_grant_removed":
				err = os.Remove(f.sql.grantFile)
			case "replay_rbac_removed":
				err = os.Remove(f.sql.registryFiles["rbac_bindings"])
			}
			if err != nil && mode != "commit_unknown" {
				t.Fatal(err)
			}
			f.sql.bridge.base.commitUnknown = false
			replay, err := f.deployment.Apply(context.Background())
			if mode == "replay_grant_removed" || mode == "replay_rbac_removed" {
				if err == nil || replay != (ConfigBootstrapResult{}) || f.opens != 1 || f.authority.prepares != 1 {
					t.Fatal("revoked source reached credentials", replay, err)
				}
				return
			}
			if err != nil || !replay.Replayed || replay.Version != 1 || f.sql.commits != 2 || f.sql.reserves != 1 || !reflect.DeepEqual(stable, f.sql.rows) {
				t.Fatal("deployment historical retry consumed again", replay, err)
			}
			if mode != "commit_unknown" && replay.OperationPublicID != first.OperationPublicID {
				t.Fatal("replay changed operation")
			}
			if f.opens != 2 || f.authority.prepares != 2 || f.databases[1].PingContext(context.Background()) == nil {
				t.Fatal("retry renewed preparation or leaked DB")
			}
		})
	}
}

func TestBootstrapDeploymentCandidatesPreparationAndLateFilesBeforeCredentials(t *testing.T) {
	for _, mode := range []string{"prepare_error", "grant_removed", "rbac_removed", "non_rbac_removed", "canceled", "missing_owner", "typed_nil_owner"} {
		t.Run(mode, func(t *testing.T) {
			f := newDeploymentCandidateFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			before := consumerIntegrationClone(f.sql.rows)
			f.authority.afterPrepare = func() error {
				switch mode {
				case "prepare_error":
					return errors.New("PRIVATE preparation diagnostic")
				case "grant_removed":
					return os.Remove(f.sql.grantFile)
				case "rbac_removed":
					return os.Remove(f.sql.registryFiles["rbac_bindings"])
				case "non_rbac_removed":
					return os.Remove(f.sql.nonRBACFile)
				case "canceled":
					cancel()
				}
				return nil
			}
			if mode == "missing_owner" {
				delete(f.deployment.sources.References, bootstrapReferencePurposes[0])
			}
			if mode == "typed_nil_owner" {
				var empty *admissionTestValidator
				f.deployment.sources.References[bootstrapReferencePurposes[0]] = empty
			}
			out, err := f.deployment.Apply(ctx)
			if err == nil || out != (ConfigBootstrapResult{}) || strings.Contains(err.Error(), "PRIVATE") || f.sql.commits != 0 || f.sql.reserves != 0 || !reflect.DeepEqual(before, f.sql.rows) {
				t.Fatal("invalid preparation escaped", mode, out, err)
			}
			if mode == "non_rbac_removed" {
				if f.opens != 1 {
					t.Fatal("physical failure wrongly bypassed L3 branch decision", f.opens)
				}
			} else if f.opens != 0 {
				t.Fatal("unsafe pre-credential source failure opened DB", mode)
			}
		})
	}
}
