package systembackupexecution

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"path/filepath"
	"reflect"
	"time"

	d "clawreef/internal/systembackupdispatch"
	owner "clawreef/internal/systembackupinstallationowner"
	"clawreef/internal/systembackupinstallationowner/install"
	reg "clawreef/internal/systembackupkekregistry"
)

// A separately observed read service, never a cold/stopped business writer.
// The full provider references remain in the signed deployment and frozen
// source metadata. A public request cannot supply these selections or pins.
type FormalVaultProviderDependency struct {
	Version  string                                 `json:"schema_version"`
	Workload install.VaultProviderWorkloadSelection `json:"workload"`
	Observer install.BootstrapSourceFilePin         `json:"observer"`
}

type formalVaultProviderFacts struct {
	Version       string
	Selection     FormalVaultProviderDependency
	Scope         install.VaultProviderScopeData
	Native        owner.InstalledVaultDependencyData
	BindingSHA256 string
}

func validateFormalVaultDependencies(cfg DeploymentConfig) error {
	if len(cfg.ProviderDependencies) > 1 {
		return d.ErrNotReady
	}
	for _, p := range cfg.ProviderDependencies {
		w := p.Workload
		if p.Version != "formal-vault-provider-dependency.v1" || w.Deployment == "" || w.DeploymentUID == "" || w.Container == "" || w.ImageID == "" || w.Service == "" || w.ServiceUID == "" || w.Claim == "" || w.ClaimUID == "" || w.DataMountPath == "" || !filepath.IsAbs(p.Observer.File) || filepath.Clean(p.Observer.File) != p.Observer.File || len(p.Observer.SHA256) != 64 || w.Claim == cfg.Workspace.Claim || w.Claim == cfg.StagingClaim {
			return d.ErrNotReady
		}
		for _, writer := range cfg.Writers {
			if writer.Name == w.Deployment || writer.UID == w.DeploymentUID {
				return d.ErrNotReady
			}
		}
		if cfg.RuntimeSources != nil {
			for _, writer := range cfg.RuntimeSources.Deployments {
				if writer.Name == w.Deployment || writer.UID == w.DeploymentUID {
					return d.ErrNotReady
				}
			}
		}
		if cfg.CaptureScope != "six-part" || cfg.FormalVerifier == nil {
			return d.ErrNotReady
		}
	}
	return nil
}

func readFormalVaultObserver(pin install.BootstrapSourceFilePin) (owner.InstalledVaultDependencyConfig, error) {
	var cfg owner.InstalledVaultDependencyConfig
	raw, e := pinnedDeploymentFile(pin.File, pin.SHA256, 262144)
	if e != nil {
		return cfg, d.ErrNotReady
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&cfg) != nil || dec.Decode(new(any)) != io.EOF || cfg.IdentityMode != "metadata-only" || cfg.TransitMount != "transit" {
		return cfg, d.ErrNotReady
	}
	return cfg, nil
}

// The genuine SQL task/recovery gate surrounds all concrete native reads.
// The observer confers no Generate/Unwrap/sign permission and cannot fabricate
// an Installer, private original hold, task, coverage or source-recovery proof.
func (s *DeploymentService) observeFormalVaultDependencies(ctx context.Context, o *PublicJobOwner, in d.Input, recovery bool) ([]formalVaultProviderFacts, error) {
	if s == nil || o == nil || ctx == nil || ctx.Err() != nil || validateFormalVaultDependencies(s.Config) != nil {
		return nil, d.ErrNotReady
	}
	if len(s.Config.ProviderDependencies) == 0 {
		return nil, nil
	}
	if s.Source == nil || o.Client == nil || o.Gate.Authority.DB == nil || s.formalVerifier == nil {
		return nil, d.ErrNotReady
	}
	guard := func() error {
		if recovery {
			return o.Gate.Recovery.Check(ctx, in.Authority)
		}
		return o.Gate.Check(ctx, in.Authority)
	}
	if guard() != nil || s.checkSourceIdentity(ctx, s.Source) != nil {
		return nil, d.ErrNotReady
	}
	binding := s.formalVerifier.Binding
	if binding.InstallationID != s.Config.InstallationID {
		return nil, d.ErrNotReady
	}
	bindingSHA, e := reg.BindingFingerprint(binding)
	if e != nil {
		return nil, d.ErrNotReady
	}
	currentBinding := func() error {
		if guard() != nil {
			return d.ErrNotReady
		}
		tx, e := o.Gate.Authority.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted, ReadOnly: true})
		if e != nil {
			return d.ErrNotReady
		}
		defer tx.Rollback()
		facts, e := (&reg.SQLStore{}).ReadBindingTx(ctx, tx, s.Config.InstallationID, binding.ConfigRef)
		// A revoked crypto purpose never becomes usable through this metadata read.
		// Recovery still needs a live service for the independent source-resume path.
		if e != nil || facts.RowVersion == 0 || facts.BindingSHA256 != bindingSHA || !reg.SameSecurityBinding(facts.Binding, binding) || !recovery && (facts.GenerateRevoked != nil || facts.UnwrapRevoked != nil) {
			return d.ErrNotReady
		}
		if tx.Commit() != nil {
			return d.ErrNotReady
		}
		return guard()
	}
	if currentBinding() != nil {
		return nil, d.ErrNotReady
	}
	out := make([]formalVaultProviderFacts, 0, len(s.Config.ProviderDependencies))
	for _, selected := range s.Config.ProviderDependencies {
		cfg, e := readFormalVaultObserver(selected.Observer)
		if e != nil || cfg.Endpoint != binding.Provider.Endpoint || cfg.CASHA256 != binding.Provider.CAPEMSHA256 || cfg.PinnedKeyName != binding.Provider.KeyName || cfg.PinnedKeyVersion != binding.Key.ProviderVersion {
			return nil, d.ErrNotReady
		}
		observer, e := owner.NewInstalledVaultDependencyObserver(cfg, o.Client, s.Config.Namespace, s.Config.NamespaceUID)
		if e != nil {
			return nil, d.ErrNotReady
		}
		// Close after this individual bounded observation, including every failure.
		facts, e := func() (formalVaultProviderFacts, error) {
			defer observer.Close()
			target := owner.Target{InstallationID: s.Config.InstallationID, Namespace: s.Config.Namespace, NamespaceUID: s.Config.NamespaceUID}
			scope, e := install.ObserveInstalledVaultProviderScope(ctx, s.Source, o.Client, target, selected.Workload, cfg.Endpoint)
			if e != nil || guard() != nil {
				return formalVaultProviderFacts{}, d.ErrNotReady
			}
			proof, e := observer.Observe(ctx)
			if e != nil {
				return formalVaultProviderFacts{}, d.ErrNotReady
			}
			native, until, e := proof.Data(ctx)
			if e != nil || !time.Now().Before(until) {
				return formalVaultProviderFacts{}, d.ErrNotReady
			}
			repeated, e := install.ObserveInstalledVaultProviderScope(ctx, s.Source, o.Client, target, selected.Workload, cfg.Endpoint)
			again, e2 := readFormalVaultObserver(selected.Observer)
			if e != nil || e2 != nil || !reflect.DeepEqual(cfg, again) || !reflect.DeepEqual(scope, repeated) || proof.Recheck(ctx, time.Now().UTC()) != nil || currentBinding() != nil || proof.Recheck(ctx, time.Now().UTC()) != nil {
				return formalVaultProviderFacts{}, d.ErrNotReady
			}
			return formalVaultProviderFacts{Version: "formal-vault-provider-source-facts.v1", Selection: selected, Scope: scope, Native: native, BindingSHA256: bindingSHA}, nil
		}()
		if e != nil {
			return nil, e
		}
		out = append(out, facts)
	}
	if guard() != nil {
		return nil, d.ErrNotReady
	}
	return out, nil
}

// The original source-registry producer AND its enrolled consumer independently
// repeat the same dependency before/after their full SQL/Kube/native census.
// This pre-signing path does not require a future A2 binding/task or invent one.
func (x *bootstrapSourceRegistryReader) observeBootstrapVaultDependencies(clients *productionMetadataClients) ([]formalVaultProviderFacts, error) {
	if x == nil || x.access == nil || clients == nil || clients.API == nil || validateFormalVaultDependencies(x.config) != nil || x.checkPhysical(x.physical) != nil {
		return nil, install.ErrInstall
	}
	if len(x.config.ProviderDependencies) == 0 {
		return nil, nil
	}
	binding, e := x.connection("source_sql")
	if e != nil {
		return nil, install.ErrInstall
	}
	db, verified, e := openBootstrapSourceSQL(x.ctx, x.access, binding)
	if e != nil {
		return nil, install.ErrInstall
	}
	defer db.Close()
	floor := time.Time{}
	if x.checkSQLIdentity(x.physical, db, binding, verified, &floor) != nil {
		return nil, install.ErrInstall
	}
	out := make([]formalVaultProviderFacts, 0, len(x.config.ProviderDependencies))
	for _, selected := range x.config.ProviderDependencies {
		cfg, e := readFormalVaultObserver(selected.Observer)
		if e != nil {
			return nil, install.ErrInstall
		}
		o, e := owner.NewInstalledVaultDependencyObserver(cfg, clients.API, x.config.Namespace, x.config.NamespaceUID)
		if e != nil {
			return nil, install.ErrInstall
		}
		actual, e := func() (formalVaultProviderFacts, error) {
			defer o.Close()
			scope, e := install.ObserveInstalledVaultProviderScope(x.physical, db, clients.API, x.association.Target, selected.Workload, cfg.Endpoint)
			if e != nil || x.checkPhysical(x.physical) != nil {
				return formalVaultProviderFacts{}, install.ErrInstall
			}
			proof, e := o.Observe(x.physical)
			if e != nil {
				return formalVaultProviderFacts{}, install.ErrInstall
			}
			native, _, e := proof.Data(x.physical)
			if e != nil {
				return formalVaultProviderFacts{}, install.ErrInstall
			}
			repeated, e := install.ObserveInstalledVaultProviderScope(x.physical, db, clients.API, x.association.Target, selected.Workload, cfg.Endpoint)
			again, e2 := readFormalVaultObserver(selected.Observer)
			if e != nil || e2 != nil || !reflect.DeepEqual(scope, repeated) || !reflect.DeepEqual(cfg, again) || proof.Recheck(x.physical, time.Now().UTC()) != nil || x.checkPhysical(x.physical) != nil {
				return formalVaultProviderFacts{}, install.ErrInstall
			}
			return formalVaultProviderFacts{Version: "formal-vault-provider-source-facts.v1", Selection: selected, Scope: scope, Native: native}, nil
		}()
		if e != nil {
			return nil, e
		}
		out = append(out, actual)
	}
	if x.checkSQLIdentity(x.physical, db, binding, verified, &floor) != nil || x.checkPhysical(x.physical) != nil {
		return nil, install.ErrInstall
	}
	return out, nil
}

// Readiness's genuine signed source-owner delegation repeats the actual
// dependency; it cannot borrow a task grant or manufacture a bootstrap reader.
func (x *sourceSQLObservation) observeSourceVaultDependencies(ctx context.Context) ([]formalVaultProviderFacts, error) {
	if x == nil || x.delegation == nil || x.delegation.service == nil || x.delegation.owner == nil || x.source == nil || x.control == nil || x.recheck(ctx) != nil {
		return nil, ErrSourceWriterObservationIncomplete
	}
	s, o := x.delegation.service, x.delegation.owner
	if len(s.Config.ProviderDependencies) == 0 {
		return nil, nil
	}
	if validateFormalVaultDependencies(s.Config) != nil || s.formalVerifier == nil {
		return nil, ErrSourceWriterObservationIncomplete
	}
	binding := s.formalVerifier.Binding
	bindingSHA, e := reg.BindingFingerprint(binding)
	if e != nil || binding.InstallationID != s.Config.InstallationID {
		return nil, ErrSourceWriterObservationIncomplete
	}
	checkBinding := func() error {
		if x.recheck(ctx) != nil {
			return ErrSourceWriterObservationIncomplete
		}
		tx, e := x.control.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted, ReadOnly: true})
		if e != nil {
			return ErrSourceWriterObservationIncomplete
		}
		defer tx.Rollback()
		facts, e := (&reg.SQLStore{}).ReadBindingTx(ctx, tx, s.Config.InstallationID, binding.ConfigRef)
		if e != nil || facts.RowVersion == 0 || facts.BindingSHA256 != bindingSHA || !reg.SameSecurityBinding(facts.Binding, binding) || facts.GenerateRevoked != nil || facts.UnwrapRevoked != nil || tx.Commit() != nil {
			return ErrSourceWriterObservationIncomplete
		}
		return x.recheck(ctx)
	}
	if checkBinding() != nil {
		return nil, ErrSourceWriterObservationIncomplete
	}
	out := make([]formalVaultProviderFacts, 0, len(s.Config.ProviderDependencies))
	for _, selected := range s.Config.ProviderDependencies {
		cfg, e := readFormalVaultObserver(selected.Observer)
		if e != nil || cfg.Endpoint != binding.Provider.Endpoint || cfg.CASHA256 != binding.Provider.CAPEMSHA256 || cfg.PinnedKeyName != binding.Provider.KeyName || cfg.PinnedKeyVersion != binding.Key.ProviderVersion {
			return nil, ErrSourceWriterObservationIncomplete
		}
		observer, e := owner.NewInstalledVaultDependencyObserver(cfg, o.Client, s.Config.Namespace, s.Config.NamespaceUID)
		if e != nil {
			return nil, ErrSourceWriterObservationIncomplete
		}
		actual, e := func() (formalVaultProviderFacts, error) {
			defer observer.Close()
			target := owner.Target{InstallationID: s.Config.InstallationID, Namespace: s.Config.Namespace, NamespaceUID: s.Config.NamespaceUID}
			scope, e := install.ObserveInstalledVaultProviderScope(ctx, x.source, o.Client, target, selected.Workload, cfg.Endpoint)
			if e != nil || x.recheck(ctx) != nil {
				return formalVaultProviderFacts{}, ErrSourceWriterObservationIncomplete
			}
			proof, e := observer.Observe(ctx)
			if e != nil {
				return formalVaultProviderFacts{}, ErrSourceWriterObservationIncomplete
			}
			native, _, e := proof.Data(ctx)
			if e != nil {
				return formalVaultProviderFacts{}, ErrSourceWriterObservationIncomplete
			}
			repeated, e := install.ObserveInstalledVaultProviderScope(ctx, x.source, o.Client, target, selected.Workload, cfg.Endpoint)
			again, e2 := readFormalVaultObserver(selected.Observer)
			if e != nil || e2 != nil || !reflect.DeepEqual(scope, repeated) || !reflect.DeepEqual(cfg, again) || checkBinding() != nil || proof.Recheck(ctx, time.Now().UTC()) != nil {
				return formalVaultProviderFacts{}, ErrSourceWriterObservationIncomplete
			}
			return formalVaultProviderFacts{Version: "formal-vault-provider-source-facts.v1", Selection: selected, Scope: scope, Native: native, BindingSHA256: bindingSHA}, nil
		}()
		if e != nil {
			return nil, e
		}
		out = append(out, actual)
	}
	if x.recheck(ctx) != nil {
		return nil, ErrSourceWriterObservationIncomplete
	}
	return out, nil
}
