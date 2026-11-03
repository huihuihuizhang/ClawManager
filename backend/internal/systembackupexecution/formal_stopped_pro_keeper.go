package systembackupexecution

import (
	b "clawreef/internal/systembackup/publicadapter"
	q "clawreef/internal/systembackup/quiesce"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
)

// Installation-owned transport inputs, contained in the pinned deployment
// configuration. Endpoints and paths are not accepted from a task/API body.
type FormalStoppedProObserverConfig struct {
	CAFile, CASHA256, CertificateFile, CertificateSHA256, KeyFile, KeySHA256 string
	Endpoints                                                                map[string]q.ProofEndpoint
}

func (s *DeploymentService) formalStoppedProObserver() (*q.StoppedProNodeObservationClient, error) {
	if s == nil || s.Config.RuntimeSources == nil || s.Config.RuntimeSources.StoppedProObserver == nil {
		return nil, d.ErrNotReady
	}
	config := s.Config.RuntimeSources.StoppedProObserver
	for _, pin := range []struct{ file, digest string }{{config.CAFile, config.CASHA256}, {config.CertificateFile, config.CertificateSHA256}, {config.KeyFile, config.KeySHA256}} {
		raw, err := pinnedDeploymentFile(pin.file, pin.digest, 262144)
		clear(raw)
		if err != nil {
			return nil, err
		}
	}
	client, err := q.NewStoppedProNodeObservationClient(config.Endpoints, config.CAFile, config.CertificateFile, config.KeyFile)
	if err != nil {
		return nil, err
	}
	// Detect replacement between pin verification and TLS certificate loading.
	for _, pin := range []struct{ file, digest string }{{config.CAFile, config.CASHA256}, {config.CertificateFile, config.CertificateSHA256}, {config.KeyFile, config.KeySHA256}} {
		raw, err := pinnedDeploymentFile(pin.file, pin.digest, 262144)
		clear(raw)
		if err != nil {
			return nil, err
		}
	}
	return client, nil
}

func (s *DeploymentService) formalStoppedProBaseline(ctx context.Context, a d.Authority, source b.InstanceIdentity) (q.StoppedProBaseline, error) {
	var zero q.StoppedProBaseline
	if s == nil || s.Runtime == nil || s.Runtime.Owner == nil || s.captureMaterials == nil || s.captureMaterials.Discovery == nil {
		return zero, d.ErrNotReady
	}
	// Calling the real constructor revalidates all original CA/cert/key pins and
	// exact authenticated endpoint contracts; the controller uses its pinned client.
	if _, err := s.formalStoppedProObserver(); err != nil {
		return zero, err
	}
	material, err := currentStoppedProMaterialFor(s.captureMaterials.Discovery.PersistentMounts, source)
	if err != nil {
		return zero, err
	}
	o := s.Runtime.Owner
	// The current storage projection is read from actual original SQL, not from
	// the signed material alone. No forward grant fallback creates recovery rights.
	read := func(recovery bool) error {
		tx, err := o.Gate.Authority.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
		if err != nil {
			return err
		}
		defer tx.Rollback()
		var recheck func() error
		if recovery {
			if o.Gate.Recovery.CheckTx(ctx, tx, a) != nil {
				return c.ErrExecutionAuthority
			}
			recheck = func() error { return o.Gate.Recovery.CheckTx(ctx, tx, a) }
		} else {
			guard, err := o.Gate.Authority.Bind(ctx, tx, a)
			if err != nil {
				return err
			}
			recheck = func() error { return guard.Recheck(ctx, tx) }
		}
		actual, err := readCurrentStoppedProSQLStorage(ctx, tx, []b.InstanceIdentity{source})
		if err != nil {
			return err
		}
		var expected currentStoppedProSQLStorage
		for _, mount := range material.Layout.Mounts {
			if mount.MountID == "workspace" {
				expected = currentStoppedProSQLStorage{Claim: mount.Claim, MountPath: mount.MountPath}
			}
		}
		if !reflect.DeepEqual(actual[source.ID], expected) {
			return d.ErrNotReady
		}
		if err := recheck(); err != nil {
			return err
		}
		return tx.Rollback()
	}
	// Choose the authority from its actual SQL state; failure of the forward
	// check is followed by the independent full recovery check, never a bypass.
	if o.Gate.Authority.Check(ctx, a) == nil {
		err = read(false)
	} else {
		err = read(true)
	}
	if err != nil || recheckCurrentStoppedProMaterial(ctx, o.Client, s.Config, *material) != nil {
		return zero, d.ErrNotReady
	}
	return material.Baseline, nil
}

func (s *DeploymentService) observeFormalStoppedProRecovery(ctx context.Context, in d.Input, writer b.FrozenWriter, runtime c.SourceRecoveryRuntime) (json.RawMessage, error) {
	if runtime.Spec.Kind != "stopped" || runtime.Spec.Source.Mode != "pro" || writer.Original != runtime.Spec.Stopped {
		return nil, c.ErrSourceRecoveryStoppedWitnessRequired
	}
	material, err := currentStoppedProMaterialFor(s.captureMaterials.Discovery.PersistentMounts, runtime.Spec.Source)
	if err != nil || recheckCurrentStoppedProMaterial(ctx, s.Runtime.Owner.Client, s.Config, *material) != nil {
		return nil, c.ErrSourceRecoveryStoppedWitnessRequired
	}
	// Fresh native observation is performed by the concrete controller; source
	// material and SQL row data are not themselves positive native witnesses.
	record, err := s.RuntimeControl.ObserveStoppedProSourceRecovery(ctx, in.Authority, writer)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Version, Kind string
		Runtime       c.SourceRecoveryRuntime
		Material      CurrentStoppedProSourceMaterial
		Native        c.RuntimeStoppedProRecord
	}{"source-recovery-current-stopped-pro.v1", "stopped", runtime, *material, record})
}
