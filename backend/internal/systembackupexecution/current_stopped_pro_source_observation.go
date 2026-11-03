package systembackupexecution

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	b "clawreef/internal/systembackup/publicadapter"
	d "clawreef/internal/systembackupdispatch"
)

// ObserveCurrentStoppedProSourceMaterials repeats the authenticated production
// SQL and native metadata reads. It returns comparison DATA only; D must still
// acquire and continuously retain its own gate/keeper and P7 opaque proof.
func (s *DeploymentService) ObserveCurrentStoppedProSourceMaterials(ctx context.Context) ([]CurrentStoppedProSourceMaterial, error) {
	x, err := s.newSourceSQLObservation(ctx)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithDeadline(ctx, x.delegation.until)
	defer cancel()
	first, err := x.observeInventory(ctx)
	if err != nil {
		return nil, err
	}
	if s.captureMaterials == nil || s.captureMaterials.Discovery == nil {
		return nil, d.ErrNotReady
	}
	scope := s.captureMaterials.Discovery.PersistentMounts
	if _, err := persistentMountsForInstances(scope, first.source.Instances); err != nil {
		return nil, err
	}
	if err := checkCurrentStoppedProSQL(scope, first.sql.metadata, first.source.Instances); err != nil {
		return nil, err
	}
	read := func() ([]CurrentStoppedProSourceMaterial, error) {
		out := []CurrentStoppedProSourceMaterial{}
		for _, instance := range first.source.Instances {
			if !isCurrentStoppedPro(instance) {
				continue
			}
			m, err := currentStoppedProMaterialFor(scope, instance)
			if err != nil {
				return nil, err
			}
			actual, err := observeCurrentStoppedPro(ctx, x.delegation.owner.Client, s.Config, instance, first.sql.metadata.CurrentStoppedProStorage[instance.ID])
			if err != nil || !reflect.DeepEqual(actual, *m) || x.recheck(ctx) != nil {
				return nil, d.ErrNotReady
			}
			out = append(out, actual)
		}
		return out, nil
	}
	out, err := read()
	if err != nil {
		return nil, err
	}
	last, err := read()
	if err != nil || !reflect.DeepEqual(out, last) {
		return nil, d.ErrNotReady
	}
	final, err := x.observeInventory(ctx)
	if err != nil || final.sha256 != first.sha256 || !reflect.DeepEqual(final.sql.metadata, first.sql.metadata) || x.recheck(ctx) != nil || !time.Now().Before(x.delegation.until) {
		return nil, d.ErrNotReady
	}
	// A detached projection cannot mutate the service's signed scope.
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, d.ErrNotReady
	}
	var detached []CurrentStoppedProSourceMaterial
	if json.Unmarshal(raw, &detached) != nil {
		return nil, d.ErrNotReady
	}
	return detached, nil
}

func currentStoppedProDiagnostic(instance b.InstanceIdentity, m CurrentStoppedProSourceMaterial) InstanceMountObservation {
	copy := m
	return InstanceMountObservation{InstanceID: instance.ID, UserID: instance.UserID, Generation: instance.Generation, Type: instance.Type, Status: instance.Status, Workspace: instance.Workspace, Namespace: instance.Namespace, CurrentStoppedPro: &copy, Issues: []InstanceMountInputIssue{}, Mounts: []InstanceMountObservationEntry{}}
}
