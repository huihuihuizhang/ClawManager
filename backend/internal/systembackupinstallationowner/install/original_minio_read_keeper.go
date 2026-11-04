package install

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	sb "clawreef/internal/systembackup"
	c "clawreef/internal/systembackupcontroller"
)

type OriginalMinIOReadKeeperSelection struct {
	Deployment, DeploymentUID string
	Materials                 BootstrapSourceFilePin
	OutputAccounts            []string
}
type originalMinIOReadKeeper struct {
	set             *PreparedOriginalWriterSet
	writer          *originalDeploymentMaintenance
	selection       OriginalMinIOReadKeeperSelection
	gate            *sb.MinIOReadServiceGate
	held, recovered *sb.VerifiedMinIOReadServiceObservation
}

func (r *originalMinIOReadKeeper) check(ctx context.Context) error {
	if r == nil || r.set == nil || r.writer == nil || r.writer.minio != r || r.writer.owner != r.set.owner || originalMaintenanceReadCheck(ctx, r.set.owner, r.writer.recovery) != nil {
		return ErrInstall
	}
	if r.writer.recovery == nil && r.set.used {
		if r.set.owner.checkCurrentGate(ctx, c.GateAcquiring, c.GateHeld) != nil || r.set.checkApplicationGate(ctx, "acquiring", "held") != nil {
			return ErrInstall
		}
	}
	raw, e := readBootstrapSourcePin(r.selection.Materials, 262144)
	clear(raw)
	if e != nil {
		return ErrInstall
	}
	d, e := r.writer.current(ctx)
	if e != nil || d.Generation != r.writer.original.Generation || *d.Spec.Replicas != r.writer.replicas || d.Status.ReadyReplicas != r.writer.replicas || d.Status.ObservedGeneration < d.Generation {
		return ErrInstall
	}
	pods, e := r.writer.currentPods(ctx, d, true)
	if e != nil || !reflect.DeepEqual(pods, r.writer.pods) {
		return ErrInstall
	}
	return originalMaintenanceReadCheck(ctx, r.set.owner, r.writer.recovery)
}
func (s *PreparedOriginalWriterSet) prepareMinIOReadKeeper(ctx context.Context, w *originalDeploymentMaintenance, selection OriginalMinIOReadKeeperSelection) error {
	if s == nil || w == nil || w.minio != nil || w.redis != nil || selection.Deployment != w.selection.Name || selection.DeploymentUID != w.selection.UID || w.replicas != 1 || len(w.pods) != 1 {
		return ErrInstall
	}
	raw, e := readBootstrapSourcePin(selection.Materials, 262144)
	var projection struct {
		Version string
		Native  sb.MinIOReadGateInput
	}
	if e != nil || json.Unmarshal(raw, &projection) != nil || projection.Version != "original-minio-source-read-materials.v1" && projection.Version != "original-minio-source-read-identities.v2" || projection.Native.Namespace != w.namespace || projection.Native.NamespaceUID != s.initial.NamespaceUID || projection.Native.Pod != w.pods[0].Name || projection.Native.PodUID != w.pods[0].UID || projection.Native.Operation != "" || projection.Native.InventorySHA256 != "" {
		return ErrInstall
	}
	r := &originalMinIOReadKeeper{set: s, writer: w, selection: selection}
	w.minio = r
	r.gate, e = sb.PrepareMinIOReadServiceGateFromMaterials(ctx, s.owner.operator.installer.kube, selection.Materials.File, selection.Materials.SHA256, s.owner.operation, s.inventorySHA, selection.OutputAccounts, r.check)
	if e != nil {
		return e
	}
	checkpoint, e := json.Marshal(struct{ Version, DeploymentCheckpoint, OriginalNativeSHA256 string }{"original-deployment-native-minio-checkpoint.v1", w.original.Checkpoint, r.gate.OriginalDigest()})
	if e != nil {
		return ErrInstall
	}
	w.original.Checkpoint = string(checkpoint)
	return r.check(ctx)
}
func (r *originalMinIOReadKeeper) acquire(ctx context.Context) error {
	w := r.writer
	if w.stopDispatched || r.check(ctx) != nil || w.journal.append(ctx, w.ID(), "minio_native_gate_send_unknown", &w.original, r.selection) != nil {
		return ErrInstall
	}
	w.stopDispatched = true
	if r.gate.Acquire(ctx) != nil {
		return ErrInstall
	}
	return r.observeHeld(ctx)
}
func (r *originalMinIOReadKeeper) observeHeld(ctx context.Context) error {
	if r.check(ctx) != nil {
		return ErrInstall
	}
	proof, e := r.gate.ObserveHeld(ctx)
	if e != nil {
		return e
	}
	r.held = proof
	return nil
}
func (r *originalMinIOReadKeeper) restore(ctx context.Context, fence *originalWriterRecoveryFence) error {
	if fence == nil || fence.owner != r.set.owner || fence.checkReleasing(ctx) != nil {
		return ErrInstall
	}
	r.writer.recovery = fence
	if r.writer.journal.append(ctx, r.writer.ID(), "minio_native_restore_send_unknown", &r.writer.original, nil) != nil {
		return ErrInstall
	}
	if sb.RestoreMinIOReadServiceGateFromMaterials(ctx, r.gate, r.selection.Materials.File, r.selection.Materials.SHA256, r.set.owner.operation, r.set.inventorySHA, r.selection.OutputAccounts, r.check) != nil {
		return ErrInstall
	}
	return r.observeRecovered(ctx)
}
func (r *originalMinIOReadKeeper) observeRecovered(ctx context.Context) error {
	if r.check(ctx) != nil {
		return ErrInstall
	}
	if !r.writer.stopDispatched {
		if sb.RestoreMinIOReadServiceGateFromMaterials(ctx, r.gate, r.selection.Materials.File, r.selection.Materials.SHA256, r.set.owner.operation, r.set.inventorySHA, r.selection.OutputAccounts, r.check) != nil {
			return ErrInstall
		}
	}
	proof, e := r.gate.ObserveRecovered(ctx)
	if e != nil {
		return e
	}
	r.recovered = proof
	return nil
}

func (h *OriginalWriterHold) originalMinIOReadServicePeer(ctx context.Context, podUID, containerID, imageID string) (string, time.Time, error) {
	if h == nil || h.set == nil || h.set.actualHold != h {
		return "", time.Time{}, ErrInstall
	}
	for _, w := range h.set.deployments {
		if w.minio == nil || w.minio.held == nil {
			continue
		}
		r := w.minio
		data := r.held.Data()
		if data.PodUID != podUID {
			continue
		}
		if r.held.Recheck(ctx, h.set.owner.operation, h.set.inventorySHA, "held", time.Now().UTC()) != nil {
			return "", time.Time{}, ErrInstall
		}
		matched := false
		for _, p := range w.pods {
			if p.UID == podUID {
				for _, id := range p.Containers {
					matched = matched || id == containerID
				}
			}
		}
		raw, e := readBootstrapSourcePin(r.selection.Materials, 262144)
		var material struct{ Native sb.MinIOReadGateInput }
		if e != nil || json.Unmarshal(raw, &material) != nil || material.Native.ImageID != imageID || !matched {
			return "", time.Time{}, ErrInstall
		}
		stable := struct{ PodUID, DeploymentID, OriginalSHA256, Operation, Inventory string }{data.PodUID, data.DeploymentID, data.OriginalSHA256, data.Operation, data.InventorySHA256}
		return originalObjectSHA(stable), data.ValidUntil, nil
	}
	return "", time.Time{}, ErrInstall
}
