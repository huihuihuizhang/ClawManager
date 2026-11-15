package install

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"clawreef/internal/systembackup/kube"
	q "clawreef/internal/systembackup/quiesce"
	c "clawreef/internal/systembackupcontroller"
)

// Registers only the actual observed keeper, once, against the selected node
// source. A lost response retains the exact claim/request for independent
// recovery; it never generates another reservation to retry registration.
func (h *originalLonghornKeeper) register(ctx context.Context, native *q.SharedRuntimeNodeClient, source q.LonghornExt4SourceCoordinates) error {
	if h == nil || native == nil || h.registration != nil || h.checkForward(ctx) != nil || h.checkOriginalPod(ctx) != nil || h.record.UID == "" || h.process.UID == "" || len(h.process.Containers) != 1 {
		return ErrInstall
	}
	p := h.set.owner
	b := source.Binding
	if source.Claim != (q.LonghornExt4Claim{}) || source.Attempt != 0 || b.OperationID != "" || b.ReservationID != "" || b.Generation != 0 || b.FenceEpoch != 0 || b.InventorySHA256 != "" || !b.ExpiresAt.IsZero() {
		return ErrInstall
	}
	if b.Kind != q.LonghornExt4Protocol || b.InstallationID != p.operator.installer.plan.Target.InstallationID || b.Namespace != h.plan.Identity.Namespace || b.NamespaceUID != h.plan.NamespaceUID || b.Node != h.plan.Node || b.NodeUID != h.plan.NodeUID || source.PVCName != h.plan.Source.Name || source.PVCUID != h.plan.Source.UID || source.PVUID != h.plan.Source.PVUID || source.ProviderPodUID != h.writer.pods[0].UID {
		return ErrInstall
	}
	identity, err := q.LonghornExt4SourceIdentity(source.OriginalSourceSHA256, source.ProviderNamespaceUID, b.NodeUID)
	if err != nil || identity != source.Identity {
		return ErrInstall
	}
	process, err := (kube.WorkerObserver{Client: p.operator.installer.kube}).Observe(ctx, h.record, kube.WorkerSecurity{NodeUIDs: map[string]string{h.plan.Node: h.plan.NodeUID}, Volumes: []kube.MountIdentity{h.plan.Source}, ServiceAccountName: h.plan.ServiceAccount, ServiceAccountUID: h.serviceAccountUID})
	if err != nil || !kube.SameWorkerProcess(process, h.process) {
		return ErrInstall
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return ErrInstall
	}
	b.OperationID, b.ReservationID = p.operation, hex.EncodeToString(random[:])
	b.InventorySHA256, b.Generation, b.FenceEpoch = h.set.inventorySHA, p.token.Generation, p.token.FencingToken
	b.ExpiresAt = p.until.UTC().Truncate(time.Microsecond)
	keeper := &q.LonghornExt4Keeper{OriginalPodUID: h.writer.pods[0].UID, PodName: process.Name, PodUID: process.UID, ContainerID: process.Containers[0]}
	request := q.LonghornExt4Request{Action: "register", Binding: b, Attempt: 1, SourceIdentity: identity, Keeper: keeper}
	request.RegistrationBoundarySHA256 = originalObjectSHA([]any{h.plan, h.record, request})
	claim := c.OriginalAdoptionReservation{Version: c.OriginalAdoptionReservationVersion, OperationID: p.operation, ReservationID: b.ReservationID, InstallationID: b.InstallationID, ServerUUID: p.operator.installer.plan.Target.ServerUUID, Database: p.operator.installer.plan.Target.Database, Scope: c.CaptureGateScope, GateOwner: p.token.Owner, GateGeneration: p.token.Generation, AcquisitionEpoch: p.token.FencingToken, AcquisitionRowVersion: p.token.RowVersion, Phase: c.GateAcquiring, WriterID: h.writer.ID(), SourceWritersSHA256: h.set.inventorySHA, ControlKind: "platform-quiesce", NativeRequestSHA256: request.RegistrationBoundarySHA256, NotBefore: p.operator.sqlTime.UTC().Truncate(time.Microsecond), ExpiresAt: b.ExpiresAt}
	if _, err := c.OriginalAdoptionReservationIdentitySHA256(claim); err != nil {
		return ErrInstall
	}
	h.registration, h.reservation, h.native = &request, claim, native
	proof, _, err := p.forwardLonghorn(ctx, native, h.set.journal, claim, h.registration)
	if err != nil {
		return err
	}
	response := proof.Response()
	if response.Phase != "prepared" || response.NativeState != "rw" {
		return ErrInstall
	}
	h.registered = true
	return nil
}
