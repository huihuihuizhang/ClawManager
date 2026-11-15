package install

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"reflect"
	"time"

	q "clawreef/internal/systembackup/quiesce"
	c "clawreef/internal/systembackupcontroller"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type originalLonghornRWXHold struct {
	set                 *PreparedOriginalWriterSet
	source              q.LonghornExt4SourceCoordinates
	clients             []originalLonghornRWXClient
	registration        *q.LonghornExt4Request
	reservation         c.OriginalAdoptionReservation
	synced              []q.LonghornExt4Request
	clientRegistrations []q.LonghornExt4Request
	registered          bool
	syncSent            bool
	acquireSent         bool
	held                *q.VerifiedLonghornExt4Observation
	released            *q.VerifiedLonghornExt4Observation
}

func (h *originalLonghornRWXHold) ID() string { return "longhorn-rwx/" + h.source.Identity }

func (h *originalLonghornRWXHold) register(ctx context.Context) error {
	if h == nil || h.set == nil || h.registration != nil || len(h.clients) == 0 || h.set.owner.checkCurrentGate(ctx, c.GateAcquiring) != nil {
		return ErrInstall
	}
	p := h.set.owner
	b := h.source.Binding
	if h.source.Claim != (q.LonghornExt4Claim{}) || h.source.Attempt != 0 || b.OperationID != "" || b.ReservationID != "" || b.Generation != 0 || b.FenceEpoch != 0 || b.InventorySHA256 != "" || !b.ExpiresAt.IsZero() || b.Kind != q.LonghornExt4Protocol || b.InstallationID != p.operator.installer.plan.Target.InstallationID {
		return ErrInstall
	}
	identity, err := q.LonghornExt4SourceIdentity(h.source.OriginalSourceSHA256, h.source.ProviderNamespaceUID, b.NodeUID)
	if err != nil || identity != h.source.Identity {
		return ErrInstall
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return ErrInstall
	}
	b.OperationID, b.ReservationID = p.operation, hex.EncodeToString(random[:])
	b.InventorySHA256, b.Generation, b.FenceEpoch = h.set.inventorySHA, p.token.Generation, p.token.FencingToken
	b.ExpiresAt = p.until.UTC().Truncate(time.Microsecond)
	request := q.LonghornExt4Request{Action: "register", Binding: b, Attempt: 1, SourceIdentity: identity}
	request.RegistrationBoundarySHA256 = originalObjectSHA([]any{h.source, h.clients, request})
	claim := c.OriginalAdoptionReservation{Version: c.OriginalAdoptionReservationVersion, OperationID: p.operation, ReservationID: b.ReservationID, InstallationID: b.InstallationID, ServerUUID: p.operator.installer.plan.Target.ServerUUID, Database: p.operator.installer.plan.Target.Database, Scope: c.CaptureGateScope, GateOwner: p.token.Owner, GateGeneration: p.token.Generation, AcquisitionEpoch: p.token.FencingToken, AcquisitionRowVersion: p.token.RowVersion, Phase: c.GateAcquiring, WriterID: h.ID(), SourceWritersSHA256: h.set.inventorySHA, ControlKind: "platform-quiesce", NativeRequestSHA256: request.RegistrationBoundarySHA256, NotBefore: p.operator.sqlTime.UTC().Truncate(time.Microsecond), ExpiresAt: b.ExpiresAt}
	if _, err := c.OriginalAdoptionReservationIdentitySHA256(claim); err != nil {
		return ErrInstall
	}
	// Retain this target before the first uncertain register. Recovery consumes
	// its exact journal entry, including when no successful reply was returned.
	h.registration, h.reservation = &request, claim
	proof, _, err := p.forwardLonghorn(ctx, h.set.longhornClient, h.set.journal, claim, h.registration)
	if err != nil || proof.Response().Phase != "prepared" || proof.Response().NativeState != "rw" {
		return ErrInstall
	}
	h.registered = true
	// App replicas also mount this site's workspace. Register their original
	// mount descriptors while live, before any Deployment is scaled down.
	for _, client := range h.clients {
		request := originalLonghornRWXClientRegistration(*h.registration, client, h.clientIsColdWriter(client))
		h.clientRegistrations = append(h.clientRegistrations, request)
		proof, _, err := p.forwardLonghorn(ctx, h.set.longhornClient, h.set.journal, claim, &request)
		if err != nil || proof.Response().Phase != "client-prepared" || proof.Response().NativeState != "nfs-client" {
			return ErrInstall
		}
	}
	return nil
}

func originalLonghornRWXClientRegistration(provider q.LonghornExt4Request, client originalLonghornRWXClient, mustExit bool) q.LonghornExt4Request {
	request := provider
	request.Action = "register-client"
	request.Binding.Node, request.Binding.NodeUID = client.Template.Binding.Node, client.Template.Binding.NodeUID
	request.SourceIdentity = client.Template.Identity
	request.ClientPodName, request.ClientPodUID, request.ClientContainerID = client.PodName, client.PodUID, client.ContainerID
	request.ClientMustExit = mustExit
	request.RegistrationBoundarySHA256 = originalObjectSHA([]any{provider, client, mustExit})
	return request
}

func (h *originalLonghornRWXHold) clientIsColdWriter(client originalLonghornRWXClient) bool {
	for _, writer := range h.set.deployments {
		if writer.namespace != client.Template.PodNamespace {
			continue
		}
		for _, pod := range writer.pods {
			if originalLonghornRWXProcessCovered(client, pod) {
				return true
			}
		}
	}
	return false
}

// The original App clients may have exited; their entries remain in the sync
// cohort. Remaining live clients must be frozen runtimes or the recorded
// read-only attachment. A template alone never proves writer drain.
func (h *originalLonghornRWXHold) checkDrainedClients(ctx context.Context) error {
	if h == nil || h.set == nil || h.set.longhornMaterials == nil {
		return ErrInstall
	}
	if h.set.checkSharedRuntimeLifecycle(ctx) != nil {
		return ErrInstall
	}
	current, err := originalLonghornRWXClients(ctx, h.set.owner.operator.installer.kube, *h.set.longhornMaterials)
	if err != nil {
		return ErrInstall
	}
	exited := map[string]bool{}
	for _, client := range h.set.longhornRWXClients {
		stopped, err := h.clientDeploymentStopped(ctx, client)
		if err != nil {
			return err
		}
		if stopped {
			exited[originalObjectSHA(client)] = true
		}
	}
	if !originalLonghornRWXLiveCohortMatches(h.set.longhornRWXClients, current, exited) {
		return ErrInstall
	}
	for _, client := range h.clients {
		if exited[originalObjectSHA(client)] {
			continue // Native sync independently requires original CRI/task exit.
		}
		frozen := false
		for _, actor := range h.set.sharedLifecycle {
			if originalLonghornRWXProcessCovered(client, actor.request.AgentPod) && actor.current != nil && actor.current.Response().Phase == "frozen" {
				frozen = true
			}
		}
		if frozen {
			continue
		}
		pod, err := h.set.owner.operator.installer.kube.CoreV1().Pods(client.Template.PodNamespace).Get(ctx, client.PodName, metav1.GetOptions{})
		if err != nil || string(pod.UID) != client.PodUID || pod.DeletionTimestamp != nil || originalObjectSHA(pod.Spec) != client.SpecSHA {
			return ErrInstall
		}
		readOnly := false
		for _, container := range pod.Spec.Containers {
			if container.Name != client.ContainerName {
				continue
			}
			for _, mount := range container.VolumeMounts {
				if mount.Name == client.Volume && mount.MountPath == client.Template.MountPoint {
					readOnly = mount.ReadOnly
				}
			}
		}
		attachment := false
		for _, pin := range h.set.selection.TeamAttachments {
			if pin.PodUID == client.PodUID && pin.Choice.Namespace == client.Template.PodNamespace && pin.Choice.Pod == client.PodName && pin.PodSpecSHA256 == client.SpecSHA && pin.PVCUID == client.Template.PVCUID && pin.PVUID == client.Template.PVUID {
				attachment = true
			}
		}
		if !readOnly || !attachment || h.set.recheckTeamAttachments(ctx, nil) != nil {
			return ErrInstall
		}
	}
	return nil
}

func originalLonghornRWXLiveCohortMatches(original, current []originalLonghornRWXClient, exited map[string]bool) bool {
	expected := []originalLonghornRWXClient{}
	for _, client := range original {
		if !exited[originalObjectSHA(client)] {
			expected = append(expected, client)
		}
	}
	return reflect.DeepEqual(expected, current)
}

func (h *originalLonghornRWXHold) clientDeploymentStopped(ctx context.Context, client originalLonghornRWXClient) (bool, error) {
	for _, writer := range h.set.deployments {
		if writer.namespace != client.Template.PodNamespace {
			continue
		}
		for _, pod := range writer.pods {
			if !originalLonghornRWXProcessCovered(client, pod) {
				continue
			}
			if !writer.stopDispatched {
				return false, nil
			}
			dep, err := writer.current(ctx)
			if err != nil || dep.Spec.Replicas == nil || *dep.Spec.Replicas != 0 || dep.Status.Replicas != 0 || dep.Status.ObservedGeneration < dep.Generation {
				return false, ErrInstall
			}
			pods, err := writer.currentPods(ctx, dep, false)
			if err != nil || len(pods) != 0 {
				return false, ErrInstall
			}
			return true, nil
		}
	}
	return false, nil
}

// A shared owner freezes one container cgroup, not arbitrary extra containers
// in the same Pod. Pod UID equality alone cannot cover a debug/sidecar writer.
func originalLonghornRWXProcessCovered(client originalLonghornRWXClient, agent q.PodIdentity) bool {
	if client.PodUID == "" || client.ContainerID == "" || agent.UID != client.PodUID || agent.Name != client.PodName {
		return false
	}
	for _, container := range agent.Containers {
		if container == client.ContainerID {
			return true
		}
	}
	return false
}

func (h *originalLonghornRWXHold) syncClients(ctx context.Context) error {
	if h == nil || !h.registered || h.registration == nil || len(h.clientRegistrations) != len(h.clients) || h.syncSent || len(h.synced) != 0 || h.checkDrainedClients(ctx) != nil {
		return ErrInstall
	}
	h.syncSent = true
	for i, registered := range h.clientRegistrations {
		if registered.ClientMustExit != h.clientIsColdWriter(h.clients[i]) {
			return ErrInstall
		}
		request := registered
		request.Action = "sync-client"
		request.DrainBoundarySHA256 = originalObjectSHA([]any{*h.registration, h.clients, h.clientRegistrations})
		proof, _, err := h.set.owner.forwardLonghorn(ctx, h.set.longhornClient, h.set.journal, h.reservation, &request)
		if err != nil {
			return err
		}
		if proof.Response().Phase != "client-synced" || proof.Response().NativeState != "nfs-client" {
			return ErrInstall
		}
		h.synced = append(h.synced, request)
	}
	return h.checkDrainedClients(ctx)
}

func (h *originalLonghornRWXHold) acquire(ctx context.Context) error {
	if h == nil || !h.registered || h.acquireSent || len(h.synced) != len(h.clients) || h.checkDrainedClients(ctx) != nil {
		return ErrInstall
	}
	request := *h.registration
	request.Action, request.DrainBoundarySHA256 = "acquire", originalObjectSHA(h.synced)
	h.acquireSent, h.held = true, nil
	proof, _, err := h.set.owner.forwardLonghorn(ctx, h.set.longhornClient, h.set.journal, h.reservation, &request)
	if err != nil {
		return err
	}
	h.held = proof
	return h.recheckHeld(time.Now())
}

func (h *originalLonghornRWXHold) checkHeld(ctx context.Context) error {
	if h == nil || !h.acquireSent || h.held == nil || h.checkDrainedClients(ctx) != nil {
		return ErrInstall
	}
	request := *h.registration
	request.Action = "check-held"
	reservation := h.reservation
	reservation.Phase = h.set.owner.token.State
	h.held = nil
	proof, _, err := h.set.owner.forwardLonghorn(ctx, h.set.longhornClient, h.set.journal, reservation, &request)
	if err != nil {
		return err
	}
	h.held = proof
	return h.recheckHeld(time.Now())
}

func (h *originalLonghornRWXHold) recheckHeld(now time.Time) error {
	if h == nil || h.registration == nil || h.held == nil || !h.acquireSent {
		return ErrInstall
	}
	r := h.held.Response()
	if r.Action != "acquire" && r.Action != "check-held" || r.Phase != "held" || r.NativeState != "freeze-stable" || r.SourceIdentity != h.registration.SourceIdentity || r.Attempt != h.registration.Attempt || !reflect.DeepEqual(r.Binding, h.registration.Binding) || !reflect.DeepEqual(r.Claim, h.registration.Claim) || r.HeldObservedAt.IsZero() || now.Before(r.HeldObservedAt) || now.Sub(r.HeldObservedAt) > 10*time.Second || !now.Before(r.ExpiresAt) {
		return ErrInstall
	}
	return nil
}
