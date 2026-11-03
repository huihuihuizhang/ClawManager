package install

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"reflect"
	"time"

	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/flow"
	q "clawreef/internal/systembackup/quiesce"
	c "clawreef/internal/systembackupcontroller"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type originalStoppedProMaintenance struct {
	owner        *OriginalWriterMaintenance
	journal      *originalWriterJournal
	original     *originalStoppedProObservation
	native       *q.StoppedProNodeObservationClient
	request      q.StoppedProNodeObservationRequest
	state        flow.State
	claim        c.OriginalAdoptionReservation
	proof        *q.VerifiedStoppedProNodeObservation
	anchor, boot string
	recovery     *originalWriterRecoveryFence
}

func (s *originalStoppedProMaintenance) ID() string { return s.original.baseline.SourceKey }

// Input construction consumes only the actual original SQL/Kubernetes read
// above. Instance generation and extant controller generation stay separate.
func (p *OriginalWriterMaintenance) newStoppedProMaintenance(ctx context.Context, observed *originalStoppedProObservation, native *q.StoppedProNodeObservationClient, j *originalWriterJournal) (*originalStoppedProMaintenance, error) {
	if p.checkCurrentGate(ctx, c.GateAcquiring) != nil || observed == nil || native == nil || j == nil || j.inventory == "" {
		return nil, ErrInstall
	}
	b := observed.baseline
	sha, err := domain.OriginalStoppedSourceBaselineSHA256(b)
	if err != nil || sha != observed.sha {
		return nil, ErrInstall
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return nil, ErrInstall
	}
	reservation := hex.EncodeToString(id[:])
	node := b.Volumes[0]
	baseline := q.StoppedProBaseline{SourceKey: b.SourceKey, RuntimeType: b.Source.Type, InstanceID: uint64(b.Source.ID), UserID: uint64(b.Source.UserID), InstanceGeneration: uint64(b.Source.Generation), NamespaceUID: b.NamespaceUID, CurrentConfigSHA256: observed.sha, ControllerUID: b.ControllerUID, ControllerSpecSHA256: b.ControllerSpecSHA256, ControllerGeneration: b.ControllerGeneration}
	for _, v := range b.Volumes {
		baseline.Volumes = append(baseline.Volumes, q.StoppedProVolume{NamespaceUID: b.NamespaceUID, ClaimName: v.PVCName, ClaimUID: v.PVCUID, PVName: v.PVName, PVUID: v.PVUID, PVSpecSHA256: v.PVSpecSHA256, DataNodeUID: v.NodeUID, UniqueNodeEvidenceSHA256: originalObjectSHA(v), HostPath: v.SourcePath})
	}
	binding := q.ObservationBinding{Kind: q.StoppedProObservationProtocol, InstallationID: p.operator.installer.plan.Target.InstallationID, OperationID: p.operation, ReservationID: reservation, InventorySHA256: j.inventory, Namespace: b.Namespace, NamespaceUID: b.NamespaceUID, Node: node.Node, NodeUID: node.NodeUID, Generation: uint64(b.Source.Generation), FenceEpoch: p.token.FencingToken, ExpiresAt: p.until.UTC().Truncate(time.Microsecond)}
	// Stable request correlation excludes nonce/deadline/phase, and excludes
	// ReservationIdentitySHA itself. There is no self-referential hash cycle.
	state := flow.State{UID: b.SourceKey, Generation: int64(b.Source.Generation), Running: false, Checkpoint: q.StoppedProBaselineSHA256(baseline)}
	request := q.StoppedProNodeObservationRequest{Action: "prepare", Binding: binding, Baseline: baseline, OriginalStateSHA256: originalObjectSHA(state)}
	nativeSHA := q.StoppedProNativeScopeSHA256(request)
	claim := c.OriginalAdoptionReservation{Version: c.OriginalAdoptionReservationVersion, OperationID: p.operation, ReservationID: reservation, InstallationID: binding.InstallationID, ServerUUID: p.operator.installer.plan.Target.ServerUUID, Database: p.operator.installer.plan.Target.Database, Scope: c.CaptureGateScope, GateOwner: p.token.Owner, GateGeneration: p.token.Generation, AcquisitionEpoch: p.token.FencingToken, AcquisitionRowVersion: p.token.RowVersion, Phase: c.GateAcquiring, WriterID: b.SourceKey, SourceWritersSHA256: j.inventory, ControlKind: "original-stopped-native", NativeRequestSHA256: nativeSHA, NotBefore: p.operator.sqlTime.UTC().Truncate(time.Microsecond), ExpiresAt: binding.ExpiresAt}
	identity, err := c.OriginalAdoptionReservationIdentitySHA256(claim)
	if err != nil {
		return nil, ErrInstall
	}
	request.OriginalReservationIdentitySHA256 = identity
	request.NativeScopeSHA256 = nativeSHA
	s := &originalStoppedProMaintenance{owner: p, journal: j, original: observed, native: native, request: request, state: state, claim: claim}
	if s.recheckSources(ctx) != nil || j.append(ctx, s.ID(), "current_stopped_baseline", &state, struct {
		Baseline domain.OriginalStoppedSourceBaseline
		Request  q.StoppedProNodeObservationRequest
		Claim    c.OriginalAdoptionReservation
	}{b, request, claim}) != nil {
		return nil, ErrInstall
	}
	return s, nil
}

// Volumes and unique node are reread at all four native boundaries. A node
// label change, rebind, recycled claim/volume, inaccessible path or node reboot
// is never repaired by finding a similarly named directory elsewhere.
func (s *originalStoppedProMaintenance) recheckSources(ctx context.Context) error {
	if originalMaintenanceReadCheck(ctx, s.owner, s.recovery) != nil {
		return ErrInstall
	}
	b := s.original.baseline
	if expected := s.original.storage; expected != nil {
		if s.recheckCurrentStoppedController(ctx) != nil {
			return ErrInstall
		}
		var current originalStoppedProStorage
		if s.owner.operator.installer.db.QueryRowContext(ctx, `SELECT COALESCE(pvc_name,''),mount_path FROM instances WHERE id=?`, b.Source.ID).Scan(&current.Claim, &current.MountPath) != nil || current != *expected {
			return ErrInstall
		}
	}
	k := s.owner.operator.installer.kube
	ns, err := k.CoreV1().Namespaces().Get(ctx, b.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != b.NamespaceUID || ns.DeletionTimestamp != nil {
		return ErrInstall
	}
	for _, v := range b.Volumes {
		claim, err := k.CoreV1().PersistentVolumeClaims(b.Namespace).Get(ctx, v.PVCName, metav1.GetOptions{})
		if err != nil || string(claim.UID) != v.PVCUID || claim.DeletionTimestamp != nil || originalObjectSHA(claim.Spec) != v.PVCSpecSHA256 {
			return ErrInstall
		}
		pv, err := k.CoreV1().PersistentVolumes().Get(ctx, v.PVName, metav1.GetOptions{})
		if err != nil || string(pv.UID) != v.PVUID || pv.DeletionTimestamp != nil || originalObjectSHA(pv.Spec) != v.PVSpecSHA256 || pv.Spec.ClaimRef == nil || string(pv.Spec.ClaimRef.UID) != v.ClaimRefUID || pv.Spec.NodeAffinity == nil {
			return ErrInstall
		}
		nodes, err := k.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			return ErrInstall
		}
		matched := 0
		for n := range nodes.Items {
			node := &nodes.Items[n]
			yes, err := originalPVMatchesNode(pv.Spec.NodeAffinity.Required, node)
			if err != nil {
				return ErrInstall
			}
			if yes {
				matched++
				if node.Name != v.Node || string(node.UID) != v.NodeUID || node.DeletionTimestamp != nil || node.Status.NodeInfo.MachineID != v.MachineID || node.Status.NodeInfo.BootID != v.BootID {
					return ErrInstall
				}
			}
		}
		if matched != 1 {
			return ErrInstall
		}
	}
	if b.ControllerKind == "Deployment" {
		d, err := k.AppsV1().Deployments(b.Namespace).Get(ctx, b.ControllerName, metav1.GetOptions{})
		if err != nil || string(d.UID) != b.ControllerUID || d.Generation != b.ControllerGeneration || originalObjectSHA(d.Spec) != b.ControllerSpecSHA256 || d.Spec.Replicas == nil || *d.Spec.Replicas != 0 || d.Status.Replicas != 0 {
			return ErrInstall
		}
	}
	// SQL source identity remains original and stopped, even after other
	// running sources have legitimately advanced their recovery generations.
	tx, err := s.owner.operator.installer.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrInstall
	}
	defer tx.Rollback()
	instances, err := domain.ReadSourceInstances(ctx, tx)
	if err != nil {
		return ErrInstall
	}
	found := false
	for _, instance := range instances {
		if instance.ID == b.Source.ID {
			found = reflect.DeepEqual(instance, b.Source)
		}
	}
	if !found || tx.Rollback() != nil {
		return ErrInstall
	}
	return nil
}

func (s *originalStoppedProMaintenance) observe(ctx context.Context, phase string) error {
	if s.recheckSources(ctx) != nil {
		return ErrInstall
	}
	if phase == "prepare" {
		if s.anchor != "" || s.owner.checkCurrentGate(ctx, c.GateAcquiring) != nil {
			return ErrInstall
		}
	} else if phase == "stopped" {
		if s.owner.checkCurrentGate(ctx, c.GateAcquiring, c.GateHeld) != nil {
			return ErrInstall
		}
	} else if phase == "recovery-stopped" || phase == "recovered-stopped" {
		if s.recovery == nil || s.recovery.owner != s.owner || s.recovery.checkReleasing(ctx) != nil {
			return ErrInstall
		}
	} else {
		return ErrInstall
	}
	request := s.request
	request.Action = phase
	request.Anchor = s.anchor
	proof, err := s.native.ObserveWriter(ctx, request, s.state)
	if err != nil {
		return ErrInstall
	}
	out := proof.Response()
	if phase == "prepare" {
		s.anchor = out.Anchor
		s.boot = out.BootID
	} else if out.Anchor != s.anchor || out.BootID != s.boot {
		return ErrInstall
	}
	if s.journal.append(ctx, s.ID(), "native_"+phase, &s.state, struct {
		Request     q.StoppedProNodeObservationRequest
		Observation q.StoppedProNodeObservationResponse
	}{request, out}) != nil || s.recheckSources(ctx) != nil {
		return ErrInstall
	}
	s.proof = proof
	return nil
}
