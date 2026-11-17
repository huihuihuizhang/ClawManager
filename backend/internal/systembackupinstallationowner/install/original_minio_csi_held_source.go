package install

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	c "clawreef/internal/systembackupcontroller"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Coordinates are expectations from the held original operation. The native
// reader must independently observe the actual CRI bind and Longhorn device.
type OriginalMinIOCSIPhysicalCoordinates struct {
	OperationID, InstallationID, Namespace, NamespaceUID                                 string
	Node, NodeUID, MachineID, BootID                                                     string
	PVCName, PVCUID, PVName, PVUID, VolumeHandle                                         string
	OriginalPodUID, OriginalContainerID                                                  string
	KeeperPodName, KeeperPodUID, KeeperContainerID, KeeperContainerName, KeeperMountPath string
}

type OriginalMinIOCSIPhysicalSource struct {
	origin *OriginalMinIOCSIPhysicalSource
	hold   *OriginalWriterHold
	keeper *originalLonghornKeeper
	warm   *OriginalProtectedMinIOWarmHistory
}

func (*OriginalMinIOCSIPhysicalSource) MarshalJSON() ([]byte, error) { return nil, ErrInstall }

func originalCSIContainerID(raw string) (string, error) {
	id, ok := strings.CutPrefix(raw, "containerd://")
	if !ok || !digestPattern.MatchString(id) {
		return "", ErrInstall
	}
	return id, nil
}

// Called with the writer-set lock already held. Never acquire it recursively.
func (h *OriginalWriterHold) originalMinIOCSIHeldSourceLocked(ctx context.Context, pin BootstrapSourceFilePin) (*OriginalMinIOCSIPhysicalSource, error) {
	if h == nil || h.set == nil || h.set.minioHistory == nil || h.set.minioHistory.warm == nil || h.recheckBeforeSQL(ctx) != nil {
		return nil, ErrInstall
	}
	warm := h.set.minioHistory.warm
	if warm.origin != warm || warm.set != h.set || warm.failed || !consumerSameContext(ctx, warm.ctx) || warm.native.PlanFile == "" || warm.native.PlanSHA256 == "" || pin.File == "" || pin.SHA256 == "" {
		return nil, ErrInstall
	}
	var selected *originalLonghornKeeper
	for _, keeper := range h.set.longhornKeepers {
		if keeper == nil || keeper.set != h.set || keeper.writer == nil {
			return nil, ErrInstall
		}
		if keeper.writer != h.set.minioHistory.writer {
			continue
		}
		if selected != nil || keeper.plan.Identity.Namespace != h.set.initial.Namespace || keeper.plan.NamespaceUID != h.set.initial.NamespaceUID || keeper.plan.Source.Name == "" || keeper.plan.Source.UID == "" || keeper.plan.Source.PVName == "" || keeper.plan.Source.PVUID == "" || keeper.checkHeld(ctx) != nil {
			return nil, ErrInstall
		}
		selected = keeper
	}
	if selected == nil || len(selected.writer.pods) != 1 || selected.writer.pods[0].UID != warm.facts.PodUID || len(selected.writer.pods[0].Containers) != 1 || selected.writer.pods[0].Containers[0] == "" || len(selected.process.Containers) != 1 || selected.process.UID == "" {
		return nil, ErrInstall
	}
	if _, err := originalCSIContainerID(selected.process.Containers[0]); err != nil {
		return nil, ErrInstall
	}
	if _, err := originalCSIContainerID(selected.writer.pods[0].Containers[0]); err != nil {
		return nil, ErrInstall
	}
	raw, err := readBootstrapSourcePin(pin, 262144)
	if err != nil || len(raw) == 0 {
		return nil, ErrInstall
	}
	// Definition is independently parsed by the provider; this check binds the
	// exact selected bytes to this hold before it can become an authority.
	x := &OriginalMinIOCSIPhysicalSource{hold: h, keeper: selected, warm: warm}
	x.origin = x
	return x, nil
}

func (x *OriginalMinIOCSIPhysicalSource) Check(ctx context.Context) error {
	if x == nil || x.origin != x || x.hold == nil || x.keeper == nil || x.warm == nil || ctx == nil || ctx.Err() != nil || x.hold.ctx == nil || x.hold.ctx.Err() != nil || x.hold.closed || x.hold.adoptionUnknown || x.hold.set == nil || x.hold.set.actualHold != x.hold || x.hold.set.minioHistory == nil || x.hold.set.minioHistory.warm != x.warm || x.warm.origin != x.warm || x.warm.failed || x.keeper.set != x.hold.set || x.keeper.writer != x.hold.set.minioHistory.writer || x.hold.set.owner.checkCurrentGate(x.hold.ctx, c.GateHeld) != nil {
		return ErrInstall
	}
	if until, ok := ctx.Deadline(); ok && !time.Now().Before(until) {
		return ErrInstall
	}
	if x.hold.recheckBeforeSQL(x.hold.ctx) != nil || x.keeper.checkHeld(x.hold.ctx) != nil {
		return ErrInstall
	}
	return nil
}

func (x *OriginalMinIOCSIPhysicalSource) Coordinates(ctx context.Context) (OriginalMinIOCSIPhysicalCoordinates, error) {
	var out OriginalMinIOCSIPhysicalCoordinates
	if x.Check(ctx) != nil {
		return out, ErrInstall
	}
	h, k := x.hold, x.keeper
	source, ok := h.set.longhornSources[k.plan.Identity.Namespace+"/"+k.plan.Source.Name]
	if !ok || source.Binding.Namespace != h.set.initial.Namespace || source.Binding.NamespaceUID != h.set.initial.NamespaceUID || source.PVCUID != k.plan.Source.UID || source.PVUID != k.plan.Source.PVUID || source.ProviderPodUID != x.warm.facts.PodUID || source.ProviderContainerID != k.writer.pods[0].Containers[0] || source.MountPoint != "/data" || source.VolumeHandle == "" {
		return out, ErrInstall
	}
	node, err := h.set.owner.operator.installer.kube.CoreV1().Nodes().Get(h.ctx, k.plan.Node, metav1.GetOptions{})
	if err != nil || string(node.UID) != k.plan.NodeUID || node.DeletionTimestamp != nil || node.Status.NodeInfo.BootID == "" || node.Status.NodeInfo.MachineID == "" {
		return out, ErrInstall
	}
	originalID, originalErr := originalCSIContainerID(k.writer.pods[0].Containers[0])
	keeperID, keeperErr := originalCSIContainerID(k.process.Containers[0])
	if originalErr != nil || keeperErr != nil {
		return out, ErrInstall
	}
	out = OriginalMinIOCSIPhysicalCoordinates{OperationID: h.set.owner.operation, InstallationID: h.set.owner.operator.installer.plan.Target.InstallationID, Namespace: k.plan.Identity.Namespace, NamespaceUID: k.plan.NamespaceUID, Node: k.plan.Node, NodeUID: k.plan.NodeUID, MachineID: node.Status.NodeInfo.MachineID, BootID: node.Status.NodeInfo.BootID, PVCName: k.plan.Source.Name, PVCUID: k.plan.Source.UID, PVName: k.plan.Source.PVName, PVUID: k.plan.Source.PVUID, VolumeHandle: source.VolumeHandle, OriginalPodUID: x.warm.facts.PodUID, OriginalContainerID: originalID, KeeperPodName: k.process.Name, KeeperPodUID: k.process.UID, KeeperContainerID: keeperID, KeeperContainerName: "attachment", KeeperMountPath: "/source"}
	if x.Check(ctx) != nil {
		return OriginalMinIOCSIPhysicalCoordinates{}, ErrInstall
	}
	return out, nil
}

func (x *OriginalMinIOCSIPhysicalSource) NativePlan(ctx context.Context) (BootstrapSourceFilePin, error) {
	if x.Check(ctx) != nil {
		return BootstrapSourceFilePin{}, ErrInstall
	}
	originalID, err := originalCSIContainerID(x.keeper.writer.pods[0].Containers[0])
	if err != nil {
		return BootstrapSourceFilePin{}, ErrInstall
	}
	pin := BootstrapSourceFilePin{File: x.warm.native.PlanFile, SHA256: x.warm.native.PlanSHA256}
	raw, err := readBootstrapSourcePin(pin, 262144)
	var plan struct {
		Profile     string `json:"profile"`
		PodUID      string `json:"pod_uid"`
		ContainerID string `json:"container_id"`
	}
	if err != nil || json.Unmarshal(raw, &plan) != nil || plan.Profile != "original-minio-longhorn-csi-native-raw-cut.v1" || plan.PodUID != x.warm.facts.PodUID || plan.ContainerID != originalID || x.Check(ctx) != nil {
		return BootstrapSourceFilePin{}, ErrInstall
	}
	return pin, nil
}
