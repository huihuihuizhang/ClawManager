package install

import (
	"context"
	"errors"
	"reflect"
	"time"

	"clawreef/internal/systembackup/kube"
	q "clawreef/internal/systembackup/quiesce"
	c "clawreef/internal/systembackupcontroller"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type originalLonghornKeeper struct {
	registered        bool
	acquireDispatched bool
	held              *q.VerifiedLonghornExt4Observation
	released          *q.VerifiedLonghornExt4Observation
	cleaned           bool
	native            *q.SharedRuntimeNodeClient
	registration      *q.LonghornExt4Request
	reservation       c.OriginalAdoptionReservation
	set               *PreparedOriginalWriterSet
	writer            *originalDeploymentMaintenance
	plan              kube.LonghornAttachmentKeeper
	serviceAccountUID string
	journal           *originalKeeperResourceJournal
	record            kube.ResourceRecord
	process           kube.WorkerProcess
}

// Prepare only reads the actual writer/PVC/PV/node and journals the fixed
// keeper request. It does not create a Pod or claim that the volume is held.
func (s *PreparedOriginalWriterSet) prepareLonghornKeeper(ctx context.Context, writer *originalDeploymentMaintenance, image string) (*originalLonghornKeeper, error) {
	if s == nil || s.owner.check(ctx) != nil || writer == nil || writer.owner != s.owner || writer.journal != s.journal || len(writer.pods) != 1 || writer.replicas != 1 {
		return nil, ErrInstall
	}
	k := s.owner.operator.installer.kube
	clients, ok := k.(*originalKubernetesClients)
	if !ok || clients.resources == nil {
		return nil, ErrInstall
	}
	pod, err := k.CoreV1().Pods(writer.namespace).Get(ctx, writer.pods[0].Name, metav1.GetOptions{})
	if err != nil || string(pod.UID) != writer.pods[0].UID {
		return nil, ErrInstall
	}
	roots, volumes, err := s.classifyPodPersistentVolumes(ctx, pod)
	if err != nil || len(roots) != 0 || len(volumes) != 1 {
		return nil, ErrInstall
	}
	v := volumes[0]
	pv, err := k.CoreV1().PersistentVolumes().Get(ctx, v.PVName, metav1.GetOptions{})
	if err != nil || string(pv.UID) != v.PVUID || pv.Spec.CSI == nil || pv.Spec.CSI.Driver != "driver.longhorn.io" || pv.Spec.CSI.VolumeHandle != v.Handle || !reflect.DeepEqual(pv.Spec.AccessModes, []core.PersistentVolumeAccessMode{core.ReadWriteOnce}) {
		return nil, ErrInstall
	}
	node, err := k.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
	if err != nil || node.UID == "" || node.DeletionTimestamp != nil {
		return nil, ErrInstall
	}
	sa, err := k.CoreV1().ServiceAccounts(writer.namespace).Get(ctx, "default", metav1.GetOptions{})
	if err != nil || sa.UID == "" || sa.DeletionTimestamp != nil {
		return nil, ErrInstall
	}
	id := kube.Identity{Namespace: writer.namespace, Name: "sbk-keeper-" + originalObjectSHA([]string{s.owner.operation, writer.ID(), v.ClaimUID})[:32], Owner: "adoption-" + s.owner.operation}
	plan := kube.LonghornAttachmentKeeper{Identity: id, NamespaceUID: writer.namespaceUID, Node: pod.Spec.NodeName, NodeUID: string(node.UID), ServiceAccount: "default", Image: image, Executable: "/backup-shared-runtime-node-owner", Source: kube.MountIdentity{Volume: "source", Kind: "PersistentVolumeClaim", Name: v.ClaimName, UID: v.ClaimUID, PVName: v.PVName, PVUID: v.PVUID, SHA256: kube.ContentHash(pv.Spec)}}
	if _, err := kube.LonghornAttachmentKeeperJob(plan); err != nil {
		return nil, ErrInstall
	}
	h := &originalLonghornKeeper{set: s, writer: writer, plan: plan, serviceAccountUID: string(sa.UID)}
	h.journal = &originalKeeperResourceJournal{journal: s.journal, identity: id, check: h.checkForward}
	if s.journal.append(ctx, writer.ID(), "longhorn_keeper_plan", nil, struct {
		Plan                              kube.LonghornAttachmentKeeper
		ServiceAccountUID, OriginalPodUID string
	}{plan, h.serviceAccountUID, writer.pods[0].UID}) != nil {
		return nil, ErrInstall
	}
	return h, nil
}

func (h *originalLonghornKeeper) checkForward(ctx context.Context) error {
	if h == nil || h.set == nil || h.writer == nil || h.set.owner.checkCurrentGate(ctx, c.GateAcquiring) != nil {
		return ErrInstall
	}
	if _, err := h.writer.current(ctx); err != nil {
		return ErrInstall
	}
	sa, err := h.set.owner.operator.installer.kube.CoreV1().ServiceAccounts(h.plan.Identity.Namespace).Get(ctx, h.plan.ServiceAccount, metav1.GetOptions{})
	if err != nil || string(sa.UID) != h.serviceAccountUID || sa.DeletionTimestamp != nil {
		return ErrInstall
	}
	return nil
}

func (h *originalLonghornKeeper) create(ctx context.Context) error {
	if h.checkForward(ctx) != nil || h.record.Intent.Kind != "" {
		return ErrInstall
	}
	if h.checkOriginalPod(ctx) != nil {
		return ErrInstall
	}
	clients, ok := h.set.owner.operator.installer.kube.(*originalKubernetesClients)
	if !ok || clients.resources == nil {
		return ErrInstall
	}
	job, err := kube.LonghornAttachmentKeeperJob(h.plan)
	if err != nil {
		return err
	}
	intent, err := kube.Intent(kube.LonghornKeeperResource, job)
	if err != nil {
		return err
	}
	// Runner may return a zero record when a post-create journal write fails.
	// Retain the frozen request so fresh recovery can reread the durable record.
	h.record = kube.ResourceRecord{Intent: intent}
	runner := kube.Runner{Client: clients.resources, Journal: h.journal, CheckFence: h.checkForward}
	record, err := kube.ReconcileLonghornAttachmentKeeper(ctx, clients, runner, h.plan)
	if record.Intent.Kind != "" {
		h.record = record
	}
	if err != nil && (!errors.Is(err, kube.ErrPending) || h.record.UID == "") {
		return err
	}
	for {
		if h.checkForward(ctx) != nil || h.checkOriginalPod(ctx) != nil {
			return ErrInstall
		}
		process, err := (kube.WorkerObserver{Client: clients}).Observe(ctx, h.record, kube.WorkerSecurity{NodeUIDs: map[string]string{h.plan.Node: h.plan.NodeUID}, Volumes: []kube.MountIdentity{h.plan.Source}, ServiceAccountName: h.plan.ServiceAccount, ServiceAccountUID: h.serviceAccountUID})
		if err == nil {
			h.process = process
			return h.set.journal.append(ctx, h.writer.ID(), "longhorn_keeper_process_observed", nil, process)
		}
		if !errors.Is(err, kube.ErrPending) {
			return err
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ErrInstall
		case <-timer.C:
		}
	}
}

func (h *originalLonghornKeeper) checkOriginalPod(ctx context.Context) error {
	dep, err := h.writer.current(ctx)
	if err != nil {
		return ErrInstall
	}
	pods, err := h.writer.currentPods(ctx, dep, true)
	if err != nil || !reflect.DeepEqual(pods, h.writer.pods) {
		return ErrInstall
	}
	return nil
}
