package systembackupexecution

import (
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"sync"
	"time"

	sb "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/flow"
	b "clawreef/internal/systembackup/publicadapter"
	q "clawreef/internal/systembackup/quiesce"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	"clawreef/internal/systembackupinstallationowner/install"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type FormalMinIOReadKeeperSelection struct {
	Deployment, DeploymentUID   string
	Materials, ReaderCredential install.BootstrapSourceFilePin
	ReaderAccount               string
	OutputAccounts              []string
	Native                      sb.MinIOReadGateInput
}
type formalMinIOReadWriter struct {
	mu             sync.Mutex
	service        *DeploymentService
	owner          *PublicJobOwner
	in             d.Input
	ref            PlatformDeployment
	selection      FormalMinIOReadKeeperSelection
	base, original flow.State
	gate           *sb.MinIOReadServiceGate
	inventory      string
	recovery       bool
}

func (w *formalMinIOReadWriter) ID() string {
	return "deployment/" + w.ref.Namespace + "/" + w.ref.Name
}
func (s *DeploymentService) formalMinIOSelection(ref PlatformDeployment) (*FormalMinIOReadKeeperSelection, error) {
	var out *FormalMinIOReadKeeperSelection
	for _, selected := range s.Config.MinIOReadKeepers {
		if selected.Deployment != ref.Name {
			continue
		}
		if out != nil || selected.DeploymentUID != ref.UID || selected.Native.Namespace != ref.Namespace || selected.Native.NamespaceUID != s.Config.NamespaceUID {
			return nil, d.ErrNotReady
		}
		copy := selected
		out = &copy
	}
	return out, nil
}
func (w *formalMinIOReadWriter) nativeCheck(ctx context.Context) error {
	if w.recovery {
		if w.owner.Gate.CheckRecovery(ctx, w.in.Authority, w.ID(), d.WriterState(w.original)) != nil {
			return d.ErrNotReady
		}
	} else if w.owner.Gate.Check(ctx, w.in.Authority) != nil {
		return d.ErrNotReady
	}
	if w.service.checkAutoscalers(ctx, w.ref) != nil {
		return d.ErrNotReady
	}
	var cp sourceRecoveryCheckpoint
	if json.Unmarshal([]byte(w.base.Checkpoint), &cp) != nil {
		return d.ErrNotReady
	}
	deployment, e := w.owner.Client.AppsV1().Deployments(w.ref.Namespace).Get(ctx, w.ref.Name, metav1.GetOptions{})
	if e != nil || string(deployment.UID) != w.base.UID || deployment.Generation != w.base.Generation || deployment.DeletionTimestamp != nil || deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 || deployment.Status.ReadyReplicas != 1 || deployment.Status.ObservedGeneration < deployment.Generation {
		return d.ErrNotReady
	}
	spec := deployment.Spec.DeepCopy()
	spec.Replicas = nil
	if hashJSON(spec) != cp.SpecSHA256 {
		return d.ErrNotReady
	}
	pod, e := w.owner.Client.CoreV1().Pods(w.ref.Namespace).Get(ctx, w.selection.Native.Pod, metav1.GetOptions{})
	if e != nil || string(pod.UID) != w.selection.Native.PodUID || pod.DeletionTimestamp != nil || len(cp.Pods) != 1 || len(pod.Status.ContainerStatuses) != 1 || pod.Status.ContainerStatuses[0].ContainerID == "" || len(cp.Pods[0].Containers) != 1 || cp.Pods[0].Containers[0] != pod.Status.ContainerStatuses[0].ContainerID || !pod.Status.ContainerStatuses[0].Ready || pod.Status.ContainerStatuses[0].State.Running == nil {
		return d.ErrNotReady
	}
	raw, e := pinnedDeploymentFile(w.selection.Materials.File, w.selection.Materials.SHA256, 262144)
	var material struct {
		Native                                    sb.MinIOReadGateInput
		ReaderCredential, CaptureReaderCredential install.BootstrapSourceFilePin
	}
	if e != nil || json.Unmarshal(raw, &material) != nil || !reflect.DeepEqual(material.Native, w.selection.Native) || material.CaptureReaderCredential != w.selection.ReaderCredential {
		return d.ErrNotReady
	}
	reader, e := pinnedDeploymentFile(material.ReaderCredential.File, material.ReaderCredential.SHA256, 16384)
	if e != nil {
		return d.ErrNotReady
	}
	defer clear(reader)
	var account struct{ AccessKey string }
	if json.Unmarshal(reader, &account) != nil || account.AccessKey != w.selection.ReaderAccount {
		return d.ErrNotReady
	}
	return ctx.Err()
}
func (s *DeploymentService) buildFormalMinIOReadWriter(ctx context.Context, o *PublicJobOwner, in d.Input, source b.SourceInventory, ref PlatformDeployment, frozen []b.FrozenWriter) (flow.Writer, bool, error) {
	selected, e := s.formalMinIOSelection(ref)
	if e != nil || selected == nil {
		return nil, selected != nil, e
	}
	if selected.Native.Operation != "" || selected.Native.InventorySHA256 != "" || len(selected.Native.OutputAccounts) != 0 || s.captureMaterials == nil || s.captureMaterials.Objects.Objects == nil || selected.ReaderCredential.File != s.captureMaterials.Objects.CredentialFile || selected.ReaderCredential.SHA256 != s.captureMaterials.Objects.CredentialSHA256 || selected.Native.Endpoint != "https://"+s.captureMaterials.Objects.Objects.Address || selected.Native.CAFile != s.captureMaterials.Objects.Objects.CAFile || selected.Native.CASHA256 != s.captureMaterials.Objects.Objects.CASHA256 {
		return nil, true, d.ErrNotReady
	}
	id := "deployment/" + ref.Namespace + "/" + ref.Name
	key := formalRedisCacheKey(in.Authority, id)
	s.minioReadMu.Lock()
	defer s.minioReadMu.Unlock()
	if w := s.minioRead[key]; w != nil {
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.owner != o || !reflect.DeepEqual(w.selection, *selected) {
			return nil, true, d.ErrNotReady
		}
		if frozen != nil {
			matched := false
			for _, old := range frozen {
				if old.ID == id && old.Original == w.original {
					matched = true
				}
			}
			if !matched {
				return nil, true, d.ErrNotReady
			}
		}
		if o.Gate.Check(ctx, in.Authority) != nil && o.Gate.CheckRecovery(ctx, in.Authority, id, d.WriterState(w.original)) != nil {
			return nil, true, d.ErrNotReady
		}
		w.in = in
		return w, true, nil
	}
	if len(s.minioRead) >= 64 {
		return nil, true, d.ErrNotReady
	}
	w := &formalMinIOReadWriter{service: s, owner: o, in: in, ref: ref, selection: *selected, inventory: c.MinIOReadServiceInventorySHA(in.Authority, source, id)}
	if frozen != nil {
		found := false
		for _, old := range frozen {
			if old.ID == id {
				if found {
					return nil, true, d.ErrNotReady
				}
				found = true
				w.original = old.Original
				w.base = old.Original
			}
		}
		if !found || o.Gate.CheckRecovery(ctx, in.Authority, id, d.WriterState(w.original)) != nil {
			return nil, true, d.ErrNotReady
		}
		w.recovery = true
		w.gate, e = sb.OpenMinIOReadServiceRecoveryFromMaterials(ctx, o.Client, selected.Materials.File, selected.Materials.SHA256, w.inventory[:32], w.inventory, selected.OutputAccounts, w.nativeCheck)
		if e != nil {
			return nil, true, e
		}
	} else {
		physical := &q.DeploymentWriter{Platform: true, Client: o.Client, Namespace: ref.Namespace, Name: ref.Name, UID: ref.UID, FenceID: in.Authority.TaskPublicID + "/attempt/" + strconv.FormatUint(in.Authority.AttemptNo, 10), Guard: func(ctx context.Context, _ string, _ flow.State) error { return o.Gate.Check(ctx, in.Authority) }, ConfirmStopped: func(context.Context, flow.State, []q.PodIdentity) error { return d.ErrNotReady }, ConfirmResumed: func(context.Context, flow.State) error { return d.ErrNotReady }}
		w.base, e = physical.Observe(ctx)
		if e != nil || !w.base.Running {
			return nil, true, d.ErrNotReady
		}
		w.gate, e = sb.PrepareMinIOReadServiceGateFromMaterials(ctx, o.Client, selected.Materials.File, selected.Materials.SHA256, w.inventory[:32], w.inventory, selected.OutputAccounts, w.nativeCheck)
		if e != nil {
			return nil, true, e
		}
		var cp struct {
			Version, Namespace, Name, FenceID, SpecSHA256 string
			Replicas                                      int32
			Pods                                          []q.PodIdentity
		}
		if json.Unmarshal([]byte(w.base.Checkpoint), &cp) != nil || cp.Replicas != 1 || len(cp.Pods) != 1 || cp.Pods[0].UID != selected.Native.PodUID {
			w.gate.Close()
			return nil, true, d.ErrNotReady
		}
		cp.FenceID += "/minio/" + w.gate.OriginalDigest()
		if len(cp.FenceID) > 128 {
			w.gate.Close()
			return nil, true, d.ErrNotReady
		}
		raw, e := json.Marshal(cp)
		if e != nil {
			w.gate.Close()
			return nil, true, e
		}
		w.original = w.base
		w.original.Checkpoint = string(raw)
	}
	if s.minioRead == nil {
		s.minioRead = map[string]*formalMinIOReadWriter{}
	}
	s.minioRead[key] = w
	return w, true, nil
}
func (w *formalMinIOReadWriter) Observe(ctx context.Context) (flow.State, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.nativeCheck(ctx) != nil {
		return flow.State{}, d.ErrNotReady
	}
	return w.original, nil
}
func (w *formalMinIOReadWriter) Pause(ctx context.Context, state flow.State) (flow.ACK, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if state != w.original || w.recovery || w.nativeCheck(ctx) != nil || w.gate.Acquire(ctx) != nil {
		return flow.ACK{}, d.ErrNotReady
	}
	return flow.ACK{UID: state.UID, Generation: state.Generation, Stopped: true}, nil
}
func (w *formalMinIOReadWriter) CheckPaused(ctx context.Context, state flow.State) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if state != w.original || w.nativeCheck(ctx) != nil {
		return d.ErrNotReady
	}
	proof, e := w.gate.ObserveHeld(ctx)
	if e != nil {
		return e
	}
	return proof.Recheck(ctx, w.inventory[:32], w.inventory, "held", time.Now())
}
func (w *formalMinIOReadWriter) Resume(ctx context.Context, state flow.State) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if state != w.original {
		return d.ErrNotReady
	}
	w.recovery = true
	if sb.RestoreMinIOReadServiceGateFromMaterials(ctx, w.gate, w.selection.Materials.File, w.selection.Materials.SHA256, w.inventory[:32], w.inventory, w.selection.OutputAccounts, w.nativeCheck) != nil {
		return d.ErrNotReady
	}
	return w.nativeCheck(ctx)
}
func (s *DeploymentService) observeFormalMinIOReadRecovery(ctx context.Context, in d.Input, writer b.FrozenWriter, source b.SourceInventory, metadata productionCaptureMetadata) (c.SourceRecoveryObservation, error) {
	var zero c.SourceRecoveryObservation
	s.minioReadMu.Lock()
	w := s.minioRead[formalRedisCacheKey(in.Authority, writer.ID)]
	s.minioReadMu.Unlock()
	if w == nil {
		return zero, c.ErrSourceRecoveryProofRequired
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.owner.Gate.CheckRecovery(ctx, in.Authority, writer.ID, d.WriterState(writer.Original)) != nil {
		return zero, c.ErrSourceRecoveryProofRequired
	}
	w.in = in
	if writer.Original != w.original || !w.recovery || w.nativeCheck(ctx) != nil || !reflect.DeepEqual(metadata.MinIOReadKeepers, s.Config.MinIOReadKeepers) {
		return zero, c.ErrSourceRecoveryProofRequired
	}
	proof, e := w.gate.ObserveRecovered(ctx)
	if e != nil {
		return zero, e
	}
	pod, e := w.owner.Client.CoreV1().Pods(w.ref.Namespace).Get(ctx, w.selection.Native.Pod, metav1.GetOptions{})
	if e != nil {
		return zero, e
	}
	binding := productionSourceBinding{service: s, owner: w.owner}
	observed, e := binding.observeRecoveredPod(ctx, pod, metadata, writer)
	if e != nil {
		return zero, e
	}
	raw, e := json.Marshal(observed)
	if e != nil {
		return zero, e
	}
	facts := c.MinIOReadServiceRecoveryFacts{Version: "source-recovery-minio-native-iam.v1", Kind: "minio_read_service", TaskPublicID: in.Authority.TaskPublicID, AttemptNo: in.Authority.AttemptNo, ConfigSHA256: in.Authority.ConfigSHA256, InventorySHA256: c.MinIOReadServiceInventorySHA(in.Authority, source, writer.ID), PolicySHA256: hashJSON(metadata.MinIOReadKeepers), OriginalNativeSHA256: w.gate.OriginalDigest(), Native: proof.Data(), Recovered: []json.RawMessage{raw}}
	if w.nativeCheck(ctx) != nil || proof.Recheck(ctx, facts.Native.Operation, facts.InventorySHA256, "recovered", time.Now()) != nil {
		return zero, c.ErrSourceRecoveryProofRequired
	}
	return c.NewMinIOReadServiceRecoveryObservation(ctx, in.Authority, writer, facts, proof)
}
