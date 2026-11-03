package systembackupexecution

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
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

// The existing platform registry ID is preserved. Stopped=true means that the
// protected Redis writer capability is paused; no PID/CRI-exit claim is made.
type formalRedisReadWriter struct {
	mu             sync.Mutex
	service        *DeploymentService
	owner          *PublicJobOwner
	in             d.Input
	ref            PlatformDeployment
	selection      install.OriginalRedisReadKeeperSelection
	base, original flow.State
	gate           *sb.RedisReadServiceGate
	recovery       bool
}

func (w *formalRedisReadWriter) ID() string {
	return "deployment/" + w.ref.Namespace + "/" + w.ref.Name
}
func formalRedisCacheKey(a d.Authority, id string) string {
	return a.TaskPublicID + "/" + strconv.FormatUint(a.AttemptNo, 10) + "/" + a.ConfigSHA256 + "/" + id
}

func (s *DeploymentService) formalRedisSelection(ref PlatformDeployment) (*install.OriginalRedisReadKeeperSelection, error) {
	var out *install.OriginalRedisReadKeeperSelection
	for _, selected := range s.Config.RedisReadKeepers {
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

func (s *DeploymentService) buildFormalRedisReadWriter(ctx context.Context, o *PublicJobOwner, in d.Input, source b.SourceInventory, ref PlatformDeployment, frozen []b.FrozenWriter) (flow.Writer, bool, error) {
	selection, e := s.formalRedisSelection(ref)
	if e != nil || selection == nil {
		return nil, selection != nil, e
	}
	if selection.Native.Operation != "" || selection.Native.InventorySHA256 != "" || selection.Port < 1 || selection.Port > 65535 || selection.ServerName == "" || (selection.ClientCertificate == nil) != (selection.ClientKey == nil) {
		return nil, true, d.ErrNotReady
	}
	if s.captureMaterials == nil || s.captureMaterials.Discovery == nil {
		return nil, true, d.ErrNotReady
	}
	if reflect.DeepEqual(selection.Native.Policy, sb.RedisCapturePolicy{}) {
		selection.Native.Policy = s.captureMaterials.Discovery.Redis
	} else if !reflect.DeepEqual(selection.Native.Policy, s.captureMaterials.Discovery.Redis) {
		return nil, true, d.ErrNotReady
	}
	id := "deployment/" + ref.Namespace + "/" + ref.Name
	key := formalRedisCacheKey(in.Authority, id)
	s.redisReadMu.Lock()
	defer s.redisReadMu.Unlock()
	if w := s.redisRead[key]; w != nil {
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.owner != o || !reflect.DeepEqual(w.selection, *selection) {
			return nil, true, d.ErrNotReady
		}
		if frozen != nil {
			matched := false
			for _, original := range frozen {
				if original.ID == id {
					matched = original.Original == w.original
				}
			}
			if !matched {
				return nil, true, d.ErrNotReady
			}
		}
		// Only a currently authorized real original task may rebind mutable SQL
		// authority coordinates; original native operation/custody is unchanged.
		if o.Gate.Check(ctx, in.Authority) != nil && o.Gate.CheckRecovery(ctx, in.Authority, id, d.WriterState(w.original)) != nil {
			return nil, true, d.ErrNotReady
		}
		w.in = in
		return w, true, nil
	}
	// A restarted process must not mint a new original ACL from a currently
	// fenced server. Missing original private handles fail closed on replay.
	if frozen != nil || len(s.redisRead) >= 64 || s.captureMaterials == nil || s.captureMaterials.Discovery == nil || !reflect.DeepEqual(selection.Native.Policy, s.captureMaterials.Discovery.Redis) {
		return nil, true, d.ErrNotReady
	}
	mount := s.captureMaterials.Redis
	if mount.Redis == nil || mount.Redis.ServerName != selection.ServerName || mount.Redis.CAFile != selection.CA.File || mount.Redis.CASHA256 != selection.CA.SHA256 || mount.CredentialFile != selection.ReaderCredential.File || mount.CredentialSHA256 != selection.ReaderCredential.SHA256 {
		return nil, true, d.ErrNotReady
	}
	w := &formalRedisReadWriter{service: s, owner: o, in: in, ref: ref, selection: *selection}
	physical := &q.DeploymentWriter{Platform: true, Client: o.Client, Namespace: ref.Namespace, Name: ref.Name, UID: ref.UID, FenceID: in.Authority.TaskPublicID + "/attempt/" + strconv.FormatUint(in.Authority.AttemptNo, 10), Guard: func(ctx context.Context, _ string, _ flow.State) error { return o.Gate.Check(ctx, in.Authority) }, ConfirmStopped: func(context.Context, flow.State, []q.PodIdentity) error { return d.ErrNotReady }, ConfirmResumed: func(context.Context, flow.State) error { return d.ErrNotReady }}
	w.base, e = physical.Observe(ctx)
	if e != nil || !w.base.Running {
		return nil, true, d.ErrNotReady
	}
	var cp sourceRecoveryCheckpoint
	if json.Unmarshal([]byte(w.base.Checkpoint), &cp) != nil || cp.Replicas != 1 || len(cp.Pods) != 1 || cp.Pods[0].UID != selection.Native.PodUID || cp.Pods[0].Name != selection.Native.Pod {
		return nil, true, d.ErrNotReady
	}
	admin, reader, e := w.connect(ctx)
	if e != nil {
		return nil, true, e
	}
	custodyKey, e := pinnedDeploymentFile(selection.CustodyKey.File, selection.CustodyKey.SHA256, 32)
	if e != nil || len(custodyKey) != 32 {
		admin.Close()
		reader.Close()
		clear(custodyKey)
		return nil, true, d.ErrNotReady
	}
	defer clear(custodyKey)
	native := selection.Native
	native.InventorySHA256 = c.RedisReadServiceInventorySHA(in.Authority, source, id)
	native.Operation = native.InventorySHA256[:32]
	w.gate, e = sb.PrepareRedisReadServiceGate(ctx, admin, reader, o.Client, native, w.nativeCheck, custodyKey)
	if e != nil {
		admin.Close()
		reader.Close()
		return nil, true, e
	}
	// Retain the existing deployment checkpoint vocabulary for source resource
	// capture. Its fence now ALSO binds the original native ACL digest.
	cp.FenceID += "/redis/" + w.gate.OriginalDigest()
	if len(cp.FenceID) > 128 {
		w.gate.Close()
		return nil, true, d.ErrNotReady
	}
	// Use the exact existing wire field set/order, not the observer projection
	// (sourceRecoveryCheckpoint also contains fields of other runtime kinds).
	raw, e := json.Marshal(struct {
		Version, Namespace, Name, FenceID, SpecSHA256 string
		Replicas                                      int32
		Pods                                          []q.PodIdentity
	}{cp.Version, cp.Namespace, cp.Name, cp.FenceID, cp.SpecSHA256, cp.Replicas, cp.Pods})
	if e != nil {
		w.gate.Close()
		return nil, true, e
	}
	w.original = w.base
	w.original.Checkpoint = string(raw)
	if s.redisRead == nil {
		s.redisRead = map[string]*formalRedisReadWriter{}
	}
	s.redisRead[key] = w
	return w, true, nil
}

func (w *formalRedisReadWriter) nativeCheck(ctx context.Context) error {
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
	if e != nil || string(pod.UID) != w.selection.Native.PodUID || pod.DeletionTimestamp != nil || len(pod.Spec.Containers) != 1 || pod.Spec.Containers[0].Name != w.selection.Native.Container || len(pod.Spec.InitContainers) != 0 || len(pod.Spec.EphemeralContainers) != 0 || len(pod.Status.ContainerStatuses) != 1 || !pod.Status.ContainerStatuses[0].Ready || pod.Status.ContainerStatuses[0].State.Running == nil || len(cp.Pods) != 1 || len(cp.Pods[0].Containers) != 1 || cp.Pods[0].Containers[0] != pod.Status.ContainerStatuses[0].ContainerID {
		return d.ErrNotReady
	}
	parent := metav1.GetControllerOf(pod)
	if parent == nil || parent.Kind != "ReplicaSet" {
		return d.ErrNotReady
	}
	rs, e := w.owner.Client.AppsV1().ReplicaSets(w.ref.Namespace).Get(ctx, parent.Name, metav1.GetOptions{})
	if e != nil || rs.UID != parent.UID || rs.DeletionTimestamp != nil {
		return d.ErrNotReady
	}
	parent = metav1.GetControllerOf(rs)
	if parent == nil || parent.Kind != "Deployment" || string(parent.UID) != w.ref.UID || parent.Name != w.ref.Name {
		return d.ErrNotReady
	}
	for _, pin := range w.pins() {
		raw, e := pinnedDeploymentFile(pin.File, pin.SHA256, 262144)
		clear(raw)
		if e != nil {
			return e
		}
	}
	return ctx.Err()
}
func hashJSON(value any) string { raw, _ := json.Marshal(value); return hash(raw) }
func (w *formalRedisReadWriter) pins() []install.BootstrapSourceFilePin {
	s := w.selection
	pins := []install.BootstrapSourceFilePin{s.CA, s.KeeperCredential, s.ReaderCredential, s.CustodyKey}
	if s.ClientCertificate != nil {
		pins = append(pins, *s.ClientCertificate, *s.ClientKey)
	}
	return pins
}
func (w *formalRedisReadWriter) connect(ctx context.Context) (_ *sb.RedisClient, _ *sb.RedisClient, err error) {
	if w.nativeCheck(ctx) != nil {
		return nil, nil, d.ErrNotReady
	}
	s := w.selection
	ca, e := pinnedDeploymentFile(s.CA.File, s.CA.SHA256, 262144)
	roots := x509.NewCertPool()
	if e != nil || !roots.AppendCertsFromPEM(ca) {
		return nil, nil, d.ErrNotReady
	}
	transport := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: s.ServerName}
	if s.ClientCertificate != nil {
		cert, e := pinnedDeploymentFile(s.ClientCertificate.File, s.ClientCertificate.SHA256, 262144)
		if e != nil {
			return nil, nil, e
		}
		key, e := pinnedDeploymentFile(s.ClientKey.File, s.ClientKey.SHA256, 262144)
		if e != nil {
			return nil, nil, e
		}
		defer clear(key)
		pair, e := tls.X509KeyPair(cert, key)
		if e != nil {
			return nil, nil, d.ErrNotReady
		}
		transport.Certificates = []tls.Certificate{pair}
	}
	pod, e := w.owner.Client.CoreV1().Pods(s.Native.Namespace).Get(ctx, s.Native.Pod, metav1.GetOptions{})
	if e != nil || string(pod.UID) != s.Native.PodUID || net.ParseIP(pod.Status.PodIP) == nil {
		return nil, nil, d.ErrNotReady
	}
	clients := []*sb.RedisClient{}
	defer func() {
		if err != nil {
			for _, client := range clients {
				client.Close()
			}
		}
	}()
	for n, pin := range []install.BootstrapSourceFilePin{s.KeeperCredential, s.ReaderCredential} {
		raw, e := pinnedDeploymentFile(pin.File, pin.SHA256, 65536)
		if e != nil {
			return nil, nil, e
		}
		var credential struct {
			Username string `json:"username,omitempty"`
			Password []byte `json:"password,omitempty"`
		}
		e = strictBootstrapSourceJSON(raw, &credential)
		clear(raw)
		account, db := s.Native.KeeperAccount, 0
		if n == 1 {
			account, db = s.Native.ReaderAccount, s.Native.Policy.Policy.DB
		}
		if e != nil || credential.Username != account || len(credential.Password) == 0 {
			clear(credential.Password)
			return nil, nil, d.ErrNotReady
		}
		client, e := sb.ConnectRedis(ctx, sb.RedisOptions{Address: net.JoinHostPort(pod.Status.PodIP, strconv.Itoa(s.Port)), Username: account, Password: string(credential.Password), Database: db, TLS: transport.Clone(), MaxReplyBytes: 64 << 20})
		clear(credential.Password)
		if e != nil {
			return nil, nil, e
		}
		clients = append(clients, client)
	}
	if w.nativeCheck(ctx) != nil {
		return nil, nil, d.ErrNotReady
	}
	return clients[0], clients[1], nil
}
func (w *formalRedisReadWriter) Observe(ctx context.Context) (flow.State, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.nativeCheck(ctx) != nil {
		return flow.State{}, d.ErrNotReady
	}
	return w.original, nil
}
func (w *formalRedisReadWriter) Pause(ctx context.Context, original flow.State) (flow.ACK, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if original != w.original || w.recovery || w.nativeCheck(ctx) != nil || w.gate.Acquire(ctx) != nil {
		return flow.ACK{}, d.ErrNotReady
	}
	return flow.ACK{UID: original.UID, Generation: original.Generation, Stopped: true}, nil
}
func (w *formalRedisReadWriter) CheckPaused(ctx context.Context, original flow.State) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if original != w.original {
		return d.ErrNotReady
	}
	return w.gate.Recheck(ctx)
}
func (w *formalRedisReadWriter) Resume(ctx context.Context, original flow.State) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if original != w.original {
		return d.ErrNotReady
	}
	w.recovery = true
	admin, reader, e := w.connect(ctx)
	if e != nil {
		return e
	}
	if e = w.gate.RestoreWithFreshClients(ctx, admin, reader, w.nativeCheck); e != nil {
		admin.Close()
		reader.Close()
		return e
	}
	return w.nativeCheck(ctx)
}

func (s *DeploymentService) observeFormalRedisReadRecovery(ctx context.Context, in d.Input, writer b.FrozenWriter, source b.SourceInventory, metadata productionCaptureMetadata) (c.SourceRecoveryObservation, error) {
	var zero c.SourceRecoveryObservation
	s.redisReadMu.Lock()
	w := s.redisRead[formalRedisCacheKey(in.Authority, writer.ID)]
	s.redisReadMu.Unlock()
	if w == nil {
		return zero, c.ErrSourceRecoveryProofRequired
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.owner.Gate.CheckRecovery(ctx, in.Authority, writer.ID, d.WriterState(writer.Original)) != nil {
		return zero, c.ErrSourceRecoveryProofRequired
	}
	w.in = in
	if writer.Original != w.original || !w.recovery || !reflect.DeepEqual(metadata.Redis, w.selection.Native.Policy) || w.nativeCheck(ctx) != nil {
		return zero, c.ErrSourceRecoveryProofRequired
	}
	proof, e := w.gate.ObserveRecovered(ctx, w.nativeCheck)
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
	facts := c.RedisReadServiceRecoveryFacts{Version: "source-recovery-redis-native-acl.v1", Kind: "redis_read_service", TaskPublicID: in.Authority.TaskPublicID, AttemptNo: in.Authority.AttemptNo, ConfigSHA256: in.Authority.ConfigSHA256, InventorySHA256: c.RedisReadServiceInventorySHA(in.Authority, source, writer.ID), PolicySHA256: hashJSON(metadata.Redis), OriginalACLSHA256: w.gate.OriginalDigest(), Native: proof.Data(), Recovered: []json.RawMessage{raw}}
	if w.nativeCheck(ctx) != nil || proof.Recheck(ctx, facts.Native.Operation, facts.InventorySHA256, "recovered", time.Now()) != nil {
		return zero, c.ErrSourceRecoveryProofRequired
	}
	return c.NewRedisReadServiceRecoveryObservation(ctx, in.Authority, writer, facts, proof)
}
