package install

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"reflect"
	"strconv"

	sb "clawreef/internal/systembackup"
	c "clawreef/internal/systembackupcontroller"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// INPUTS only. No service-name exemption, caller observation, gate ACK, lease
// count or TTL is accepted. Operation/inventory must be empty and are filled
// exclusively from the genuine complete original set. The selected Deployment
// still participates in the unfiltered complete namespace census.
type OriginalRedisReadKeeperSelection struct {
	Deployment, DeploymentUID, ServerName              string
	Port                                               int
	CA, KeeperCredential, ReaderCredential, CustodyKey BootstrapSourceFilePin
	ClientCertificate, ClientKey                       *BootstrapSourceFilePin `json:",omitempty"`
	Native                                             sb.RedisReadGateInput
}
type originalRedisReadKeeper struct {
	set             *PreparedOriginalWriterSet
	writer          *originalDeploymentMaintenance
	selection       OriginalRedisReadKeeperSelection
	gate            *sb.RedisReadServiceGate
	held, recovered *sb.VerifiedRedisReadServiceObservation
}
type originalRedisCredential struct {
	Username string `json:"username,omitempty"`
	Password []byte `json:"password,omitempty"`
}

func (r *originalRedisReadKeeper) check(ctx context.Context) error {
	if r == nil || r.set == nil || r.writer == nil || r.writer.redis != r || r.writer.owner != r.set.owner || originalMaintenanceReadCheck(ctx, r.set.owner, r.writer.recovery) != nil {
		return ErrInstall
	}
	if r.writer.recovery == nil && r.set.used {
		if r.set.owner.checkCurrentGate(ctx, c.GateAcquiring, c.GateHeld) != nil || r.set.checkApplicationGate(ctx, "acquiring", "held") != nil {
			return ErrInstall
		}
	}
	for _, pin := range r.pins() {
		raw, e := readBootstrapSourcePin(pin, 262144)
		clear(raw)
		if e != nil {
			return ErrInstall
		}
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
func (r *originalRedisReadKeeper) pins() []BootstrapSourceFilePin {
	pins := []BootstrapSourceFilePin{r.selection.CA, r.selection.KeeperCredential, r.selection.ReaderCredential, r.selection.CustodyKey}
	if r.selection.ClientCertificate != nil {
		pins = append(pins, *r.selection.ClientCertificate)
	}
	if r.selection.ClientKey != nil {
		pins = append(pins, *r.selection.ClientKey)
	}
	return pins
}
func (r *originalRedisReadKeeper) connect(ctx context.Context) (_ *sb.RedisClient, _ *sb.RedisClient, err error) {
	if r.check(ctx) != nil {
		return nil, nil, ErrInstall
	}
	s := r.selection
	ca, e := readBootstrapSourcePin(s.CA, 262144)
	if e != nil {
		return nil, nil, ErrInstall
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, nil, ErrInstall
	}
	transport := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: s.ServerName}
	if s.ClientCertificate != nil {
		cert, e := readBootstrapSourcePin(*s.ClientCertificate, 262144)
		if e != nil {
			return nil, nil, ErrInstall
		}
		key, e := readBootstrapSourcePin(*s.ClientKey, 262144)
		if e != nil {
			return nil, nil, ErrInstall
		}
		defer clear(key)
		pair, e := tls.X509KeyPair(cert, key)
		if e != nil {
			return nil, nil, ErrInstall
		}
		transport.Certificates = []tls.Certificate{pair}
	}
	pod, e := r.set.owner.operator.installer.kube.CoreV1().Pods(s.Native.Namespace).Get(ctx, s.Native.Pod, metav1.GetOptions{})
	if e != nil || string(pod.UID) != s.Native.PodUID || net.ParseIP(pod.Status.PodIP) == nil {
		return nil, nil, ErrInstall
	}
	clients := make([]*sb.RedisClient, 0, 2)
	defer func() {
		if err != nil {
			for _, client := range clients {
				_ = client.Close()
			}
		}
	}()
	for n, pin := range []BootstrapSourceFilePin{s.KeeperCredential, s.ReaderCredential} {
		raw, e := readBootstrapSourcePin(pin, 65536)
		if e != nil {
			return nil, nil, ErrInstall
		}
		var credential originalRedisCredential
		e = decodeExact(raw, &credential)
		clear(raw)
		account, db := s.Native.KeeperAccount, 0
		if n == 1 {
			account, db = s.Native.ReaderAccount, s.Native.Policy.Policy.DB
		}
		if e != nil || credential.Username != account || len(credential.Password) == 0 {
			return nil, nil, ErrInstall
		}
		client, e := sb.ConnectRedis(ctx, sb.RedisOptions{Address: net.JoinHostPort(pod.Status.PodIP, strconv.Itoa(s.Port)), Username: account, Password: string(credential.Password), Database: db, TLS: transport.Clone(), MaxReplyBytes: 64 << 20})
		clear(credential.Password)
		if e != nil {
			return nil, nil, ErrInstall
		}
		clients = append(clients, client)
	}
	if r.check(ctx) != nil {
		return nil, nil, ErrInstall
	}
	return clients[0], clients[1], nil
}

func (s *PreparedOriginalWriterSet) prepareRedisReadKeeper(ctx context.Context, w *originalDeploymentMaintenance, selection OriginalRedisReadKeeperSelection) error {
	if s == nil || w == nil || w.redis != nil || selection.Deployment != w.selection.Name || selection.DeploymentUID != w.selection.UID || w.replicas != 1 || len(w.pods) != 1 || selection.Native.Namespace != w.namespace || selection.Native.NamespaceUID != s.initial.NamespaceUID || selection.Native.Pod != w.pods[0].Name || selection.Native.PodUID != w.pods[0].UID || selection.Native.Operation != "" || selection.Native.InventorySHA256 != "" || selection.ServerName == "" || selection.Port < 1 || selection.Port > 65535 || (selection.ClientCertificate == nil) != (selection.ClientKey == nil) {
		return ErrInstall
	}
	r := &originalRedisReadKeeper{set: s, writer: w, selection: selection}
	w.redis = r
	admin, reader, e := r.connect(ctx)
	if e != nil {
		return e
	}
	key, e := readBootstrapSourcePin(selection.CustodyKey, 32)
	if e != nil {
		admin.Close()
		reader.Close()
		return ErrInstall
	}
	defer clear(key)
	in := selection.Native
	in.Operation = s.owner.operation
	in.InventorySHA256 = s.inventorySHA
	r.gate, e = sb.PrepareRedisReadServiceGate(ctx, admin, reader, s.owner.operator.installer.kube, in, r.check, key)
	if e != nil {
		admin.Close()
		reader.Close()
		return e
	}
	checkpoint, e := json.Marshal(struct{ Version, DeploymentCheckpoint, OriginalACLSHA256 string }{"original-deployment-native-redis-checkpoint.v1", w.original.Checkpoint, r.gate.OriginalDigest()})
	if e != nil {
		return ErrInstall
	}
	w.original.Checkpoint = string(checkpoint)
	return r.check(ctx)
}
func (r *originalRedisReadKeeper) acquire(ctx context.Context) error {
	w := r.writer
	if w.stopDispatched || r.check(ctx) != nil || w.journal.append(ctx, w.ID(), "redis_acl_gate_send_unknown", &w.original, r.selection.Native) != nil {
		return ErrInstall
	}
	w.stopDispatched = true
	if r.gate.Acquire(ctx) != nil {
		return ErrInstall
	}
	return r.observeHeld(ctx)
}
func (r *originalRedisReadKeeper) observeHeld(ctx context.Context) error {
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
func (r *originalRedisReadKeeper) restore(ctx context.Context, fence *originalWriterRecoveryFence) error {
	if fence == nil || fence.owner != r.set.owner || fence.checkReleasing(ctx) != nil {
		return ErrInstall
	}
	r.writer.recovery = fence
	if r.writer.journal.append(ctx, r.writer.ID(), "redis_acl_restore_send_unknown", &r.writer.original, nil) != nil {
		return ErrInstall
	}
	admin, reader, e := r.connect(ctx)
	if e != nil {
		return e
	}
	if r.gate.RestoreWithFreshClients(ctx, admin, reader, r.check) != nil {
		_ = admin.Close()
		_ = reader.Close()
		return ErrInstall
	}
	return r.observeRecovered(ctx)
}
func (r *originalRedisReadKeeper) observeRecovered(ctx context.Context) error {
	if r.check(ctx) != nil {
		return ErrInstall
	}
	if !r.writer.stopDispatched {
		if r.gate.ConfirmNeverAcquired(ctx, r.check) != nil {
			return ErrInstall
		}
	}
	proof, e := r.gate.ObserveRecovered(ctx, r.check)
	if e != nil {
		return e
	}
	r.recovered = proof
	return nil
}

// The original complete source collector may consume this concrete held
// Redis reader. A matching server/DB alone cannot choose a different policy.
func (h *OriginalWriterHold) CaptureOriginalRedis(ctx context.Context, policy sb.RedisCapturePolicy, dst io.Writer) error {
	if h == nil || h.set == nil || dst == nil {
		return ErrInstall
	}
	h.set.mu.Lock()
	defer h.set.mu.Unlock()
	if h.recheckBeforeSQL(ctx) != nil {
		return ErrInstall
	}
	var selected *originalRedisReadKeeper
	for _, w := range h.set.deployments {
		if w.redis != nil && reflect.DeepEqual(w.redis.selection.Native.Policy, policy) {
			if selected != nil {
				return ErrInstall
			}
			selected = w.redis
		}
	}
	if selected == nil {
		return ErrInstall
	}
	return selected.gate.Capture(ctx, dst, selected.check)
}
