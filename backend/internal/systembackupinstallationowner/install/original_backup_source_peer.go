package install

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// This is a finite classification of an ACTUAL original native actor's selected
// startup. It is not a role exemption or a claim about arbitrary software's
// ability to make files. The caller still collects all logical SQL/history,
// retained controllers and known independent backup consumers. These two image
// locators were actually observed in B's original field inventory; they are
// comparison DATA and confer no hold/SQL/coverage authority.
const originalPeerMySQLImage = "10.130.14.23:5000/mysql@sha256:5ea882b1859d3a61814e527215563d809a9f2bf70ffa24c9280f2ff6798f1977"
const originalPeerRedisImage = "docker.io/library/redis@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf"

func classifyOriginalBackupSourcePeer(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, pod *corev1.Pod, spec *corev1.PodSpec, c *corev1.Container, status *corev1.ContainerStatus, init bool) (originalBackupStartupDisposition, error) {
	zero := originalBackupStartupDisposition{}
	if !originalEmptyHistoryOwner(ctx, p, h, false) || h.set.historyMounted == nil || !h.set.historyMounted.local(ctx) || h.set.historyMounted.installer != p.operator.installer {
		return zero, ErrInstall
	}
	// An old template without an actually associated original Pod must be
	// interpreted independently. A current tag or a fabricated status cannot
	// give that old template the current native actor's identity.
	if pod == nil || spec == nil || c == nil || status == nil {
		return zero, errOriginalBackupConsumerUnclassified
	}
	actual, err := originalPeerCapturedPod(h, pod)
	if err != nil {
		return zero, err
	}
	if !originalPeerContainerMatches(actual, spec, c, status, init) {
		return zero, ErrInstall
	}
	if init {
		// Real overridden init scripts are concrete additional startup inputs;
		// they are not silently covered by the main native server's identity.
		return zero, errOriginalBackupConsumerUnclassified
	}
	profile := ""
	until := p.until
	for _, cap := range []time.Time{h.set.owner.until, h.set.historyMounted.until, p.reservation.ExpiresAt} {
		if cap.IsZero() {
			return zero, ErrInstall
		}
		if cap.Before(until) {
			until = cap
		}
	}
	if cap, ok := ctx.Deadline(); !ok {
		return zero, ErrInstall
	} else if cap.Before(until) {
		until = cap
	}
	var native any
	switch status.ImageID {
	case originalPeerMySQLImage:
		if !originalPeerNativeEntry(spec, c, "mysqld") {
			return zero, errOriginalBackupConsumerUnclassified
		}
		// This is the same native identity relation used by D's real original
		// preflight, re-read through the authenticated TLS/UUID pinned SQL
		// connection. A selected Role alone cannot make an arbitrary Pod a DB.
		var uuid, host string
		if p.operator.installer.db.QueryRowContext(ctx, "SELECT @@server_uuid, @@hostname").Scan(&uuid, &host) != nil || uuid != p.operator.installer.plan.Target.ServerUUID || host == "" || actual.Status.Phase != corev1.PodRunning || actual.Name != host && actual.Spec.Hostname != host {
			return zero, ErrInstall
		}
		profile = "original-observed-native-mysql-startup.v1"
		native = struct{ ServerUUID, Hostname string }{uuid, host}
	case originalPeerRedisImage:
		if !originalPeerNativeEntry(spec, c, "redis-server") {
			return zero, errOriginalBackupConsumerUnclassified
		}
		matched := false
		for _, w := range h.set.deployments {
			if w == nil || w.owner != h.set.owner || w.redis == nil || w.redis.set != h.set || w.redis.writer != w || w.redis.held == nil {
				continue
			}
			proof := w.redis.held
			data := proof.Data()
			if data.PodUID != string(actual.UID) {
				continue
			}
			member := false
			for _, old := range w.pods {
				member = member || old.UID == string(actual.UID) && old.Name == actual.Name && old.Node == actual.Spec.NodeName
			}
			if matched || !member || proof.Recheck(ctx, h.set.owner.operation, h.set.inventorySHA, "held", time.Now().UTC()) != nil || data.ServerRunID == "" || data.ACLStateSHA256 == "" {
				return zero, ErrInstall
			}
			matched = true
			if data.ValidUntil.Before(until) {
				until = data.ValidUntil
			}
			// Exclude changing read timestamps from source identity; preserve the
			// ORIGINAL cap separately. Re-reading cannot extend the producer cap.
			native = struct{ PodUID, ServerRunID, ACLStateSHA256, Operation, Inventory string }{data.PodUID, data.ServerRunID, data.ACLStateSHA256, data.Operation, data.InventorySHA256}
		}
		if !matched {
			return zero, errOriginalBackupConsumerUnclassified
		}
		profile = "original-held-native-redis-startup.v1"
	default:
		return classifyOriginalBackupNativePeer(ctx, p, h, actual, spec, c, status, until)
	}
	if !time.Now().Before(until) || !originalEmptyHistoryOwner(ctx, p, h, false) {
		return zero, ErrInstall
	}
	return originalBackupStartupDisposition{kind: "original_non_backup_consumer", version: profile, sourceSHA256: originalObjectSHA(struct {
		Version, PodUID, ImageID string
		Container                corev1.Container
		Native                   any
	}{profile, string(actual.UID), status.ImageID, *c, native}), until: until}, nil
}

// The public helper parameters are DATA. Resolve them back to the original
// private API capture and initial complete Pod census before using any field.
func originalPeerCapturedPod(h *OriginalWriterHold, input *corev1.Pod) (*corev1.Pod, error) {
	if h == nil || h.set == nil || h.set.historyMounted == nil || input == nil || input.UID == "" {
		return nil, ErrInstall
	}
	initial := false
	for _, pin := range h.set.initial.Pods {
		initial = initial || pin.UID == string(input.UID) && pin.Name == input.Name
	}
	if !initial {
		return nil, ErrInstall
	}
	var found *corev1.Pod
	for _, o := range h.set.historyMounted.objects {
		if o == nil || o.kind != "Pod" || o.uid != string(input.UID) {
			continue
		}
		var old corev1.Pod
		if found != nil || hash(o.body) != o.digest || json.Unmarshal(o.body, &old) != nil || o.namespace != old.Namespace || o.name != old.Name || o.uid != string(old.UID) || !reflect.DeepEqual(old, *input) {
			return nil, ErrInstall
		}
		found = &old
	}
	if found == nil {
		return nil, ErrInstall
	}
	return found, nil
}

func originalPeerContainerMatches(pod *corev1.Pod, spec *corev1.PodSpec, c *corev1.Container, status *corev1.ContainerStatus, init bool) bool {
	if pod == nil || spec == nil || c == nil || status == nil || status.Name != c.Name || status.ImageID == "" || status.ContainerID == "" {
		return false
	}
	containers, statuses := pod.Spec.Containers, pod.Status.ContainerStatuses
	requested := spec.Containers
	if init {
		containers, statuses, requested = pod.Spec.InitContainers, pod.Status.InitContainerStatuses, spec.InitContainers
	}
	count := 0
	for _, x := range requested {
		if x.Name == c.Name {
			if !reflect.DeepEqual(x, *c) {
				return false
			}
			count++
		}
	}
	if count != 1 {
		return false
	}
	count = 0
	for _, x := range containers {
		if x.Name == c.Name {
			// Pod and retained controller must select the same actual container.
			// A differing override/mount is not excused by sharing an imageID.
			if !originalPeerCapturedContainerEqual(pod, spec, x, *c) {
				return false
			}
			count++
		}
	}
	if count != 1 {
		return false
	}
	count = 0
	for _, x := range statuses {
		if x.Name == c.Name {
			if !reflect.DeepEqual(x, *status) {
				return false
			}
			count++
		}
	}
	if count != 1 {
		return false
	}
	for _, mount := range c.VolumeMounts {
		var old, selected *corev1.Volume
		for n := range pod.Spec.Volumes {
			if pod.Spec.Volumes[n].Name == mount.Name {
				if old != nil {
					return false
				}
				old = &pod.Spec.Volumes[n]
			}
		}
		for n := range spec.Volumes {
			if spec.Volumes[n].Name == mount.Name {
				if selected != nil {
					return false
				}
				selected = &spec.Volumes[n]
			}
		}
		if old == nil || selected == nil || !reflect.DeepEqual(*old, *selected) {
			return false
		}
	}
	return true
}

// Recognize only the native server invocation. Actual alternate scripts,
// config-file startup entries and explicit module/init loaders remain concrete
// unsupported inputs. Ordinary server settings are not treated as hypothetical
// backup programs, and generic native write capabilities add no global gate.
func originalPeerNativeEntry(spec *corev1.PodSpec, c *corev1.Container, binary string) bool {
	if spec == nil || c == nil || c.Lifecycle != nil || len(c.VolumeDevices) != 0 {
		return false
	}
	if len(c.Command) > 1 || len(c.Command) == 1 && c.Command[0] != binary && c.Command[0] != "/usr/local/bin/"+binary && c.Command[0] != "/usr/sbin/"+binary {
		return false
	}
	args := c.Args
	if len(args) > 0 && args[0] == binary {
		args = args[1:]
	}
	for _, arg := range args {
		if strings.ContainsAny(arg, "\x00\r\n") || strings.Contains(arg, "$(") {
			return false
		}
	}
	if len(args) > 0 && !strings.HasPrefix(args[0], "--") {
		return false
	}
	for n := 0; n < len(args); n++ {
		option := strings.SplitN(args[n], "=", 2)
		key := option[0]
		allowed := false
		if binary == "mysqld" {
			switch key {
			case "--innodb-use-native-aio", "--binlog-expire-logs-seconds", "--max-binlog-size", "--port", "--datadir", "--ssl-ca", "--ssl-cert", "--ssl-key", "--require-secure-transport", "--tls-version":
				allowed = true
			}
		} else if binary == "redis-server" {
			switch key {
			case "--appendonly", "--port", "--tls-port", "--tls-cert-file", "--tls-key-file", "--tls-ca-cert-file", "--tls-auth-clients", "--aclfile", "--bind", "--protected-mode", "--dir", "--dbfilename", "--save":
				allowed = true
			}
		}
		if !allowed {
			return false
		}
		if len(option) == 1 {
			n++
			if n >= len(args) || strings.HasPrefix(args[n], "--") {
				return false
			}
		}
	}
	if len(c.EnvFrom) != 0 {
		return false
	}
	for _, env := range c.Env {
		if env.Name == "LD_PRELOAD" || env.Name == "LD_LIBRARY_PATH" || env.Name == "BASH_ENV" || env.Name == "ENV" {
			return false
		}
	}
	for _, m := range c.VolumeMounts {
		if m.MountPath == "/" || m.MountPath == "/bin" || strings.HasPrefix(m.MountPath, "/bin/") || m.MountPath == "/usr" || strings.HasPrefix(m.MountPath, "/usr/") || m.MountPath == "/docker-entrypoint.sh" || strings.HasPrefix(m.MountPath, "/docker-entrypoint-initdb.d") || m.MountPath == "/etc" || strings.HasPrefix(m.MountPath, "/etc/mysql") || strings.HasPrefix(m.MountPath, "/etc/redis") {
			return false
		}
	}
	return true
}
