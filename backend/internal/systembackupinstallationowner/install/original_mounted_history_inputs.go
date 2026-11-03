package install

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Current referenced Kubernetes API bytes, not actual container mount bytes,
// loaded process configuration, a complete historical universe or admission.
// The authenticated original writer preflight is the only production caller.
// Never journal, export, serialize or use this as PreparedCoverage. In
// particular, original historical versions and native filesystem contents
// remain required even when this current Kubernetes read succeeded.
type originalMountedHistoryInputs struct {
	origin    *originalMountedHistoryInputs
	installer *Installer
	ctx       context.Context
	at        time.Time
	until     time.Time
	revision  string
	objects   map[string]*originalMountedHistoryObject
	bindings  []originalMountedHistoryBinding
	closed    bool
}

type originalMountedHistoryObject struct {
	kind, namespace, name, uid, resourceVersion, digest string
	body                                                []byte
}

type originalMountedHistoryBinding struct {
	OwnerKind, OwnerName, OwnerUID, Container, Input, Kind, Name, Key string
}

const originalMountedHistoryMaxObjects = 512
const originalMountedHistoryMaxObjectBytes = 2 << 20
const originalMountedHistoryMaxBytes = 16 << 20
const originalMountedHistoryMaxBindings = 4096

func (*originalMountedHistoryInputs) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*originalMountedHistoryInputs) String() string               { return "OriginalMountedHistoryInputs" }
func (*originalMountedHistoryInputs) GoString() string             { return "OriginalMountedHistoryInputs" }

// Caller has just authenticated the original set and obtained these actual
// API objects through readKubernetesCensus. No public DTO or replacement context is
// accepted. All I/O precedes source stop and final SQL locks. The set retains
// these referenced API bytes even if original Pods are later stopped/deleted.
// API body stability does NOT establish what kubelet projected or the process
// loaded: subPath/config reload lag and retired versions remain UNKNOWN.
func readOriginalMountedHistoryInputs(ctx context.Context, i *Installer, pods []corev1.Pod, deployments []appsv1.Deployment, until time.Time) (result *originalMountedHistoryInputs, err error) {
	if ctx == nil || ctx.Err() != nil || i == nil || nilClient(i.kube) || i.plan.Target.Namespace == "" || i.plan.Target.NamespaceUID == "" || !time.Now().Before(until) {
		return nil, ErrInstall
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || len(pods)+len(deployments) == 0 {
		return nil, ErrInstall
	}
	if deadline.Before(until) {
		until = deadline
	}
	s := &originalMountedHistoryInputs{installer: i, ctx: ctx, at: time.Now(), until: until, objects: make(map[string]*originalMountedHistoryObject)}
	s.origin = s
	defer func() {
		if err != nil {
			s.close()
		}
	}()
	if s.checkNamespace(ctx) != nil {
		return nil, ErrInstall
	}
	owners := make(map[string]bool)
	addOwner := func(kind, namespace, name, uid, rv string, spec corev1.PodSpec, body any) error {
		key := kind + "/" + name
		if namespace != i.plan.Target.Namespace || name == "" || uid == "" || rv == "" || owners[key] {
			return ErrInstall
		}
		owners[key] = true
		if s.retain(kind, namespace, name, uid, rv, body) != nil {
			return ErrInstall
		}
		bind := func(container, input, refKind, refName, key string) error {
			if refName == "" || len(s.bindings) >= originalMountedHistoryMaxBindings {
				return ErrInstall
			}
			s.bindings = append(s.bindings, originalMountedHistoryBinding{kind, name, uid, container, input, refKind, refName, key})
			return s.readReference(ctx, refKind, refName)
		}
		for _, volume := range spec.Volumes {
			if volume.Secret != nil && bind("", "volume:"+volume.Name, "Secret", volume.Secret.SecretName, "") != nil {
				return ErrInstall
			}
			if volume.ConfigMap != nil && bind("", "volume:"+volume.Name, "ConfigMap", volume.ConfigMap.Name, "") != nil {
				return ErrInstall
			}
			if volume.Projected != nil {
				for _, source := range volume.Projected.Sources {
					if source.Secret != nil && bind("", "projected:"+volume.Name, "Secret", source.Secret.Name, "") != nil {
						return ErrInstall
					}
					if source.ConfigMap != nil && bind("", "projected:"+volume.Name, "ConfigMap", source.ConfigMap.Name, "") != nil {
						return ErrInstall
					}
				}
			}
		}
		container := func(c corev1.Container) error {
			for _, source := range c.EnvFrom {
				if source.SecretRef != nil && bind(c.Name, "envFrom", "Secret", source.SecretRef.Name, "") != nil {
					return ErrInstall
				}
				if source.ConfigMapRef != nil && bind(c.Name, "envFrom", "ConfigMap", source.ConfigMapRef.Name, "") != nil {
					return ErrInstall
				}
			}
			for _, v := range c.Env {
				if v.ValueFrom == nil {
					continue
				}
				if v.ValueFrom.SecretKeyRef != nil && bind(c.Name, "env:"+v.Name, "Secret", v.ValueFrom.SecretKeyRef.Name, v.ValueFrom.SecretKeyRef.Key) != nil {
					return ErrInstall
				}
				if v.ValueFrom.ConfigMapKeyRef != nil && bind(c.Name, "env:"+v.Name, "ConfigMap", v.ValueFrom.ConfigMapKeyRef.Name, v.ValueFrom.ConfigMapKeyRef.Key) != nil {
					return ErrInstall
				}
			}
			return nil
		}
		for _, c := range spec.InitContainers {
			if container(c) != nil {
				return ErrInstall
			}
		}
		for _, c := range spec.Containers {
			if container(c) != nil {
				return ErrInstall
			}
		}
		for _, c := range spec.EphemeralContainers {
			if container(corev1.Container{Name: c.Name, Env: c.Env, EnvFrom: c.EnvFrom}) != nil {
				return ErrInstall
			}
		}
		return nil
	}
	for n := range pods {
		p := &pods[n]
		if p.DeletionTimestamp != nil || addOwner("Pod", p.Namespace, p.Name, string(p.UID), p.ResourceVersion, p.Spec, p) != nil {
			return nil, ErrInstall
		}
	}
	for n := range deployments {
		d := &deployments[n]
		if d.DeletionTimestamp != nil || addOwner("Deployment", d.Namespace, d.Name, string(d.UID), d.ResourceVersion, d.Spec.Template.Spec, d) != nil {
			return nil, ErrInstall
		}
	}
	// Re-read every referenced material, not merely its owner spec/hash. Parent
	// preflight separately repeats the entire namespace/controller/Pod census.
	if s.recheckReferences(ctx) != nil {
		return nil, ErrInstall
	}
	keys := make([]string, 0, len(s.objects))
	for key := range s.objects {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	type pin struct{ Kind, Namespace, Name, UID, ResourceVersion, SHA256 string }
	pins := make([]pin, 0, len(keys))
	for _, key := range keys {
		o := s.objects[key]
		pins = append(pins, pin{o.kind, o.namespace, o.name, o.uid, o.resourceVersion, o.digest})
	}
	// Only identity/digests are used in the original set definition. Bytes and
	// bindings (which may contain private names) remain in this private object.
	s.revision = originalObjectSHA(struct {
		Version string
		Pins    []pin
	}{"original-mounted-history-inputs.v1", pins})
	return s, nil
}

func (s *originalMountedHistoryInputs) local(ctx context.Context) bool {
	return ctx != nil && s != nil && s.origin == s && !s.closed && s.installer != nil && !nilClient(s.installer.kube) && consumerSameContext(ctx, s.ctx) && ctx.Err() == nil && !time.Now().Before(s.at) && time.Now().Before(s.until)
}

func (s *originalMountedHistoryInputs) checkNamespace(ctx context.Context) error {
	if !s.local(ctx) {
		return ErrInstall
	}
	native, cancel := context.WithDeadline(ctx, s.until)
	defer cancel()
	ns, err := s.installer.kube.CoreV1().Namespaces().Get(native, s.installer.plan.Target.Namespace, metav1.GetOptions{})
	if err != nil || !s.local(ctx) || ns.Name != s.installer.plan.Target.Namespace || ns.DeletionTimestamp != nil || string(ns.UID) != s.installer.plan.Target.NamespaceUID {
		return ErrInstall
	}
	return nil
}

func (s *originalMountedHistoryInputs) retain(kind, namespace, name, uid, rv string, value any) error {
	if uid == "" || rv == "" {
		return ErrInstall
	}
	b, err := json.Marshal(value)
	if err != nil || len(b) == 0 || len(b) > originalMountedHistoryMaxObjectBytes {
		clear(b)
		return ErrInstall
	}
	key := kind + "/" + namespace + "/" + name
	if old := s.objects[key]; old != nil {
		defer clear(b)
		if old.uid != uid || old.resourceVersion != rv || old.digest != hash(b) {
			return ErrInstall
		}
		return nil
	}
	total := len(b)
	for _, o := range s.objects {
		total += len(o.body)
	}
	if len(s.objects) >= originalMountedHistoryMaxObjects || total > originalMountedHistoryMaxBytes {
		clear(b)
		return ErrInstall
	}
	s.objects[key] = &originalMountedHistoryObject{kind, namespace, name, uid, rv, hash(b), b}
	return nil
}

func (s *originalMountedHistoryInputs) readReference(ctx context.Context, kind, name string) error {
	if !s.local(ctx) {
		return ErrInstall
	}
	ns := s.installer.plan.Target.Namespace
	native, cancel := context.WithDeadline(ctx, s.until)
	defer cancel()
	switch kind {
	case "ConfigMap":
		o, err := s.installer.kube.CoreV1().ConfigMaps(ns).Get(native, name, metav1.GetOptions{})
		if err != nil || !s.local(ctx) || o.Name != name || o.Namespace != ns || o.DeletionTimestamp != nil {
			return ErrInstall
		}
		return s.retain(kind, ns, name, string(o.UID), o.ResourceVersion, o)
	case "Secret":
		o, err := s.installer.kube.CoreV1().Secrets(ns).Get(native, name, metav1.GetOptions{})
		if err != nil || !s.local(ctx) || o.Name != name || o.Namespace != ns || o.DeletionTimestamp != nil {
			return ErrInstall
		}
		return s.retain(kind, ns, name, string(o.UID), o.ResourceVersion, o)
	default:
		return ErrInstall
	}
}

// Original Pod deletion during an actual authenticated hold does not erase
// retained bytes. This method rechecks original material objects only; native
// hold/census code must separately verify the expected stopped owner state.
// Never call this native method while final SQL locks are held.
func (s *originalMountedHistoryInputs) recheckReferences(ctx context.Context) (err error) {
	if !s.local(ctx) {
		return ErrInstall
	}
	defer func() {
		if err != nil {
			s.close()
		}
	}()
	if s.checkNamespace(ctx) != nil {
		return ErrInstall
	}
	keys := make([]string, 0, len(s.objects))
	for key, o := range s.objects {
		if o.kind == "ConfigMap" || o.kind == "Secret" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		o := s.objects[key]
		if s.readReference(ctx, o.kind, o.name) != nil {
			return ErrInstall
		}
	}
	if !s.local(ctx) || s.checkNamespace(ctx) != nil {
		return ErrInstall
	}
	return nil
}

func (s *originalMountedHistoryInputs) close() {
	if s == nil {
		return
	}
	s.closed = true
	for _, o := range s.objects {
		clear(o.body)
		o.body = nil
	}
	s.objects = nil
	s.bindings = nil
	s.revision = ""
}
