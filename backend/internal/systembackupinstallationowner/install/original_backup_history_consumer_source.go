package install

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"sort"
	"time"

	a "clawreef/internal/systembackupkekadapter"
	reg "clawreef/internal/systembackupkekregistry"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var errOriginalBackupConsumerUnclassified = errors.New("actual original backup consumer startup or source mapping unclassified")

// A/C's exact-image/startup classifiers return DATA, not NoS3 or authority.
// They must identify this actual immutable image/entrypoint/mount combination.
// Unknown overrides, wrappers, standalone writers or missing original versions
// remain specific refusals. The real source constructor below owns the complete
// finite API/SQL roster and positive branch; callers cannot submit this value.
type originalBackupStartupDisposition struct {
	kind, version, sourceSHA256  string
	requiresOriginalLegacyLayout bool
	until                        time.Time
}

type originalFiniteBackupConsumerSource struct {
	origin              *originalFiniteBackupConsumerSource
	ctx                 context.Context
	prep                *PreparedOriginalAdoptionSQLCut
	hold                *OriginalWriterHold
	mounted             *originalMountedHistoryInputs
	mountedRevision     string
	initial             []originalBackupHistoryConsumer
	rsRevision          string
	until               time.Time
	resolved            *originalResolvedBackupHistorySources
	controllerInventory *originalHistoryControllerInventory
	failed              bool
}

func (*originalFiniteBackupConsumerSource) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*originalFiniteBackupConsumerSource) String() string {
	return "OriginalFiniteBackupConsumerSource"
}
func (*originalFiniteBackupConsumerSource) GoString() string {
	return "OriginalFiniteBackupConsumerSource"
}

// Actual production constructor. It reads the genuine retained original
// Pod/Deployment source and actual complete current controller/retired-RS
// roster under the one original holder; no callback/manifest/Passed input.
// General business config.Load and arbitrary hypothetical programs are not
// additional history consumers. Known independent backup startup is rejected
// with its concrete origin until its actual bootstrap/mapping is supported.
func (p *PreparedOriginalAdoptionSQLCut) PrepareOriginalBackupConsumerHistorySource(ctx context.Context, h *OriginalWriterHold) (originalBackupHistoryConsumerSource, error) {
	if p == nil || h == nil || h.set == nil {
		return nil, ErrInstall
	}
	h.set.mu.Lock()
	defer h.set.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	if !originalEmptyHistoryOwner(ctx, p, h, false) || h.recheckBeforeSQL(ctx) != nil || p.operator.authority(ctx, p.enrollment) != nil {
		return nil, ErrInstall
	}
	m := h.set.historyMounted
	if m == nil || !m.local(ctx) || m.installer != p.operator.installer {
		return nil, ErrInstall
	}
	until, bounded := ctx.Deadline()
	if !bounded {
		return nil, ErrInstall
	}
	for _, cap := range []time.Time{p.until, h.set.owner.until, p.reservation.ExpiresAt, m.until} {
		if cap.IsZero() {
			return nil, ErrInstall
		}
		if cap.Before(until) {
			until = cap
		}
	}
	s := &originalFiniteBackupConsumerSource{ctx: ctx, prep: p, hold: h, mounted: m, mountedRevision: m.revision, until: until}
	s.origin = s
	consumers, rs, cap, err := s.observe(ctx)
	if err != nil {
		s.failed = true
		return nil, err
	}
	if cap.Before(s.until) {
		s.until = cap
	}
	s.initial, s.rsRevision = consumers, rs
	if !s.local(ctx, false) || h.recheckBeforeSQL(ctx) != nil {
		return nil, ErrInstall
	}
	return s, nil
}

func (s *originalFiniteBackupConsumerSource) local(ctx context.Context, final bool) bool {
	return s != nil && s.origin == s && !s.failed && consumerSameContext(ctx, s.ctx) && originalEmptyHistoryOwner(ctx, s.prep, s.hold, final) && s.mounted != nil && s.hold.set.historyMounted == s.mounted && s.mounted.local(ctx) && s.mounted.revision == s.mountedRevision && !s.until.IsZero() && time.Now().Before(s.until)
}

// Actual captured original material, never a caller Pod/SourceDescriptor.
func (s *originalFiniteBackupConsumerSource) originalObjects() (map[string]*corev1.Pod, map[string]*appsv1.Deployment, error) {
	pods := map[string]*corev1.Pod{}
	deps := map[string]*appsv1.Deployment{}
	for _, o := range s.mounted.objects {
		if o == nil || hash(o.body) != o.digest || o.namespace != s.prep.operator.installer.plan.Target.Namespace {
			return nil, nil, ErrInstall
		}
		switch o.kind {
		case "Pod":
			var p corev1.Pod
			if json.Unmarshal(o.body, &p) != nil || p.Name != o.name || string(p.UID) != o.uid || p.Namespace != o.namespace || pods[o.uid] != nil {
				return nil, nil, ErrInstall
			}
			pods[o.uid] = &p
		case "Deployment":
			var d appsv1.Deployment
			if json.Unmarshal(o.body, &d) != nil || d.Name != o.name || string(d.UID) != o.uid || d.Namespace != o.namespace || deps[o.uid] != nil {
				return nil, nil, ErrInstall
			}
			deps[o.uid] = &d
		}
	}
	if len(pods) != len(s.hold.set.initial.Pods) || len(deps) != len(s.hold.set.initial.Deployments) {
		return nil, nil, ErrInstall
	}
	for _, pin := range s.hold.set.initial.Pods {
		if pods[pin.UID] == nil || pods[pin.UID].Name != pin.Name {
			return nil, nil, ErrInstall
		}
	}
	for _, pin := range s.hold.set.initial.Deployments {
		if deps[pin.UID] == nil || deps[pin.UID].Name != pin.Name {
			return nil, nil, ErrInstall
		}
	}
	return pods, deps, nil
}

func originalConsumerGap(kind, name, container string) error {
	return OriginalWriterSourceFailure{Dependency: "original_backup_consumer_unclassified:" + kind + "/" + name + "/" + container}
}

func (s *originalFiniteBackupConsumerSource) classify(ctx context.Context, pod *corev1.Pod, spec *corev1.PodSpec, c *corev1.Container, status *corev1.ContainerStatus, init bool) (originalBackupStartupDisposition, error) {
	d, err := classifyOriginalBackupViewStartup(spec, c, status, init)
	if err == nil {
		return d, nil
	}
	if !errors.Is(err, errOriginalBackupConsumerUnclassified) {
		return originalBackupStartupDisposition{}, err
	}
	// C's concrete native-source peer classifier checks actual source identity;
	// service names or a requested writer Role are not blanket exemptions.
	return classifyOriginalBackupSourcePeer(ctx, s.prep, s.hold, pod, spec, c, status, init)
}

func originalContainerStatus(statuses []corev1.ContainerStatus, name string) *corev1.ContainerStatus {
	var found *corev1.ContainerStatus
	for i := range statuses {
		if statuses[i].Name == name {
			if found != nil {
				return nil
			}
			found = &statuses[i]
		}
	}
	return found
}

func originalConsumerFact(id string, d originalBackupStartupDisposition, owner any) originalBackupHistoryConsumer {
	return originalBackupHistoryConsumer{id: id, kind: d.kind, sourceVersion: d.version, sourceSHA256: originalObjectSHA(struct {
		Version, ProfileSource string
		Original               any
	}{"original-observed-backup-consumer.v1", d.sourceSHA256, owner})}
}

func (s *originalFiniteBackupConsumerSource) requireOriginalLegacyLayout(d originalBackupStartupDisposition) bool {
	if !d.requiresOriginalLegacyLayout {
		return true
	}
	return originalRetainedLegacyLayoutMatches(s.prep.observed.Facts())
}

func originalRetainedLegacyLayoutMatches(f a.SQLCoverageCensusFacts) bool {
	seen := map[string]a.SQLCoverageTable{}
	for _, t := range f.Tables {
		if _, duplicate := seen[t.Table]; duplicate {
			return false
		}
		seen[t.Table] = t
	}
	for _, name := range a.RetainedOriginalLegacySourceTables() {
		t, ok := seen[name]
		if !ok || t.Rows != 0 || t.Bytes != 0 {
			return false
		}
	}
	return len(a.RetainedOriginalLegacySourceTables()) == 35
}

func (s *originalFiniteBackupConsumerSource) observe(ctx context.Context) ([]originalBackupHistoryConsumer, string, time.Time, error) {
	if !s.local(ctx, false) || s.mounted.recheckReferences(ctx) != nil || s.hold.recheckBeforeSQL(ctx) != nil || s.prep.operator.authority(ctx, s.prep.enrollment) != nil {
		return nil, "", time.Time{}, ErrInstall
	}
	pods, deps, err := s.originalObjects()
	if err != nil {
		return nil, "", time.Time{}, err
	}
	out := []originalBackupHistoryConsumer{}
	until := s.until
	consume := func(id string, d originalBackupStartupDisposition, body any) error {
		if d.version == "" || !digestPattern.MatchString(d.sourceSHA256) || !s.requireOriginalLegacyLayout(d) {
			return ErrInstall
		}
		switch d.kind {
		case "original_non_backup_consumer", "original_legacy_sql_snapshot", "original_public_sql_snapshot":
		default:
			return errOriginalBackupConsumerUnclassified
		}
		if !d.until.IsZero() && d.until.Before(until) {
			until = d.until
		}
		out = append(out, originalConsumerFact(id, d, body))
		if len(out) > 512 {
			return ErrInstall
		}
		return nil
	}
	// Every actual original Pod, including completed/failed/init containers.
	// No status/TTL/success filter may erase a known original source.
	for uid, pod := range pods {
		if len(pod.Spec.EphemeralContainers) != 0 {
			return nil, "", time.Time{}, originalConsumerGap("Pod", pod.Name, "ephemeral")
		}
		for i := range pod.Spec.Containers {
			c := &pod.Spec.Containers[i]
			status := originalContainerStatus(pod.Status.ContainerStatuses, c.Name)
			d, e := s.classify(ctx, pod, &pod.Spec, c, status, false)
			if e != nil {
				return nil, "", time.Time{}, originalConsumerGap("Pod", pod.Name, c.Name)
			}
			if e = consume("pod/"+uid+"/"+c.Name, d, struct {
				PodUID string
				Spec   corev1.PodSpec
				Status *corev1.ContainerStatus
			}{uid, pod.Spec, status}); e != nil {
				return nil, "", time.Time{}, e
			}
		}
		for i := range pod.Spec.InitContainers {
			c := &pod.Spec.InitContainers[i]
			status := originalContainerStatus(pod.Status.InitContainerStatuses, c.Name)
			d, e := s.classify(ctx, pod, &pod.Spec, c, status, true)
			if e != nil {
				return nil, "", time.Time{}, originalConsumerGap("PodInit", pod.Name, c.Name)
			}
			if e = consume("pod-init/"+uid+"/"+c.Name, d, struct {
				PodUID string
				Spec   corev1.PodSpec
				Status *corev1.ContainerStatus
			}{uid, pod.Spec, status}); e != nil {
				return nil, "", time.Time{}, e
			}
		}
	}
	// Complete actual retained ReplicaSets. A missing old image/version is a
	// concrete UNKNOWN. Do not substitute a current mutable tag or fabricate a
	// Pod/imageID for an old template. A's classifier accepts nil status ONLY
	// when the actual template's immutable image source is independently known.
	type rsFact struct{ Name, UID, OwnerUID, TemplateSHA256 string }
	rss := []rsFact{}
	k := s.prep.operator.installer.kube
	ns := s.hold.set.initial.Namespace
	more := ""
	rv := ""
	seen := map[string]bool{}
	rsOwners := map[string]string{}
	for {
		page, e := k.AppsV1().ReplicaSets(ns).List(ctx, metav1.ListOptions{Limit: 500, Continue: more})
		if e != nil || page.ResourceVersion == "" || (rv != "" && rv != page.ResourceVersion) {
			return nil, "", time.Time{}, ErrInstall
		}
		rv = page.ResourceVersion
		for i := range page.Items {
			r := &page.Items[i]
			uid := string(r.UID)
			owner := metav1.GetControllerOf(r)
			if uid == "" || seen[uid] || len(seen) >= 10000 || r.DeletionTimestamp != nil || owner == nil || owner.Kind != "Deployment" || deps[string(owner.UID)] == nil {
				return nil, "", time.Time{}, originalConsumerGap("ReplicaSet", r.Name, "owner")
			}
			seen[uid] = true
			rsOwners[uid] = string(owner.UID)
			if r.CreationTimestamp.IsZero() || r.CreationTimestamp.Time.After(s.mounted.at) {
				return nil, "", time.Time{}, originalConsumerGap("ReplicaSet", r.Name, "created_after_original_capture")
			}
			rss = append(rss, rsFact{r.Name, uid, string(owner.UID), originalObjectSHA(r.Spec.Template)})
			if len(r.Spec.Template.Spec.EphemeralContainers) != 0 {
				return nil, "", time.Time{}, originalConsumerGap("ReplicaSet", r.Name, "ephemeral")
			}
			for init, containers := range map[bool][]corev1.Container{false: r.Spec.Template.Spec.Containers, true: r.Spec.Template.Spec.InitContainers} {
				for j := range containers {
					c := &containers[j]
					var status *corev1.ContainerStatus
					var actual *corev1.Pod
					for _, p := range pods {
						po := metav1.GetControllerOf(p)
						if po != nil && po.Kind == "ReplicaSet" && string(po.UID) == uid {
							var candidate *corev1.ContainerStatus
							if init {
								candidate = originalContainerStatus(p.Status.InitContainerStatuses, c.Name)
							} else {
								candidate = originalContainerStatus(p.Status.ContainerStatuses, c.Name)
							}
							if candidate != nil {
								if status != nil && status.ImageID != candidate.ImageID {
									return nil, "", time.Time{}, originalConsumerGap("ReplicaSet", r.Name, c.Name)
								}
								if actual == nil || string(p.UID) < string(actual.UID) {
									status, actual = candidate, p
								}
							}
						}
					}
					d, e := s.classify(ctx, actual, &r.Spec.Template.Spec, c, status, init)
					if e != nil {
						return nil, "", time.Time{}, originalConsumerGap("ReplicaSet", r.Name, c.Name)
					}
					prefix := "replicaset/"
					if init {
						prefix = "replicaset-init/"
					}
					if e = consume(prefix+uid+"/"+c.Name, d, struct {
						ReplicaSet rsFact
						Container  corev1.Container
						Status     *corev1.ContainerStatus
					}{rss[len(rss)-1], *c, status}); e != nil {
						return nil, "", time.Time{}, e
					}
				}
			}
		}
		if page.Continue == "" {
			break
		}
		if page.Continue == more {
			return nil, "", time.Time{}, ErrInstall
		}
		more = page.Continue
	}
	// Include every actual original Deployment template, including zero
	// replicas/newly selected entrypoints with no current Pod or RS. Their
	// concrete unknown startup cannot disappear from the finite source roster.
	for uid, dep := range deps {
		if len(dep.Spec.Template.Spec.EphemeralContainers) != 0 {
			return nil, "", time.Time{}, originalConsumerGap("Deployment", dep.Name, "ephemeral")
		}
		for init, containers := range map[bool][]corev1.Container{false: dep.Spec.Template.Spec.Containers, true: dep.Spec.Template.Spec.InitContainers} {
			for i := range containers {
				c := &containers[i]
				var status *corev1.ContainerStatus
				var actual *corev1.Pod
				for _, pod := range pods {
					owner := metav1.GetControllerOf(pod)
					if owner == nil || owner.Kind != "ReplicaSet" || rsOwners[string(owner.UID)] != uid {
						continue
					}
					var old *corev1.Container
					list := pod.Spec.Containers
					if init {
						list = pod.Spec.InitContainers
					}
					for j := range list {
						if list[j].Name == c.Name {
							old = &list[j]
						}
					}
					if old == nil || old.Image != c.Image || !reflect.DeepEqual(old.Command, c.Command) || !reflect.DeepEqual(old.Args, c.Args) {
						continue
					}
					var candidate *corev1.ContainerStatus
					if init {
						candidate = originalContainerStatus(pod.Status.InitContainerStatuses, c.Name)
					} else {
						candidate = originalContainerStatus(pod.Status.ContainerStatuses, c.Name)
					}
					if candidate != nil && (actual == nil || string(pod.UID) < string(actual.UID)) {
						status, actual = candidate, pod
					}
				}
				d, e := s.classify(ctx, actual, &dep.Spec.Template.Spec, c, status, init)
				if e != nil {
					return nil, "", time.Time{}, originalConsumerGap("Deployment", dep.Name, c.Name)
				}
				prefix := "deployment/"
				if init {
					prefix = "deployment-init/"
				}
				if e = consume(prefix+uid+"/"+c.Name, d, struct {
					DeploymentUID string
					Template      corev1.PodTemplateSpec
					Status        *corev1.ContainerStatus
				}{uid, dep.Spec.Template, status}); e != nil {
					return nil, "", time.Time{}, e
				}
			}
		}
	}
	// A fresh complete Deployment walk prevents a new/unlisted/changed
	// controller from being hidden by the original holder's older API paging.
	more = ""
	rv = ""
	seenDeps := map[string]bool{}
	for {
		page, e := k.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{Limit: 500, Continue: more})
		if e != nil || page.ResourceVersion == "" || (rv != "" && rv != page.ResourceVersion) {
			return nil, "", time.Time{}, ErrInstall
		}
		rv = page.ResourceVersion
		for i := range page.Items {
			d := &page.Items[i]
			uid := string(d.UID)
			old := deps[uid]
			if old == nil || seenDeps[uid] || len(seenDeps) >= 10000 || d.Name != old.Name || originalDeploymentSpecSHA(d) != originalDeploymentSpecSHA(old) {
				return nil, "", time.Time{}, originalConsumerGap("Deployment", d.Name, "source_or_membership_change")
			}
			seenDeps[uid] = true
		}
		if page.Continue == "" {
			break
		}
		if page.Continue == more {
			return nil, "", time.Time{}, ErrInstall
		}
		more = page.Continue
	}
	if len(seenDeps) != len(deps) {
		return nil, "", time.Time{}, ErrInstall
	}
	// Kept source Pods must retain their original container identity. Stopped
	// writer Pods may be absent; complete real holder rechecks own that absence.
	more = ""
	rv = ""
	currentSeen := map[string]bool{}
	for {
		page, e := k.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{Limit: 500, Continue: more})
		if e != nil || page.ResourceVersion == "" || (rv != "" && rv != page.ResourceVersion) {
			return nil, "", time.Time{}, ErrInstall
		}
		rv = page.ResourceVersion
		for i := range page.Items {
			p := &page.Items[i]
			uid := string(p.UID)
			old := pods[uid]
			if old == nil || currentSeen[uid] || len(currentSeen) >= 10000 {
				return nil, "", time.Time{}, originalConsumerGap("Pod", p.Name, "original_identity")
			}
			currentSeen[uid] = true
			identity := func(statuses []corev1.ContainerStatus) map[string][2]string {
				m := map[string][2]string{}
				for _, c := range statuses {
					m[c.Name] = [2]string{c.ContainerID, c.ImageID}
				}
				return m
			}
			if !reflect.DeepEqual(p.Spec, old.Spec) || !reflect.DeepEqual(p.OwnerReferences, old.OwnerReferences) || !reflect.DeepEqual(identity(p.Status.ContainerStatuses), identity(old.Status.ContainerStatuses)) || !reflect.DeepEqual(identity(p.Status.InitContainerStatuses), identity(old.Status.InitContainerStatuses)) {
				return nil, "", time.Time{}, originalConsumerGap("Pod", p.Name, "restart_or_source_change")
			}
		}
		if page.Continue == "" {
			break
		}
		if page.Continue == more {
			return nil, "", time.Time{}, ErrInstall
		}
		more = page.Continue
	}
	if s.hold.recheckBeforeSQL(ctx) != nil || s.prep.operator.authority(ctx, s.prep.enrollment) != nil || !s.local(ctx, false) || !time.Now().Before(until) {
		return nil, "", time.Time{}, ErrInstall
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	sort.Slice(rss, func(i, j int) bool { return rss[i].UID < rss[j].UID })
	if len(out) == 0 {
		return nil, "", time.Time{}, ErrInstall
	}
	return out, originalObjectSHA(struct {
		Version     string
		ReplicaSets []rsFact
	}{"original-finite-retained-controller-roster.v1", rss}), until, nil
}

func (s *originalFiniteBackupConsumerSource) boundConsumers(input []originalBackupHistoryConsumer) []originalBackupHistoryConsumer {
	if s == nil || s.controllerInventory == nil {
		return nil
	}
	result := append([]originalBackupHistoryConsumer(nil), input...)
	for i := range result {
		result[i].sourceSHA256 = originalObjectSHA(struct{ Version, Consumer, Mounted, Controllers string }{"original-consumer-with-full-original-inputs.v2", input[i].sourceSHA256, s.mountedRevision, s.controllerInventory.revision})
	}
	return result
}

func (s *originalFiniteBackupConsumerSource) readOriginalBackupHistoryConsumers(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, m *originalHistorySQLMetadata) (*originalResolvedBackupHistorySources, error) {
	if !s.local(ctx, false) || s.prep != p || s.hold != h || m == nil || !m.local(ctx, false) || m.prep != p || m.hold != h || !m.classifiesOriginalSQL(ctx, p.observed.Facts()) {
		return nil, ErrInstall
	}
	if s.controllerInventory == nil {
		inventory, e := readOriginalHistoryControllerInventoryLocked(ctx, p, h, m)
		if e != nil {
			return nil, e
		}
		for _, item := range inventory.items {
			if item.kind != "ReplicaSet" {
				inventory.close()
				return nil, originalConsumerGap(item.kind, item.name, "controller_requires_original_source_gate_and_mapping")
			}
			var rs appsv1.ReplicaSet
			decoder := json.NewDecoder(bytes.NewReader(item.body))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&rs) != nil || decoder.Decode(new(any)) != io.EOF || string(rs.UID) != item.uid || rs.Name != item.name {
				inventory.close()
				return nil, ErrInstall
			}
		}
		s.controllerInventory = inventory
		if inventory.until.Before(s.until) {
			s.until = inventory.until
		}
	} else if s.controllerInventory.metadata != m || s.controllerInventory.recheckBeforeOriginalSQLLocked(ctx) != nil {
		return nil, ErrInstall
	}
	if s.resolved != nil {
		if s.resolved.metadata != m || s.recheckOriginalBackupHistoryConsumersBeforeSQL(ctx, s.resolved) != nil {
			return nil, ErrInstall
		}
		return s.resolved, nil
	}
	current, rs, until, e := s.observe(ctx)
	if e != nil || !reflect.DeepEqual(current, s.initial) || rs != s.rsRevision {
		return nil, ErrInstall
	}
	if until.After(s.until) {
		until = s.until
	}
	if m.until.Before(until) {
		until = m.until
	}
	now, e := p.operator.installer.database(ctx, p.operator.installer.db, until)
	if e != nil || now.Before(m.original.ObservedAt) {
		return nil, ErrInstall
	}
	r := &originalResolvedBackupHistorySources{ctx: ctx, prep: p, hold: h, metadata: m, producer: s, consumers: s.boundConsumers(current), roots: []originalBackupHistoryRoot{}, external: nil, observedAt: now, until: until}
	r.origin = r
	r.revision = originalResolvedBackupHistoryRevision(r)
	s.resolved = r
	return r, nil
}

func (s *originalFiniteBackupConsumerSource) recheckOriginalBackupHistoryConsumersBeforeSQL(ctx context.Context, r *originalResolvedBackupHistorySources) (err error) {
	defer func() {
		if err != nil && s != nil && s.origin == s {
			s.failed = true
		}
	}()
	if !s.local(ctx, false) || r == nil || r != s.resolved || r.origin != r || r.producer != s || r.metadata == nil || !r.metadata.local(ctx, false) || r.revision != originalResolvedBackupHistoryRevision(r) || !time.Now().Before(r.until) {
		return ErrInstall
	}
	if s.controllerInventory == nil || s.controllerInventory.metadata != r.metadata || s.controllerInventory.recheckBeforeOriginalSQLLocked(ctx) != nil {
		return ErrInstall
	}
	current, rs, until, e := s.observe(ctx)
	if e != nil || !reflect.DeepEqual(current, s.initial) || !reflect.DeepEqual(s.boundConsumers(current), r.consumers) || rs != s.rsRevision || until.Before(r.until) {
		return ErrInstall
	}
	return nil
}

func (s *originalFiniteBackupConsumerSource) recheckOriginalBackupHistoryConsumersLocked(ctx context.Context, tx *sql.Tx, locked reg.LockedSnapshot, now time.Time, r *originalResolvedBackupHistorySources) error {
	if !s.local(ctx, true) || r == nil || r != s.resolved || r.origin != r || r.producer != s || r.metadata == nil || r.metadata.boundTx != tx || r.metadata.coverage == nil || r.metadata.coverage.tx != tx || r.metadata.coverage.sourceSet == nil || r.metadata.coverage.sourceSet.consumerSource != s || now.IsZero() || now.Before(r.observedAt) || !now.Before(r.until) || r.revision != originalResolvedBackupHistoryRevision(r) {
		return ErrInstall
	}
	if s.controllerInventory == nil || !s.controllerInventory.matchesOriginalSQLPhase(ctx, r.metadata, now) {
		return ErrInstall
	}
	f := locked.Facts()
	if f.Database != r.metadata.original.Database || f.InstallationID != r.metadata.original.InstallationID || f.References == nil || len(f.References) != 0 || f.Epoch != r.metadata.epoch {
		return ErrInstall
	}
	// Source rows are already locked by the original cut. No Kube/native I/O,
	// separate tx, earlier-prefix acquisition or new source/cap is allowed here.
	if r.metadata.installed.recheckLocked(ctx, tx) != nil {
		return ErrInstall
	}
	_, e := s.prep.operator.installer.database(ctx, tx, r.until)
	return e
}

var _ originalBackupHistoryConsumerSource = (*originalFiniteBackupConsumerSource)(nil)
