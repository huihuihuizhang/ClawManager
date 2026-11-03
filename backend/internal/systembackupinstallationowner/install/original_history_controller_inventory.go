package install

import (
	"context"
	"io"
	"reflect"
	"sort"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// Actual currently retained controller definitions, including scale-zero
// ReplicaSets. This is source DATA, not all deleted historical versions, a
// consumer classifier, NoS3, a writer fence or PreparedCoverage. Raw unknown
// object fields are retained for D's real supported-consumer decoder.
type originalHistoryControllerInventory struct {
	origin                  *originalHistoryControllerInventory
	ctx                     context.Context
	prep                    *PreparedOriginalAdoptionSQLCut
	hold                    *OriginalWriterHold
	metadata                *originalHistorySQLMetadata
	namespace, namespaceUID string
	items                   []originalHistoryControllerDefinition
	collections             []originalHistoryControllerCollection
	revision                string
	observedAt, until       time.Time
	failed                  bool
}

type originalHistoryControllerDefinition struct {
	kind, namespace, name, uid, version, sha256 string
	body                                        []byte
}
type originalHistoryControllerCollection struct{ kind, resource, version string }
type originalHistoryControllerResource struct {
	kind, resource, apiVersion string
	client                     rest.Interface
}

func (*originalHistoryControllerInventory) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*originalHistoryControllerInventory) String() string {
	return "OriginalHistoryControllerInventory"
}
func (*originalHistoryControllerInventory) GoString() string {
	return "OriginalHistoryControllerInventory"
}
func (r *originalHistoryControllerInventory) close() {
	if r == nil {
		return
	}
	if r.origin == r || r.origin == nil {
		for n := range r.items {
			clear(r.items[n].body)
		}
	}
	r.items = nil
	r.failed = true
}

// D's concrete producer calls this from its first real read(ctx,p,h,metadata),
// already under original set.mu -> prep.mu. No caller client/namespace/body or
// context replacement is accepted. Store the actual returned pointer; repeated
// source reads use its actual recheck, not a new cap or new empty observation.
func readOriginalHistoryControllerInventoryLocked(ctx context.Context, p *PreparedOriginalAdoptionSQLCut, h *OriginalWriterHold, m *originalHistorySQLMetadata) (result *originalHistoryControllerInventory, err error) {
	if !originalEmptyHistoryOwner(ctx, p, h, false) || m == nil || m.prep != p || m.hold != h || !m.local(ctx, false) || h.recheckBeforeSQL(ctx) != nil || p.operator.authority(ctx, p.enrollment) != nil {
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
	i := p.operator.installer
	r := &originalHistoryControllerInventory{ctx: ctx, prep: p, hold: h, metadata: m, namespace: i.plan.Target.Namespace, namespaceUID: i.plan.Target.NamespaceUID, until: until}
	r.origin = r
	defer func() {
		if err != nil {
			r.close()
		}
	}()
	r.items, r.collections, err = r.readActual(ctx)
	if err != nil {
		return nil, err
	}
	r.revision = originalHistoryControllerRevision(r.namespace, r.namespaceUID, r.items, r.collections)
	r.observedAt = time.Now().UTC()
	if err = r.recheckBeforeOriginalSQLLocked(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *originalHistoryControllerInventory) local(ctx context.Context, final bool) bool {
	if r == nil || r.origin != r || r.failed || !consumerSameContext(ctx, r.ctx) || !originalEmptyHistoryOwner(ctx, r.prep, r.hold, final) || r.metadata == nil || r.metadata.prep != r.prep || r.metadata.hold != r.hold || !r.metadata.local(ctx, final) || r.namespace == "" || r.namespaceUID == "" || !time.Now().Before(r.until) {
		return false
	}
	i := r.prep.operator.installer
	if i == nil || r.namespace != i.plan.Target.Namespace || r.namespaceUID != i.plan.Target.NamespaceUID {
		return false
	}
	for _, item := range r.items {
		if hash(item.body) != item.sha256 {
			return false
		}
	}
	if r.revision != "" && r.revision != originalHistoryControllerRevision(r.namespace, r.namespaceUID, r.items, r.collections) {
		return false
	}
	return true
}

func (r *originalHistoryControllerInventory) guard(ctx context.Context) error {
	if !r.local(ctx, false) || r.hold.recheckBeforeSQL(ctx) != nil || r.prep.operator.authority(ctx, r.prep.enrollment) != nil || !r.local(ctx, false) {
		return ErrInstall
	}
	return nil
}

func (r *originalHistoryControllerInventory) readActual(ctx context.Context) (items []originalHistoryControllerDefinition, collections []originalHistoryControllerCollection, err error) {
	if r.guard(ctx) != nil {
		return nil, nil, ErrInstall
	}
	i := r.prep.operator.installer
	ns, err := i.kube.CoreV1().Namespaces().Get(ctx, r.namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != r.namespaceUID || ns.DeletionTimestamp != nil {
		return nil, nil, ErrInstall
	}
	resources := []originalHistoryControllerResource{
		{"ReplicaSet", "replicasets", "apps/v1", i.kube.AppsV1().RESTClient()},
		{"StatefulSet", "statefulsets", "apps/v1", i.kube.AppsV1().RESTClient()},
		{"DaemonSet", "daemonsets", "apps/v1", i.kube.AppsV1().RESTClient()},
		{"Job", "jobs", "batch/v1", i.kube.BatchV1().RESTClient()},
		{"CronJob", "cronjobs", "batch/v1", i.kube.BatchV1().RESTClient()},
	}
	defer func() {
		if err != nil {
			for n := range items {
				clear(items[n].body)
			}
		}
	}()
	total := 0
	uids := map[string]bool{}
	for _, resource := range resources {
		part, version, e := readOriginalHistoryControllerPages(ctx, resource, r.namespace)
		if e != nil {
			return items, nil, e
		}
		for _, item := range part {
			if uids[item.uid] {
				for n := range part {
					clear(part[n].body)
				}
				return items, nil, ErrInstall
			}
			uids[item.uid] = true
			total += len(item.body)
		}
		items = append(items, part...)
		if len(items) > 1024 || total > 32<<20 {
			return items, nil, ErrInstall
		}
		collections = append(collections, originalHistoryControllerCollection{resource.kind, resource.resource, version})
	}
	if r.guard(ctx) != nil {
		return items, nil, ErrInstall
	}
	sort.Slice(items, func(a, b int) bool {
		if items[a].kind != items[b].kind {
			return items[a].kind < items[b].kind
		}
		return items[a].name < items[b].name
	})
	return items, collections, nil
}

// Actual bounded LIST pages. Collection RV is fixed within each pagination
// sequence; Continue must truly reach empty. No name/label/phase/time filtering.
func readOriginalHistoryControllerPages(ctx context.Context, source originalHistoryControllerResource, namespace string) (result []originalHistoryControllerDefinition, version string, err error) {
	if ctx == nil || ctx.Err() != nil || source.client == nil || namespace == "" {
		return nil, "", ErrInstall
	}
	v := reflect.ValueOf(source.client)
	if v.Kind() == reflect.Pointer && v.IsNil() {
		return nil, "", ErrInstall
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, "", ErrInstall
	}
	seenTokens := map[string]bool{}
	seenNames := map[string]bool{}
	seenUIDs := map[string]bool{}
	next := ""
	total := 0
	defer func() {
		if err != nil {
			for n := range result {
				clear(result[n].body)
			}
			result = nil
		}
	}()
	for page := 0; page < 64; page++ {
		request := source.client.Get().Namespace(namespace).Resource(source.resource).SetHeader("Accept", "application/json").Param("limit", "128")
		if next != "" {
			request = request.Param("continue", next)
		}
		body, e := request.Stream(ctx)
		if e != nil {
			return result, "", ErrInstall
		}
		raw, e := io.ReadAll(io.LimitReader(body, 8<<20+1))
		closeErr := body.Close()
		if e != nil || closeErr != nil || len(raw) > 8<<20 || ctx.Err() != nil {
			clear(raw)
			return result, "", ErrInstall
		}
		items, rv, token, e := decodeOriginalHistoryControllerPage(raw, source, namespace)
		clear(raw)
		if e != nil {
			return result, "", e
		}
		if version == "" {
			version = rv
		}
		if version != rv {
			for n := range items {
				clear(items[n].body)
			}
			return result, "", ErrInstall
		}
		for _, item := range items {
			if seenNames[item.name] || seenUIDs[item.uid] {
				for n := range items {
					clear(items[n].body)
				}
				return result, "", ErrInstall
			}
			seenNames[item.name] = true
			seenUIDs[item.uid] = true
			total += len(item.body)
		}
		result = append(result, items...)
		if len(result) > 1024 || total > 32<<20 {
			return result, "", ErrInstall
		}
		if token == "" {
			return result, version, nil
		}
		if len(token) > 8192 || seenTokens[token] {
			return result, "", ErrInstall
		}
		seenTokens[token] = true
		next = token
	}
	return result, "", ErrInstall
}

// Global LIST RV may advance because another namespace changed. It is retained
// as locator DATA but not compared across rounds. Exact original member UID/RV
// and FULL original member bytes must still match; no object fields are dropped.
func originalHistoryControllerRevision(namespace, uid string, items []originalHistoryControllerDefinition, collections []originalHistoryControllerCollection) string {
	type member struct{ Kind, Namespace, Name, UID, Version, SHA256 string }
	type collection struct{ Kind, Resource string }
	members := make([]member, 0, len(items))
	kinds := make([]collection, 0, len(collections))
	for _, item := range items {
		members = append(members, member{item.kind, item.namespace, item.name, item.uid, item.version, item.sha256})
	}
	for _, item := range collections {
		kinds = append(kinds, collection{item.kind, item.resource})
	}
	sort.Slice(members, func(a, b int) bool {
		if members[a].Kind != members[b].Kind {
			return members[a].Kind < members[b].Kind
		}
		return members[a].Name < members[b].Name
	})
	sort.Slice(kinds, func(a, b int) bool { return kinds[a].Kind < kinds[b].Kind })
	return originalObjectSHA(struct {
		Version, Namespace, UID string
		Members                 []member
		Collections             []collection
	}{"original-retained-history-controller-inputs.v1", namespace, uid, members, kinds})
}

func (r *originalHistoryControllerInventory) recheckBeforeOriginalSQLLocked(ctx context.Context) (err error) {
	if r == nil {
		return ErrInstall
	}
	defer func() {
		if err != nil {
			r.close()
		}
	}()
	if !r.local(ctx, false) || r.observedAt.IsZero() || !digestPattern.MatchString(r.revision) {
		return ErrInstall
	}
	items, collections, err := r.readActual(ctx)
	if err != nil {
		return err
	}
	defer func() {
		for n := range items {
			clear(items[n].body)
		}
	}()
	if originalHistoryControllerRevision(r.namespace, r.namespaceUID, items, collections) != r.revision {
		return ErrInstall
	}
	return nil
}

// SQL-only phase: association/cap/data integrity only. D's actual producer must
// still bind its original captured inputs to the genuine current tx/epoch.
func (r *originalHistoryControllerInventory) matchesOriginalSQLPhase(ctx context.Context, m *originalHistorySQLMetadata, now time.Time) bool {
	return r != nil && r.metadata == m && !r.observedAt.IsZero() && !now.IsZero() && !now.Before(r.observedAt) && now.Before(r.until) && r.local(ctx, true) && r.revision == originalHistoryControllerRevision(r.namespace, r.namespaceUID, r.items, r.collections)
}
