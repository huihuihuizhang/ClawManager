package worker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"

	c "clawreef/internal/systembackup"
	"clawreef/internal/systembackup/flow"
	"clawreef/internal/systembackup/quiesce"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/dynamic"
)

// All fields are frozen public scope, never API credentials or source content.
// A separate source credential/identity is required for each of the two parts.
type ResourceCaptureSpec struct {
	Part               string                   `json:"part"`
	Namespace          string                   `json:"namespace"`
	NamespaceUID       string                   `json:"namespace_uid"`
	ServiceAccountName string                   `json:"service_account_name"`
	ServiceAccountUID  string                   `json:"service_account_uid"`
	Selections         []c.KubernetesSelection  `json:"selections"`
	MaxItems           int                      `json:"max_items"`
	OriginalWriters    []ResourceWriterOriginal `json:"original_writers"`
}

type ResourceWriterOriginal struct {
	ID    string     `json:"id"`
	State flow.State `json:"state"`
}

type ResourceCaptureSources struct {
	Client    dynamic.Interface
	Authorize func(context.Context, Invocation) error
	close     func()
}

func (s *ResourceCaptureSources) Close() {
	if s != nil && s.close != nil {
		s.close()
	}
}

func resourceCaptureOperation(op string) bool {
	return op == "capture-deployment-resources" || op == "capture-secret-bundle"
}

func validResourceCapture(r Request) bool {
	s := r.Resources
	if s == nil || !resourceCaptureOperation(r.Operation) || r.Version != Version || s.NamespaceUID == "" || s.ServiceAccountUID == "" || len(validation.IsDNS1123Label(s.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(s.ServiceAccountName)) != 0 || s.MaxItems < 1 || s.MaxItems > 10000 || s.Selections == nil || len(s.Selections) > s.MaxItems || r.TeamWorkspace != nil || r.Teams != nil || r.Database != nil || r.RuntimePolicy != nil || r.WorkBuddyIdentity != nil || r.PolicyVersion != "" || len(r.Files) != 0 || r.MaxFiles != 0 || r.MaxFileBytes != 0 || r.MaxArchiveBytes <= 0 || r.MaxArchiveBytes > 32<<20 || r.MaxCompressedBytes <= 0 || r.MaxCompressedBytes > 32<<20 {
		return false
	}
	if (s.Part == "deployment_resources" && r.Operation != "capture-deployment-resources") || (s.Part == "secret_bundle" && r.Operation != "capture-secret-bundle") || (s.Part != "deployment_resources" && s.Part != "secret_bundle") {
		return false
	}
	seen := map[string]bool{}
	originals := map[string]ResourceWriterOriginal{}
	if s.OriginalWriters == nil || len(s.OriginalWriters) > s.MaxItems {
		return false
	}
	for _, w := range s.OriginalWriters {
		if originals[w.ID].ID != "" || len(w.State.Checkpoint) > 128<<10 {
			return false
		}
		originals[w.ID] = w
	}
	for _, ref := range s.Selections {
		key := ref.Group + "/" + ref.Version + "/" + ref.Resource + "/" + ref.Name
		if !c.ValidKubernetesSelection(ref, s.Part) || len(validation.IsDNS1123Subdomain(ref.Name)) != 0 || seen[key] {
			return false
		}
		seen[key] = true
		if ref.Resource == "cronjobs" {
			return false
		} // no admitted CronJob writer checkpoint adapter yet
		if ref.Resource == "deployments" {
			id := "deployment/" + s.Namespace + "/" + ref.Name
			w, ok := originals[id]
			if !ok || w.State.UID != ref.UID {
				return false
			}
			if _, err := quiesce.DeploymentOriginalReplicas(s.Namespace, ref.Name, w.State); err != nil {
				return false
			}
			delete(originals, id)
		}
	}
	return len(originals) == 0
}

func authorizeResourceSource(ctx context.Context, env *ResourceCaptureSources, i Invocation) error {
	if env == nil || env.Client == nil || env.Authorize == nil || !validResourceCapture(i.Request) {
		return ErrNotReady
	}
	raw, err := json.Marshal(i)
	var detached Invocation
	if err != nil || len(raw) > 1<<20 || json.Unmarshal(raw, &detached) != nil {
		return ErrRequest
	}
	return env.Authorize(ctx, detached)
}

func captureResourceSource(ctx context.Context, env *ResourceCaptureSources, i Invocation, dst io.Writer, check func() error) error {
	guard := func(ctx context.Context) error {
		if ctx.Err() != nil || check == nil || check() != nil {
			return ErrNotReady
		}
		return authorizeResourceSource(ctx, env, i)
	}
	if guard(ctx) != nil {
		return ErrNotReady
	}
	s := i.Request.Resources
	header, err := json.Marshal(struct {
		Version string              `json:"schema_version"`
		Scope   ResourceCaptureSpec `json:"scope"`
	}{"resource-capture-history.v1", *s})
	if err != nil || len(header) > 512<<10 {
		return ErrRequest
	}
	if _, err = dst.Write(append(header, '\n')); err != nil {
		return err
	}
	return c.CaptureKubernetesResourcesGuarded(ctx, env.Client, dst, s.Namespace, s.NamespaceUID, s.Part, s.Selections, c.ObjectBudget{MaxItems: s.MaxItems, MaxBytes: i.Request.MaxArchiveBytes}, guard)
}

// Independent data-only readback exposes the exact pre-pause checkpoints and
// current captured objects separately. It never applies either to a cluster.
func ReadResourceCaptureArchive(ctx context.Context, src io.Reader, expected ResourceCaptureSpec, maxBytes int64, onResource func(c.KubernetesSelection, json.RawMessage) error) error {
	if ctx == nil || ctx.Err() != nil || src == nil || maxBytes < 1 || maxBytes > 32<<20 {
		return ErrRequest
	}
	r := bufio.NewReaderSize(io.LimitReader(src, maxBytes+1), 512<<10+1)
	header, err := r.ReadSlice('\n')
	if err != nil || len(header) > 512<<10 {
		return ErrExecution
	}
	wanted, _ := json.Marshal(struct {
		Version string              `json:"schema_version"`
		Scope   ResourceCaptureSpec `json:"scope"`
	}{"resource-capture-history.v1", expected})
	if !bytes.Equal(header, append(wanted, '\n')) {
		return ErrExecution
	}
	used := len(header)
	first, err := r.ReadSlice('\n')
	var identity c.KubernetesRecord
	if err != nil || json.Unmarshal(first, &identity) != nil || identity.Kind != "kubernetes_history_v1" || identity.Namespace != expected.Namespace || identity.NamespaceUID != expected.NamespaceUID || identity.Part != expected.Part {
		return ErrExecution
	}
	pinned := map[c.KubernetesSelection]bool{}
	for _, ref := range expected.Selections {
		pinned[ref] = true
	}
	err = c.ReadKubernetesHistory(ctx, io.MultiReader(bytes.NewReader(append([]byte(nil), first...)), r), expected.Part, c.ObjectBudget{MaxItems: expected.MaxItems, MaxBytes: maxBytes - int64(used)}, func(ref c.KubernetesSelection, raw json.RawMessage) error {
		if !pinned[ref] {
			return ErrExecution
		}
		delete(pinned, ref)
		if onResource != nil {
			return onResource(ref, raw)
		}
		return nil
	})
	if err != nil || len(pinned) != 0 {
		return ErrExecution
	}
	return nil
}
