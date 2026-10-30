package systembackupexecution

import (
	"bytes"
	"clawreef/internal/runtimecustody"
	"clawreef/internal/services"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/flow"
	b "clawreef/internal/systembackup/publicadapter"
	"clawreef/internal/systembackup/staging"
	c "clawreef/internal/systembackupcontroller"
	d "clawreef/internal/systembackupdispatch"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// Every reference is in the independently pinned deployment configuration.
// It identifies an ORIGINAL create request receipt, never rebuilt settings.
type GatewayOriginalReference struct {
	Source       b.InstanceIdentity `json:"source"`
	File         string             `json:"file"`
	CipherSHA256 string             `json:"cipher_sha256"`
	PlainSHA256  string             `json:"plain_sha256"`
	KeyRef       string             `json:"key_ref"`
}
type RuntimeSourceConfig struct {
	Supported         []b.AgentKind              `json:"supported"`
	Namespaces        []string                   `json:"namespaces"`
	AgentTokenFile    string                     `json:"agent_token_file,omitempty"`
	AgentCAFile       string                     `json:"agent_ca_file,omitempty"`
	AgentCASHA256     string                     `json:"agent_ca_sha256,omitempty"`
	Originals         []GatewayOriginalReference `json:"gateway_originals"`
	LeaseParticipants []string                   `json:"lease_participants"`
	Deployments       []PlatformDeployment       `json:"deployments"`
	WorkspaceRoot     string                     `json:"workspace_root"`
}

func (r RuntimeSourceConfig) validate() error {
	if len(r.Supported) == 0 || len(r.Namespaces) != 1 || len(r.LeaseParticipants) == 0 || !path.IsAbs(r.WorkspaceRoot) || path.Clean(r.WorkspaceRoot) != r.WorkspaceRoot || r.WorkspaceRoot == "/" {
		return d.ErrNotReady
	}
	namespaces := map[string]bool{}
	for _, ns := range r.Namespaces {
		if ns == "" || namespaces[ns] {
			return d.ErrNotReady
		}
		namespaces[ns] = true
	}
	ids := map[string]bool{}
	for _, id := range r.LeaseParticipants {
		if id == "" || len(id) > 128 || ids[id] {
			return d.ErrNotReady
		}
		ids[id] = true
	}
	sources := map[int]bool{}
	for _, ref := range r.Originals {
		if ref.Source.ID <= 0 || ref.Source.Generation <= 0 || ref.Source.Mode != "lite" || sources[ref.Source.ID] || (ref.Source.Namespace != "" && !namespaces[ref.Source.Namespace]) || !filepath.IsAbs(ref.File) || ref.KeyRef == "" || len(ref.CipherSHA256) != 64 || len(ref.PlainSHA256) != 64 {
			return d.ErrNotReady
		}
		sources[ref.Source.ID] = true
	}
	for _, dep := range r.Deployments {
		if !namespaces[dep.Namespace] || dep.Name == "" || dep.UID == "" {
			return d.ErrNotReady
		}
	}
	kinds := map[b.AgentKind]bool{}
	for _, kind := range r.Supported {
		if kinds[kind] || kind.Type == "" || kind.OS != "linux" || (kind.Mode != "lite" && kind.Mode != "pro") {
			return d.ErrNotReady
		}
		kinds[kind] = true
		if kind.Mode == "lite" && (!filepath.IsAbs(r.AgentTokenFile) || !filepath.IsAbs(r.AgentCAFile) || filepath.Clean(r.AgentCAFile) != r.AgentCAFile || len(r.AgentCASHA256) != 64) {
			return d.ErrNotReady
		}
	}
	return nil
}

// This binding is shared with the real Agent client's original request store.
// Original generation is never replaced by the recovery reservation generation.
func GatewayOriginalBinding(installation string, ref GatewayOriginalReference) staging.Binding {
	return runtimecustody.Binding(installation, runtimecustody.Identity{InstanceID: ref.Source.ID, UserID: ref.Source.UserID, Generation: ref.Source.Generation, WorkspacePath: ref.Source.Workspace}, ref.PlainSHA256)
}

type deploymentRecordKeys struct{ owner *PublicJobOwner }

func (k deploymentRecordKeys) Resolve(ctx context.Context, a d.Authority, ref string) (string, []byte, error) {
	if k.owner.Gate.Authority.Check(ctx, a) == nil {
		return k.owner.Gate.Records.Keys.Resolve(ctx, a, ref)
	}
	if e := k.owner.Gate.Recovery.Check(ctx, a); e != nil {
		return "", nil, e
	}
	return k.owner.Gate.Recovery.Identity.Resolve(ctx, a, ref)
}
func (s *DeploymentService) originalGateway(ctx context.Context, a d.Authority, source b.InstanceIdentity) (services.RuntimeAgentCreateGatewayRequest, error) {
	var zero services.RuntimeAgentCreateGatewayRequest
	for _, ref := range s.Config.RuntimeSources.Originals {
		if ref.Source.ID != source.ID {
			continue
		}
		if ref.Source != source {
			return zero, c.ErrExecutionRecord
		}
		sealed, e := pinnedDeploymentFile(ref.File, ref.CipherSHA256, 8<<20)
		if e != nil {
			return zero, e
		}
		actual, key, e := (deploymentRecordKeys{s.Runtime.Owner}).Resolve(ctx, a, ref.KeyRef)
		defer clear(key)
		if e != nil || actual != ref.KeyRef || len(key) != 32 {
			return zero, c.ErrExecutionAuthority
		}
		var plain bytes.Buffer
		defer func() { clear(plain.Bytes()) }()
		if staging.Open(ctx, bytes.NewReader(sealed), &plain, key, GatewayOriginalBinding(a.InstallationID, ref), 7<<20) != nil || hash(plain.Bytes()) != ref.PlainSHA256 {
			return zero, c.ErrExecutionRecord
		}
		decoder := json.NewDecoder(bytes.NewReader(plain.Bytes()))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&zero) != nil || decoder.Decode(new(any)) != io.EOF || zero.Generation != source.Generation || zero.InstanceID != source.ID || zero.UserID != source.UserID || zero.WorkspacePath != source.Workspace {
			return services.RuntimeAgentCreateGatewayRequest{}, c.ErrExecutionRecord
		}
		return zero, nil
	}
	return zero, d.ErrNotReady
}

type runtimeLeaseProbe struct{ owner *PublicJobOwner }

func (p runtimeLeaseProbe) Check(ctx context.Context) error {
	var phase string
	var outstanding int
	// Idle is possible only for recovery replay after the original release;
	// SQLRuntimeControl still validates that exact released-capture proof under
	// its original recovery authority. This probe itself grants no operation.
	if p.owner.Gate.Authority.DB.QueryRowContext(ctx, `SELECT phase,(SELECT COUNT(*) FROM system_backup_mutation_leases WHERE scope=? AND released_at IS NULL) FROM system_backup_gate WHERE scope=?`, p.owner.Gate.Authority.ApplicationScope, p.owner.Gate.Authority.ApplicationScope).Scan(&phase, &outstanding) != nil || (phase != "idle" && phase != "acquiring" && phase != "held" && phase != "releasing") || outstanding != 0 {
		return d.ErrNotReady
	}
	return nil
}

type runtimeDeploymentProbe struct {
	s   *DeploymentService
	ref PlatformDeployment
}

func (p runtimeDeploymentProbe) Check(ctx context.Context) error {
	return p.s.checkAutoscalers(ctx, p.ref)
}

func nativeBackupAgent(cfg RuntimeSourceConfig) (services.BackupGatewayAgent, error) {
	token, e := readPrivate(cfg.AgentTokenFile, 16384)
	if e != nil {
		return nil, e
	}
	defer clear(token)
	if len(bytes.TrimSpace(token)) == 0 {
		return nil, c.ErrExecutionAuthority
	}
	caPEM, e := pinnedDeploymentFile(cfg.AgentCAFile, cfg.AgentCASHA256, 1<<20)
	if e != nil {
		return nil, e
	}
	client, err := services.NewRuntimeAgentClientWithPinnedCA(string(bytes.TrimSpace(token)), caPEM)
	if err != nil {
		return nil, c.ErrExecutionAuthority
	}
	agent, ok := client.(services.BackupGatewayAgent)
	if !ok {
		return nil, d.ErrNotReady
	}
	return agent, nil
}

func (s *DeploymentService) attachRuntimeSources(o *PublicJobOwner, profile b.LinuxProfileConfig) (b.LinuxProfileConfig, error) {
	cfg := s.Config.RuntimeSources
	if cfg == nil {
		return profile, nil
	}
	grant := s.Forward.DeploymentBinding()
	if cfg.validate() != nil || s.Config.SourceDatabase != grant.Database || s.Config.SourceServerUUID != grant.ServerUUID {
		return profile, c.ErrExecutionAuthority
	}
	controls := c.RuntimeControlConfig{Namespace: s.Config.Namespace, Gate: o.Gate, Keys: deploymentRecordKeys{o}, Client: o.Client, GatewayOriginalForTask: s.originalGateway, ParticipantChecks: map[string]c.ReadinessProbe{}, DeploymentChecks: map[string]c.ReadinessProbe{}, PollInterval: 200 * time.Millisecond, StopProofForTask: func(a d.Authority, ns string) c.RuntimeArmedStopProof { return o.StopWitnessIn(a, ns) }}
	for _, id := range cfg.LeaseParticipants {
		controls.ParticipantChecks[id] = runtimeLeaseProbe{o}
	}
	for _, ref := range cfg.Deployments {
		controls.DeploymentChecks[ref.Namespace+"/"+ref.Name] = runtimeDeploymentProbe{s, ref}
	}
	platformIDs := map[string]bool{}
	for _, ref := range s.Config.Writers {
		id := "deployment/" + ref.Namespace + "/" + ref.Name
		platformIDs[id] = true
		controls.AdditionalWriterIDs = append(controls.AdditionalWriterIDs, id)
	}
	if cfg.AgentTokenFile != "" {
		agent, e := nativeBackupAgent(*cfg)
		if e != nil {
			return profile, e
		}
		controls.Agent = agent
	}
	runtime, e := c.NewSQLRuntimeControl(controls)
	if e != nil {
		return profile, e
	}
	s.RuntimeControl = runtime
	platformBuilder := profile.BuildWriters
	profile.Supported = map[b.AgentKind]bool{}
	for _, kind := range cfg.Supported {
		profile.Supported[kind] = true
	}
	profile.BuildWriters = func(ctx context.Context, in d.Input, inv b.SourceInventory, frozen []b.FrozenWriter) ([]flow.Writer, error) {
		if s.validateRuntimeInventory(inv) != nil {
			return nil, d.ErrNotReady
		}
		if frozen == nil {
			if e := s.checkRuntimeWorkspace(ctx, o.Client, inv.Instances); e != nil {
				return nil, e
			}
		}
		var platformFrozen, runtimeFrozen []b.FrozenWriter
		if frozen != nil {
			platformFrozen = []b.FrozenWriter{}
			runtimeFrozen = []b.FrozenWriter{}
			for _, w := range frozen {
				if platformIDs[w.ID] {
					platformFrozen = append(platformFrozen, w)
				} else {
					runtimeFrozen = append(runtimeFrozen, w)
				}
			}
		}
		platformInv := inv
		platformInv.Instances = nil
		platform, e := platformBuilder(ctx, in, platformInv, platformFrozen)
		if e != nil {
			return nil, e
		}
		sources, e := runtime.BuildWriters(ctx, in, inv, runtimeFrozen)
		if e != nil {
			return nil, e
		}
		return append(platform, sources...), nil
	}
	return profile, nil
}

func (s *DeploymentService) validateRuntimeInventory(inv b.SourceInventory) error {
	cfg := s.Config.RuntimeSources
	if cfg == nil || len(cfg.Namespaces) != 1 || cfg.Namespaces[0] != s.Config.Namespace || inv.Database != s.Config.SourceDatabase || inv.ServerUUID != s.Config.SourceServerUUID {
		return d.ErrNotReady
	}
	allowed := map[string]bool{}
	for _, ns := range cfg.Namespaces {
		allowed[ns] = true
	}
	kinds := map[b.AgentKind]bool{}
	for _, k := range cfg.Supported {
		kinds[k] = true
	}
	for _, source := range inv.Instances {
		// A null Lite locator is resolved by D from the actual binding before
		// contacting the source. The raw inventory and its hash remain unchanged.
		missingLiteLocator := source.Namespace == "" && source.Mode == "lite" && source.Status == "running"
		if (!allowed[source.Namespace] && !missingLiteLocator) || (source.Namespace != "" && source.Namespace != s.Config.Namespace) || !kinds[b.AgentKind{Type: source.Type, Mode: source.Mode, Variant: source.Variant, OS: source.OS}] || (source.Status != "running" && source.Status != "stopped") {
			return d.ErrNotReady
		}
		// The capture mounts one reviewed workspace tree. A runtime outside it
		// cannot be represented by this workspace-only deployment profile.
		root := s.Config.RuntimeSources.WorkspaceRoot
		if source.Workspace == "" || path.Clean(source.Workspace) != source.Workspace || !strings.HasPrefix(source.Workspace, root+"/") {
			return d.ErrNotReady
		}
	}
	return nil
}
func (s *DeploymentService) runtimeInventory(ctx context.Context, in d.Input, x b.Discovery, platform map[string]bool) error {
	var inv b.SourceInventory
	if json.Unmarshal(x.Source, &inv) != nil || hash(x.Source) != x.SourceSHA256 || s.validateRuntimeInventory(inv) != nil || s.RuntimeControl == nil {
		return d.ErrNotReady
	}
	var frozen []b.FrozenWriter
	seen := map[string]bool{}
	for _, w := range x.Writers {
		if seen[w.ID] {
			return d.ErrNotReady
		}
		seen[w.ID] = true
		if platform[w.ID] {
			delete(platform, w.ID)
		} else {
			frozen = append(frozen, w)
		}
	}
	if len(platform) != 0 {
		return d.ErrNotReady
	}
	// Rebind to saved D custody and the complete live participant registry.
	// A frozen list cannot manufacture a fresh reservation or source mapping.
	_, e := s.RuntimeControl.BuildWriters(ctx, in, inv, frozen)
	return e
}
func (s *DeploymentService) checkRuntimeSources(ctx context.Context) error {
	tx, e := s.Source.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if e != nil {
		return e
	}
	defer tx.Rollback()
	instances, e := domain.ReadSourceInstances(ctx, tx)
	if e != nil {
		return e
	}
	if e = s.validateRuntimeInventory(b.SourceInventory{Database: s.Config.SourceDatabase, ServerUUID: s.Config.SourceServerUUID, Instances: instances}); e != nil {
		return e
	}
	if e = s.checkRuntimeWorkspace(ctx, s.Runtime.Owner.Client, instances); e != nil {
		return e
	}
	for _, source := range instances {
		if source.Mode != "lite" || source.Status != "running" {
			continue
		}
		found := false
		for _, ref := range s.Config.RuntimeSources.Originals {
			if ref.Source == source {
				if _, e := pinnedDeploymentFile(ref.File, ref.CipherSHA256, 8<<20); e != nil {
					return e
				}
				found = true
				break
			}
		}
		if !found {
			return d.ErrNotReady
		}
	}
	// Registration is performed by the existing gate owner during installation;
	// discovery never silently drops or invents a background participant.
	rows, e := s.Runtime.Owner.Gate.Authority.DB.QueryContext(ctx, "SELECT participant_id FROM system_backup_participants WHERE scope=? ORDER BY participant_id", s.Config.ApplicationScope)
	if e != nil {
		return e
	}
	defer rows.Close()
	registered := map[string]bool{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			return d.ErrNotReady
		}
		registered[id] = true
	}
	if rows.Err() != nil {
		return d.ErrNotReady
	}
	for _, id := range s.Config.RuntimeSources.LeaseParticipants {
		if !registered[id] {
			return d.ErrNotReady
		}
	}
	for _, ref := range s.Config.RuntimeSources.Deployments {
		if e = s.checkAutoscalers(ctx, ref); e != nil {
			return e
		}
	}
	return nil
}

// A pathname alone does not prove that a source is inside the captured tree.
// This profile supports the same PVC and matching subpath; other storage needs
// an independently reviewed profile instead of silently claiming coverage.
func (s *DeploymentService) checkRuntimeWorkspace(ctx context.Context, client kubernetes.Interface, instances []b.InstanceIdentity) error {
	if s.Config.Workspace.NFS != nil {
		return s.checkNFSRuntimeWorkspace(ctx, client, instances)
	}
	target, e := client.CoreV1().PersistentVolumeClaims(s.Config.Namespace).Get(ctx, s.Config.Workspace.Claim, metav1.GetOptions{})
	if e != nil || target.Spec.VolumeName == "" || target.DeletionTimestamp != nil {
		return d.ErrNotReady
	}
	pinned := false
	for _, ref := range s.Config.Security.Volumes {
		if ref.Kind == "PersistentVolumeClaim" && ref.Name == target.Name && ref.UID == string(target.UID) && ref.PVName == target.Spec.VolumeName && ref.PVUID != "" {
			pv, e := client.CoreV1().PersistentVolumes().Get(ctx, ref.PVName, metav1.GetOptions{})
			if e == nil && string(pv.UID) == ref.PVUID && pv.DeletionTimestamp == nil {
				pinned = true
			}
		}
	}
	if !pinned {
		return d.ErrNotReady
	}
	for _, source := range instances {
		if source.Status != "running" {
			continue
		}
		namespace, name, uid := source.Namespace, source.Pod, ""
		if source.Mode == "lite" {
			if s.RuntimeControl == nil {
				return d.ErrNotReady
			}
			mapped, e := s.RuntimeControl.ResolveGatewaySource(ctx, source)
			if e != nil {
				return e
			}
			namespace, name, uid = mapped.RuntimeNamespace(), mapped.RuntimePod(), mapped.UID
		}
		if namespace != s.Config.Namespace || name == "" {
			return d.ErrNotReady
		}
		pod, e := client.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if e != nil || pod.DeletionTimestamp != nil {
			return d.ErrNotReady
		}
		if uid != "" && string(pod.UID) != uid {
			return d.ErrNotReady
		}
		found := false
		expected := path.Join(s.Config.Workspace.SubPath, strings.TrimPrefix(source.Workspace, s.Config.RuntimeSources.WorkspaceRoot+"/"))
		for _, container := range pod.Spec.Containers {
			for _, mount := range container.VolumeMounts {
				ancestor := source.Workspace == mount.MountPath || strings.HasPrefix(source.Workspace, mount.MountPath+"/")
				descendant := strings.HasPrefix(mount.MountPath, source.Workspace+"/")
				if !ancestor && !descendant {
					continue
				}
				if mount.SubPathExpr != "" || path.Clean(mount.MountPath) != mount.MountPath {
					return d.ErrNotReady
				}
				relative := mount.SubPath
				wanted := expected
				if ancestor && source.Workspace != mount.MountPath {
					relative = path.Join(mount.SubPath, strings.TrimPrefix(source.Workspace, mount.MountPath+"/"))
				}
				if descendant {
					wanted = path.Join(s.Config.Workspace.SubPath, strings.TrimPrefix(mount.MountPath, s.Config.RuntimeSources.WorkspaceRoot+"/"))
				}
				if path.Clean(relative) != path.Clean(wanted) {
					return d.ErrNotReady
				}
				matched := false
				for _, volume := range pod.Spec.Volumes {
					if volume.Name != mount.Name || volume.PersistentVolumeClaim == nil {
						continue
					}
					claim, e := client.CoreV1().PersistentVolumeClaims(namespace).Get(ctx, volume.PersistentVolumeClaim.ClaimName, metav1.GetOptions{})
					if e == nil && claim.DeletionTimestamp == nil && claim.Spec.VolumeName == target.Spec.VolumeName {
						matched = true
					}
				}
				if !matched {
					return d.ErrNotReady
				}
				found = found || ancestor
			}
		}
		if !found {
			return d.ErrNotReady
		}
	}
	return nil
}

// The NFS worker mounts only the installation-owned subpath. Every live source
// must resolve to that exact export and a descendant of that subpath; a nested
// or aliased mount cannot silently add content outside the capture tree.
func (s *DeploymentService) checkNFSRuntimeWorkspace(ctx context.Context, client kubernetes.Interface, instances []b.InstanceIdentity) error {
	cfg := s.Config.Workspace
	if cfg.NFS == nil || !cfg.validSource(s.Config.InstallationID) {
		return d.ErrNotReady
	}
	ownedRoot := path.Join(s.Config.RuntimeSources.WorkspaceRoot, cfg.SubPath)
	for _, source := range instances {
		if !strings.HasPrefix(source.Workspace, ownedRoot+"/") {
			return d.ErrNotReady
		}
		if source.Status != "running" {
			continue
		}
		namespace, name, uid := source.Namespace, source.Pod, ""
		if source.Mode == "lite" {
			if s.RuntimeControl == nil {
				return d.ErrNotReady
			}
			mapped, err := s.RuntimeControl.ResolveGatewaySource(ctx, source)
			if err != nil {
				return err
			}
			namespace, name, uid = mapped.RuntimeNamespace(), mapped.RuntimePod(), mapped.UID
		}
		if namespace != s.Config.Namespace || name == "" {
			return d.ErrNotReady
		}
		pod, err := client.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil || pod.DeletionTimestamp != nil || (uid != "" && string(pod.UID) != uid) {
			return d.ErrNotReady
		}
		found := false
		for _, container := range pod.Spec.Containers {
			for _, mount := range container.VolumeMounts {
				ancestor := source.Workspace == mount.MountPath || strings.HasPrefix(source.Workspace, mount.MountPath+"/")
				descendant := strings.HasPrefix(mount.MountPath, source.Workspace+"/")
				if !ancestor && !descendant {
					continue
				}
				if descendant || mount.SubPathExpr != "" || !path.IsAbs(mount.MountPath) || path.Clean(mount.MountPath) != mount.MountPath ||
					(mount.SubPath != "" && (path.IsAbs(mount.SubPath) || path.Clean(mount.SubPath) != mount.SubPath || mount.SubPath == ".." || strings.HasPrefix(mount.SubPath, "../"))) {
					return d.ErrNotReady
				}
				relative := strings.TrimPrefix(source.Workspace, mount.MountPath)
				relative = strings.TrimPrefix(relative, "/")
				physical := path.Join(mount.SubPath, relative)
				if physical != cfg.SubPath && !strings.HasPrefix(physical, cfg.SubPath+"/") {
					return d.ErrNotReady
				}
				matched := false
				for _, volume := range pod.Spec.Volumes {
					if volume.Name != mount.Name {
						continue
					}
					if volume.NFS == nil || volume.NFS.Server != cfg.NFS.Server || volume.NFS.Path != cfg.NFS.Export {
						return d.ErrNotReady
					}
					matched = true
				}
				if !matched {
					return d.ErrNotReady
				}
				found = true
			}
		}
		if !found {
			return d.ErrNotReady
		}
	}
	return nil
}
