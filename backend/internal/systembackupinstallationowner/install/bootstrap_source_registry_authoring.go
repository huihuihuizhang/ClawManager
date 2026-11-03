package install

import (
	"context"
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	owner "clawreef/internal/systembackupinstallationowner"
)

// Unsigned, independently pinned source-selection DATA for the original
// administrator's PRE-capture action. It contains no final config/grant,
// metadata scope, registry content hash, prepared V2 grant or observation.
// Only Installer authentication below creates the non-serializable capability.
type BootstrapSourceAuthoringSelection struct {
	Version                                              string
	Deployment, MaterialsTemplate, ExecutionProfile      BootstrapSourceFilePin
	Controller                                           BootstrapSourceController
	ApplicationScope, PartsVersion, SourceWritersVersion string
	PartsFile, SourceWritersFile                         string
	Connections                                          []BootstrapSourceConnection
	RuntimeAgent                                         *BootstrapSourceRuntimeAgentV2
	NotBefore, Until                                     time.Time
}

const BootstrapSourceAuthoringSelectionVersion = "original-source-registry-authoring-selection.v1"

type BootstrapSourceRegistryAuthoring struct {
	mu                  sync.Mutex
	origin              *BootstrapSourceRegistryAuthoring
	failed              atomic.Bool
	closed              bool
	ctx, physical       context.Context
	cancel              context.CancelFunc
	operator            *authenticatedOperator
	enrollment          EnrollmentPin
	initial             HeadCAS
	floor, start, until time.Time
	selection           BootstrapSourceAuthoringSelection
	files               []consumerPinnedFile
}

func (*BootstrapSourceRegistryAuthoring) MarshalJSON() ([]byte, error) { return nil, ErrInstall }
func (*BootstrapSourceRegistryAuthoring) String() string {
	return "OriginalInstallerSourceRegistryAuthoring"
}
func (*BootstrapSourceRegistryAuthoring) GoString() string {
	return "OriginalInstallerSourceRegistryAuthoring"
}

func (p *BootstrapSourceRegistryAuthoring) reject() error {
	if p != nil {
		p.failed.Store(true)
		if p.origin != nil {
			p.origin.failed.Store(true)
		}
	}
	return ErrInstall
}

func readBootstrapSourceAuthoringFile(pin consumerPinnedFile) ([]byte, error) {
	if pin.limit > 262144 {
		if pin.limit != 8<<20 {
			return nil, ErrInstall
		}
		return ReadSourceMaterialFile(pin.path)
	}
	return ReadPrivateFile(pin.path, pin.limit)
}

func validateBootstrapSourceAuthoring(s BootstrapSourceAuthoringSelection, target owner.Target) error {
	if s.Version != BootstrapSourceAuthoringSelectionVersion || s.Controller.Namespace != target.Namespace || s.Controller.NamespaceUID != target.NamespaceUID || s.ApplicationScope == "" || len(s.ApplicationScope) > 256 || strings.ContainsAny(s.ApplicationScope, "\x00\r\n") || s.NotBefore.IsZero() || !s.NotBefore.Before(s.Until) || s.Until.Sub(s.NotBefore) > 24*time.Hour || len(s.Connections) != 5 {
		return ErrInstall
	}
	for _, v := range []string{s.PartsVersion, s.SourceWritersVersion} {
		if v == "" || len(v) > 128 || strings.ContainsAny(v, "\x00\r\n") {
			return ErrInstall
		}
	}
	for _, v := range []string{s.Controller.Deployment, s.Controller.DeploymentUID, s.Controller.ReplicaSet, s.Controller.ReplicaSetUID, s.Controller.Pod, s.Controller.PodUID, s.Controller.ServiceAccount, s.Controller.ServiceAccountUID} {
		if v == "" || len(v) > 256 || strings.ContainsAny(v, "\x00\r\n") {
			return ErrInstall
		}
	}
	for _, pin := range []BootstrapSourceFilePin{s.Deployment, s.MaterialsTemplate, s.ExecutionProfile} {
		if !bootstrapSourcePinValid(pin) {
			return ErrInstall
		}
	}
	for n, purpose := range []string{"control_sql", "source_api", "source_objects", "source_redis", "source_sql"} {
		c := s.Connections[n]
		u, err := url.Parse(c.Endpoint)
		if err != nil || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.Opaque != "" || c.Purpose != purpose || c.Account == "" || len(c.Account) > 256 || strings.ContainsAny(c.Account, "\x00\r\n") || !bootstrapSourcePinValid(c.CA) || !bootstrapSourcePinValid(c.Credential) || c.IdentitySHA256 != "" || c.ScopeSHA256 != "" {
			return ErrInstall
		}
		if (purpose == "control_sql" || purpose == "source_sql") && (u.Scheme != "mysql+tls" || c.ServerUUID == "" || c.Database == "") || purpose == "source_redis" && u.Scheme != "rediss" || (purpose == "source_api" || purpose == "source_objects") && u.Scheme != "https" {
			return ErrInstall
		}
	}
	control, source := s.Connections[0], s.Connections[4]
	if control.ServerUUID != target.ServerUUID || control.Database != target.Database || control.Account == source.Account || control.Credential.File == source.Credential.File {
		return ErrInstall
	}
	if a := s.RuntimeAgent; a != nil {
		if a.ScopeSHA256 != "" || len(a.Operations) != 2 || a.Operations[0] != "backup_capabilities_read" || a.Operations[1] != "gateway_state_read" || !bootstrapSourcePinValid(a.CA) || !bootstrapSourcePinValid(a.Credential) {
			return ErrInstall
		}
	}
	if !filepath.IsAbs(s.PartsFile) || filepath.Clean(s.PartsFile) != s.PartsFile || !filepath.IsAbs(s.SourceWritersFile) || filepath.Clean(s.SourceWritersFile) != s.SourceWritersFile || s.PartsFile == s.SourceWritersFile {
		return ErrInstall
	}
	return nil
}

// Authenticate the REAL original operator/enrollment/current signed ledger.
// This action precedes the final config/capture/metadata/V2 signatures and
// grants only the explicitly selected native READs. No issuer key is required.
func (i *Installer) PrepareBootstrapSourceRegistryAuthoring(ctx context.Context, password []byte, enrollment EnrollmentPin, selectionFile, selectionSHA string) (*BootstrapSourceRegistryAuthoring, error) {
	if !bootstrapSourcePinValid(BootstrapSourceFilePin{selectionFile, selectionSHA}) {
		return nil, ErrInstall
	}
	raw, err := readBootstrapSourcePin(BootstrapSourceFilePin{selectionFile, selectionSHA}, 262144)
	var selection BootstrapSourceAuthoringSelection
	if err != nil || decodeExact(raw, &selection) != nil || i == nil || validateBootstrapSourceAuthoring(selection, i.plan.Target) != nil {
		return nil, ErrInstall
	}
	if consumerNil(ctx) || ctx.Err() != nil {
		return nil, ErrInstall
	}
	parentDeadline, bounded := ctx.Deadline()
	if !bounded {
		return nil, ErrInstall
	}
	start := time.Now().UTC().Truncate(time.Microsecond)
	until := start.Add(30 * time.Second)
	for _, end := range []time.Time{selection.Until, parentDeadline} {
		if end.Before(until) {
			until = end
		}
	}
	if start.Before(selection.NotBefore) || !start.Before(until) {
		return nil, ErrInstall
	}
	physical, cancel := context.WithDeadline(ctx, until)
	// The actual Installer operator is authenticated on this one bounded child,
	// so its enrollment/admin/CAS reads ALSO stop at the original physical cap.
	// Public access methods still require the exact original caller context.
	s, err := i.authenticate(physical, password)
	if err != nil || s.authority(physical, enrollment) != nil {
		cancel()
		return nil, ErrInstall
	}
	current, now, err := snapshot(physical, s)
	if err != nil || current.cas.State == "revoked" || now.Before(selection.NotBefore) || !now.Before(selection.Until) || current.cas.HeadRevision > 0 && (now.Before(current.head.NotBefore) || !now.Before(current.head.Until) || selection.Until.After(current.head.Until)) {
		cancel()
		return nil, ErrInstall
	}
	p := &BootstrapSourceRegistryAuthoring{ctx: ctx, physical: physical, cancel: cancel, operator: s, enrollment: enrollment, initial: current.cas, floor: now, start: start, until: until, selection: selection, files: []consumerPinnedFile{{selectionFile, selectionSHA, 262144}}}
	p.origin = p
	p.files = append(p.files, consumerPinnedFile{selection.Deployment.File, selection.Deployment.SHA256, 262144}, consumerPinnedFile{selection.MaterialsTemplate.File, selection.MaterialsTemplate.SHA256, 8 << 20}, consumerPinnedFile{selection.ExecutionProfile.File, selection.ExecutionProfile.SHA256, 262144})
	for _, c := range selection.Connections {
		p.files = append(p.files, consumerPinnedFile{c.CA.File, c.CA.SHA256, 262144}, consumerPinnedFile{c.Credential.File, c.Credential.SHA256, 65536})
	}
	if a := selection.RuntimeAgent; a != nil {
		p.files = append(p.files, consumerPinnedFile{a.CA.File, a.CA.SHA256, 262144}, consumerPinnedFile{a.Credential.File, a.Credential.SHA256, 65536})
	}
	for _, file := range p.files {
		if file.path == selection.PartsFile || file.path == selection.SourceWritersFile {
			cancel()
			return nil, p.reject()
		}
	}
	if p.RecheckAuthority(ctx) != nil {
		cancel()
		return nil, p.reject()
	}
	return p, nil
}

func (p *BootstrapSourceRegistryAuthoring) local(ctx context.Context) error {
	if p == nil || p.origin != p || p.failed.Load() || p.closed || !consumerSameContext(ctx, p.ctx) || p.physical == nil || p.physical.Err() != nil || p.operator == nil || !p.operator.live(p.physical) {
		return p.reject()
	}
	now := time.Now().UTC()
	if now.Before(p.start) || now.Before(p.selection.NotBefore) || !now.Before(p.until) || !now.Before(p.selection.Until) {
		return p.reject()
	}
	for _, pin := range p.files {
		raw, err := readBootstrapSourceAuthoringFile(pin)
		actual := hash(raw)
		clear(raw)
		if err != nil || actual != pin.sha {
			return p.reject()
		}
	}
	if p.physical.Err() != nil || ctx.Err() != nil || !time.Now().Before(p.until) {
		return p.reject()
	}
	return nil
}

// Per-request local pin/window checks bracket every native read. Real current
// SQL/admin/enrollment/CAS/controller checks additionally bracket observation
// phases and the create-only export through RecheckAuthority below.
func (p *BootstrapSourceRegistryAuthoring) Check(ctx context.Context) error {
	if p == nil || p.origin != p {
		return p.reject()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.local(ctx)
}
func (p *BootstrapSourceRegistryAuthoring) Read(ctx context.Context, pin BootstrapSourceFilePin) ([]byte, error) {
	if p == nil || p.origin != p {
		return nil, p.reject()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.local(ctx) != nil {
		return nil, p.reject()
	}
	for _, f := range p.files {
		if pin.File == f.path && pin.SHA256 == f.sha {
			raw, err := readBootstrapSourceAuthoringFile(f)
			if err != nil || hash(raw) != f.sha || p.local(ctx) != nil {
				clear(raw)
				return nil, p.reject()
			}
			return raw, nil
		}
	}
	return nil, p.reject()
}
func (p *BootstrapSourceRegistryAuthoring) NativeContext(ctx context.Context) (context.Context, error) {
	if p.Check(ctx) != nil {
		return nil, ErrInstall
	}
	return p.physical, nil
}
func (p *BootstrapSourceRegistryAuthoring) Bounds(ctx context.Context) (time.Time, time.Time, error) {
	if p.Check(ctx) != nil {
		return time.Time{}, time.Time{}, ErrInstall
	}
	return p.start, p.until, nil
}
func (p *BootstrapSourceRegistryAuthoring) Selection(ctx context.Context) (BootstrapSourceAuthoringSelection, owner.Target, error) {
	if p.Check(ctx) != nil {
		return BootstrapSourceAuthoringSelection{}, owner.Target{}, ErrInstall
	}
	raw, err := json.Marshal(p.selection)
	var out BootstrapSourceAuthoringSelection
	if err != nil || json.Unmarshal(raw, &out) != nil {
		return out, owner.Target{}, p.reject()
	}
	return out, p.operator.installer.plan.Target, nil
}
func (p *BootstrapSourceRegistryAuthoring) RecheckAuthority(ctx context.Context) error {
	if p == nil || p.origin != p {
		return p.reject()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.local(ctx) != nil || p.operator.authority(p.physical, p.enrollment) != nil {
		return p.reject()
	}
	current, now, err := snapshot(p.physical, p.operator)
	if err != nil || current.cas != p.initial || current.cas.State == "revoked" || now.Before(p.floor) || now.Before(p.selection.NotBefore) || !now.Before(p.selection.Until) || observeBootstrapSourceController(p.physical, p.operator.installer.kube, p.operator.installer.plan.Target, p.selection.Controller) != nil || p.local(ctx) != nil {
		return p.reject()
	}
	// The final original SQL clock/CAS sample follows controller and file tails.
	// Native API calls remain outside either short Installer SQL snapshot.
	last, after, err := snapshot(p.physical, p.operator)
	if err != nil || last.cas != p.initial || last.cas.State == "revoked" || after.Before(now) || after.Before(p.floor) || after.Before(p.selection.NotBefore) || !after.Before(p.selection.Until) || p.physical.Err() != nil || !p.operator.live(p.physical) {
		return p.reject()
	}
	p.floor = after
	return nil
}
func (p *BootstrapSourceRegistryAuthoring) Close() {
	if p == nil || p.origin != p {
		_ = p.reject()
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.failed.Store(true)
	p.cancel()
}
