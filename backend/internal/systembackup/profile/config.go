// Package profile assembles the concrete Linux/Kubernetes users+instances
// execution driver. Configuration describes explicit mounts; discovery verifies
// the complete SQL inventory and live resource identities rather than guessing
// persistent paths from an agent brand.
package profile

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"clawreef/internal/services"
	"clawreef/internal/systembackup/artifact"
	"clawreef/internal/systembackup/assets"
	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/domain"
	"clawreef/internal/systembackup/quiesce"
	"clawreef/internal/systembackup/recovery"
	"clawreef/internal/systembackup/worker"
	"io"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var ErrProfile = errors.New("backup_profile_unavailable")
var name = regexp.MustCompile(`^[a-z][a-z0-9-]{0,48}$`)

type Claim struct{ Name, UID string }
type Instance struct {
	ID                                                                          int
	Namespace, PodName, WorkloadKind, WorkloadName, VolumeName, Workspace, Node string
	// Only stopped instances need an explicit source volume because their Pod no
	// longer exists. It is checked against the SQL instance and live PVC/PV.
	StoppedVolume *corev1.Volume
	SubPath       string
	Endpoint      string
	Restart       services.RuntimeAgentCreateGatewayRequest
	Files         []worker.FileRule
	SnapshotClass string
	Policy        string
}
type Config struct {
	// target profiles can restore an artifact with no source connection.
	Mode                                                                    string
	ID, Namespace, TargetNamespace, WorkerImage, ServiceAccount, ControlURL string
	Source, Target                                                          worker.DatabaseSpec
	Staging                                                                 map[string]Claim
	Evidence                                                                Claim
	TargetStorageClass, TargetStorageSize                                   string
	PolicyVersion, KeyVersion, SignerID                                     string
	Instances                                                               []Instance
	Configs                                                                 domain.JSONRegistry
	WorkBuddy                                                               *domain.WorkBuddySchema
	Dependencies                                                            map[string]domain.TableAdapter
	RuntimePolicies                                                         map[string]worker.RuntimePolicy
	Assets                                                                  assets.Inventory
	MaxFiles, MaxFileBytes, MaxArchiveBytes, MaxCompressedBytes             int64
	// ExclusiveNFSProofURL is an authenticated proof service supplied by the
	// storage owner. Required for NFS: cluster Pod enumeration alone cannot prove
	// that external hosts have been fenced. Empty means NFS is not ready.
	ExclusiveNFSProofURL  string
	Applications          []ApplicationDeployment
	WriterProofURL        string
	LegacyPermits         map[string]control.AppProcess
	SixDomainModule       *recovery.Reference `json:",omitempty"`
	AcceptancePolicy      *recovery.Reference `json:",omitempty"`
	SharedWorkspaceModule *recovery.Reference `json:",omitempty"`
}
type Driver struct {
	Config                           Config
	SixDomain                        SixDomainOwner
	SharedWorkspace                  SharedWorkspaceOwner
	Store                            control.SQLStore
	Vault                            control.Vault
	Source, SourceAdmin, TargetAdmin *sql.DB
	Client                           kubernetes.Interface
	Dynamic                          dynamic.Interface
	Identities                       control.WorkerIdentities
	Proof                            *quiesce.ProofClient
	Agent                            services.BackupGatewayAgent
	AgentProbe                       func(context.Context, string, string) error
	ExternalNFSProof                 func(context.Context, string, string) error
	WriterProof                      func(context.Context, WriterProofRequest) error
	OpenObject                       func(context.Context, assets.ObjectRef) (io.ReadCloser, error)
	Keys                             artifact.SecretKeys
	Publisher                        control.Publisher
	Staging, Evidence                *os.Root
}

func (d *Driver) Metadata() control.Profile {
	raw, _ := json.Marshal(d.Config)
	sum := sha256.Sum256(raw)
	kinds := []string{"backup", "drill", "preflight"}
	if d.Config.Mode == "backup" {
		kinds = []string{"backup"}
	}
	if d.Config.Mode == "target" {
		kinds = []string{"drill", "preflight"}
	}
	return control.Profile{ID: d.Config.ID, Revision: hex.EncodeToString(sum[:]), Kinds: kinds, AcceptancePolicy: d.Config.AcceptancePolicy}
}
func (c Config) Validate() error {
	if c.WorkBuddy != nil && c.WorkBuddy.Layout != "" && *c.WorkBuddy != *domain.WorkBuddyUIDSchema() {
		return ErrProfile
	}
	if c.AcceptancePolicy != nil && (c.AcceptancePolicy.Validate() != nil || c.SixDomainModule == nil || c.Mode != "backup") {
		return ErrProfile
	}
	if c.SharedWorkspaceModule != nil && (c.Mode != "target" || c.SharedWorkspaceModule.Validate() != nil) {
		return ErrProfile
	}
	if c.SixDomainModule != nil && (c.Mode != "backup" || c.SixDomainModule.Validate() != nil) {
		return ErrProfile
	}
	if c.Mode != "" && c.Mode != "backup" && c.Mode != "target" {
		return ErrProfile
	}
	u, e := url.Parse(c.ControlURL)
	if e != nil || u.Scheme != "https" || u.Path != "/worker/v1" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ErrProfile
	}
	if _, e = endpoint(u.Host); e != nil {
		return e
	}
	if !strings.Contains(c.WorkerImage, "@sha256:") || c.ServiceAccount == "" || !strings.HasPrefix(c.Target.Name, "cm_drill_") || !strings.HasPrefix(c.TargetNamespace, "cm-drill-") || c.Evidence.Name == "" || c.Evidence.UID == "" {
		return ErrProfile
	}
	if !name.MatchString(c.ID) || c.Namespace == "" || c.TargetNamespace == "" || c.Source.Name == c.Target.Name && c.Source.ServerUUID == c.Target.ServerUUID || c.PolicyVersion == "" || c.KeyVersion == "" || c.SignerID == "" || c.MaxFiles <= 0 || c.MaxFileBytes <= 0 || c.MaxArchiveBytes < c.MaxFileBytes || c.MaxCompressedBytes <= 0 || c.Source.Name == "" || c.Target.Name == "" || c.TargetStorageClass == "" || c.TargetStorageSize == "" || len(c.Instances) > 9998 {
		return ErrProfile
	}
	seen := map[int]bool{}
	for id, policy := range c.RuntimePolicies {
		if id == "" || policy.Validate() != nil {
			return ErrProfile
		}
	}
	for _, i := range c.Instances {
		if i.ID <= 0 || seen[i.ID] || i.Namespace == "" || i.Workspace == "" || (i.WorkloadKind != "Pod" && i.WorkloadKind != "Deployment" && i.WorkloadKind != "Gateway" && i.WorkloadKind != "Stopped") {
			return ErrProfile
		}
		seen[i.ID] = true
		policy, ok := c.RuntimePolicies[i.Policy]
		if !ok || (len(i.Files) != 0 && !jsonEqual(i.Files, policy.Files)) {
			return ErrProfile
		}
		if c.Staging[i.Namespace].UID == "" {
			return ErrProfile
		}
	}
	for _, ns := range []string{c.Namespace, c.TargetNamespace} {
		if c.Staging[ns].Name == "" || c.Staging[ns].UID == "" {
			return ErrProfile
		}
	}
	return nil
}
func (d *Driver) Probe(ctx context.Context) error {
	if d.Config.AcceptancePolicy != nil {
		a, ok := d.SixDomain.(SixDomainAcceptanceOwner)
		if !ok || a.ProbeAcceptance(ctx, *d.Config.AcceptancePolicy) != nil {
			return ErrProfile
		}
	}
	if d.Config.SharedWorkspaceModule != nil && (d.SharedWorkspace == nil || d.SharedWorkspace.Probe(ctx, *d.Config.SharedWorkspaceModule) != nil) {
		return ErrProfile
	}
	if d.Config.SixDomainModule != nil && (d.SixDomain == nil || d.SixDomain.Probe(ctx, *d.Config.SixDomainModule) != nil) {
		return ErrProfile
	}
	if d.Config.Validate() != nil || d.Store.DB == nil || d.Client == nil || d.Dynamic == nil || d.Proof == nil || d.Staging == nil || d.Evidence == nil || len(d.Keys[d.Config.KeyVersion]) != 32 || len(d.Publisher.Signers[d.Config.SignerID]) != ed25519.PrivateKeySize {
		return ErrProfile
	}
	for index, pair := range []struct {
		db   *sql.DB
		spec worker.DatabaseSpec
	}{{d.Source, d.Config.Source}, {d.TargetAdmin, d.Config.Target}} {
		if index == 0 && d.Config.Mode == "target" {
			continue
		}
		if index == 1 && d.Config.Mode == "backup" {
			continue
		}
		if pair.db == nil {
			return ErrProfile
		}
		var database, uuid string
		if pair.db.QueryRowContext(ctx, "SELECT DATABASE(), @@server_uuid").Scan(&database, &uuid) != nil || database != pair.spec.Name || uuid != pair.spec.ServerUUID {
			return ErrProfile
		}
	}
	var uuid string
	if d.Store.DB.QueryRowContext(ctx, "SELECT @@server_uuid").Scan(&uuid) != nil || (d.Config.Mode != "target" && uuid != d.Config.Source.ServerUUID) {
		return ErrProfile
	}
	if d.Config.Mode != "target" {
		if d.Config.Assets.Validate() != nil || len(d.Config.Assets.Objects) > 0 && d.OpenObject == nil {
			return ErrProfile
		}
		if len(d.Config.Applications) == 0 || d.Config.WriterProofURL == "" || d.WriterProof == nil {
			return ErrProfile
		}
		if _, e := d.applicationCoverage(ctx); e != nil {
			return e
		}
		if d.SourceAdmin == nil {
			return ErrProfile
		}
		if _, e := domain.Catalog(ctx, d.Source); e != nil {
			return ErrProfile
		}
		for _, table := range []string{"instances", "instance_runtime_bindings", "runtime_pods"} {
			var engine string
			if d.Source.QueryRowContext(ctx, "SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=? AND TABLE_NAME=?", d.Config.Source.Name, table).Scan(&engine) != nil || engine != "InnoDB" {
				return ErrProfile
			}
		}
	}
	// Fail before source pause when schema/permissions for cross-schema atomic
	// restart bookkeeping or newly installed control tables are unavailable.
	for _, table := range []string{"system_backup_private_records", "system_backup_worker_processes", "system_backup_credentials", "system_backup_identities", "system_backup_app_processes", "system_backup_mutation_resolutions"} {
		var n int
		if d.Store.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table+" WHERE 1=0").Scan(&n) != nil {
			return ErrProfile
		}
	}
	var n int
	if d.Store.DB.QueryRowContext(ctx, "SELECT COUNT(process_id) FROM system_backup_mutations WHERE 1=0").Scan(&n) != nil {
		return ErrProfile
	}
	if d.Store.DB.QueryRowContext(ctx, "SELECT COUNT(restart_result) FROM system_backup_pauses WHERE 1=0").Scan(&n) != nil {
		return ErrProfile
	}
	for ns, claim := range d.Config.Staging {
		if _, e := d.claim(ctx, ns, claim); e != nil {
			return e
		}
	}
	return ctx.Err()
}
func (d *Driver) fence(ctx context.Context, t control.Task, recovery bool) error {
	if !recovery {
		current, e := d.Store.Get(ctx, t.ID)
		if e != nil || !current.CanCancel || current.Deadline <= time.Now().UnixMilli() {
			return control.ErrFence
		}
	}
	tx, e := d.Store.DB.BeginTx(ctx, nil)
	if e != nil {
		return ErrProfile
	}
	defer tx.Rollback()
	if e = d.Store.Fence(ctx, tx, t); e != nil {
		return e
	}
	return nil
}
func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
