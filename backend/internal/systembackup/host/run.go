package host

import (
	"context"
	"database/sql"
	"net"
	"os"
	"strings"
	"time"

	"clawreef/internal/services"
	"clawreef/internal/systembackup/artifact"
	"clawreef/internal/systembackup/control"
	"clawreef/internal/systembackup/kube"
	"clawreef/internal/systembackup/profile"
	"clawreef/internal/systembackup/quiesce"
	"clawreef/internal/systembackup/recovery"
	"clawreef/internal/systembackup/worker"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func openDatabase(spec worker.DatabaseSpec, credentialFile string) (*sql.DB, error) {
	var credential worker.DatabaseCredential
	if ReadJSON(credentialFile, &credential) != nil {
		return nil, control.ErrInvalid
	}
	defer clear(credential.Password)
	db, e := worker.OpenDatabase(&spec, &credential)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(12)
	db.SetMaxIdleConns(4)
	return db, nil
}

// Run performs no schema installation. All external writes are task-driven and
// use Pipeline's journal/fence. Failure of either loop stops the entire host.
type OwnerFactories map[string]func(*profile.Driver, recovery.Reference) (profile.SixDomainOwner, error)
type SharedWorkspaceFactories map[string]func(*profile.Driver, recovery.Reference) (profile.SharedWorkspaceOwner, error)
type Adapters struct {
	SixDomain       OwnerFactories
	SharedWorkspace SharedWorkspaceFactories
	CatalogCodecs   CatalogCodecs
}

func Run(ctx context.Context, c Config, report func(string)) error {
	return RunWithOwners(ctx, c, report, nil)
}
func RunWithOwners(ctx context.Context, c Config, report func(string), owners OwnerFactories) error {
	return RunWithAdapters(ctx, c, report, Adapters{SixDomain: owners})
}
func RunWithAdapters(ctx context.Context, c Config, report func(string), adapters Adapters) error {
	if c.Validate() != nil {
		return control.ErrInvalid
	}
	if len(c.Profiles) == 0 {
		return runCatalogOnly(ctx, c, report, adapters.CatalogCodecs)
	}
	keys, issuer, e := c.materials()
	defer keys.Clear()
	if e != nil {
		return e
	}
	var closeFunctions []func()
	defer func() {
		for i := len(closeFunctions) - 1; i >= 0; i-- {
			closeFunctions[i]()
		}
	}()
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	db, e := control.OpenControlDatabase(bounded, c.ControlDatabase)
	cancel()
	if e != nil {
		return e
	}
	closeFunctions = append(closeFunctions, func() { db.Close() })
	store := control.SQLStore{DB: db}
	vault := control.Vault{Store: store, WriteVersion: keys.VaultVersion, Keys: keys.Vault}
	var rc *rest.Config
	if c.Kubeconfig == "" {
		rc, e = rest.InClusterConfig()
	} else {
		rc, e = clientcmd.BuildConfigFromFlags("", c.Kubeconfig)
	}
	if e != nil {
		return control.ErrNotReady
	}
	rc.Timeout = 10 * time.Second
	rc.UserAgent = "clawmanager-backup-controller"
	client, e := kubernetes.NewForConfig(rc)
	if e != nil {
		return control.ErrNotReady
	}
	dynamicClient, e := dynamic.NewForConfig(rc)
	if e != nil {
		return control.ErrNotReady
	}
	proof, e := quiesce.NewProofClient(c.NodeEndpoints, c.NodeProof.CA, c.NodeProof.Certificate, c.NodeProof.Key)
	if e != nil {
		return e
	}
	roots := make([]*os.Root, 3)
	for idx, path := range []string{c.StagingPath, c.EvidencePath, c.ArtifactPath} {
		r, e := os.OpenRoot(path)
		if e != nil {
			return control.ErrNotReady
		}
		roots[idx] = r
		closeFunctions = append(closeFunctions, func() { r.Close() })
	}
	publisher := control.Publisher{Store: store, Signers: keys.Signers, Directory: artifact.Directory{Root: roots[2], Keys: artifact.SecretKeys(keys.Wrapping), VerifyKeys: keys.Verify, MaxCiphertextBytes: 1 << 40, MaxPlaintextBytes: 1 << 40}}
	identities := control.WorkerIdentities{Vault: vault, Client: client, Issuer: issuer}
	active := map[string]string{}
	for id, r := range c.ActiveRevisions {
		active[id] = r
	}
	for _, p := range c.Catalogs {
		delete(active, p.ID)
	}
	pipeline := &control.Pipeline{Store: store, Vault: vault, ActiveRevisions: active}
	drivers := map[string]*profile.Driver{}
	for _, p := range c.Profiles {
		d := &profile.Driver{Config: p.Config, Store: store, Vault: vault, Client: client, Dynamic: dynamicClient, Identities: identities, Proof: proof, Keys: artifact.SecretKeys(keys.Wrapping), Publisher: publisher, Staging: roots[0], Evidence: roots[1]}
		open := func(spec worker.DatabaseSpec, file string, dst **sql.DB) error {
			value, e := openDatabase(spec, file)
			if e == nil {
				*dst = value
				closeFunctions = append(closeFunctions, func() { value.Close() })
			}
			return e
		}
		if p.Config.Mode != "target" {
			if e = open(p.Config.Source, p.SourceCredential, &d.Source); e != nil {
				return e
			}
			if e = open(p.Config.Source, p.SourceAdminCredential, &d.SourceAdmin); e != nil {
				return e
			}
		}
		if p.Config.Mode != "backup" {
			if e = open(p.Config.Target, p.TargetAdminCredential, &d.TargetAdmin); e != nil {
				return e
			}
		}
		capability := func(caFile, tokenFile string) (*profile.CapabilityClient, error) {
			ca, e := ReadFile(caFile, 64<<10)
			if e != nil {
				return nil, e
			}
			token, e := ReadFile(tokenFile, 4096)
			if e != nil {
				return nil, e
			}
			defer clear(token)
			return profile.NewCapabilityClient(ca, strings.TrimSpace(string(token)))
		}
		if p.RuntimeToken != "" {
			cap, e := capability(p.RuntimeCA, p.RuntimeToken)
			if e != nil {
				return e
			}
			closeFunctions = append(closeFunctions, cap.Close)
			d.AgentProbe = cap.Agent
			agent := services.NewRuntimeAgentClientWithHTTPClient(cap.Token, cap.HTTP)
			var ok bool
			d.Agent, ok = agent.(services.BackupGatewayAgent)
			if !ok {
				return control.ErrInvalid
			}
		}
		if p.Config.ExclusiveNFSProofURL != "" {
			cap, e := capability(p.StorageCA, p.StorageToken)
			if e != nil {
				return e
			}
			closeFunctions = append(closeFunctions, cap.Close)
			d.ExternalNFSProof = cap.NFS
		}
		m := d.Metadata()
		if p.Objects != nil && p.Config.Mode != "target" {
			read, close, e := objectReader(*p.Objects)
			if e != nil {
				return e
			}
			d.OpenObject = read
			closeFunctions = append(closeFunctions, close)
		}
		if p.Config.WriterProofURL != "" {
			cap, e := capability(p.WriterCA, p.WriterToken)
			if e != nil {
				return e
			}
			closeFunctions = append(closeFunctions, cap.Close)
			d.WriterProof = func(ctx context.Context, r profile.WriterProofRequest) error {
				return cap.WriterCoverage(ctx, p.Config.WriterProofURL, r)
			}
		}
		// Missing owner factories remain unavailable during probes; never
		// downgrade an explicitly selected six-domain configuration.
		if module := p.Config.SixDomainModule; module != nil {
			if factory := adapters.SixDomain[module.ID]; factory != nil {
				d.SixDomain, e = factory(d, *module)
				if e != nil {
					return control.ErrNotReady
				}
			}
		}
		if module := p.Config.SharedWorkspaceModule; module != nil {
			if factory := adapters.SharedWorkspace[module.ID]; factory != nil {
				d.SharedWorkspace, e = factory(d, *module)
				if e != nil {
					return control.ErrNotReady
				}
			}
		}
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		e = d.VerifyControllerRoots(bounded, os.Getenv("POD_NAMESPACE"), os.Getenv("POD_NAME"), os.Getenv("POD_UID"), c.StagingPath, c.EvidencePath)
		cancel()
		if e != nil {
			return e
		}
		drivers[m.ID+"/"+m.Revision] = d
		pipeline.Drivers = append(pipeline.Drivers, d)
	}
	resolve := func(ctx context.Context, g control.WorkerGrant) (*profile.Driver, control.Task, error) {
		t, e := store.Get(ctx, g.TaskID)
		if e != nil || t.ProfileRevision != g.ProfileRevision {
			return nil, t, control.ErrFence
		}
		d := drivers[t.Request.Profile+"/"+t.ProfileRevision]
		if d == nil {
			return nil, t, control.ErrNotReady
		}
		return d, t, nil
	}
	authorizer := control.WorkerAuthorizer{Store: store, Keys: artifact.SecretKeys(keys.Wrapping), Lifetime: 5 * time.Minute,
		Credentials: func(ctx context.Context, g control.WorkerGrant) (*worker.DatabaseCredential, error) {
			d, t, e := resolve(ctx, g)
			if e != nil {
				return nil, e
			}
			admin := d.TargetAdmin
			if g.Invocation.Request.Operation == "capture-database" {
				admin = d.SourceAdmin
			}
			return (control.DatabaseCredentials{Vault: vault, Admin: admin}).Load(ctx, t, g.CredentialRef)
		},
		ValidateLive: func(ctx context.Context, g control.WorkerGrant, point string) error {
			d, _, e := resolve(ctx, g)
			if e != nil {
				return e
			}
			return (control.LiveWorkers{Store: store, Observer: kube.WorkerObserver{Client: client}, Proof: proof, CheckEvidence: d.EvidenceCheck}).Validate(ctx, g, point)
		},
	}
	listener, e := net.Listen("tcp", c.Listen)
	if e != nil {
		return control.ErrNotReady
	}
	defer listener.Close()
	run, stop := context.WithCancel(ctx)
	defer stop()
	results := make(chan error, 2)
	bindings, closeCatalog, e := CatalogBindingsWithCodecs(c.Catalogs, adapters.CatalogCodecs)
	if e != nil {
		return e
	}
	defer closeCatalog()
	executor := control.NewCatalogExecutor(store, vault, pipeline, bindings)
	service := control.Service{Store: store, Publisher: publisher, Controller: control.Controller{Store: store, Executor: executor, Owner: c.Owner, Lease: 30 * time.Second, RecoveryTimeout: 5 * time.Minute}, PollInterval: time.Second, ProbeTimeout: 10 * time.Second, OnError: report}
	go func() {
		results <- worker.ServeControl(run, listener, c.Relay.CA, c.Relay.Certificate, c.Relay.Key, authorizer)
	}()
	go func() { results <- service.Run(run) }()
	result := <-results
	stop()
	<-results
	return result
}
