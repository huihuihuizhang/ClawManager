package main

import (
	"context"
	stdsql "database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"clawreef/internal/config"
	"clawreef/internal/db"
	"clawreef/internal/services/k8s"
	"clawreef/internal/services/leader"
	"clawreef/internal/systembackupcontroller"
	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	defaultHealthAddress      = ":9003"
	defaultLeaderLease        = "clawmanager-system-backup-controller"
	dependencyProbeInterval   = 15 * time.Second
	dependencyProbeTimeout    = 5 * time.Second
	dependencyUnavailableCode = "dependency_probe_failed"
)

type controllerStatus struct {
	leading           atomic.Bool
	mu                sync.RWMutex
	ready             bool
	reason            string
	configEnabled     bool
	effectiveEnabled  bool
	configVersion     uint64
	catalogHash       string
	dependenciesReady bool
	dependencyReason  string
}

type controllerReadiness struct {
	ready             bool
	reason            string
	configEnabled     bool
	effectiveEnabled  bool
	configVersion     uint64
	catalogHash       string
	dependenciesReady bool
	dependencyReason  string
}

func (s *controllerStatus) setBootstrapFailure(err error) bool {
	reason := string(systembackupcontroller.BootstrapFailureCodeOf(err))
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := s.ready || s.reason != reason
	s.ready = false
	s.reason = reason
	s.configEnabled = false
	s.effectiveEnabled = false
	s.configVersion = 0
	s.catalogHash = ""
	return changed
}

func (s *controllerStatus) setReady(snapshot systembackupcontroller.BootstrapSnapshot) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := !s.ready ||
		s.configEnabled != snapshot.ConfigEnabled ||
		s.effectiveEnabled != snapshot.EffectiveEnabled ||
		s.configVersion != snapshot.ConfigVersion ||
		s.catalogHash != snapshot.MigrationCatalogHash
	s.ready = true
	s.reason = ""
	s.configEnabled = snapshot.ConfigEnabled
	s.effectiveEnabled = snapshot.EffectiveEnabled
	s.configVersion = snapshot.ConfigVersion
	s.catalogHash = snapshot.MigrationCatalogHash
	return changed
}

func (s *controllerStatus) setDependenciesReady() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := !s.dependenciesReady || s.dependencyReason != ""
	s.dependenciesReady = true
	s.dependencyReason = ""
	return changed
}

func (s *controllerStatus) setDependencyFailure(reason string) bool {
	if reason == "" {
		reason = dependencyUnavailableCode
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := s.dependenciesReady || s.dependencyReason != reason
	s.dependenciesReady = false
	s.dependencyReason = reason
	return changed
}

func (s *controllerStatus) readiness() controllerReadiness {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return controllerReadiness{
		ready:             s.ready,
		reason:            s.reason,
		configEnabled:     s.configEnabled,
		effectiveEnabled:  s.effectiveEnabled,
		configVersion:     s.configVersion,
		catalogHash:       s.catalogHash,
		dependenciesReady: s.dependenciesReady,
		dependencyReason:  s.dependencyReason,
	}
}

type databasePinger interface {
	PingContext(context.Context) error
}

type kubernetesControllerReadinessProbe struct {
	Client    kubernetes.Interface
	Namespace string
	LeaseName string
}

func (p kubernetesControllerReadinessProbe) Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.Client == nil {
		return errors.New("nil Kubernetes readiness client")
	}
	if strings.TrimSpace(p.Namespace) == "" || strings.TrimSpace(p.LeaseName) == "" {
		return errors.New("empty Kubernetes leader lease identity")
	}
	resources, err := p.Client.Discovery().ServerResourcesForGroupVersion("coordination.k8s.io/v1")
	if err != nil {
		return fmt.Errorf("discover coordination API: %w", err)
	}
	if resources == nil {
		return errors.New("coordination API discovery returned no resource list")
	}
	leasesFound := false
	for _, resource := range resources.APIResources {
		if resource.Name == "leases" {
			leasesFound = true
			break
		}
	}
	if !leasesFound {
		return errors.New("coordination API does not publish leases")
	}
	if _, err := p.Client.CoordinationV1().Leases(p.Namespace).Get(ctx, p.LeaseName, metav1.GetOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("read leader lease: %w", err)
	}
	for _, verb := range []string{"create", "get", "update", "patch"} {
		name := p.LeaseName
		if verb == "create" {
			name = ""
		}
		review, err := p.Client.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: p.Namespace,
				Verb:      verb,
				Group:     "coordination.k8s.io",
				Version:   "v1",
				Resource:  "leases",
				Name:      name,
			}},
		}, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("review leader lease %s permission: %w", verb, err)
		}
		if review.Status.EvaluationError != "" {
			return fmt.Errorf("review leader lease %s permission: %s", verb, review.Status.EvaluationError)
		}
		if !review.Status.Allowed {
			return fmt.Errorf("leader lease %s permission denied", verb)
		}
	}
	return nil
}

func runDependencyProbe(ctx context.Context, status *controllerStatus, probe systembackupcontroller.ReadinessProbe) {
	if status == nil {
		return
	}
	if probe == nil {
		status.setDependencyFailure(dependencyUnavailableCode)
		return
	}
	check := func() {
		probeCtx, cancel := context.WithTimeout(ctx, dependencyProbeTimeout)
		err := probe.Check(probeCtx)
		cancel()
		if err != nil {
			if status.setDependencyFailure(dependencyUnavailableCode) {
				log.Printf("[system-backup-controller] dependency readiness failed: %v", err)
			}
			return
		}
		if status.setDependenciesReady() {
			log.Printf("[system-backup-controller] dependency readiness restored")
		}
	}
	check()
	ticker := time.NewTicker(dependencyProbeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}

func runLeaderControlLoop(ctx context.Context, run func(context.Context) error, failures chan<- error, cancelRuntime context.CancelFunc) {
	err := run(ctx)
	if ctx.Err() != nil {
		return
	}
	if err == nil {
		err = errors.New("control loop exited without leader cancellation")
	}
	select {
	case failures <- fmt.Errorf("leader control loop stopped: %w", err):
	default:
	}
	cancelRuntime()
}

func envDuration(name string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a Go duration: %w", name, err)
	}
	return value, nil
}

func envInt(name string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", name, err)
	}
	return value, nil
}

func envBool(name string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean: %w", name, err)
	}
	return value, nil
}

func controllerIdentity() string {
	identity := strings.TrimSpace(os.Getenv("POD_NAME"))
	if identity == "" {
		identity, _ = os.Hostname()
	}
	if identity == "" {
		identity = "unknown"
	}
	return "system-backup-controller:" + identity
}

func healthHandler(pinger databasePinger, status *controllerStatus, metrics ...http.Handler) http.Handler {
	mux := http.NewServeMux()
	if len(metrics) > 0 && metrics[0] != nil {
		mux.Handle("/metrics", metrics[0])
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, request *http.Request) {
		if pinger == nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("disabled\n"))
			return
		}
		pingCtx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
		defer cancel()
		if err := pinger.PingContext(pingCtx); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		readiness := status.readiness()
		if !readiness.ready {
			if readiness.reason == "" {
				readiness.reason = "bootstrap_pending"
			}
			http.Error(w, "bootstrap not ready: "+readiness.reason, http.StatusServiceUnavailable)
			return
		}
		if !readiness.dependenciesReady {
			if readiness.dependencyReason == "" {
				readiness.dependencyReason = dependencyUnavailableCode
			}
			http.Error(w, "dependencies not ready: "+readiness.dependencyReason, http.StatusServiceUnavailable)
			return
		}
		configMode := "disabled"
		if readiness.configEnabled {
			configMode = "enabled"
		}
		effectiveMode := "disabled"
		if readiness.effectiveEnabled {
			effectiveMode = "enabled"
		}
		catalogPrefix := readiness.catalogHash
		if len(catalogPrefix) > 12 {
			catalogPrefix = catalogPrefix[:12]
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if status.leading.Load() {
			_, _ = fmt.Fprintf(w, "leader config=%s effective=%s config_version=%d catalog=%s\n", configMode, effectiveMode, readiness.configVersion, catalogPrefix)
		} else {
			_, _ = fmt.Fprintf(w, "standby config=%s effective=%s config_version=%d catalog=%s\n", configMode, effectiveMode, readiness.configVersion, catalogPrefix)
		}
	})

	return mux
}

func startHealthServer(ctx context.Context, address string, pinger databasePinger, status *controllerStatus, metrics ...http.Handler) *http.Server {
	server := &http.Server{
		Addr:              address,
		Handler:           healthHandler(pinger, status, metrics...),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[system-backup-controller] health server failed: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	return server
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	status := &controllerStatus{}
	healthAddress := strings.TrimSpace(os.Getenv("SYSTEM_BACKUP_CONTROLLER_HEALTH_ADDRESS"))
	if healthAddress == "" {
		healthAddress = defaultHealthAddress
	}
	enabled, err := envBool("SYSTEM_BACKUP_CONTROLLER_ENABLED", false)
	if err != nil {
		return err
	}
	if !enabled {
		log.Printf("[system-backup-controller] disabled by feature gate")
		_ = startHealthServer(rootCtx, healthAddress, nil, status)
		<-rootCtx.Done()
		return nil
	}
	if err := systembackupcontroller.ValidateControllerDatabaseCredentials(os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), cfg.Database.User); err != nil {
		return err
	}
	if !cfg.LeaderElection.Enabled {
		return errors.New("system backup controller requires Kubernetes leader election")
	}
	installationID := strings.TrimSpace(os.Getenv("SYSTEM_BACKUP_ORIGIN_INSTALLATION_ID"))
	environmentEnabled, err := envBool("SYSTEM_BACKUP_ENABLED", false)
	if err != nil {
		return err
	}
	systemBackupRequired, err := envBool("SYSTEM_BACKUP_REQUIRED", false)
	if err != nil {
		return err
	}
	bootstrapInterval, err := envDuration("SYSTEM_BACKUP_CONTROLLER_BOOTSTRAP_INTERVAL", systembackupcontroller.DefaultBootstrapCheckInterval)
	if err != nil {
		return err
	}
	sweepLimit, err := envInt("SYSTEM_BACKUP_CONTROLLER_SWEEP_LIMIT", systembackupcontroller.MaxDeadlineSweepBatch)
	if err != nil {
		return err
	}
	catalog, err := db.EmbeddedMigrationCatalog()
	if err != nil {
		return fmt.Errorf("compute embedded migration catalog: %w", err)
	}
	requirements := systembackupcontroller.BootstrapRequirements{
		InstallationID:       installationID,
		EnvironmentEnabled:   environmentEnabled,
		SystemBackupRequired: systemBackupRequired,
		Catalog:              catalog,
	}
	if err := requirements.Validate(); err != nil {
		return fmt.Errorf("validate bootstrap requirements: %w", err)
	}

	session, err := db.ConnectSystemBackupController(cfg.Database)
	if err != nil {
		return fmt.Errorf("connect control database: %w", err)
	}
	defer db.Close()
	sqlDB, ok := session.Driver().(*stdsql.DB)
	if !ok || sqlDB == nil {
		return errors.New("control database driver is not *sql.DB")
	}
	grantProbe := systembackupcontroller.SQLControllerGrantProbe{DB: sqlDB, Schema: cfg.Database.Database, User: cfg.Database.User}
	grantCtx, cancelGrantCheck := context.WithTimeout(rootCtx, dependencyProbeTimeout)
	grantErr := grantProbe.Check(grantCtx)
	cancelGrantCheck()
	if grantErr != nil {
		return fmt.Errorf("controller database grant admission failed: %w", grantErr)
	}
	controllerTelemetry := &systembackupcontroller.ControllerTelemetry{}
	_ = startHealthServer(rootCtx, healthAddress, sqlDB, status, systembackupcontroller.QueueBudgetMetricsHandler{
		Collector:      systembackupcontroller.SQLQueueBudgetReader{DB: sqlDB},
		InstallationID: installationID,
		Leader:         status.leading.Load,
		Controller:     controllerTelemetry,
		Ready: func() bool {
			readiness := status.readiness()
			return readiness.ready && readiness.dependenciesReady
		},
	})
	if err := k8s.Initialize(cfg); err != nil {
		return fmt.Errorf("initialize Kubernetes client: %w", err)
	}
	k8sClient := k8s.GetClient()
	if k8sClient == nil || k8sClient.Clientset == nil || k8sClient.Config == nil {
		return errors.New("Kubernetes client or REST config is unavailable")
	}
	readinessK8sConfig := rest.CopyConfig(k8sClient.Config)
	readinessK8sConfig.Timeout = dependencyProbeTimeout
	readinessK8sClient, err := kubernetes.NewForConfig(readinessK8sConfig)
	if err != nil {
		return fmt.Errorf("initialize bounded Kubernetes readiness client: %w", err)
	}
	owner := controllerIdentity()
	leaseName := strings.TrimSpace(os.Getenv("SYSTEM_BACKUP_CONTROLLER_LEADER_LEASE_NAME"))
	if leaseName == "" {
		leaseName = defaultLeaderLease
	}
	leaderConfig := leader.Config{
		Namespace:     cfg.LeaderElection.Namespace,
		LeaseName:     leaseName,
		Identity:      owner,
		LeaseDuration: time.Duration(cfg.LeaderElection.LeaseDuration) * time.Second,
		RenewDeadline: time.Duration(cfg.LeaderElection.RenewDeadline) * time.Second,
		RetryPeriod:   time.Duration(cfg.LeaderElection.RetryPeriod) * time.Second,
	}
	dependencyProbe := systembackupcontroller.ReadinessProbeSet{
		grantProbe,
		systembackupcontroller.SQLUTCReadinessProbe{DB: sqlDB},
		systembackupcontroller.SQLClaimReadinessProbe{DB: sqlDB},
		systembackupcontroller.SQLDeadlineAlertReadinessProbe{DB: sqlDB},
		kubernetesControllerReadinessProbe{
			Client:    readinessK8sClient,
			Namespace: leaderConfig.Namespace,
			LeaseName: leaderConfig.LeaseName,
		},
	}
	go runDependencyProbe(rootCtx, status, dependencyProbe)
	log.Printf("[system-backup-controller] supervising owner=%s lease=%s/%s env_enabled=%t required=%t", owner, cfg.LeaderElection.Namespace, leaseName, environmentEnabled, systemBackupRequired)
	supervisor := systembackupcontroller.BootstrapSupervisor{
		Checker:           systembackupcontroller.SQLBootstrapChecker{DB: sqlDB},
		Requirements:      requirements,
		CheckInterval:     bootstrapInterval,
		WorkerStopTimeout: systembackupcontroller.DefaultWorkerStopTimeout,
		Worker: func(workerCtx context.Context, snapshot systembackupcontroller.BootstrapSnapshot) error {
			admissionCtx, cancelAdmission := context.WithTimeout(workerCtx, dependencyProbeTimeout)
			admissionErr := dependencyProbe.Check(admissionCtx)
			cancelAdmission()
			if admissionErr != nil {
				return fmt.Errorf("controller dependency admission failed before leadership: %w", admissionErr)
			}
			runtimeCtx, cancelRuntime := context.WithCancel(workerCtx)
			defer cancelRuntime()
			runtimeErrors := make(chan error, 1)
			var leaderBootstrapReconciled atomic.Bool
			stateReconciler := systembackupcontroller.SQLInstallationStateReconciler{DB: sqlDB}
			gateInitializer := systembackupcontroller.SQLGateInitializer{DB: sqlDB}
			policy := snapshot.Policy
			gateRecovery := systembackupcontroller.GateRecoveryReconciler{
				Store:            systembackupcontroller.SQLGateRecoveryStore{DB: sqlDB},
				InstallationID:   snapshot.InstallationID,
				Owner:            owner,
				Policy:           snapshot.GatePolicy,
				RunningReadiness: nil,
				Limit:            sweepLimit,
			}
			if err := gateRecovery.Validate(); err != nil {
				return fmt.Errorf("validate gate recovery reconciler: %w", err)
			}
			killSwitch := systembackupcontroller.KillSwitchReconciler{
				Store:            systembackupcontroller.SQLKillSwitchStore{DB: sqlDB},
				InstallationID:   snapshot.InstallationID,
				EffectiveEnabled: snapshot.EffectiveEnabled,
				Limit:            sweepLimit,
			}
			if err := killSwitch.Validate(); err != nil {
				return fmt.Errorf("validate kill-switch reconciler: %w", err)
			}
			sweeper := systembackupcontroller.DeadlineSweeper{
				Store:          systembackupcontroller.SQLDeadlineStore{DB: sqlDB},
				InstallationID: snapshot.InstallationID,
				Owner:          owner,
				Policy:         policy,
				Limit:          sweepLimit,
			}
			if err := sweeper.Validate(); err != nil {
				return fmt.Errorf("validate deadline sweeper: %w", err)
			}
			loop := systembackupcontroller.ControlLoop{
				Guard: systembackupcontroller.ReadinessProbeSet{
					grantProbe,
					systembackupcontroller.SQLUTCReadinessProbe{DB: sqlDB},
				},
				GateRecovery: gateRecovery,
				KillSwitch:   killSwitch,
				Deadline:     sweeper,
				Interval:     policy.ReconcileInterval,
				OnResult: func(result systembackupcontroller.ControlLoopResult) {
					controllerTelemetry.ObserveReconcile(result, time.Now())
					if result.Err != nil {
						log.Printf("[system-backup-controller] control pass failed gate_selected=%d gate_fenced=%d gate_proof_blocked=%d kill_selected=%d kill_transitioned=%d deadline_selected=%d deadline_acquired=%d deadline_expired=%d: %v", result.GateRecovery.Selected, result.GateRecovery.FencedForRelease, result.GateRecovery.ParticipantProofBlock, result.KillSwitch.Selected, result.KillSwitch.Transitioned, result.Deadline.Selected, result.Deadline.Acquired, result.Deadline.Expired, result.Err)
						return
					}
					log.Printf("[system-backup-controller] control pass gate_selected=%d gate_idle=%d gate_fenced=%d gate_contention=%d gate_proof_blocked=%d kill_selected=%d kill_transitioned=%d kill_contention=%d deadline_selected=%d deadline_acquired=%d deadline_expired=%d deadline_contention=%d guard_rejections=%d", result.GateRecovery.Selected, result.GateRecovery.ReturnedIdle, result.GateRecovery.FencedForRelease, result.GateRecovery.CASContentions, result.GateRecovery.ParticipantProofBlock, result.KillSwitch.Selected, result.KillSwitch.Transitioned, result.KillSwitch.CASContentions, result.Deadline.Selected, result.Deadline.Acquired, result.Deadline.Expired, result.Deadline.ClaimContentions, result.Deadline.GuardRejections)
				},
			}
			log.Printf("[system-backup-controller] runtime start installation=%s matrix=%s config_version=%d config_enabled=%t effective_enabled=%t monitoring_armed=%t applied_migrations=%d catalog=%s", snapshot.InstallationID, snapshot.MatrixKey, snapshot.ConfigVersion, snapshot.ConfigEnabled, snapshot.EffectiveEnabled, snapshot.MonitoringArmed, snapshot.AppliedMigrationCount, snapshot.MigrationCatalogHash)
			leader.Run(runtimeCtx, k8sClient.Clientset, leaderConfig, leader.Callbacks{
				OnStartedLeading: func(leaderCtx context.Context) {
					if !leaderBootstrapReconciled.Load() {
						if err := stateReconciler.Reconcile(leaderCtx, requirements, snapshot); err != nil {
							select {
							case runtimeErrors <- fmt.Errorf("reconcile installation state as leader: %w", err):
							default:
							}
							cancelRuntime()
							return
						}
						if err := gateInitializer.Ensure(leaderCtx, snapshot.InstallationID, snapshot.GatePolicy); err != nil {
							select {
							case runtimeErrors <- fmt.Errorf("ensure capture gate as leader: %w", err):
							default:
							}
							cancelRuntime()
							return
						}
						leaderBootstrapReconciled.Store(true)
					}
					controllerTelemetry.LeaderStarted()
					status.leading.Store(true)
					go runLeaderControlLoop(leaderCtx, loop.Run, runtimeErrors, cancelRuntime)
				},
				OnStoppedLeading: func() {
					status.leading.Store(false)
				},
			})
			status.leading.Store(false)
			select {
			case runtimeErr := <-runtimeErrors:
				return runtimeErr
			default:
				return nil
			}
		},
		OnResult: func(result systembackupcontroller.BootstrapSupervisorResult) {
			if result.Err != nil {
				if status.setBootstrapFailure(result.Err) {
					log.Printf("[system-backup-controller] runtime blocked code=%s: %v", systembackupcontroller.BootstrapFailureCodeOf(result.Err), result.Err)
				}
				return
			}
			if status.setReady(result.Snapshot) {
				log.Printf("[system-backup-controller] runtime ready installation=%s matrix=%s config_version=%d effective_enabled=%t", result.Snapshot.InstallationID, result.Snapshot.MatrixKey, result.Snapshot.ConfigVersion, result.Snapshot.EffectiveEnabled)
			}
		},
	}
	if err := supervisor.Run(rootCtx); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("supervise controller bootstrap: %w", err)
	}
	status.leading.Store(false)
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("[system-backup-controller] %v", err)
	}
}
